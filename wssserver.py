# server.py
import asyncio
from datetime import datetime
import sqlite3
import socketio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport

# === CONFIGURATION ===
AUTH_TOKEN = "bf6c405b-2901-48f3-8598-b6f1ef0b2e5a"  # Shared secret for agent registration
DB_PATH = "agents.db"
GRAPHQL_URL = "https://whchkqogsyitogbywgve.graphql.eu-central-1.nhost.run/v1"
HASURA_ADMIN_SECRET = "BtTjE$0+6DHvZ$54IyaPKV)eiVkz@s$E"
ALLOWED_ORIGINS = [
    "https://algobillionaire.com",
    "https://agentapi.algobillionaire.com",
    "http://localhost:3000",
    "http://localhost:8080",
]
# === SOCKET.IO SERVER SETUP ===
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins=ALLOWED_ORIGINS)

fastapp = FastAPI()
app = socketio.ASGIApp(sio, other_asgi_app=fastapp# or "*" if no cookies/credentials
)

# In-memory store for registered agents
agents = {}  # { agent_id: { sid: str } }
ui_clients = {}  # { ui_sid: agent_id }

AGENT_ROOM_PREFIX = "agent:"
def agent_room(agent_id: str) -> str:
    return f"{AGENT_ROOM_PREFIX}{agent_id}"
# === SOCKET.IO EVENTS ===
def register_or_update_agent(agent_id, name, token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute('''
        INSERT INTO agents (agent_id, name, token, last_seen, is_online)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(agent_id) DO UPDATE SET
            name=excluded.name,
            token=excluded.token,
            last_seen=excluded.last_seen,
            is_online=1
    ''', (agent_id, name, token, now))
    conn.commit()
    conn.close()
def mark_all_offline():
    conn = sqlite3.connect("agents.db")
    c = conn.cursor()
    c.execute("UPDATE agents SET is_online = 0")
    conn.commit()
    conn.close()

def mark_agent_offline(agent_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute('''
        UPDATE agents
        SET is_online = 0,
            last_seen = ?
        WHERE agent_id = ?
    ''', (now, agent_id))
    conn.commit()
    conn.close()

mark_all_offline()

@sio.event
async def connect(sid, environ):
    print(f"[+] Client connected: {sid}")


@sio.event
async def disconnect(sid):
    disconnected_agent = None
    if sid in ui_clients:
        agent_id = ui_clients.pop(sid, None)
        if agent_id:
            await sio.leave_room(sid, agent_room(agent_id))
    for agent_id, info in list(agents.items()):
        if info["sid"] == sid:
            disconnected_agent = agent_id
            del agents[agent_id]
            mark_agent_offline(agent_id)
            break
    print(f"[−] Agent {disconnected_agent or sid} disconnected")

@sio.event
async def register_agent(sid, data):
    agent_id = data.get("agent_id")
    auth = data.get("auth")

    # if auth != AUTH_TOKEN:
    #     print(f"[!] Unauthorized attempt from: {sid}")
    #     return

    agents[agent_id] = {"sid": sid}
    register_or_update_agent(agent_id, "agent", AUTH_TOKEN)
    print(f"[✓] Agent registered: {agent_id}")

@sio.event
async def ui_register(sid, data):
    agent_id = data.get("agent_id")
    if not agent_id:
        return {"status": "error", "message": "agent_id required"}

    old_agent = ui_clients.get(sid)
    if old_agent and old_agent != agent_id:
        await sio.leave_room(sid, agent_room(old_agent))

    await sio.enter_room(sid, agent_room(agent_id))
    ui_clients[sid] = agent_id
    print(f"[👤] UI {sid} subscribed to {agent_id}")
    return {"status": "success"}


# ==============================
# TERMINAL RELAY
# ==============================
@sio.event
async def exec_command(sid, data):
    agent_id = data.get("agent_id")
    if not agent_id or agent_id not in agents:
        return {"status": "error", "message": "Agent not connected"}
    try:
        res = await sio.call("exec_command", data, to=agents[agent_id]["sid"], timeout=30)
        return res or {"status": "ok"}
    except asyncio.TimeoutError:
        return {"status": "error", "message": "Agent timed out"}

@sio.event
async def command_output(sid, data):
    agent_id = data.get("agent_id")
    if not agent_id:
        return
    await sio.emit("command_output", data, room=agent_room(agent_id))

@sio.event
async def script_output(sid, data):
    agent_id = data.get("agent_id")
    filename = data.get("filename")
    log = data.get("log", "")
    print(f"[📝 Output from {agent_id} | {filename}]\n{log[-500:]}")

@sio.event
async def metrics(sid, data):
    print(f"[📊 Metrics from {data.get('agent_id')}]: {data}")

# When agent reports completion
@sio.on("script_done")
async def on_script_done(sid, data):
    script_id = data["script_id"]
    print(f"[✓] Script {script_id} completed successfully.")
    await update_script_status(script_id, "stopped", "success")

@sio.on("script_failed")
async def on_script_failed(sid, data):
    script_id = data["script_id"]
    print(f"[❌] Script {script_id} failed.")
    await update_script_status(script_id, "stopped", "error")

async def update_script_status(script_id, status, log_status):
    HEADERS = {
    "x-hasura-admin-secret": HASURA_ADMIN_SECRET
    }
    transport = AIOHTTPTransport(url=GRAPHQL_URL, headers=HEADERS)
    async with Client(transport=transport, fetch_schema_from_transport=True) as session:
        # Step 1: Fetch current config
        get_config_query = gql("""
            query GetScriptConfig($id: uuid!) {
                scripts_by_pk(id: $id) {
                    config
                }
            }
        """)
        response = await session.execute(get_config_query, variable_values={"id": script_id})
        config = response["scripts_by_pk"]["config"]

        # Step 2: Update status in config
        config["status"] = status  # e.g., "Running", "Stopped"

        # Step 3: Update both config and script_logs in a single mutation
        mutation = gql("""
            mutation UpdateBoth($id: uuid!, $config: jsonb!, $log_status: String!) {
              update_scripts_by_pk(pk_columns: {id: $id}, _set: {config: $config}) {
                id
              }
              update_script_logs(where: {script_id: {_eq: $id}}, _set: {status: $log_status}) {
                affected_rows
              }
            }
        """)

        variables = {
            "id": script_id,
            "config": config,
            "log_status": log_status  # e.g., "success", "error"
        }

        result = await session.execute(mutation, variable_values=variables)
        return result

    

# === UTILITY FUNCTION TO SEND COMMAND TO AGENT AND WAIT FOR RESPONSE ===
async def send_to_agent(agent_id: str, event: str, payload: dict, timeout: int = 5):
    agent = agents.get(agent_id)
    if agent:
        try:
            response = await sio.call(event, payload, to=agent["sid"], timeout=timeout)
            print(f"[✓] Response from agent '{agent_id}' for event '{event}': {response}")
            return response  # this could be metrics, logs, etc.
        except asyncio.TimeoutError:
            print(f"[⚠️] Agent '{agent_id}' did not respond to '{event}' in time.")
            return None
    return None
fastapp.add_middleware(
    CORSMiddleware,
 allow_origins=ALLOWED_ORIGINS,
         allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# === FASTAPI ENDPOINTS (UI -> SERVER -> AGENT) ===
# Attach routes to FastAPI app as usual
@fastapp.get("/")
async def root():
    return {"status": "WebSocket new!"}

@fastapp.post("/upload_script")
async def upload_script(payload: dict):
    try:
        res = await sio.call("upload_script", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
    
@fastapp.post("/upload_script_from_url")
async def upload_script_from_url(payload: dict):
    try:
        res = await sio.call("upload_script_from_url", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
@fastapp.post("/clone_script")
async def clone_script(payload: dict):
    try:
        res = await sio.call("clone_script", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
@fastapp.post("/upload_file")
async def upload_file(payload: dict):
    try:
        res = await sio.call("upload_file", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/delete_file")
async def upload_file(payload: dict):
    try:
        res = await sio.call("delete_file", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_tables")
async def upload_file(payload: dict):
    try:
        res = await sio.call("get_tables", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_table_data")
async def upload_file(payload: dict):
    try:
        res = await sio.call("get_table_data", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/read_file")
async def read_file(payload: dict):
    try:
        res = await sio.call("get_file", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")


@fastapp.post("/run_script")
async def run_script(payload: dict):
    try:
        await sio.emit("run_script", payload, to=agents[payload["agent_id"]]["sid"])
        return {"status": "success", "log": "Script execution started -view full logs in the logs page"}
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")


    
@fastapp.post("/run_dependency")
async def run_script(payload: dict):
    try:
        res = await sio.call("run_dependency", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/run_install_dependency")
async def run_install_script(payload: dict):
    try:
        res = await sio.call("run_install_dependency", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/setup_cron")
async def setup_cron(payload: dict):
    try:
        res = await sio.call("setup_cron", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/remove_cron")
async def remove_cron(payload: dict):
    try:
        res = await sio.call("remove_cron", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/toggle_cron")
async def remove_cron(payload: dict):
    try:
        res = await sio.call("toggle_cron", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
@fastapp.post("/setup_background")
async def setup_cron(payload: dict):
    try:
        res = await sio.call("setup_background", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/remove_pm2")
async def remove_pm2(payload: dict):
    try:
        res = await sio.call("remove_pm2", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/toggle_pm2")
async def remove_cron(payload: dict):
    try:
        res = await sio.call("toggle_pm2", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_logs")
async def get_logs(payload: dict):
    try:
        res = await sio.call("get_logs", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/chatbot")
async def chatbot(payload: dict):
    try:
        res = await sio.call("chatbot", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_metrics")
async def get_metrics(payload: dict):
    try:
        res = await sio.call("get_metrics", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")


