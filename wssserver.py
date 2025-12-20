0.# server.py
import asyncio
from datetime import datetime
import json
import sqlite3

import requests
import socketio
from fastapi import FastAPI, HTTPException,Body, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from datetime import datetime, timedelta
import uuid
import httpx
from httpx import HTTPStatusError

def generate_token() -> str:
    return str(uuid.uuid4())
TOKEN_LIFETIME_DAYS = 7  # Default token lifetime

# === CONFIGURATION ===
AUTH_TOKEN = "bf6c405b-2901-48f3-8598-b6f1ef0b2e5a"  # Shared secret for agent registration
Push_NOTIFICATION_KEY = "os_v2_app_wdlpptpojbhpfik7ekric6hhm4qiqixkqqeux6fjfv4myqcruvpzboetkfujhpxgb6pt43thozn5iybpf3df4i4fgy3vzl4wayqam5i"  # FCM server key for push notifications
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
    print(f"[✓] Agent registered: {data}")

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

# Deploy script status update function
    
@sio.on("deploy_started")
async def on_deploy_started(sid, data):
    """
    data = {
      user_id: uuid,
      script_name: str,
      file_path: str | None,
      process_name: str | None,
      type: "pm2",
      job_id: str | None
    }
    """
    print("Deployment started")

    task_id = await insert_deployed_task(
        user_id=data["user_id"],
        script_name=data["script_name"],
        file_path=data.get("file_path"),
        process_name=data.get("process_name"),
        task_type=data.get("type", "pm2"),
        job_id=data.get("job_id"),
        status="deploying",
        log="Deployment started"
    )

    # Send task_id back to agent (CRITICAL)
    await sio.emit("deploy_task_id", {"task_id": task_id}, to=sid)

@sio.on("deploy_done")
async def on_deploy_done(sid, data):
    """
    data = {
      task_id: uuid,
      pm2_process_id: int | None,
      message: str | None
    }
    """
    print("Deployment completed")

    await update_deployed_task(
        task_id=data["task_id"],
        status="running",
        pm2_process_id=data.get("pm2_process_id"),
        log=data.get("message", "Deployment completed successfully"),
        source="agent"
    )

@sio.on("deploy_failed")
async def on_deploy_failed(sid, data):
    """
    data = {
      task_id: uuid,
      error: str
    }
    """
    print(" Deployment failed")

    await update_deployed_task(
        task_id=data["task_id"],
        status="error",
        pm2_process_id=None,
        log=data.get("error", "Deployment failed"),
        source="agent"
    )

async def insert_deployed_task(
    user_id: str,
    script_name: str,
    file_path: str | None,
    process_name: str | None,
    task_type: str,
    job_id: str | None,
    status: str,
    log: str
) -> str:
    transport = AIOHTTPTransport(
        url=GRAPHQL_URL,
        headers={"x-hasura-admin-secret": HASURA_ADMIN_SECRET}
    )

    async with Client(transport=transport, fetch_schema_from_transport=True) as session:

        # Step 1: Insert deployed task
        result = await session.execute(
            gql("""
                mutation InsertDeployedTask(
                  $user_id: uuid!,
                  $script_name: String!,
                  $file_path: String,
                  $process_name: String,
                  $type: String!,
                  $job_id: String,
                  $status: String!
                ) {
                  insert_deployed_tasks_one(
                    object: {
                      user_id: $user_id
                      script_name: $script_name
                      file_path: $file_path
                      process_name: $process_name
                      type: $type
                      job_id: $job_id
                      status: $status
                    }
                  ) {
                    id
                  }
                }
            """),
            variable_values={
                "user_id": user_id,
                "script_name": script_name,
                "file_path": file_path,
                "process_name": process_name,
                "type": task_type,
                "job_id": job_id,
                "status": status
            }
        )

        task_id = result["insert_deployed_tasks_one"]["id"]

        # Step 2: Insert initial log
        await session.execute(
            gql("""
                mutation InsertDeployLog(
                  $task_id: uuid!,
                  $log: String!,
                  $source: String!
                ) {
                  insert_deployed_task_logs_one(
                    object: {
                      task_id: $task_id
                      level: "INFO"
                      source: $source
                      log: $log
                    }
                  ) {
                    id
                  }
                }
            """),
            variable_values={
                "task_id": task_id,
                "log": log,
                "source": "system"
            }
        )

        return task_id

async def update_deployed_task(
    task_id: str,
    status: str,
    log: str,
    source: str,
    pm2_process_id: int | None = None
):
    transport = AIOHTTPTransport(
        url=GRAPHQL_URL,
        headers={"x-hasura-admin-secret": HASURA_ADMIN_SECRET}
    )

    async with Client(transport=transport, fetch_schema_from_transport=True) as session:

        await session.execute(
            gql("""
                mutation UpdateDeployedTask(
                  $task_id: uuid!,
                  $status: String!,
                  $pm2_process_id: Int,
                  $log: String!,
                  $source: String!
                ) {
                  update_deployed_tasks_by_pk(
                    pk_columns: {id: $task_id},
                    _set: {
                      status: $status
                      pm2_process_id: $pm2_process_id
                      updated_at: now()
                    }
                  ) {
                    id
                  }

                  insert_deployed_task_logs_one(
                    object: {
                      task_id: $task_id
                      level: "INFO"
                      source: $source
                      log: $log
                    }
                  ) {
                    id
                  }
                }
            """),
            variable_values={
                "task_id": task_id,
                "status": status,
                "pm2_process_id": pm2_process_id,
                "log": log,
                "source": source
            }
        )

@sio.on("deploy_progress")
async def on_deploy_progress(sid, data):
    """
    data = {
      task_id: uuid,
      log: str,
      level: INFO | ERROR | WARN,
      source: agent | system
    }
    """
    task_id = data["task_id"]
    log = data["log"]
    level = data.get("level", "INFO")
    source = data.get("source", "agent")

    await insert_deploy_log(
        task_id=task_id,
        log=log,
        level=level,
        source=source
    )

async def insert_deploy_log(
    task_id: str,
    log: str,
    level: str = "INFO",
    source: str = "agent"
):
    transport = AIOHTTPTransport(
        url=GRAPHQL_URL,
        headers={"x-hasura-admin-secret": HASURA_ADMIN_SECRET}
    )

    async with Client(transport=transport, fetch_schema_from_transport=True) as session:
        await session.execute(
            gql("""
                mutation InsertDeployLog(
                  $task_id: uuid!,
                  $log: String!,
                  $level: String!,
                  $source: String!
                ) {
                  insert_deployed_task_logs_one(
                    object: {
                      task_id: $task_id
                      log: $log
                      level: $level
                      source: $source
                    }
                  ) {
                    id
                  }
                }
            """),
            variable_values={
                "task_id": task_id,
                "log": log,
                "level": level,
                "source": source
            }
        )

# Deploy script endpoint
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


# ==============================
# TOKEN MANAGEMENT (NEW TABLE)
# This block contains utilities and endpoints for managing tokens separately.
# It is intentionally placed at the end of the file so it is easy to find.
# ==============================

# SQL for token management table:
# CREATE TABLE IF NOT EXISTS tokens (
#     token TEXT PRIMARY KEY,
#     agent_id TEXT,
#     issued_at TEXT,
#     expires_at TEXT,
#     revoked INTEGER DEFAULT 0,
#     meta TEXT
# );

def init_token_table():
    """Create a dedicated tokens table for token lifecycle management."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            agent_id TEXT,
            issued_at TEXT,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            meta TEXT
        );
    ''')
    conn.commit()
    conn.close()

def save_token_entry(token: str, agent_id: str, expires_at: str, meta: str = None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    issued_at = datetime.utcnow().isoformat()
    c.execute('''
        INSERT OR REPLACE INTO tokens (token, agent_id, issued_at, expires_at, revoked, meta)
        VALUES (?, ?, ?, ?, 0, ?)
    ''', (token, agent_id, issued_at, expires_at, meta))
    conn.commit()
    conn.close()

def revoke_token(token: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE tokens SET revoked = 1 WHERE token = ?', (token,))
    conn.commit()
    conn.close()

def is_token_revoked(token: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT revoked FROM tokens WHERE token = ?', (token,))
    row = c.fetchone()
    conn.close()
    return bool(row and row[0] == 1)

def fetch_token_row(token: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT token, agent_id, issued_at, expires_at, revoked, meta FROM tokens WHERE token = ?', (token,))
    row = c.fetchone()
    conn.close()
    return row

def issue_and_store_token_for_agent(agent_id: str, lifetime_days: float = TOKEN_LIFETIME_DAYS, meta: str = None):
    token = generate_token()
    expires_at = (datetime.utcnow() + timedelta(days=lifetime_days)).isoformat()
    save_token_entry(token, agent_id, expires_at, meta)
    return token, expires_at

def validate_token_against_tokens_table(token: str):
    """Validate token using the tokens table: existence, expiry, revoked status.
    Returns associated agent_id if valid, otherwise raises HTTPException."""
    row = fetch_token_row(token)
    if not row:
        raise HTTPException(status_code=403, detail="Invalid token (not found)")

    _token, agent_id, issued_at, expires_at, revoked, meta = row
    if revoked == 1:
        raise HTTPException(status_code=401, detail="Token revoked")

    if expires_at and datetime.utcnow() > datetime.fromisoformat(expires_at):
        raise HTTPException(status_code=401, detail="Token expired")

    return agent_id


# ==============================
# TOKEN API ENDPOINTS
# Includes: Generate, Refresh, and Protected Example
# ==============================


@fastapp.post("/token/generate")
async def generate_token_api(payload: dict = Body(...)):
    """Generate and store a new token for the provided agent_id."""
    agent_id = payload.get("agent_id")
    meta = payload.get("meta")

    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    token, expires_at = issue_and_store_token_for_agent(agent_id, meta=meta)
    return {
        "agent_id": agent_id,
        "token": token,
        "expires_at": expires_at,
        "message": "Token generated successfully"
    }

HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Authorization": f"Basic {Push_NOTIFICATION_KEY}",
}



from typing import List, Optional, Dict, Any


ONESIGNAL_URL = "https://api.onesignal.com/notifications"
ONESIGNAL_APP_ID = "b0d6f7cd-ee48-4ef2-a15f-22a28178e767"

# Config
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.5  # seconds
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 10.0

_DEFAULT_TIMEOUT = httpx.Timeout(
    connect=CONNECT_TIMEOUT,
    read=READ_TIMEOUT,
    write=10.0,
    pool=10.0
)


async def send_notification(contents, headings=None, include_player_ids=None,
                            included_segments=None, data=None, url=None, web_buttons=None):

    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "contents": contents,
    }

    if headings:
        payload["headings"] = headings
    if include_player_ids:
        payload["include_player_ids"] = include_player_ids
    if included_segments:
        payload["included_segments"] = included_segments
    if data:
        payload["data"] = data
    if url:
        payload["url"] = url
    if web_buttons:
        payload["web_buttons"] = web_buttons

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        resp = await client.post(ONESIGNAL_URL, json=payload, headers=HEADERS)
        try:
            resp.raise_for_status()
            try:
                j = resp.json()
            except Exception:
                j = {"raw": resp.text}
            return {"ok": True, "status_code": resp.status_code, "onesignal": j}
        except httpx.HTTPStatusError as e:
            # Log body for debugging
            print("❌ OneSignal error:", e.response.status_code, e.response.text)
            return {
                "ok": False,
                "status_code": e.response.status_code,
                "onesignal": e.response.text,
                "error": str(e),
            }



async def delete_player(player_id= None):
    """
    Permanently delete a player (device) from OneSignal.
    After deletion, that player ID will no longer receive notifications.
    """
    HEADERS = {
        "Content-Type": "application/json;",
        "Authorization": f"Basic {Push_NOTIFICATION_KEY}",
    }
    url = f"https://api.onesignal.com/apps/b0d6f7cd-ee48-4ef2-a15f-22a28178e767/subscriptions/{player_id}"

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        resp = await client.delete(url, headers=HEADERS)
        try:
            resp.raise_for_status()
            return {
                "ok": True,
                "status_code": resp.status_code,
                "response": resp.json() if resp.text else {},
            }
        except httpx.HTTPStatusError as e:
            return {
                "ok": False,
                "status_code": e.response.status_code,
                "error": e.response.text,
            }
        
@fastapp.post("/delete_playerone")
async def delete_playerone(payload: dict = Body(...)):
    """Generate and store a new token for the provided agent_id."""
    player_ids = payload.get("player_ids")

    res = await delete_player(player_id= player_ids)
    return {
        "status": "success" if res.get("ok") else "error",
        "response": res,
        "player_ids": player_ids
    }

@fastapp.post("/send_push")
async def send_push(payload: dict = Body(...)):
    """Generate and store a new token for the provided agent_id."""
    agent_id = payload.get("agent_id")
    meta = payload.get("meta")
    player_ids = payload.get("player_ids")
    title = payload.get("title", "AlgoBillionaire Alert")
    message = payload.get("message", "New trading signal available")
    data = payload.get("data")
    url = payload.get("url")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    res = await send_notification(
        contents={"en": message},
        headings={"en": title},
        include_player_ids=player_ids,
        included_segments=None,
        data=data,
        url=url
    )
    return {
        "status": "success" if res.get("ok") else "error",
        "response": res
    }


@fastapp.post("/token/refresh")
async def refresh_token_api(payload: dict = Body(...)):
    """Refresh (re-issue) a token for an existing agent."""
    old_token = payload.get("token")
    if not old_token:
        raise HTTPException(status_code=400, detail="token is required")

    row = fetch_token_row(old_token)
    if not row:
        raise HTTPException(status_code=403, detail="Invalid token")

    _, agent_id, _, expires_at, revoked, _ = row
    if revoked == 1:
        raise HTTPException(status_code=401, detail="Token revoked")

    # revoke old token
    revoke_token(old_token)

    # issue new one
    new_token, new_expiry = issue_and_store_token_for_agent(agent_id)
    return {
        "agent_id": agent_id,
        "token": new_token,
        "expires_at": new_expiry,
        "message": "Token refreshed successfully"
    }


# ==============================
# PROTECTED ROUTE EXAMPLE
# Demonstrates token-based protection using the tokens table.
# ==============================

def verify_token_dependency(authorization: str = Header(None)):
    """FastAPI dependency for verifying tokens from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split("Bearer ")[1].strip()
    agent_id = validate_token_against_tokens_table(token)
    return agent_id


@fastapp.get("/protected")
async def protected_example(agent_id: str = Depends(verify_token_dependency)):
    """A sample endpoint protected by token authentication."""
    return {
        "message": f"Hello Agent {agent_id}, you have access!",
        "status": "success"
    }

init_token_table()

# NOTE: this new table is separate from the older 'agents' table token field.
# You can choose to (a) keep both in sync, (b) use only the tokens table for auth checks,
# or (c) migrate existing per-agent tokens into this tokens table.
#
# Important next steps (do NOT modify the file automatically if you don't want to):
# 1) Create the tokens table (run once):
#       >>> from wssserver import init_token_table
#       >>> init_token_table()
#
# 2) When issuing a new token for an agent, prefer:
#       token, expires_at = issue_and_store_token_for_agent('agent-123')
#    This will also save the token into the tokens table.
#
# 3) To revoke a token:
#       revoke_token('<token>')
#
# 4) To use the tokens table for request validation, call validate_token_against_tokens_table(token)
#    from your FastAPI dependency instead of (or in addition to) your current verify logic.
#
# 5) If you want the register flow to also write into the tokens table, call:
#       token, expires_at = generate_token_and_expiry()
#       save_token_entry(token, agent_id, expires_at, meta=None)
#    (I left that update out so I didn't modify earlier logic.)


# === FASTAPI ENDPOINTS (UI -> SERVER -> AGENT) ===
# Attach routes to FastAPI app as usual
# @fastapp.get("/")
# async def root():
#     return {"status": "WebSocket new!"}

def verify_agent_exists(payload: dict, token_agent_id:str):
    if payload.get("agent_id") != token_agent_id:
            raise HTTPException(status_code=403, detail="agent_id mismatch")

@fastapp.post("/upload_script")
async def upload_script(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("upload_script", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/upload_script_zip")
async def upload_script_zip(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("upload_script_zip", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
    
@fastapp.post("/upload_script_from_url")
async def upload_script_from_url(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("upload_script_from_url", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
@fastapp.post("/clone_script")
async def clone_script(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("clone_script", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
@fastapp.post("/upload_file")
async def upload_file(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("upload_file", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/delete_file")
async def upload_file(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("delete_file", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_tables")
async def upload_file(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("get_tables", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_table_data")
async def upload_file(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("get_table_data", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/read_file")
async def read_file(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("get_file", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")


@fastapp.post("/run_script")
async def run_script(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        await sio.emit("run_script", payload, to=agents[payload["agent_id"]]["sid"])
        return {"status": "success", "log": "Script execution started -view full logs in the logs page"}
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")


    
@fastapp.post("/run_dependency")
async def run_script(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("run_dependency", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")



@fastapp.post("/deploy_script")
async def deploy_script(
    payload: dict,
    token_agent_id: str = Depends(verify_token_dependency)
):
    try:
        verify_agent_exists(payload, token_agent_id)

        agent_id = payload["agent_id"]
        user_id = payload["user_id"]
        script_name = payload["script_name"]
        script_path = payload["script_path"]

        # 1️⃣ CREATE task_id HERE (IMPORTANT)
        task_id = str(str(uuid.uuid4()))

        # 2️⃣ INSERT deployed_tasks (status = deploying)
        await insert_deployed_task({
            "id": task_id,
            "user_id": user_id,
            "script_name": script_name,
            "file_path": script_path,
            "status": "deploying",
            "type": "pm2"
        })

        # 3️⃣ FIRE-AND-FORGET to agent
        sio.emit(
            "deploy_script",
            {
                **payload,
                "task_id": task_id   
            },
            to=agents[agent_id]["sid"]
        )

        # 4️⃣ RETURN IMMEDIATELY
        return {
            "status": "accepted",
            "task_id": task_id
        }

    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")

@fastapp.post("/run_install_dependency")
async def run_install_script(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("run_install_dependency", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/setup_cron")
async def setup_cron(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("setup_cron", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/remove_cron")
async def remove_cron(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("remove_cron", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/toggle_cron")
async def remove_cron(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("toggle_cron", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
@fastapp.post("/setup_background")
async def setup_cron(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("setup_background", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/remove_pm2")
async def remove_pm2(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("remove_pm2", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/toggle_pm2")
async def remove_cron(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("toggle_pm2", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_logs")
async def get_logs(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("get_logs", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/chatbot")
async def chatbot(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("chatbot", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/get_metrics")
async def get_metrics(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("get_metrics", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
    
@fastapp.post("/get_public_key")
async def get_public_key(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("get_public_key", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
    
@fastapp.post("/get_credentialInfo")
async def get_metrics(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("get_credentialInfo", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/add_exchange_credential")
async def get_metrics(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("add_exchange_credential", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")
@fastapp.post("/delete_credential")
async def delete_credential(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("delete_credential", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")

@fastapp.post("/updateexchange_credential")
async def get_metrics(payload: dict,token_agent_id: str = Depends(verify_token_dependency)):
    try:
        verify_agent_exists(payload, token_agent_id)
        res = await sio.call("updateexchange_credential", payload, to=agents[payload["agent_id"]]["sid"])
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Agent response timeout")


