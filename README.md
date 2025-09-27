# WebSocket-Based MVP: Agent Control
AGENT_ID = "agent-14faa38a-9a3a-4fad-9269-6e476c1fc88a"

## Structure

- `server/`: Flask API + WebSocket server
- `agent/`: Agent that connects to API WebSocket
- `client/`: Script to simulate UI/API client

## How to Run

1. Start the API Server:
```bash
cd server
pip install -r requirements.txt
python app.py
```

2. Start the Agent (on VPS or same machine for test):
```bash
cd agent
pip install -r requirements.txt
python agent.py
```

3. Run Client to Trigger Command:
```bash
cd client
python test_request.py
```

Modify the IP/domain in `agent.py` to point to your Flask API server.

Secure the connection using `auth` and `agent_id`.

