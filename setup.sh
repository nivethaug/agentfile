#!/bin/bash
set -euo pipefail

BIN_PATH="$HOME/agent.bin"
LOG_FILE="$HOME/agent_setup.log"
SERVICE_NAME="agent-client"
VENV_BASE_DIR="$HOME/venvalgobn"
REQUIREMENTS_PATH="$VENV_BASE_DIR/requirements.txt"
AGENT_URL="https://github.com/nivethaug/agentfile/releases/download/v7.0.0/agent.bin"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

log "🚀 Starting Agent Setup"


# Get Agent ID from arg or env
AGENT_ID="${1:-${AGENT_ID:-}}"
if [ -z "$AGENT_ID" ]; then
  echo "❌ No AGENT_ID supplied. Use: AGENT_ID=agent-xxxx ./setup_agent_env.sh  (or pass as first arg)"
  exit 1
fi
log "Using AGENT_ID=$AGENT_ID"

# Install deps
if command -v apt >/dev/null 2>&1; then
  sudo apt update -y
  sudo apt install -y nodejs npm curl ca-certificates
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y nodejs npm curl ca-certificates
fi
sudo npm install -g pm2

# Download binary
log "⬇️ Downloading agent binary..."
curl -fsSL "$AGENT_URL" -o "$BIN_PATH"
chmod +x "$BIN_PATH"




# Start/Save PM2 (UTF-8 + AGENT_ID inline)
log "🚀 Starting agent..."
pm2 delete "$SERVICE_NAME" >/dev/null 2>&1 || true
LC_ALL=C.UTF-8 LANG=C.UTF-8 AGENT_ID="$AGENT_ID" \
pm2 start "$BIN_PATH" --name "$SERVICE_NAME"
pm2 save

log "✅ Installed. Logs: pm2 logs $SERVICE_NAME"
