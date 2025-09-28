#!/bin/bash
set -euo pipefail

BIN_PATH="$HOME/agent.bin"
LOG_FILE="$HOME/agent_setup.log"
SERVICE_NAME="agent-client"
VENV_BASE_DIR="$HOME/venvalgobn"
REQUIREMENTS_PATH="$VENV_BASE_DIR/requirements.txt"
AGENT_URL="https://github.com/nivethaug/agentfile/releases/download/v2.0.0/agent.bin"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

log "🚀 Starting Agent Setup"

# Get Agent ID
AGENT_ID="${1:-${AGENT_ID:-}}"
if [ -z "$AGENT_ID" ]; then
  echo "❌ No AGENT_ID supplied. Use: AGENT_ID=agent-xxxx ./setup.sh (or pass as first arg)"
  exit 1
fi
log "Using AGENT_ID=$AGENT_ID"

# Install system deps
if command -v apt >/dev/null 2>&1; then
  sudo apt update -y
  sudo apt install -y nodejs npm curl ca-certificates python3 python3-pip python3-venv
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y nodejs npm curl ca-certificates python3 python3-pip
fi
sudo npm install -g pm2

# Download agent binary
log "⬇️ Downloading agent binary..."
curl -fsSL "$AGENT_URL" -o "$BIN_PATH"
chmod +x "$BIN_PATH"

# Create venv if missing
if [ ! -d "$VENV_BASE_DIR" ]; then
  log "🧪 Creating virtual environment at $VENV_BASE_DIR"
  python3 -m venv "$VENV_BASE_DIR"
else
  log "✅ Virtual environment already exists"
fi

# Activate venv
log "🔑 Activating virtual environment..."
source "$VENV_BASE_DIR/bin/activate"

# Write requirements (includes pipreqs)
cat > "$REQUIREMENTS_PATH" <<EOF
pipreqs
EOF
log "📝 requirements.txt saved at $REQUIREMENTS_PATH"

# Install Python packages inside venv
log "📦 Installing Python packages..."
pip install --upgrade pip
pip install -r "$REQUIREMENTS_PATH"

# Start/Save PM2
log "🚀 Starting agent..."
pm2 delete "$SERVICE_NAME" >/dev/null 2>&1 || true
LC_ALL=C.UTF-8 LANG=C.UTF-8 AGENT_ID="$AGENT_ID" \
pm2 start "$BIN_PATH" --name "$SERVICE_NAME"
pm2 save

log "✅ Installed. Logs: pm2 logs $SERVICE_NAME"
