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
# === FIXED REQUIREMENTS (including pipreqs) ===
REQUIREMENTS=$(cat <<EOF
aiofiles
psutil
python-dotenv
aiohttp
httpx
python-crontab
python-socketio
pipreqs
EOF
)

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

# Step 1: Install Python + pip + venv
log "📦 Installing python3, pip3, and venv..."
sudo apt update -y
sudo apt install -y python3 python3-pip python3-venv || {
    log "❌ Failed to install Python packages"; exit 1;
}

# Step 2: Create virtual environment
if [ ! -d "$VENV_BASE_DIR" ]; then
    log "🧪 Creating virtual environment at $VENV_BASE_DIR"
    python3 -m venv "$VENV_BASE_DIR" || {
        log "❌ Failed to create virtual environment"; exit 1;
    }
else
    log "✅ Virtual environment already exists"
fi



# Step 4: Write requirements.txt
echo "$REQUIREMENTS" > "$REQUIREMENTS_PATH"
log "📝 requirements.txt saved at $REQUIREMENTS_PATH"

# Step 5: Install Python packages
log "📦 Installing Python packages in virtualenv..."
pip install --upgrade pip
pip install -r "$REQUIREMENTS_PATH" || {
    log "❌ Package installation failed"; exit 1;
}

# Start/Save PM2 (UTF-8 + AGENT_ID inline)
log "🚀 Starting agent..."
pm2 delete "$SERVICE_NAME" >/dev/null 2>&1 || true
LC_ALL=C.UTF-8 LANG=C.UTF-8 AGENT_ID="$AGENT_ID" \
pm2 start "$BIN_PATH" --name "$SERVICE_NAME"
pm2 save

log "✅ Installed. Logs: pm2 logs $SERVICE_NAME"
