#!/bin/bash
set -euo pipefail

HOMEDIR="$HOME/algobn-agent"
LOG_FILE="$HOMEDIR/agent_setup.log"
SERVICE_NAME="agent-client"
VENV_BASE_DIR="$HOMEDIR/venvalgobn"
REQUIREMENTS_PATH="$VENV_BASE_DIR/requirements.txt"
EXTRACT_DIR="$HOMEDIR/agent"
AGENT_PATH="$EXTRACT_DIR/agent.py"
MACHINE_ID=$(uuidgen)

mkdir -p "$HOMEDIR"   # ✅ ensure directory exists before writing log

# Direct URL to agent.py
AGENT_URL="https://github.com/nivethaug/agentfile/releases/download/v1.2.0/agent.py"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

log "🚀 Starting Agent Setup"

# Get Agent ID
AGENT_ID="${1:-${AGENT_ID:-}}"
if [ -z "${AGENT_ID}" ]; then
  echo "❌ No AGENT_ID supplied. Use: AGENT_ID=agent-xxxx ./setup.sh (or pass as first arg)"
  exit 1
fi
log "Using AGENT_ID=$AGENT_ID"

# Install only minimal system deps (no desktop/X11 packages)
if command -v apt >/dev/null 2>&1; then
  sudo apt update -y
  sudo apt install -y --no-install-recommends \
    curl ca-certificates python3 python3-pip python3-venv nodejs npm
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y curl ca-certificates python3 python3-pip nodejs npm
else
  log "❌ No supported package manager found (apt or yum)."
  exit 1
fi

# Ensure pm2 installed
sudo npm install -g pm2

# Prepare app dir
log "📁 Preparing directory at $EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"

# Download agent.py directly
log "⬇️ Downloading agent.py to $AGENT_PATH"
curl -fsSL "$AGENT_URL" -o "$AGENT_PATH"
chmod +x "$AGENT_PATH"

# Create venv if missing
if [ ! -d "$VENV_BASE_DIR" ]; then
  log "🧪 Creating virtual environment at $VENV_BASE_DIR"
  python3 -m venv "$VENV_BASE_DIR"
else
  log "✅ Virtual environment already exists"
fi

# Activate venv
log "🔑 Activating virtual environment..."
# shellcheck disable=SC1091
source "$VENV_BASE_DIR/bin/activate"

# Write runtime requirements (adjust as needed)
cat > "$REQUIREMENTS_PATH" <<EOF
python-socketio
aiofiles
psutil
python-crontab
python-dotenv
httpx
websockets
aiohttp
pipreqs
EOF
log "📝 requirements.txt saved at $REQUIREMENTS_PATH"

# Install Python packages
log "📦 Installing Python packages..."
pip install --upgrade pip
pip install -r "$REQUIREMENTS_PATH" || log "⚠️ Some packages failed, continuing..."

# Start with PM2 (runs agent.py directly)
log "🚀 Starting agent with PM2..."
pm2 delete "$SERVICE_NAME" >/dev/null 2>&1 || true
LC_ALL=C.UTF-8 LANG=C.UTF-8 \
AGENT_ID="$AGENT_ID" \
HOME_DIR="$HOMEDIR" \
MACHINE_ID="$MACHINE_ID" \
pm2 start "$VENV_BASE_DIR/bin/python" --name "$SERVICE_NAME" \
  --cwd "$EXTRACT_DIR" -- "$AGENT_PATH"
pm2 save

log "✅ Installed. View logs with: pm2 logs $SERVICE_NAME"
