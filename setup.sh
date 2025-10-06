#!/bin/bash
set -euo pipefail

PKG_PATH="$HOME/agent-pyc.tar.gz"
EXTRACT_DIR="$HOME/agent"
LOG_FILE="$HOME/agent_setup.log"
SERVICE_NAME="agent-client"
VENV_BASE_DIR="$HOME/venvalgobn"
REQUIREMENTS_PATH="$VENV_BASE_DIR/requirements.txt"

# Replace with your GitHub tarball URL
AGENT_URL="https://github.com/nivethaug/agentfile/releases/download/v2.1.0/agentpyc.tar.gz"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

log "🚀 Starting Agent Setup"

# Get Agent ID
AGENT_ID="${1:-${AGENT_ID:-}}"
if [ -z "$AGENT_ID" ]; then
  echo "❌ No AGENT_ID supplied. Use: AGENT_ID=agent-xxxx ./setup.sh (or pass as first arg)"
  exit 1
fi
log "Using AGENT_ID=$AGENT_ID"

# Install system deps (includes curl early)
if command -v apt >/dev/null 2>&1; then
  sudo apt update -y
  sudo apt install -y curl nodejs npm ca-certificates python3 python3-pip python3-venv
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y curl nodejs npm ca-certificates python3 python3-pip
else
  log "❌ No supported package manager found (apt or yum)."
  exit 1
fi

# Ensure pm2 installed
sudo npm install -g pm2

# Download tarball
log "⬇️ Downloading agent package..."
curl -fsSL "$AGENT_URL" -o "$PKG_PATH"

# Extract package
log "📦 Extracting agent package to $EXTRACT_DIR"
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$PKG_PATH" -C "$EXTRACT_DIR"

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

# Write runtime requirements
cat > "$REQUIREMENTS_PATH" <<EOF
python-socketio
aiofiles
psutil
python-crontab
python-dotenv
httpx
websockets
aiohttp
EOF
log "📝 requirements.txt saved at $REQUIREMENTS_PATH"

# Install Python packages
log "📦 Installing Python packages..."
pip install --upgrade pip
pip install -r "$REQUIREMENTS_PATH" || log "⚠️ Some packages failed, continuing..."

# Start with PM2
log "🚀 Starting agent..."
pm2 delete "$SERVICE_NAME" >/dev/null 2>&1 || true
LC_ALL=C.UTF-8 LANG=C.UTF-8 AGENT_ID="$AGENT_ID" \
pm2 start "$VENV_BASE_DIR/bin/python" --name "$SERVICE_NAME" \
  --cwd "$EXTRACT_DIR/agent" -- bootstrap.py
pm2 save

log "✅ Installed. Logs: pm2 logs $SERVICE_NAME"
