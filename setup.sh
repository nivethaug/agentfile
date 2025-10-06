#!/bin/bash
set -euo pipefail

PKG_PATH="$HOME/agent-pyc.tar.gz"
EXTRACT_DIR="$HOME/agent"
LOG_FILE="$HOME/agent_setup.log"
SERVICE_NAME="agent-client"

# Use a dedicated 3.11 venv path so we don't clash with older envs
VENV_BASE_DIR="$HOME/venvalgobn311"
REQUIREMENTS_PATH="$VENV_BASE_DIR/requirements.txt"

# Replace with your GitHub tarball URL (ensure filename matches your release)
AGENT_URL="https://github.com/nivethaug/agentfile/releases/download/v2.1.0/agentpyc.tar.gz"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

log "🚀 Starting Agent Setup (Python 3.11)"

# --- Agent ID ---
AGENT_ID="${1:-${AGENT_ID:-}}"
if [ -z "$AGENT_ID" ]; then
  echo "❌ No AGENT_ID supplied. Use: AGENT_ID=agent-xxxx ./setup.sh (or pass as first arg)"
  exit 1
fi
log "Using AGENT_ID=$AGENT_ID"

# --- Base system deps + curl + Node/PM2 ---
if command -v apt >/dev/null 2>&1; then
  sudo apt update -y
  sudo apt install -y curl nodejs npm ca-certificates software-properties-common
  # Install Python 3.11 (Ubuntu/Debian via deadsnakes)
  if ! command -v python3.11 >/dev/null 2>&1; then
    log "➕ Installing Python 3.11 via deadsnakes PPA"
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt update -y
    sudo apt install -y python3.11 python3.11-venv python3.11-distutils
  fi
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y curl nodejs npm ca-certificates
  # Best-effort Python 3.11 on RPM-based (paths vary by distro)
  if ! command -v python3.11 >/dev/null 2>&1; then
    log "➕ Attempting Python 3.11 install (RPM-based)"
    if command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y python3.11 python3.11-devel || true
    else
      sudo yum install -y python3.11 || true
    fi
  fi
else
  log "❌ No supported package manager found (apt or yum)."
  exit 1
fi

# PM2
if ! command -v pm2 >/dev/null 2>&1; then
  sudo npm install -g pm2
fi

# --- Ensure we have python3.11 now ---
if ! command -v python3.11 >/dev/null 2>&1; then
  log "❌ python3.11 not available after install steps. Aborting."
  exit 1
fi
PY311=$(command -v python3.11)
log "✅ Using Python: $PY311 ($($PY311 --version))"

# --- Download package ---
log "⬇️ Downloading agent package..."
curl -fsSL "$AGENT_URL" -o "$PKG_PATH"

# --- Extract package ---
log "📦 Extracting agent package to $EXTRACT_DIR"
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$PKG_PATH" -C "$EXTRACT_DIR"

# --- Create venv with Python 3.11 ---
if [ ! -d "$VENV_BASE_DIR" ]; then
  log "🧪 Creating Python 3.11 virtual environment at $VENV_BASE_DIR"
  "$PY311" -m venv "$VENV_BASE_DIR"
else
  log "✅ Virtual environment already exists: $VENV_BASE_DIR"
fi

# --- Activate venv ---
log "🔑 Activating virtual environment..."
# shellcheck disable=SC1090
source "$VENV_BASE_DIR/bin/activate"

# --- Runtime requirements ---
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

# --- Install Python packages ---
log "📦 Installing Python packages..."
pip install --upgrade pip wheel
pip install -r "$REQUIREMENTS_PATH" || log "⚠️ Some packages failed, continuing..."

# --- Start with PM2 (points to bootstrap.py inside extracted folder) ---
log "🚀 Starting agent under PM2..."
pm2 delete "$SERVICE_NAME" >/dev/null 2>&1 || true
LC_ALL=C.UTF-8 LANG=C.UTF-8 AGENT_ID="$AGENT_ID" \
pm2 start "$VENV_BASE_DIR/bin/python" --name "$SERVICE_NAME" \
  --cwd "$EXTRACT_DIR/agent" -- bootstrap.py
pm2 save

log "✅ Installed. View logs with: pm2 logs $SERVICE_NAME"
