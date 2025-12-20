#!/bin/bash
set -euo pipefail

# --- Match variables from setup.sh (adjust if you used different paths) ---
LOG_FILE="$HOME/agent_setup.log"
SERVICE_NAME="agent-client"
VENV_BASE_DIR="$HOME/venvalgobn"
REQUIREMENTS_PATH="$VENV_BASE_DIR/requirements.txt"
EXTRACT_DIR="$HOME/agent"
AGENT_PATH="$EXTRACT_DIR/agent.py"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

log "🧹 Starting uninstall for $SERVICE_NAME"

# 1) Stop & remove PM2 process (if pm2 present)
if command -v pm2 >/dev/null 2>&1; then
  log "⛔ Stopping PM2 process: $SERVICE_NAME (if running)"
  pm2 stop "$SERVICE_NAME" 2>/dev/null || true
  pm2 delete "$SERVICE_NAME" 2>/dev/null || true

  log "🗂️ Removing pm2 saved process list"
  pm2 save --force >/dev/null 2>&1 || true

  # Try to remove pm2 startup (system integration)
  log "🔁 Attempting to remove PM2 startup integration (systemd/upstart/etc.)"
  pm2 unstartup systemd >/dev/null 2>&1 || true
  pm2 unstartup >/dev/null 2>&1 || true
else
  log "ℹ️ pm2 not found on PATH — skipping pm2 stop/delete steps"
fi

# 2) Remove the agent directory and file
if [ -d "$EXTRACT_DIR" ] || [ -f "$AGENT_PATH" ]; then
  log "🗑️ Removing agent directory: $EXTRACT_DIR"
  rm -rf "$EXTRACT_DIR"
else
  log "ℹ️ No agent directory found at $EXTRACT_DIR"
fi

# 3) Remove virtual environment and installed Python packages
if [ -d "$VENV_BASE_DIR" ]; then
  log "🗑️ Removing virtual environment at $VENV_BASE_DIR"
  rm -rf "$VENV_BASE_DIR"
else
  log "ℹ️ Virtual environment not found at $VENV_BASE_DIR"
fi

# 4) Remove leftover requirement file (in case venv removed but file persisted)
if [ -f "$REQUIREMENTS_PATH" ]; then
  log "🗑️ Removing requirements file: $REQUIREMENTS_PATH"
  rm -f "$REQUIREMENTS_PATH"
fi

# 5) Remove log file
if [ -f "$LOG_FILE" ]; then
  log "🗑️ Removing log file: $LOG_FILE"
  rm -f "$LOG_FILE"
fi

# 6) Optionally uninstall pm2 globally (requires sudo / user decision)
echo
log "⚠️ Optional: pm2 may have been installed globally via 'sudo npm install -g pm2'."
log "If you want to remove the global pm2 package, run one of the following (pick appropriate):"
echo "  sudo npm uninstall -g pm2"
echo "  # or, if installed with yarn:"
echo "  sudo yarn global remove pm2"
echo

# 7) Print summary
log "✅ Uninstall steps completed (some optional items require manual action shown above)."
log "Check pm2 processes with: pm2 ls   (or 'command -v pm2' to see if pm2 is still installed)"
log "If you want to also remove any systemd service created for pm2, handle via: sudo systemctl disable <service> && sudo systemctl stop <service>"

exit 0
