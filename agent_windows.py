# agent_windows.py -- Windows-only consolidated agent with internal scheduler
# PRESERVE: upload, clone, exec_command, run_script, background (pm2) handlers, sqlite helpers, metrics, logs
# Windows-only: Task Scheduler / crontab removed; internal APScheduler used instead.

import os
import sys
import uuid
import ast
import shutil
import base64
import logging
import subprocess
import asyncio
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

# Third-party
import socketio
import psutil
import aiofiles
from dotenv import load_dotenv

# APScheduler for internal cron replacement
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.cron import CronTrigger
import traceback

# SQLite for some helpers
import sqlite3

# -------------------------
# Configuration / Defaults
# -------------------------
load_dotenv()

# Core config
SERVER_URL = os.getenv("AGENT_SERVER_URL", "https://agentapi.algobillionaire.com")
AGENT_ID = os.getenv("AGENT_ID", "agent-42e200f3-9cd6-44ee-a66a-0bab14d3490c")
AUTH_TOKEN = os.getenv("AGENT_AUTH_TOKEN", "bf6c405b-2901-48f3-8598-b6f1ef0b2e5a")

HOME_DIR = os.path.expanduser("~")
SCRIPT_DIR = os.path.join(HOME_DIR, "scripts")
LOG_BASE_DIR = os.path.join(HOME_DIR, "logs")
VENV_BASE_DIR = os.path.join(HOME_DIR, "venvalgobn")

MAX_FILE_SIZE_KB = 250
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_KB * 1024

# Ensure folders exist
os.makedirs(SCRIPT_DIR, exist_ok=True)
os.makedirs(LOG_BASE_DIR, exist_ok=True)
os.makedirs(VENV_BASE_DIR, exist_ok=True)

# Socket.io client
sio = socketio.AsyncClient()


agent_logger = logging.getLogger("agent")

def run_script_job(agent_id: str, script_id: str, filepath: str, cron_id: str | None = None):
    """
    Run a Python script scheduled by APScheduler.
    Uses setup_logger() to determine log path and captures script output.
    """
    try:
        logger = setup_logger(agent_id, script_id, mode="cron", cron_id=cron_id)

        if not os.path.exists(filepath):
            logger.warning(f"Script not found: {filepath}")
            return
        print(f"Running scheduled script: {filepath}{' (cron_id=' + cron_id + ')'}")
        log_dir = os.path.dirname(logger.handlers[0].baseFilename)
        log_path = os.path.join(log_dir, "cron.log")

        start_time = datetime.now()
        logger.info(f"=== Cron run started for {filepath} ===")

        with open(log_path, "a", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                [sys.executable, filepath],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=os.path.dirname(filepath),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            process.wait()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"✅ Cron run finished in {duration:.2f}s for {filepath}")

    except Exception as e:
        # Use a safe fallback logger if setup_logger fails
        fallback = logging.getLogger("cron_fallback")
        fallback.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        fallback.addHandler(handler)
        fallback.error(f"Error in run_script_job: {e}", exc_info=True)


# -------------------------
# Logging helpers
# -------------------------
def setup_logger(agent_id: str, script_id: str, mode: str = "run", cron_id: str | None = None) -> logging.Logger:
    """
    Create or get a logger that writes into LOG_BASE_DIR/<agent_id>/<script_id>/<mode>.log
    """
    if cron_id:
        log_dir = os.path.join(LOG_BASE_DIR, cron_id)
    else:
        log_dir = os.path.join(LOG_BASE_DIR, agent_id, script_id)
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{mode}.log")
    logger_name = f"{agent_id}_{script_id}_{mode}" if not cron_id else f"{cron_id}_{mode}"

    lg = logging.getLogger(logger_name)
    lg.setLevel(logging.INFO)
    lg.propagate = False

    if not lg.handlers:
        handler = TimedRotatingFileHandler(log_file, when="D", interval=1, backupCount=10, encoding="utf-8")
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        lg.addHandler(handler)
    return lg

# Agent-level logger
agent_logger = setup_logger(AGENT_ID, "agent", "main")

# -------------------------
# Venv helpers (per-agent)
# -------------------------
def venv_paths(venv_base_dir: str, user_id: str):
    """Return (venv_dir, python_bin, pip_bin) for Windows-only layout."""
    venv_dir = os.path.join(venv_base_dir, user_id)
    python_bin = os.path.join(venv_dir, "Scripts", "python.exe")
    pip_bin = os.path.join(venv_dir, "Scripts", "pip.exe")
    return venv_dir, python_bin, pip_bin

def create_venv_if_needed(venv_dir: str, logger: logging.Logger | None = None):
    """Create venv using the running python if not exists."""
    python_exe = sys.executable
    if not os.path.exists(venv_dir):
        agent_logger.info(f"Creating venv at {venv_dir}")
        res = subprocess.run([python_exe, "-m", "venv", venv_dir], capture_output=True, text=True)
        if res.returncode != 0:
            msg = f"Failed to create venv at {venv_dir}: {res.stderr or res.stdout}"
            (logger.error if logger else agent_logger.error)(msg)
            raise RuntimeError(msg)
        else:
            (logger.info if logger else agent_logger.info)(f"Created venv at {venv_dir}")

# -------------------------
# APScheduler (internal cron)
# -------------------------
JOB_DB = os.path.join(LOG_BASE_DIR, "scheduler_jobs.sqlite")
os.makedirs(os.path.dirname(JOB_DB), exist_ok=True)
jobstores = {'default': SQLAlchemyJobStore(url=f"sqlite:///{JOB_DB}")}
scheduler = AsyncIOScheduler(jobstores=jobstores)

def _make_job_id(instance_tag: str | None = None):
    base = str(uuid.uuid4())
    if instance_tag:
        return f"{base}_{instance_tag}"
    return base

# -------------------------
# Upload / Clone / File IO
# -------------------------
@sio.on("upload_script")
async def on_upload_script(data):
    """
    data: {
      agent_id, filename, content (base64 or escaped string)
    }
    """
    try:
        user_id = data['agent_id']
        filename = data['filename']
        content = data['content']

        script_id = str(uuid.uuid4())
        script_dir = os.path.join(SCRIPT_DIR, user_id, script_id)
        os.makedirs(script_dir, exist_ok=True)

        script_path = os.path.join(script_dir, filename)
        content_size = len(content.encode('utf-8'))
        if content_size > MAX_FILE_SIZE_BYTES:
            return {"status": "error", "log": f"Script too large. Max allowed is {MAX_FILE_SIZE_KB} KB."}

        # Try to clean content if it was quoted/escaped
        try:
            cleaned = ast.literal_eval(f'"{content}"')
        except Exception:
            cleaned = content

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(cleaned)
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            pass

        agent_logger.info(f"[upload_script] Saved {filename} for user {user_id} at {script_path} ({content_size} bytes)")

        # per-agent venv
        venv_dir, _, _ = venv_paths(VENV_BASE_DIR, user_id)
        create_venv_if_needed(venv_dir, None)

        # generate install.txt (pipreqs)
        req_output_path = os.path.join(script_dir, "install.txt")
        try:
            res = subprocess.run(["pipreqs", script_dir, "--force", "--savepath", req_output_path],
                                 capture_output=True, text=True)
            if res.returncode != 0:
                agent_logger.warning(f"pipreqs failed: {res.stderr or res.stdout}")
            else:
                agent_logger.info(f"install.txt generated at {req_output_path}")
        except FileNotFoundError:
            agent_logger.warning("pipreqs not found in PATH; skipping install.txt generation")

        return {
            "status": "success",
            "path": script_path,
            "size": content_size,
            "script_id": script_id,
            "installed_path": req_output_path,
            "install_error": '',
            "log": f"Script {filename} uploaded successfully and dependencies file created as install.txt"
        }
    except Exception as e:
        agent_logger.exception("upload_script error")
        return {"status": "error", "log": f"Upload failed: {str(e)}"}

@sio.on("clone_script")
async def on_clone_script(data):
    try:
        user_id = data['agent_id']
        existing_script_id = data['existing_script_id']
        skip_venv = data.get("skip_venv", True)

        existing_script_dir = os.path.join(SCRIPT_DIR, user_id, existing_script_id)
        if not os.path.exists(existing_script_dir):
            return {"status": "error", "log": f"Existing script ID {existing_script_id} not found for user {user_id}"}

        new_script_id = str(uuid.uuid4())
        new_script_dir = os.path.join(SCRIPT_DIR, user_id, new_script_id)
        os.makedirs(new_script_dir, exist_ok=True)

        common_venv_names = {"venv", "venv3", "env", ".venv"}
        skip_dirs = common_venv_names if skip_venv else set()

        for root, dirs, files in os.walk(existing_script_dir):
            rel_root = os.path.relpath(root, existing_script_dir)
            dest_root = os.path.join(new_script_dir, rel_root) if rel_root != "." else new_script_dir
            os.makedirs(dest_root, exist_ok=True)
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                src_path = os.path.join(root, fname)
                dest_path = os.path.join(dest_root, fname)
                shutil.copy2(src_path, dest_path)
                try:
                    os.chmod(dest_path, os.stat(src_path).st_mode)
                except Exception:
                    pass

        agent_logger.info(f"[clone_script] {existing_script_id} -> {new_script_id} for user {user_id}")
        return {"status": "success", "script_id": new_script_id, "path": new_script_dir, "log": "Script directory cloned successfully"}
    except Exception as e:
        agent_logger.exception("clone_script error")
        return {"status": "error", "log": f"Clone failed: {str(e)}"}

# -------------------------
# Dependency installation (background)
# -------------------------
async def _background_install(sio_client, *, user_id: str, script_dir: str, script_id: str, venv_base_dir: str, logger):
    try:
        venv_dir, _, pip_path = venv_paths(venv_base_dir, user_id)
        create_venv_if_needed(venv_dir, logger)

        req_output_path = os.path.join(script_dir, "install.txt")
        if not os.path.exists(req_output_path):
            msg = f"[⛔] install.txt not found at {req_output_path}"
            logger.error(msg)
            await sio_client.emit("install_done", {"status": "error", "agent_id": user_id, "script_id": script_id, "log": msg})
            return

        cmd = [pip_path, "install", "-r", req_output_path]
        logger.info(f"[install] Running: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=script_dir,
            env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
            creationflags=0  # CREATE_NO_WINDOW not needed as this is already background service/user process
        )

        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            if text:
                logger.info(text)
                await sio_client.emit("install_log", {"agent_id": user_id, "script_id": script_id, "line": text})

        rc = await proc.wait()
        if rc == 0:
            msg = f"[✅] Dependencies installed in {venv_dir}"
            logger.info(msg)
            await sio_client.emit("install_done", {"status": "success", "agent_id": user_id, "script_id": script_id, "log": msg})
        else:
            msg = f"[⛔] pip exited with code {rc}"
            logger.error(msg)
            await sio_client.emit("install_done", {"status": "error", "agent_id": user_id, "script_id": script_id, "log": msg})
    except Exception as e:
        logger.exception("run_dependency error")
        await sio_client.emit("install_done", {"status": "error", "agent_id": user_id, "script_id": script_id, "log": str(e)})

@sio.on("run_install_dependency")
async def on_run_install_dependency(data):
    user_id = data["agent_id"]
    script_dir = data["filepath"]
    script_id = data.get("script_id", "unknown")
    lg = setup_logger(AGENT_ID, script_id, "run")
    asyncio.create_task(_background_install(
        sio,
        user_id=user_id,
        script_dir=script_dir,
        script_id=script_id,
        venv_base_dir=VENV_BASE_DIR,
        logger=lg,
    ))
    return {"status": "success", "log": f"[🚀] Dependencies installation started. Check logs for progress."}

@sio.on("run_install_dependency_r")
async def on_run_install_dependency_r(data):
    try:
        user_id = data['agent_id']
        script_dir = data['filepath']
        script_id = data.get('script_id', 'unknown')
        lg = setup_logger(AGENT_ID, script_id, "run")
        venv_dir, _, pip_path = venv_paths(VENV_BASE_DIR, user_id)
        create_venv_if_needed(venv_dir, lg)
        req_output_path = os.path.join(script_dir, "install.txt")

        if not os.path.exists(req_output_path):
            msg = f"[⛔] install.txt not found at {req_output_path}"
            lg.error(msg)
            return {"status": "error", "log": msg}

        res = subprocess.run([pip_path, "install", "-r", req_output_path], capture_output=True, text=True)
        msg = f"[✅] Dependencies installed in {venv_dir}"
        lg.info(msg)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            lg.exception(err)
            return {"status": "error", "log": f"run_dependency failed: {str(err)}"}
        return {"status": "success", "log": msg}
    except Exception as e:
        agent_logger.exception("run_install_dependency_r error")
        return {"status": "error", "log": f"run_dependency failed: {str(e)}"}

# -------------------------
# File upload / get / delete
# -------------------------
@sio.on("upload_file")
async def on_upload_file(data):
    try:
        path = data['path']
        filename = data['filename']
        file_bytes_b64 = data['file_bytes']
        try:
            file_bytes = base64.b64decode(file_bytes_b64)
        except Exception as e:
            raise ValueError("Failed to decode base64 content") from e

        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            return {"status": "error", "log": f"File too large. Max allowed is {MAX_FILE_SIZE_KB} KB."}

        script_dir = os.path.join(path)
        os.makedirs(script_dir, exist_ok=True)
        file_path = os.path.join(script_dir, filename)
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(file_bytes)

        agent_logger.info(f"[upload_file] Saved {filename} at {file_path}")
        return {"status": "success", "path": file_path, "size": len(file_bytes), "filename": filename, "log": f"File '{filename}' uploaded successfully"}
    except Exception as e:
        agent_logger.exception("upload_file error")
        return {"status": "error", "log": f"Upload failed: {str(e)}"}

@sio.on("get_file")
async def on_get_file(data):
    try:
        filepath = data['filepath']
        if ".." in filepath or not os.path.isfile(filepath):
            return {"status": "error", "log": f"Invalid file path: {filepath}"}
        async with aiofiles.open(filepath, "r", encoding="utf-8") as f:
            content = await f.read()
        return {"status": "success", "filepath": filepath, "filename": os.path.basename(filepath), "content": content, "log": f"File '{os.path.basename(filepath)}' read successfully"}
    except Exception as e:
        agent_logger.exception("get_file error")
        return {"status": "error", "log": f"Read failed: {str(e)}"}

@sio.on("delete_file")
async def on_delete_file(data):
    try:
        path = data['path']
        is_folder = data.get('is_folder', False)
        target_path = path
        if is_folder:
            if not os.path.isdir(target_path):
                return {"status": "error", "log": f"Folder not found at '{target_path}'"}
            shutil.rmtree(target_path)
            agent_logger.info(f"[delete_file] Folder deleted: {target_path}")
            return {"status": "success", "log": f"Folder '{target_path}' deleted successfully", "path": target_path}
        else:
            if not os.path.isfile(target_path):
                return {"status": "error", "log": f"File not found at '{target_path}'"}
            os.remove(target_path)
            agent_logger.info(f"[delete_file] File deleted: {target_path}")
            return {"status": "success", "log": f"File '{target_path}' deleted successfully", "path": target_path}
    except Exception as e:
        agent_logger.exception("delete_file error")
        return {"status": "error", "log": f"Delete failed: {str(e)}"}

# -------------------------
# Exec command (shell)
# -------------------------
@sio.on("exec_command")
async def on_exec_command(data):
    agent_id = data.get("agent_id", AGENT_ID)
    command = data.get("command")
    cwd = data.get("cwd", HOME_DIR)
    if not command:
        return {"status": "error", "log": "No command provided"}
    try:
        # Handle 'cd' manually
        if command.startswith("cd "):
            new_dir = command[3:].strip()
            new_cwd = os.path.abspath(os.path.join(cwd, new_dir))
            if os.path.isdir(new_cwd):
                cwd = new_cwd
                await sio.emit("command_output", {"agent_id": agent_id, "line": f"Changed directory to {cwd}", "cwd": cwd, "done": True})
                return {"status": "success", "cwd": cwd}
            else:
                await sio.emit("command_output", {"agent_id": agent_id, "line": f"[⛔] No such directory: {new_dir}", "cwd": cwd, "done": True})
                return {"status": "error", "cwd": cwd}

        process = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # stream stdout
        assert process.stdout is not None
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            await sio.emit("command_output", {"agent_id": agent_id, "line": line.decode(errors="replace").rstrip(), "cwd": cwd})

        # stream stderr
        assert process.stderr is not None
        while True:
            line = await process.stderr.readline()
            if not line:
                break
            await sio.emit("command_output", {"agent_id": agent_id, "line": "[⛔] " + line.decode(errors="replace").rstrip(), "cwd": cwd})

        await process.wait()
        await sio.emit("command_output", {"agent_id": agent_id, "line": f"[✔] Command finished with code {process.returncode}", "cwd": cwd, "done": True})
        return {"status": "success", "cwd": cwd}
    except Exception as e:
        agent_logger.exception("exec_command error")
        await sio.emit("command_output", {"agent_id": agent_id, "line": f"[⛔] {str(e)}", "cwd": cwd, "done": True})
        return {"status": "error", "cwd": cwd, "log": str(e)}

# -------------------------
# Run a single script (sync)
# -------------------------
@sio.on("run_script")
async def on_run_script(data):
    filepath = data['filepath']
    script_id = data.get('script_id', 'unknown')
    lg = setup_logger(AGENT_ID, script_id, "run")
    try:
        agent_logger.info(f"[run_script] Running script: {filepath}")
        user_id = data.get('agent_id', AGENT_ID)
        venv_dir, python_bin, _ = venv_paths(VENV_BASE_DIR, user_id)
        create_venv_if_needed(venv_dir, lg)

        proc = await asyncio.create_subprocess_exec(
            python_bin, "-u", filepath,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()
        output = (stdout.decode(errors="replace") if stdout else "") + "\n" + (stderr.decode(errors="replace") if stderr else "")
        status = "script_done" if proc.returncode == 0 else "script_failed"

        lg.info("=== Script Run ===\n%s", output.strip())
        agent_logger.info(f"[run_script] {filepath} finished rc={proc.returncode}")
        await sio.emit(status, {
            "agent_id": AGENT_ID,
            "script_id": script_id,
            "return_code": proc.returncode,
            "log": output[-500:],
            "timestamp": datetime.utcnow().isoformat()
        })
        return {"status": "ok", "return_code": proc.returncode}
    except Exception as e:
        agent_logger.exception("run_script error")
        return {"status": "error", "log": f"Run failed: {e}"}

# -------------------------
# Background tasks (PM2-like) for Windows
# -------------------------
def start_windows_detached(python_bin: str, filepath: str, log_path: str) -> int:
    """
    Start a detached background python process on Windows, redirecting stdout/stderr to log_path.
    Returns PID.
    """
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log_f = open(log_path, "ab", buffering=0)
    creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        [python_bin, "-u", filepath],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags
    )
    return proc.pid

@sio.on("setup_background")
async def on_setup_background(data):
    filepath = data['filepath']
    script_id = data.get('script_id', 'unknown')
    user_id = data.get('agent_id', AGENT_ID)

    job_id = f"{AGENT_ID}_{script_id}_{uuid.uuid4().hex[:6]}"
    lg = setup_logger(AGENT_ID, script_id, "pm2", job_id)

    venv_dir, python_bin, _ = venv_paths(VENV_BASE_DIR, user_id)
    create_venv_if_needed(venv_dir, lg)

    log_path = os.path.join(LOG_BASE_DIR, job_id, 'pm2.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    process_name = f"bg_{job_id}"

    try:
        pid = start_windows_detached(python_bin, filepath, log_path)
        pidfile = os.path.join(LOG_BASE_DIR, job_id, "pid.txt")
        with open(pidfile, "w", encoding="utf-8") as f:
            f.write(str(pid))
        lg.info(f"Background task started (PID={pid}).")
        return {"status": "success", "log": f"Background task started (PID={pid})", "job_id": job_id, "process_name": process_name}
    except Exception as e:
        lg.exception("setup_background error")
        return {"status": "error", "log": f"Failed to start background task: {str(e)}"}

def load_pid(job_id: str) -> int | None:
    pidfile = os.path.join(LOG_BASE_DIR, job_id, "pid.txt")
    if not os.path.exists(pidfile):
        return None
    try:
        with open(pidfile, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return None

@sio.on("remove_pm2")
async def on_remove_pm2(data):
    script_id = data['script_id']
    job_id = data['job_id']
    lg = setup_logger(AGENT_ID, script_id, "run", job_id)
    try:
        pid = load_pid(job_id)
        if pid:
            try:
                p = psutil.Process(pid)
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                pass
        agent_logger.info(f"[remove_pm2] Background process removed: {job_id}")
        lg.info("Background process removed")
        await on_delete_file({"path": os.path.join(LOG_BASE_DIR, job_id), "is_folder": True})
        return {"status": "success", "log": "Background process removed"}
    except Exception as e:
        agent_logger.exception("remove_pm2 error")
        return {"status": "error", "log": f"Remove background process failed: {e}"}

@sio.on("toggle_pm2")
async def on_toggle_pm2(data):
    script_id = data['script_id']
    job_id = data['job_id']
    action = data['action']  # "pause" or "play"
    lg = setup_logger(AGENT_ID, script_id, "pm2", job_id)
    try:
        pid = load_pid(job_id)
        if not pid:
            return {"status": "error", "log": "PID not found for background task"}
        p = psutil.Process(pid)
        if action == "pause":
            try:
                p.suspend()
            except Exception as e:
                return {"status": "error", "log": f"Failed to pause: {e}"}
            lg.info("Background process paused")
            agent_logger.info(f"[toggle_pm2] Paused {job_id}")
        elif action == "play":
            try:
                p.resume()
            except Exception as e:
                return {"status": "error", "log": f"Failed to resume: {e}"}
            lg.info("Background process resumed")
            agent_logger.info(f"[toggle_pm2] Resumed {job_id}")
        else:
            return {"status": "error", "log": f"Unknown action '{action}'"}
        return {"status": "success", "log": f"Background process {action}d"}
    except Exception as e:
        agent_logger.exception("toggle_pm2 error")
        return {"status": "error", "log": f"Toggle background failed: {e}"}

# -------------------------
# SQLite helpers (for user)
# -------------------------
@sio.on("get_tables")
async def on_get_tables(data):
    db_path = data.get("db_path")
    if not db_path:
        return {"status": "error", "message": "Missing db_path"}
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        return {"status": "success", "tables": tables}
    except Exception as e:
        agent_logger.exception("get_tables error")
        return {"status": "error", "message": str(e)}

@sio.on("get_table_data")
async def on_get_table_data(data):
    db_path = data.get("db_path")
    table_name = data.get("table")
    if not db_path or not table_name:
        return {"status": "error", "message": "Missing db_path or table"}
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 100;")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        conn.close()
        return {"status": "success", "columns": columns, "rows": rows, "table": table_name}
    except Exception as e:
        agent_logger.exception("get_table_data error")
        return {"status": "error", "message": str(e)}

# -------------------------
# Metrics & logs
# -------------------------
@sio.on("get_logs")
async def on_get_logs(data):
    try:
        script_id = data['script_id']
        mode = data.get('mode', 'run')
        log_file = os.path.join(LOG_BASE_DIR, AGENT_ID, script_id, f"{mode}.log")
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = "[!] Log file not found"
        agent_logger.info(f"[get_logs] Sending logs for script_id={script_id}")
        return {"status": "success", "log": content[-1000:]}
    except Exception as e:
        agent_logger.exception("get_logs error")
        return {"status": "error", "log": f"Get logs failed: {e}"}

@sio.on("get_metrics")
async def on_get_metrics(data):
    try:
        is_exist = data.get('is_exist', False)
        base = {
            "cpu": psutil.cpu_percent(interval=0),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage("C:\\").percent,
            "agent_id": AGENT_ID
        }
        if not is_exist:
            base.update({
                "root_dir": HOME_DIR,
                "script_dir": SCRIPT_DIR,
                "venv_base_dir": VENV_BASE_DIR,
                "log_base_dir": LOG_BASE_DIR
            })
        agent_logger.info("get_metrics returned")
        return base
    except Exception as e:
        agent_logger.exception("get_metrics error")
        return {"status": "error", "log": f"Get metrics failed: {e}"}



@sio.on("setup_cron")
async def on_setup_cron_internal(data):
    """
    Robust handler that accepts:
      - {"interval": N}                   -> interval trigger every N minutes
      - {"cron": "*/N * * * *"}           -> interval trigger every N minutes (back-compat)
      - {"cron": "* * * * *"}             -> every minute
      - {"cron": "m h dom mon dow"}       -> full cron (5 fields) -> CronTrigger
    Returns clear error messages and logs tracebacks.
    """
    try:
        filepath = data.get("filepath")
        if not filepath:
            return {"status": "error", "log": "Missing 'filepath' in payload."}

        script_id = data.get("script_id", str(uuid.uuid4()))
        user_id = data.get("agent_id", AGENT_ID)

        # priority: explicit interval field (minutes)
        interval_minutes = None
        if "interval" in data:
            try:
                interval_minutes = int(data.get("interval"))
            except Exception:
                return {"status": "error", "log": "Invalid 'interval' value; must be integer minutes."}

        cron_expr = data.get("cron") or data.get("schedule") or None
        job_id = _make_job_id()
        setup_logger(AGENT_ID, script_id, "cron", job_id)

        # remove existing job if present
        try:
            scheduler.remove_job(job_id)
        except Exception:
            pass

        # If explicit interval provided -> use interval trigger
        if interval_minutes:
            scheduler.add_job(
                func=run_script_job,
                trigger="interval",
                minutes=interval_minutes,
                args=[user_id, script_id, filepath,job_id],
                id=job_id,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
            agent_logger.info(f"[setup_cron] Scheduled (interval) {filepath} every {interval_minutes} minutes as job {job_id}")
            return {"status": "success", "job_id": job_id, "log": f"Scheduled every {interval_minutes} minute(s)"}

        # Default to every 5 minutes if nothing provided
        if not cron_expr:
            cron_expr = "*/5 * * * *"

        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return {"status": "error", "log": "Cron expression must have 5 fields: minute hour day month day_of_week."}

        # Case: "* * * * *" -> every minute (interval=1)
        if parts[0] == "*" and all(p == "*" for p in parts[1:]):
            minutes = 1
            scheduler.add_job(
                func=run_script_job,
                trigger="interval",
                minutes=minutes,
                args=[user_id, script_id, filepath,job_id],
                id=job_id,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
            agent_logger.info(f"[setup_cron] Scheduled {filepath} every {minutes} minute(s) as job {job_id}")
            return {"status": "success", "job_id": job_id, "log": f"Scheduled every {minutes} minute(s)"}

        # Back-compat minute-step pattern '*/N * * * *' -> interval trigger
        if parts[0].startswith("*/") and all(p == "*" for p in parts[1:]):
            try:
                minutes = int(parts[0][2:])
                scheduler.add_job(
                    func=run_script_job,
                    trigger="interval",
                    minutes=minutes,
                    args=[user_id, script_id, filepath,job_id],
                    id=job_id,
                    replace_existing=True,
                    max_instances=1,
                    coalesce=True,
                )
                agent_logger.info(f"[setup_cron] Scheduled {filepath} every {minutes} minutes as job {job_id}")
                return {"status": "success", "job_id": job_id, "log": f"Scheduled every {minutes} minute(s)"}
            except Exception:
                return {"status": "error", "log": "Invalid minute interval in cron expression."}

        # Otherwise, try full CronTrigger (supports ranges, lists, names where allowed)
        try:
            cron_kwargs = {
                "minute": parts[0],
                "hour": parts[1],
                "day": parts[2],
                "month": parts[3],
                "day_of_week": parts[4],
            }
            trigger = CronTrigger(**cron_kwargs)
            scheduler.add_job(
                func=run_script_job,
                trigger=trigger,
                args=[user_id, script_id, filepath,job_id],
                id=job_id,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
            agent_logger.info(f"[setup_cron] Scheduled (cron) {filepath} with expr '{cron_expr}' as job {job_id}")
            return {"status": "success", "job_id": job_id, "log": f"Scheduled cron: {cron_expr}"}
        except Exception as exc:
            agent_logger.error("Cron parse/trigger error:\n%s", traceback.format_exc())
            return {"status": "error", "log": f"Failed to parse cron expression: {type(exc).__name__}: {str(exc)}"}
    except Exception as e:
        agent_logger.exception("setup_cron_internal unexpected error")
        return {"status": "error", "log": str(e)}


@sio.on("remove_cron")
async def on_remove_cron_internal(data):
    try:
        job_id = data['job_id']
        scheduler.remove_job(job_id)
        agent_logger.info(f"[remove_cron] Removed job {job_id}")
        # cleanup logs folder
        log_folder = os.path.join(LOG_BASE_DIR, job_id)
        if os.path.exists(log_folder):
            try:
                shutil.rmtree(log_folder)
            except Exception:
                pass
        return {"status": "success", "log": f"Removed {job_id}"}
    except Exception as e:
        agent_logger.exception("remove_cron_internal error")
        return {"status": "error", "log": str(e)}

@sio.on("toggle_cron")
async def on_toggle_cron_internal(data):
    """
    Pause/resume job: action='pause'|'play'
    """
    try:
        job_id = data['job_id']
        action = data['action']
        job = scheduler.get_job(job_id)
        if not job:
            return {"status": "error", "log": "Job not found"}
        if action == "pause":
            job.pause()
            agent_logger.info(f"[toggle_cron] Paused {job_id}")
        elif action == "play":
            job.resume()
            agent_logger.info(f"[toggle_cron] Resumed {job_id}")
        else:
            return {"status": "error", "log": "Unknown action"}
        return {"status": "success", "log": f"Job {action}d"}
    except Exception as e:
        agent_logger.exception("toggle_cron_internal error")
        return {"status": "error", "log": str(e)}

# -------------------------
# Connect / run
# -------------------------
@sio.event
async def connect():
    agent_logger.info("Connected to server")
    await sio.emit("register_agent", {"agent_id": AGENT_ID, "auth": AUTH_TOKEN})

@sio.event
async def disconnect():
    agent_logger.warning("Disconnected from server - scheduler still running")

async def start():
    try:
        scheduler.start()
        agent_logger.info("Scheduler started (jobstore persistent).")
        await sio.connect(SERVER_URL)
        await sio.wait()
    except Exception as e:
        agent_logger.exception("start error")
        # don't crash silently; let NSSM/service or caller handle restarts
        raise

if __name__ == "__main__":
    try:
        asyncio.run(start())
    except KeyboardInterrupt:
        pass
    except Exception:
        agent_logger.exception("Agent main crashed")
        raise
