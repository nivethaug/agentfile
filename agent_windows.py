
from datetime import datetime
import socketio
import asyncio
import subprocess
import psutil
import logging
from logging.handlers import TimedRotatingFileHandler
import uuid
import ast
import aiofiles
import shutil
from dotenv import load_dotenv
import os
import sys
import platform
import base64

# ==============================
# Cross‑platform helpers / flags
# ==============================

IS_WINDOWS = True  # Windows-only build, no Linux support  # True on Windows
DISK_ROOT = "C:\\" if IS_WINDOWS else "/"
PM2_PROCESS_PREFIX = "bg"

def venv_paths(venv_base_dir: str, user_id: str):
    """Return (venv_dir, python_bin, pip_bin) for current OS."""
    venv_dir = os.path.join(venv_base_dir, user_id)
    if IS_WINDOWS:
        python_bin = os.path.join(venv_dir, "Scripts", "python.exe")
        pip_bin = os.path.join(venv_dir, "Scripts", "pip.exe")
    else:
        python_bin = os.path.join(venv_dir, "bin", "python")
        pip_bin = os.path.join(venv_dir, "bin", "pip")
    return venv_dir, python_bin, pip_bin

def create_venv_if_needed(venv_dir: str, logger: logging.Logger | None = None):
    if not os.path.exists(venv_dir):
        # Use the running interpreter to create the venv for best compatibility
        res = subprocess.run([sys.executable, "-m", "venv", venv_dir], capture_output=True, text=True)
        if res.returncode != 0:
            msg = f"Failed to create venv at {venv_dir}: {res.stderr or res.stdout}"
            if logger:
                logger.error(msg)
            else:
                print("[⛔]", msg)
            raise RuntimeError(msg)
        if logger:
            logger.info(f"[✅] Created venv at {venv_dir}")
        else:
            print(f"[✅] Created venv at {venv_dir}")

def safe_chmod(path: str, mode: int):
    try:
        os.chmod(path, mode)
    except Exception:
        # Best‑effort: chmod is often a no‑op / not needed on Windows
        pass

# ============
# CONFIG / IO
# ============

load_dotenv()  # ✅ Make sure this is called before os.getenv()

SERVER_URL = "https://agentapi.algobillionaire.com"
AGENT_ID = os.getenv('AGENT_ID', 'agent-42e200f3-9cd6-44ee-a66a-0bab14d3490c')
AUTH_TOKEN = "bf6c405b-2901-48f3-8598-b6f1ef0b2e5a"
HOME_DIR = os.path.expanduser("~")
SCRIPT_DIR = os.path.join(HOME_DIR, "scripts")
LOG_BASE_DIR = os.path.join(HOME_DIR, "logs")
VENV_BASE_DIR = os.path.join(HOME_DIR, "venvalgobn")
MAX_FILE_SIZE_KB = 250
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_KB * 1024

os.makedirs(SCRIPT_DIR, exist_ok=True)
os.makedirs(LOG_BASE_DIR, exist_ok=True)
os.makedirs(VENV_BASE_DIR, exist_ok=True)

sio = socketio.AsyncClient()
logger: logging.Logger | None = None

def setup_logger(agent_id: str, script_id: str, mode: str = "run", cron_id: str | None = None) -> logging.Logger:
    log_dir = os.path.join(LOG_BASE_DIR, agent_id, script_id)
    if cron_id:
        log_dir = os.path.join(LOG_BASE_DIR, cron_id)
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

# =============
# Socket events
# =============

@sio.event
async def connect():
    print("✅ Connected to server")
    await sio.emit("register_agent", {
        "agent_id": AGENT_ID,
        "auth": AUTH_TOKEN
    })

@sio.event
async def disconnect():
    print("❌ Disconnected from server")

def generate_requirements(script_dir, req_output_path, logger=None):
    os.makedirs(os.path.dirname(req_output_path), exist_ok=True)
    try:
        res = subprocess.run(
            ["pipreqs", script_dir, "--force", "--savepath", req_output_path],
            capture_output=True, text=True
        )
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip() or "unknown error"
            (logger.error if logger else print)(f"[⛔] pipreqs failed: {err}")
        else:
            (logger.info if logger else print)(f"[📦] install.txt generated at {req_output_path}")
    except FileNotFoundError:
        (logger.error if logger else print)("pipreqs command not found. Did you install it in this environment?")

# =====================
# Upload / Clone / I/O
# =====================

@sio.on("upload_script")
async def on_upload_script(data):
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

        try:
            cleaned = ast.literal_eval(f'"{content}"')
        except Exception as e:
            raise ValueError("Failed to decode script content") from e

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(cleaned)
        safe_chmod(script_path, 0o755)
        print(f"[📥] Script saved: {filename} ({content_size} bytes) at {script_path}")

        lg = setup_logger(AGENT_ID, script_id, "run")

        # venv (per‑agent)
        venv_dir, _, _ = venv_paths(VENV_BASE_DIR, user_id)
        create_venv_if_needed(venv_dir, lg)

        # Generate install.txt
        req_output_path = os.path.join(script_dir, "install.txt")
        generate_requirements(script_dir, req_output_path, lg)
        lg.info(f"[📦] install.txt generated at {req_output_path}")

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
        print(f"[⛔ upload_script error]: {e}")
        return {"status": "error", "log": f"Upload failed: {str(e)}"}

def _copy_tree_preserve(src_dir, dst_dir, skip_dirs=None):
    skip_dirs = set(skip_dirs or [])
    for root, dirs, files in os.walk(src_dir):
        rel_root = os.path.relpath(root, src_dir)
        dest_root = os.path.join(dst_dir, rel_root) if rel_root != "." else dst_dir
        os.makedirs(dest_root, exist_ok=True)

        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in files:
            src_path = os.path.join(root, fname)
            dest_path = os.path.join(dest_root, fname)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy2(src_path, dest_path)
            try:
                st = os.stat(src_path)
                os.chmod(dest_path, st.st_mode)
            except Exception:
                pass

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
        _copy_tree_preserve(existing_script_dir, new_script_dir, skip_dirs=skip_dirs)

        print(f"[📄] Script cloned: {existing_script_id} → {new_script_id}")
        return {"status": "success", "script_id": new_script_id, "path": new_script_dir, "log": "Script directory cloned successfully"}
    except Exception as e:
        print(f"[⛔ clone_script error]: {e}")
        return {"status": "error", "log": f"Clone failed: {str(e)}"}

# =======================
# Dependency installation
# =======================

async def _background_install(sio, *, user_id: str, script_dir: str, script_id: str, venv_base_dir: str, logger):
    try:
        venv_dir, _, pip_path = venv_paths(venv_base_dir, user_id)
        create_venv_if_needed(venv_dir, logger)

        req_output_path = os.path.join(script_dir, "install.txt")
        if not os.path.exists(req_output_path):
            msg = f"[⛔] install.txt not found at {req_output_path}"
            logger.error(msg)
            await sio.emit("install_done", {"status": "error", "agent_id": user_id, "script_id": script_id, "log": msg})
            return

        cmd = [pip_path, "install", "-r", req_output_path]
        logger.info(f"[▶️] Starting dependency install: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=script_dir,
            env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
            creationflags=(subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        )

        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            if text:
                logger.info(text)
                await sio.emit("install_log", {"agent_id": user_id, "script_id": script_id, "line": text})

        rc = await proc.wait()
        if rc == 0:
            msg = f"[✅] Dependencies installed in {venv_dir}"
            logger.info(msg)
            await sio.emit("install_done", {"status": "success", "agent_id": user_id, "script_id": script_id, "log": msg})
        else:
            msg = f"[⛔] pip exited with code {rc}"
            logger.error(msg)
            await sio.emit("install_done", {"status": "error", "agent_id": user_id, "script_id": script_id, "log": msg})

    except Exception as e:
        msg = f"[⛔ run_dependency error]: {e}"
        logger.exception(msg)
        await sio.emit("install_done", {"status": "error", "agent_id": user_id, "script_id": script_id, "log": msg})

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
            print(msg)
            lg.error(msg)
            return {"status": "error", "log": msg}

        res = subprocess.run([pip_path, "install", "-r", req_output_path], capture_output=True, text=True)
        msg = f"[✅] Dependencies installed in {venv_dir}"
        print(msg); lg.info(msg)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            lg.exception(err)
            return {"status": "error", "log": f"run_dependency failed: {str(err)}"}
        return {"status": "success", "log": msg}
    except Exception as e:
        msg = f"[⛔ run_dependency error]: {e}"
        print(msg)
        return {"status": "error", "log": f"run_dependency failed: {str(e)}"}

# =================
# File upload / get
# =================

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

        print(f"[📥] File saved: {filename} ({len(file_bytes)} bytes) at {file_path}")
        return {"status": "success", "path": file_path, "size": len(file_bytes), "filename": filename, "log": f"File '{filename}' uploaded successfully"}
    except Exception as e:
        print(f"[⛔ upload_file error]: {e}")
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
        print(f"[⛔ get_file error]: {e}")
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
            print(f"[🗑️] Folder deleted: {target_path}")
            return {"status": "success", "log": f"Folder '{target_path}' deleted successfully", "path": target_path}
        else:
            if not os.path.isfile(target_path):
                return {"status": "error", "log": f"File not found at '{target_path}'"}
            os.remove(target_path)
            print(f"[🗑️] File deleted: {target_path}")
            return {"status": "success", "log": f"File '{target_path}' deleted successfully", "path": target_path}
    except Exception as e:
        print(f"[⛔ delete_file error]: {e}")
        return {"status": "error", "log": f"Delete failed: {str(e)}"}

# ==============================
# Terminal command handler (sh)
# ==============================

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

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            await sio.emit("command_output", {"agent_id": agent_id, "line": line.decode(errors="replace").rstrip(), "cwd": cwd})

        while True:
            line = await process.stderr.readline()
            if not line:
                break
            await sio.emit("command_output", {"agent_id": agent_id, "line": "[⛔] " + line.decode(errors="replace").rstrip(), "cwd": cwd})

        await process.wait()
        await sio.emit("command_output", {"agent_id": agent_id, "line": f"[✔] Command finished with code {process.returncode}", "cwd": cwd, "done": True})
        return {"status": "success", "cwd": cwd}
    except Exception as e:
        await sio.emit("command_output", {"agent_id": agent_id, "line": f"[⛔] {str(e)}", "cwd": cwd, "done": True})
        return {"status": "error", "cwd": cwd, "log": str(e)}

# ==================
# Run a single script
# ==================

@sio.on("run_script")
async def on_run_script(data):
    filepath = data['filepath']
    script_id = data.get('script_id', 'unknown')
    lg = setup_logger(AGENT_ID, script_id, "run")
    try:
        print(f"[▶️] Running script: {filepath}")
        user_id = data.get('agent_id', AGENT_ID)
        venv_dir, python_bin, _ = venv_paths(VENV_BASE_DIR, user_id)
        create_venv_if_needed(venv_dir, lg)

        process = await asyncio.create_subprocess_exec(
            python_bin, filepath,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
        output = (stdout.decode(errors="replace") if stdout else "") + "\n" + (stderr.decode(errors="replace") if stderr else "")
        status = "script_done" if process.returncode == 0 else "script_failed"

        lg.info("=== Script Run ===\n%s", output.strip())
        print(f"[📜] Script output: {output.strip()}")
        print(f"[✅] Script finished with return code: {process.returncode}{status}")
        await sio.emit(status, {
            "agent_id": AGENT_ID,
            "script_id": script_id,
            "return_code": process.returncode,
            "log": output[-500:],
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        lg.exception("Script run failed")
        print(f"[⛔ run_script error]: {e}")
        return {"status": "error", "log": f"Run failed: {e}"}

# =======================
# Scheduling (Cron/Tasks)
# =======================

def parse_simple_cron_to_minutes(expr: str) -> int | None:
    """
    Support only patterns like '*/N * * * *' (every N minutes).
    Return N (int) if matched, else None.
    """
    parts = expr.strip().split()
    if len(parts) != 5:
        return None
    minute, *_ = parts
    if minute.startswith("*/"):
        try:
            return int(minute[2:])
        except ValueError:
            return None
    if minute == "*":
        return 1
    return None

def windows_create_minutely_task(job_id: str, minutes: int, python_bin: str, filepath: str, log_path: str):
    """
    Create or update a Windows Task Scheduler job that runs every N minutes.
    Uses a hidden .vbs wrapper to run python.exe silently but still capture stdout/stderr to logs.
    """

    import textwrap

    # Prepare directories
    tasks_dir = os.path.join(LOG_BASE_DIR, "tasks")
    os.makedirs(tasks_dir, exist_ok=True)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # Short safe name for wrapper
    safe_job_name = "".join(c for c in job_id if c.isalnum() or c in ("_", "-"))[:32]
    vbs_path = os.path.join(tasks_dir, f"{safe_job_name}.vbs")

    # Make sure we use python.exe (not pythonw)
    if python_bin.lower().endswith("pythonw.exe"):
        python_bin = python_bin[:-len("pythonw.exe")] + "python.exe"

    # Build VBS content (hidden run)
    #   - Runs python.exe -u "script.py"
    #   - Redirects stdout+stderr to log_path
    #   - 0 = hidden, False = don't wait
    vbs_content = textwrap.dedent(f'''\
        Set WshShell = CreateObject("WScript.Shell")
        WshShell.Run """{python_bin}"" -u ""{filepath}"" >> ""{log_path}"" 2>&1", 0, False
    ''')

    # Write .vbs file
    with open(vbs_path, "w", encoding="utf-8") as f:
        f.write(vbs_content)

    # Delete any existing scheduled task quietly
    subprocess.run(["schtasks", "/Delete", "/TN", job_id, "/F"],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Schedule the .vbs (short path, no length issues)
    create = subprocess.run([
        "schtasks", "/Create",
        "/SC", "MINUTE",
        "/MO", str(minutes),
        "/TN", job_id,
        "/TR", f'"wscript.exe \"{vbs_path}\""',
        "/RL", "HIGHEST",
        "/F"
    ], capture_output=True, text=True)

    if create.returncode != 0:
        raise RuntimeError(create.stderr.strip() or create.stdout.strip() or "Failed to create task")

    print(f"[🕒] Windows cron task '{job_id}' created ({minutes}-min interval, hidden, with full stdout logging).")


def windows_delete_task(job_id: str):
    subprocess.run(["schtasks", "/Delete", "/TN", job_id, "/F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def windows_toggle_task(job_id: str, enable: bool):
    # Easiest is to change 'enabled' state by /CHANGE
    action = "/ENABLE" if enable else "/DISABLE"
    res = subprocess.run(["schtasks", "/Change", "/TN", job_id, action], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr or res.stdout or "Failed to toggle task")

@sio.on("setup_cron")
async def on_setup_cron(data):
    filepath = data['filepath']
    script_id = data.get('script_id', 'unknown')
    cron_expr = data['cron']
    try:
        cron_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
        job_id = f"{AGENT_ID}_{script_id}_{cron_name}"
        lg = setup_logger(AGENT_ID, script_id, "cron", job_id)

        user_id = data.get('agent_id', AGENT_ID)
        venv_dir, python_bin, _ = venv_paths(VENV_BASE_DIR, user_id)
        create_venv_if_needed(venv_dir, lg)
        log_path = os.path.join(LOG_BASE_DIR, job_id, 'cron.log')
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        if IS_WINDOWS:
            every_n = parse_simple_cron_to_minutes(cron_expr)
            if every_n is None:
                raise ValueError("On Windows, only '*/N * * * *' (every N minutes) cron is supported by this agent.")
            windows_create_minutely_task(job_id, every_n, python_bin, filepath, log_path)
            lg.info("Task Scheduler job added: every %d minute(s)", every_n)
        else:
            from crontab import CronTab
            cron = CronTab(user=True)
            cron.remove_all(comment=job_id)
            command = f"{python_bin} {filepath} >> {log_path} 2>&1"
            job = cron.new(command=command, comment=job_id)
            job.setall(cron_expr)
            cron.write()
            lg.info("Cron setup: %s", cron_expr)

        print(f"[🕒] Schedule added for {script_id}: {cron_expr}")
        return {"status": "success", "log": f"Schedule set: {cron_expr}", "job_id": job_id}
    except Exception as e:
        print(f"[⛔ setup_cron error]: {e}")
        return {"status": "error", "log": f"Setup schedule failed: {e}"}

@sio.on("remove_cron")
async def on_remove_cron(data):
    script_id = data['script_id']
    job_id = data['job_id']
    lg = setup_logger(AGENT_ID, script_id, "run")
    try:
        if IS_WINDOWS:
            windows_delete_task(job_id)
        else:
            from crontab import CronTab
            cron = CronTab(user=True)
            cron.remove_all(comment=job_id)
            cron.write()
        print(f"[🗑️] Schedule removed: {job_id}")
        lg.info("Schedule removed")
        await on_delete_file({"path": os.path.join(LOG_BASE_DIR, job_id), "is_folder": True})
        return {"status": "success", "log": "Schedule removed"}
    except Exception as e:
        lg.exception("Schedule removal failed")
        print(f"[⛔ remove_cron error]: {e}")
        return {"status": "error", "log": f"Remove schedule failed: {e}"}

@sio.on("toggle_cron")
async def on_toggle_cron(data):
    script_id = data['script_id']
    job_id = data['job_id']
    action = data['action']  # "pause" or "play"
    lg = setup_logger(AGENT_ID, script_id, "cron", job_id)
    try:
        if IS_WINDOWS:
            windows_toggle_task(job_id, enable=(action == "play"))
            lg.info("Task %s", "enabled" if action == "play" else "disabled")
        else:
            from crontab import CronTab
            cron = CronTab(user=True)
            modified = False
            for job in cron:
                if job.comment == job_id:
                    if action == "pause" and job.enabled:
                        job.enable(False)
                        lg.info("Cron job paused")
                    elif action == "play" and not job.enabled:
                        job.enable(True)
                        lg.info("Cron job resumed")
                    modified = True
                    break
            if modified:
                cron.write()
            else:
                return {"status": "error", "log": "Schedule not found"}
        return {"status": "success", "log": f"Schedule {action}d"}
    except Exception as e:
        lg.exception("Toggle schedule failed")
        print(f"[⛔ toggle_cron error]: {e}")
        return {"status": "error", "log": f"Toggle schedule failed: {e}"}

# ==============================
# Background tasks (PM2/Windows)
# ==============================

def start_windows_detached(python_bin: str, filepath: str, log_path: str) -> int:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    # Open log file for appending
    log_f = open(log_path, "ab", buffering=0)
    creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        [python_bin, filepath],
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

    process_name = f"{PM2_PROCESS_PREFIX}_{job_id}"

    try:
        if IS_WINDOWS:
            pid = start_windows_detached(python_bin, filepath, log_path)
            # Save PID to file for later control
            pidfile = os.path.join(LOG_BASE_DIR, job_id, "pid.txt")
            with open(pidfile, "w", encoding="utf-8") as f:
                f.write(str(pid))
            lg.info(f"Background task started (PID={pid}).")
            return {"status": "success", "log": f"Background task started (PID={pid})", "job_id": job_id, "process_name": process_name}
        else:
            command = ["pm2", "start", python_bin, "--name", process_name, "--log", log_path, "--", filepath]
            subprocess.run(command, check=True)
            lg.info("PM2 background task started.")
            return {"status": "success", "log": f"PM2 background task started with process: {process_name}", "job_id": job_id, "process_name": process_name}
    except subprocess.CalledProcessError as e:
        lg.error("Background setup failed: %s", str(e))
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
        if IS_WINDOWS:
            pid = load_pid(job_id)
            if pid:
                try:
                    p = psutil.Process(pid)
                    p.terminate()
                    p.wait(timeout=5)
                except Exception:
                    pass
            print(f"[🗑️] Background process removed: {job_id}")
            lg.info("Background process removed")
            await on_delete_file({"path": os.path.join(LOG_BASE_DIR, job_id), "is_folder": True})
            return {"status": "success", "log": "Background process removed"}
        else:
            subprocess.run(["pm2", "delete", f"{PM2_PROCESS_PREFIX}_{job_id}"], check=True)
            print(f"[🗑️] PM2 process removed: {job_id}")
            lg.info("PM2 process removed")
            await on_delete_file({"path": os.path.join(LOG_BASE_DIR, job_id), "is_folder": True})
            return {"status": "success", "log": "PM2 process removed"}
    except Exception as e:
        lg.exception("Background removal failed")
        print(f"[⛔ remove_pm2 error]: {e}")
        return {"status": "error", "log": f"Remove background process failed: {e}"}

@sio.on("toggle_pm2")
async def on_toggle_pm2(data):
    script_id = data['script_id']
    job_id = data['job_id']
    action = data['action']  # "pause" or "play"
    lg = setup_logger(AGENT_ID, script_id, "pm2", job_id)
    try:
        if IS_WINDOWS:
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
                print(f"[⏸️] Background process paused: {job_id}")
            elif action == "play":
                try:
                    p.resume()
                except Exception as e:
                    return {"status": "error", "log": f"Failed to resume: {e}"}
                lg.info("Background process resumed")
                print(f"[▶️] Background process resumed: {job_id}")
            else:
                return {"status": "error", "log": f"Unknown action '{action}'"}
            return {"status": "success", "log": f"Background process {action}d"}
        else:
            if action == "pause":
                subprocess.run(["pm2", "stop", f"{PM2_PROCESS_PREFIX}_{job_id}"], check=True)
                lg.info("PM2 process paused")
                print(f"[⏸️] PM2 process paused: {job_id}")
            elif action == "play":
                subprocess.run(["pm2", "start", f"{PM2_PROCESS_PREFIX}_{job_id}"], check=True)
                lg.info("PM2 process resumed")
                print(f"[▶️] PM2 process resumed: {job_id}")
            else:
                return {"status": "error", "log": f"Unknown action '{action}'"}
            return {"status": "success", "log": f"PM2 process {action}d"}
    except Exception as e:
        lg.exception("Toggle background failed")
        print(f"[⛔ toggle_pm2 error]: {e}")
        return {"status": "error", "log": f"Toggle background failed: {e}"}

# ============
# SQLite utils
# ============

import sqlite3

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
        return {"status": "error", "message": str(e)}

# ========
# Metrics
# ========

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
        print(f"[📜] Sending logs for script_id={script_id}")
        return {"status": "success", "log": content[-1000:]}
    except Exception as e:
        print(f"[⛔ get_logs error]: {e}")
        return {"status": "error", "log": f"Get logs failed: {e}"}

@sio.on("get_metrics")
async def on_get_metrics(data):
    try:
        is_exist = data['is_exist']
        base = {
            "cpu": psutil.cpu_percent(interval=0),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage(DISK_ROOT).percent,
            "agent_id": AGENT_ID
        }
        if not is_exist:
            base.update({
                "root_dir": HOME_DIR,
                "script_dir": SCRIPT_DIR,
                "venv_base_dir": VENV_BASE_DIR,
                "log_base_dir": LOG_BASE_DIR
            })
        print("✅ Sent metrics")
        return base
    except Exception as e:
        print(f"[⛔ get_metrics error]: {e}")
        return {"status": "error", "log": f"Get metrics failed: {e}"}

# =====
# Main
# =====

async def start():
    try:
        await sio.connect(SERVER_URL)
        await sio.wait()
    except Exception as e:
        print(f"[🚫] Could not connect to server: {e}")

if __name__ == "__main__":
    asyncio.run(start())
