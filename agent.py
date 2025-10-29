from datetime import datetime
import socketio
import asyncio
import subprocess
import psutil
import logging
from logging.handlers import TimedRotatingFileHandler
from crontab import CronTab
import uuid
import ast
import aiofiles
import shutil
from dotenv import load_dotenv
import os
import pathlib
from pathlib import Path
import aiohttp
import tempfile
import zipfile
import re
import base64


PM2_PROCESS_PREFIX = "bg"



load_dotenv()  # ✅ Make sure this is called before os.getenv()




# === CONFIG ===
SERVER_URL = "https://agentapi.algobillionaire.com"
AGENT_ID = os.getenv('AGENT_ID', 'agent-42e200f3-9cd6-44ee-a66a-0bab14d3490c')
AUTH_TOKEN = "bf6c405b-2901-48f3-8598-b6f1ef0b2e5a"

HOME_DIR = os.getenv("HOME_DIR", os.path.expanduser("~"))
MACHINE_ID = os.getenv("MACHINE_ID", str(uuid.getnode()))
SCRIPT_DIR = os.path.join(HOME_DIR, "scripts")
LOG_BASE_DIR = os.path.join(HOME_DIR, "logs")
VENV_BASE_DIR = os.path.join(HOME_DIR, "venvalgobn")  # fixed from relative
MAX_FILE_SIZE_KB = 250
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_KB * 1024

# === SETUP ===
os.makedirs(SCRIPT_DIR, exist_ok=True)
os.makedirs(LOG_BASE_DIR, exist_ok=True)
os.makedirs(VENV_BASE_DIR, exist_ok=True)

sio = socketio.AsyncClient()
logger = None

def setup_logger(agent_id: str, script_id: str, mode: str = "run", cron_id: str = None) -> logging.Logger:
    log_dir = os.path.join(LOG_BASE_DIR, agent_id, script_id)
    if cron_id:
        log_dir = os.path.join(LOG_BASE_DIR, cron_id)
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{mode}.log")

    logger_name = f"{agent_id}_{script_id}_{mode}"
    if cron_id:
        logger_name = f"{cron_id}_{mode}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Prevent double logging

    if not logger.handlers:
        handler = TimedRotatingFileHandler(log_file, when="D", interval=1, backupCount=10)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

@sio.event
async def connect():
    print("✅ Connected to server")
    await sio.emit("register_agent", {
        "agent_id": AGENT_ID,
        "auth": AUTH_TOKEN,
        "machine_id": MACHINE_ID
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
            if logger:
                logger.error(f"[⛔] pipreqs failed: {err}")
            else:
                print(f"[⛔] pipreqs failed: {err}")
        else:
            msg = f"[📦] install.txt generated at {req_output_path}"
            if logger:
                logger.info(msg)
            else:
                print(msg)

    except FileNotFoundError:
        err = "pipreqs command not found. Did you install it in this environment?"
        if logger:
            logger.error(f"[⛔] {err}")
        else:
            print(f"[⛔] {err}")



@sio.on("upload_script")
async def on_upload_script(data):
    try:
        user_id = data['agent_id']
        filename = data['filename']
        content = data['content']

        # ✅ Unique script folder
        script_id = str(uuid.uuid4())
        script_dir = os.path.join(SCRIPT_DIR, user_id, script_id)
        os.makedirs(script_dir, exist_ok=True)

        script_path = os.path.join(script_dir, filename)
        # ✅ Size check
        content_size = len(content.encode('utf-8'))
        if content_size > MAX_FILE_SIZE_BYTES:
            return {
                "status": "error",
                "log": f"Script too large. Max allowed is {MAX_FILE_SIZE_KB} KB."
            }
        try:
            # Safely decode escaped string (works for content like `"line1\\nline2"` etc.)
            cleaned = ast.literal_eval(f'"{content}"')
        except Exception as e:
            raise ValueError("Failed to decode script content") from e
        # ✅ Save script
        with open(script_path, "w") as f:
            f.write(cleaned)
        os.chmod(script_path, 0o755)
        print(f"[📥] Script saved: {filename} ({content_size} bytes) at {script_path}")
        logger = setup_logger(AGENT_ID, script_id, "run")
        # ✅ Create venv (per-agent)
        user_venv_path = os.path.join(VENV_BASE_DIR, user_id)
        if not os.path.exists(user_venv_path):
            subprocess.run(["python3", "-m", "venv", user_venv_path], check=True)
            logger.info(f"[✅] Created venv for user: {user_id}")
            print(f"[✅] Created venv for user: {user_id}")

        # ✅ Generate install.txt
        req_output_path = os.path.join(script_dir, "install.txt")
        generate_requirements(script_dir, req_output_path, logger)
        logger.info(f"[📦] install.txt generated at {req_output_path}")

        # # ✅ Install dependencies
        # pip_path = os.path.join(user_venv_path, "bin", "pip")
        # install_error = ''
        # res = subprocess.run([pip_path, "install", "-r", req_output_path], capture_output=True, text=True)
        # if res.returncode != 0:
        #     err = res.stderr.strip() or res.stdout.strip()
        #     logger.error(f"[⚠️] Some dependencies failed to install: {err}")
        #     install_error = f"Some dependencies failed to install: {err}"
        # else:
        #     logger.info(f"[✅] Dependencies installed in {user_venv_path}")
        #     print(f"[✅] Dependencies installed in {user_venv_path}")


        return {
            "status": "success",
            "path": script_path,
            "size": content_size,
            "script_id": script_id,
            "installed_path": req_output_path,
            "install_error": '',
            "log": f"Script {filename} uploaded successfully{'and dependencies file created as install.txt' } "
        }

    except Exception as e:
        print(f"[⛔ upload_script error]: {e}")
        return {
            "status": "error",
            "log": f"Upload failed: {str(e)}"
        }



def _sanitize_part(part: str) -> str:
    part = re.sub(r'[^A-Za-z0-9._\- ]+', '_', part)
    return part.strip()

def _safe_join(base: str, *paths: str) -> str:
    final_path = os.path.abspath(os.path.join(base, *paths))
    base_abs = os.path.abspath(base)
    if not final_path.startswith(base_abs + os.sep) and final_path != base_abs:
        raise ValueError("Attempted path traversal")
    return final_path

async def _download_zip(session: aiohttp.ClientSession, url: str, max_bytes: int):
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    total = 0
    try:
        async with session.get(url) as resp:
            resp.raise_for_status()
            clen = resp.headers.get("Content-Length")
            if clen is not None:
                try:
                    if int(clen) > max_bytes:
                        raise ValueError(f"Remote file too large ({clen} bytes). Limit is {max_bytes} bytes.")
                except Exception:
                    pass

            async for chunk in resp.content.iter_chunked(64 * 1024):
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"Downloaded file exceeds maximum size ({max_bytes} bytes).")
                temp.write(chunk)
        temp.flush()
        temp.close()
        return temp.name, total
    except Exception:
        try:
            temp.close()
            os.unlink(temp.name)
        except Exception:
            pass
        raise

def _safe_extract_zip(zip_path: str, dest_dir: str):
    extracted = []
    with zipfile.ZipFile(zip_path, 'r') as z:
        for info in z.infolist():
            name = info.filename
            if name.startswith('/') or name.startswith('\\'):
                raise ValueError("Absolute paths in zip are not allowed")
            parts = [p for p in pathlib.PurePosixPath(name).parts if p not in ('.', '')]
            if not parts:
                continue
            parts = [_sanitize_part(p) for p in parts]
            dest_path = _safe_join(dest_dir, *parts)
            if info.is_dir():
                os.makedirs(dest_path, exist_ok=True)
                continue
            parent = os.path.dirname(dest_path)
            os.makedirs(parent, exist_ok=True)
            with z.open(info, 'r') as srcf, open(dest_path, 'wb') as dstf:
                shutil.copyfileobj(srcf, dstf)
            try:
                # check first two bytes for shebang
                with open(dest_path, 'rb') as fh:
                    head = fh.read(2)
                if parts[-1].endswith(('.sh', '.py', '.pl')) or head == b'#!':
                    os.chmod(dest_path, 0o755)
            except Exception:
                pass
            rel = os.path.relpath(dest_path, dest_dir)
            extracted.append(rel)
    return extracted

def _gather_files_info(base_dir: str, relative_paths: list):
    """
    Build list of dicts: filename, file_path (rel), file_size (bytes), file_type (ext)
    Only includes files (not directories).
    """
    files = []
    for rel in relative_paths:
        full = os.path.join(base_dir, rel)
        if os.path.isfile(full):
            size = os.path.getsize(full)
            suffix = pathlib.Path(full).suffix or ''
            files.append({
                "filename": os.path.basename(full),
                "file_path": full,            # relative to returned path
                "file_size": size,
                "file_type": suffix
            })
    return files

@sio.on("upload_script_from_url")
async def on_upload_script_from_url(data):
    """
    Expecting:
    {
      "agent_id": "<user id>",
      "url": "https://.../archive.zip",
      "filename_hint": "optional-filename-or-root-folder-name"
    }
    """
    try:
        user_id = data['agent_id']
        url = data['url']
        filename_hint = data.get('filename_hint', 'uploaded_zip')

        # create unique script folder
        script_id = str(uuid.uuid4())
        script_dir = os.path.join(SCRIPT_DIR, user_id, script_id)
        os.makedirs(script_dir, exist_ok=True)

        logger = setup_logger(user_id, script_id, "run")
        logger.info(f"[📥] Downloading ZIP from URL: {url}")

        async with aiohttp.ClientSession() as session:
            try:
                zip_path, total_bytes = await _download_zip(session, url, MAX_FILE_SIZE_BYTES)
            except Exception as e:
                logger.error(f"[⛔] Download failed: {e}")
                return {
                    "status": "error",
                    "log": f"Download failed: {str(e)}"
                }

        logger.info(f"[📥] ZIP downloaded ({total_bytes} bytes) to temp: {zip_path}")

        try:
            if not zipfile.is_zipfile(zip_path):
                raise ValueError("Downloaded file is not a valid ZIP archive.")
        except Exception as e:
            try:
                os.unlink(zip_path)
            except Exception:
                pass
            logger.error(f"[⛔] Invalid ZIP: {e}")
            return {
                "status": "error",
                "log": f"Invalid ZIP archive: {str(e)}"
            }

        try:
            extracted_files = _safe_extract_zip(zip_path, script_dir)
        except Exception as e:
            try:
                shutil.rmtree(script_dir, ignore_errors=True)
            except Exception:
                pass
            try:
                os.unlink(zip_path)
            except Exception:
                pass
            logger.error(f"[⛔] Extraction failed: {e}")
            return {
                "status": "error",
                "log": f"Extraction failed: {str(e)}"
            }

        try:
            os.unlink(zip_path)
        except Exception:
            pass

        # Build files array with metadata
        files_meta = _gather_files_info(script_dir, extracted_files)

        logger.info(f"[✅] Extracted {len(extracted_files)} paths into {script_dir}")
        print(f"[📥] ZIP saved and extracted to: {script_dir} ({total_bytes} bytes)")

        return {
            "status": "success",
            "path": script_dir,
            "size": total_bytes,
            "script_id": script_id,
            "extracted_files": extracted_files,  # relative paths
            "files": files_meta,                 # detailed metadata
            "log": f"ZIP downloaded and extracted to {script_dir}"
        }

    except Exception as e:
        print(f"[⛔ upload_script_from_url error]: {e}")
        return {
            "status": "error",
            "log": f"Upload-from-url failed: {str(e)}"
        }

@sio.on("upload_script_zip")
async def on_upload_script_zip(data):
    """
    Accepts only ZIP payloads:
    {
      "agent_id": "<user id>",
      "file_b64": "<BASE64 ZIP>",
      "filename_hint": "optional-root-folder-or-name",
      "size": 12345   # optional client hint
    }
    """
    try:
        user_id = data.get("agent_id")
        if not user_id:
            return {"status": "error", "log": "Missing 'agent_id'."}

        filename_hint = data.get("filename_hint", "uploaded_zip")
        client_size_hint = data.get("size")

        # Optional pre-check
        if isinstance(client_size_hint, int) and client_size_hint > MAX_FILE_SIZE_BYTES:
            return {"status": "error", "log": f"File too large (client-reported): {client_size_hint} bytes."}

        file_b64 = data.get("file_b64")
        if not file_b64:
            return {"status": "error", "log": "Missing 'file_b64' field."}

        # Decode base64
        try:
            zip_bytes = base64.b64decode(file_b64)
        except Exception as e:
            return {"status": "error", "log": f"Failed to decode base64: {str(e)}"}

        total_bytes = len(zip_bytes)
        if total_bytes == 0 or total_bytes > MAX_FILE_SIZE_BYTES:
            return {"status": "error", "log": f"File size invalid: {total_bytes} bytes."}

        # Create unique script folder
        script_id = str(uuid.uuid4())
        script_dir = os.path.join(SCRIPT_DIR, user_id, script_id)
        os.makedirs(script_dir, exist_ok=True)
        logger = setup_logger(user_id, script_id, "run")
        logger.info(f"[📥] Receiving ZIP payload ({total_bytes} bytes)")

        # Write temp ZIP
        temp_zip_path = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4()}.zip")
        with open(temp_zip_path, "wb") as f:
            f.write(zip_bytes)

        # Validate ZIP
        if not zipfile.is_zipfile(temp_zip_path):
            os.unlink(temp_zip_path)
            shutil.rmtree(script_dir, ignore_errors=True)
            return {"status": "error", "log": "Uploaded file is not a valid ZIP."}

        # Extract safely
        extracted_files = _safe_extract_zip(temp_zip_path, script_dir)
        os.unlink(temp_zip_path)

        # Create venv per user
        user_venv_path = os.path.join(VENV_BASE_DIR, user_id)
        if not os.path.exists(user_venv_path):
            subprocess.run(["python3", "-m", "venv", user_venv_path], check=True)
            logger.info(f"[✅] Created venv for user: {user_id}")

        # Generate install.txt
        req_output_path = os.path.join(script_dir, "install.txt")

        # Gather metadata
        files_meta = _gather_files_info(script_dir, extracted_files)

        return {
            "status": "success",
            "path": script_dir,
            "size": total_bytes,
            "script_id": script_id,
            "extracted_files": extracted_files,
            "files": files_meta,
            "installed_path": req_output_path,
            "install_error": "",
            "log": f"ZIP '{filename_hint}' uploaded and extracted."
        }

    except Exception as e:
        try: shutil.rmtree(script_dir, ignore_errors=True)
        except Exception: pass
        return {"status": "error", "log": f"Upload failed: {str(e)}"}


# Helper: recursive copy that preserves metadata and optionally skips folders
def _copy_tree_preserve(src_dir, dst_dir, skip_dirs=None):
    skip_dirs = set(skip_dirs or [])
    for root, dirs, files in os.walk(src_dir):
        # compute relative path from src_dir
        rel_root = os.path.relpath(root, src_dir)
        # dest root
        dest_root = os.path.join(dst_dir, rel_root) if rel_root != "." else dst_dir
        os.makedirs(dest_root, exist_ok=True)

        # optionally skip some subdirectories (in-place modify dirs to prune walk)
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        # copy files
        for fname in files:
            src_path = os.path.join(root, fname)
            dest_path = os.path.join(dest_root, fname)

            # create parent if missing
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            # copy file with metadata
            shutil.copy2(src_path, dest_path)

            # preserve executable bit for scripts if set
            try:
                st = os.stat(src_path)
                os.chmod(dest_path, st.st_mode)
            except Exception:
                # ignore chmod failures
                pass

@sio.on("clone_script")
async def on_clone_script(data):
    try:
        user_id = data['agent_id']
        existing_script_id = data['existing_script_id']
        skip_venv = data.get("skip_venv", True)

        existing_script_dir = os.path.join(SCRIPT_DIR, user_id, existing_script_id)
        if not os.path.exists(existing_script_dir):
            return {
                "status": "error",
                "log": f"Existing script ID {existing_script_id} not found for user {user_id}"
            }

        # create new script folder
        new_script_id = str(uuid.uuid4())
        new_script_dir = os.path.join(SCRIPT_DIR, user_id, new_script_id)
        os.makedirs(new_script_dir, exist_ok=True)

        # directories to skip to avoid copying venvs/interpreter folders
        common_venv_names = {"venv", "venv3"}
        skip_dirs = common_venv_names if skip_venv else set()

        # perform recursive copy preserving metadata
        _copy_tree_preserve(existing_script_dir, new_script_dir, skip_dirs=skip_dirs)

        

        print(f"[📄] Script cloned: {existing_script_id} → {new_script_id} (full directory, no .py rename)")

        return {
            "status": "success",
            "script_id": new_script_id,
            "path": new_script_dir,
            "log": "Script directory cloned successfully (no .py renaming performed)"
        }

    except Exception as e:
        print(f"[⛔ clone_script error]: {e}")
        return {
            "status": "error",
            "log": f"Clone failed: {str(e)}"
        }

@sio.on("run_dependency")
async def on_run_dependency(data):
    try:
        user_id = data['agent_id']
        script_dir = data['filepath']
        script_id = data.get('script_id', 'unknown')

        logger = setup_logger(AGENT_ID, script_id, "run")
        # ✅ Create venv (per-agent)
        user_venv_path = os.path.join(VENV_BASE_DIR, user_id)

        # ✅ Generate requirements.txt
        req_output_path = os.path.join(script_dir, "install.txt")
        generate_requirements(script_dir, req_output_path, logger)
        logger.info(f"[📦] install.txt generated at {req_output_path}")
        print(f"[📦] install.txt generated at {req_output_path}")

        # ✅ Install dependencies
        pip_path = os.path.join(user_venv_path, "bin", "pip")
        res=subprocess.run([pip_path, "install", "-r", req_output_path], capture_output=True, text=True)
        print(f"[✅] Dependencies installed in {user_venv_path}")
        logger.info(f"[✅] Dependencies installed in {user_venv_path}")
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            logger.exception(err)
            return {
                "status": "error",
                "log": f"run_dependency failed: {str(err)}"
                }
        return {
            "status": "success",
            "log": "[✅] Dependencies installed "
        }

    except Exception as e:
        print(f"[⛔ run_dependency error]: {e}")
        logger.exception(f"[⛔ run_dependency error]: {e}")
        return {
            "status": "error",
            "log": f"run_dependency failed: {str(e)}"
        }

@sio.on("run_install_dependency_r")
async def on_run_install_dependency_r(data):
    try:
        user_id = data['agent_id']
        script_dir = data['filepath']
        script_id = data.get('script_id', 'unknown')

        logger = setup_logger(AGENT_ID, script_id, "run")

        # ✅ Create venv (per-agent)
        user_venv_path = os.path.join(VENV_BASE_DIR, user_id)

        # ✅ Generate requirements file path
        req_output_path = os.path.join(script_dir, "install.txt")

        # 🔎 Check if file exists
        if not os.path.exists(req_output_path):
            msg = f"[⛔] install.txt not found at {req_output_path}"
            print(msg)
            logger.error(msg)
            return {
                "status": "error",
                "log": msg
            }

        # ✅ Install dependencies
        pip_path = os.path.join(user_venv_path, "bin", "pip")
        res = subprocess.run([pip_path, "install", "-r", req_output_path], capture_output=True, text=True)
        msg = f"[✅] Dependencies installed in {user_venv_path}"
        print(msg)
        logger.info(msg)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            logger.exception(err)
            return {
                "status": "error",
                "log": f"run_dependency failed: {str(err)}"
            }
        return {
            "status": "success",
            "log": msg
        }

    except Exception as e:
        msg = f"[⛔ run_dependency error]: {e}"
        print(msg)
        logger.exception(msg)
        return {
            "status": "error",
            "log": f"run_dependency failed: {str(e)}"
        }

async def _background_install(
    sio,
    *,
    user_id: str,
    script_dir: str,
    script_id: str,
    venv_base_dir: str,
    logger,
):
    try:
        user_venv_path = os.path.join(venv_base_dir, user_id)
        req_output_path = os.path.join(script_dir, "install.txt")

        if not os.path.exists(req_output_path):
            msg = f"[⛔] install.txt not found at {req_output_path}"
            logger.error(msg)
            await sio.emit("install_done", {
                "status": "error",
                "agent_id": user_id,
                "script_id": script_id,
                "log": msg,
            })
            return

        # Make sure the venv (and pip) exist
        pip_path = os.path.join(user_venv_path, "bin", "pip")

        cmd = [pip_path, "install", "-r", req_output_path]
        logger.info(f"[▶️] Starting dependency install: {' '.join(cmd)}")

        # Run pip as an asyncio subprocess and stream combined stdout/stderr
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=script_dir,
            env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
        )

        # Stream logs line-by-line
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            if text:
                logger.info(text)
                await sio.emit("install_log", {
                    "agent_id": user_id,
                    "script_id": script_id,
                    "line": text
                })

        rc = await proc.wait()
        if rc == 0:
            msg = f"[✅] Dependencies installed in {user_venv_path}"
            logger.info(msg)
            await sio.emit("install_done", {
                "status": "success",
                "agent_id": user_id,
                "script_id": script_id,
                "log": msg
            })
        else:
            msg = f"[⛔] pip exited with code {rc}"
            logger.error(msg)
            await sio.emit("install_done", {
                "status": "error",
                "agent_id": user_id,
                "script_id": script_id,
                "log": msg
            })

    except Exception as e:
        msg = f"[⛔ run_dependency error]: {e}"
        logger.exception(msg)
        await sio.emit("install_done", {
            "status": "error",
            "agent_id": user_id,
            "script_id": script_id,
            "log": msg
        })


@sio.on("run_install_dependency")
async def on_run_install_dependency(data):
    user_id = data["agent_id"]
    script_dir = data["filepath"]
    script_id = data.get("script_id", "unknown")

    logger = setup_logger(AGENT_ID, script_id, "run")

    # Fire-and-forget background task
    asyncio.create_task(_background_install(
        sio,
        user_id=user_id,
        script_dir=script_dir,
        script_id=script_id,
        venv_base_dir=VENV_BASE_DIR,
        logger=logger,
    ))

    # Return immediately
    return {
        "status": "success",
        "log": f"[🚀] Dependencies installation started. Check logs for progress."
    }    

@sio.on("upload_file")
async def on_upload_file(data):
    try:
        path = data['path']
        filename = data['filename']
        file_bytes_b64 = data['file_bytes']  # base64 encoded binary

        # ✅ Decode base64 content
        import base64
        try:
            file_bytes = base64.b64decode(file_bytes_b64)
        except Exception as e:
            raise ValueError("Failed to decode base64 content") from e

        # ✅ File size check
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            return {
                "status": "error",
                "log": f"File too large. Max allowed is {MAX_FILE_SIZE_KB} KB."
            }

        # ✅ Save file to disk
        script_dir = os.path.join(path)
        os.makedirs(script_dir, exist_ok=True)
        file_path = os.path.join(script_dir, filename)

        async with aiofiles.open(file_path, "wb") as f:
            await f.write(file_bytes)

        print(f"[📥] File saved: {filename} ({len(file_bytes)} bytes) at {file_path}")

        return {
            "status": "success",
            "path": file_path,
            "size": len(file_bytes),
            "filename": filename,
            "log": f"File '{filename}' uploaded successfully"
        }

    except Exception as e:
        print(f"[⛔ upload_file error]: {e}")
        return {
            "status": "error",
            "log": f"Upload failed: {str(e)}"
        }
@sio.on("get_file")
async def on_get_file(data):
    try:
        filepath = data['filepath']

        # 🔐 Validate path
        if ".." in filepath or not os.path.isfile(filepath):
            return {
                "status": "error",
                "log": f"Invalid file path: {filepath}"
            }

        # ✅ Read file content as text
        async with aiofiles.open(filepath, "r", encoding="utf-8") as f:
            content = await f.read()

        return {
            "status": "success",
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "content": content,
            "log": f"File '{os.path.basename(filepath)}' read successfully"
        }

    except Exception as e:
        print(f"[⛔ get_file error]: {e}")
        return {
            "status": "error",
            "log": f"Read failed: {str(e)}"
        }

@sio.on("delete_file")
async def on_delete_file(data):
    try:
        path = data['path']
        is_folder = data.get('is_folder', False)

        # ✅ Construct full path
        target_path = path

        # ✅ Delete folder
        if is_folder:
            if not os.path.isdir(target_path):
                return {
                    "status": "error",
                    "log": f"Folder not found at '{target_path}'"
                }
            shutil.rmtree(target_path)
            print(f"[🗑️] Folder deleted: {target_path}")
            return {
                "status": "success",
                "log": f"Folder '{target_path}' deleted successfully",
                "path": target_path
            }

        # ✅ Delete file
        else:
            if not os.path.isfile(target_path):
                return {
                    "status": "error",
                    "log": f"File not found at '{target_path}'"
                }
            os.remove(target_path)
            print(f"[🗑️] File deleted: {target_path}")
            return {
                "status": "success",
                "log": f"File '{target_path}' deleted successfully",
                "path": target_path
            }

    except Exception as e:
        print(f"[⛔ delete_file error]: {e}")
        return {
            "status": "error",
            "log": f"Delete failed: {str(e)}"
        }

# ==============================
# TERMINAL COMMAND HANDLER
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
                await sio.emit("command_output", {
                    "agent_id": agent_id,
                    "line": f"Changed directory to {cwd}",
                    "cwd": cwd,
                    "done": True
                })
                return {"status": "success", "cwd": cwd}
            else:
                await sio.emit("command_output", {
                    "agent_id": agent_id,
                    "line": f"[⛔] No such directory: {new_dir}",
                    "cwd": cwd,
                    "done": True
                })
                return {"status": "error", "cwd": cwd}

        # Run subprocess
        process = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Stream stdout
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            await sio.emit("command_output", {
                "agent_id": agent_id,
                "line": line.decode().rstrip(),
                "cwd": cwd
            })

        # Stream stderr
        while True:
            line = await process.stderr.readline()
            if not line:
                break
            await sio.emit("command_output", {
                "agent_id": agent_id,
                "line": "[⛔] " + line.decode().rstrip(),
                "cwd": cwd
            })

        await process.wait()
        await sio.emit("command_output", {
            "agent_id": agent_id,
            "line": f"[✔] Command finished with code {process.returncode}",
            "cwd": cwd,
            "done": True
        })

        return {"status": "success", "cwd": cwd}

    except Exception as e:
        await sio.emit("command_output", {
            "agent_id": agent_id,
            "line": f"[⛔] {str(e)}",
            "cwd": cwd,
            "done": True
        })
        return {"status": "error", "cwd": cwd, "log": str(e)}
    
@sio.on("run_script")
async def on_run_script(data):
    filepath = data['filepath']
    script_id = data.get('script_id', 'unknown')
    logger = setup_logger(AGENT_ID, script_id, "run")
    try:
        print(f"[▶️] Running script: {filepath}")
        user_id = data.get('agent_id', AGENT_ID)
        user_venv_path = os.path.join(VENV_BASE_DIR, user_id)
        python_bin = os.path.join(user_venv_path, "bin", "python")

        #result = subprocess.run([python_bin, filepath], capture_output=True, text=True)
         # Start subprocess (non-blocking)
      # Async subprocess
        process = await asyncio.create_subprocess_exec(
            python_bin, filepath,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
        output = (stdout.decode() if stdout else "") + "\n" + (stderr.decode() if stderr else "")
        status = "script_done" if process.returncode == 0 else "script_failed"

        logger.info("=== Script Run ===\n%s", output.strip())
        print(f"[📜] Script output: {output.strip()}")
        print(f"[✅] Script finished with return code: {process.returncode}{status}")
        await sio.emit(status, {
            "agent_id": AGENT_ID,
            "script_id": script_id,
            "return_code": process.returncode,
            "log": output[-500:],  # limit log size
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.exception("Script run failed")
        print(f"[⛔ run_script error]: {e}")
        return {
            "status": "error",
            "log": f"Run failed: {e}"
        }

@sio.on("setup_cron")
async def on_setup_cron(data):
    filepath = data['filepath']
    script_id = data.get('script_id', 'unknown')
    
    try:
        cron_expr = data['cron']
        cron_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
        job_id = f"{AGENT_ID}_{script_id}_{cron_name}"
        logger = setup_logger(AGENT_ID, script_id,"cron",job_id)
        cron = CronTab(user=True)
        cron.remove_all(comment=job_id)
        user_id = data.get('agent_id', AGENT_ID)
        user_venv_path = os.path.join(VENV_BASE_DIR, user_id)
        python_bin = os.path.join(user_venv_path, "bin", "python")
        log_path = os.path.join(LOG_BASE_DIR, job_id, 'cron.log')

        command = f"{python_bin} {filepath} >> {log_path} 2>&1"

        job = cron.new(command=command, comment=job_id)
        job.setall(cron_expr)
        cron.write()

        print(f"[🕒] Cron job added for {script_id}: {cron_expr}")
        logger.info("Cron setup: %s", cron_expr)
        return {
            "status": "success",
            "log": f"Cron job set: {cron_expr}",
            "job_id": job_id
        }
    except Exception as e:
        logger.exception("Cron setup failed")
        print(f"[⛔ setup_cron error]: {e}")
        return {
            "status": "error",
            "log": f"Setup cron failed: {e}"
        }

@sio.on("remove_cron")
async def on_remove_cron(data):
    script_id = data['script_id']
    job_id = data['job_id']
    logger = setup_logger(AGENT_ID, script_id, "run")
    try:
        cron = CronTab(user=True)
        cron.remove_all(comment=job_id)
        cron.write()

        print(f"[🗑️] Cron job removed: {job_id}")
        logger.info("Cron job removed")
        await on_delete_file({
            "path": os.path.join(LOG_BASE_DIR, job_id),
            "is_folder": True
        })  # Clean up logs
        return {
            "status": "success",
            "log": "Cron job removed"
        }
    except Exception as e:
        logger.exception("Cron removal failed")
        print(f"[⛔ remove_cron error]: {e}")
        return {
            "status": "error",
            "log": f"Remove cron failed: {e}"
        }

@sio.on("toggle_cron")
async def on_toggle_cron(data):
    script_id = data['script_id']
    job_id = data['job_id']
    action = data['action']  # "pause" or "play"
    logger = setup_logger(AGENT_ID, script_id, "cron", job_id)

    try:
        cron = CronTab(user=True)
        modified = False

        for job in cron:
            if job.comment == job_id:
                if action == "pause" and job.enabled:
                    job.enable(False)  # Comment out
                    logger.info("Cron job paused")
                    print(f"[⏸️] Cron job paused: {job_id}")
                elif action == "play" and not job.enabled:
                    job.enable(True)  # Uncomment
                    logger.info("Cron job resumed")
                    print(f"[▶️] Cron job resumed: {job_id}")
                else:
                    logger.info(f"Cron job already in desired state: {action}")
                modified = True
                break

        if modified:
            cron.write()
            return {
                "status": "success",
                "log": f"Cron job {action}d"
            }
        else:
            return {
                "status": "error",
                "log": "Cron job not found"
            }

    except Exception as e:
        logger.exception("Toggle cron failed")
        print(f"[⛔ toggle_cron error]: {e}")
        return {
            "status": "error",
            "log": f"Toggle cron failed: {e}"
        }
    

@sio.on("setup_background")
async def on_setup_background(data):
    filepath = data['filepath']
    script_id = data.get('script_id', 'unknown')
    user_id = data.get('agent_id', AGENT_ID)
    
    job_id = f"{AGENT_ID}_{script_id}_{uuid.uuid4().hex[:6]}"
    logger = setup_logger(AGENT_ID, script_id, "pm2", job_id)

    user_venv_path = os.path.join(VENV_BASE_DIR, user_id)
    python_bin = os.path.join(user_venv_path, "bin", "python")

    log_path = os.path.join(LOG_BASE_DIR, job_id, 'pm2.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # PM2 process name
    process_name = f"{PM2_PROCESS_PREFIX}_{job_id}"

    try:
        command = [
            "pm2", "start", python_bin,
            "--name", process_name,
            "--log", log_path,
            "--", filepath
        ]
        subprocess.run(command, check=True)

        logger.info("PM2 background task started.")
        return {
            "status": "success",
            "log": f"PM2 background task started with process: {process_name}",
            "job_id": job_id,
            "process_name": process_name
        }

    except subprocess.CalledProcessError as e:
        logger.error("PM2 setup failed: %s", str(e))
        return {
            "status": "error",
            "log": f"Failed to start PM2 background task: {str(e)}"
        }    


@sio.on("remove_pm2")
async def on_remove_pm2(data):
    script_id = data['script_id']
    job_id = data['job_id']
    logger = setup_logger(AGENT_ID, script_id, "run", job_id)
    try:
        # Stop and delete the PM2 process
        subprocess.run(["pm2", "delete", f"{PM2_PROCESS_PREFIX}_{job_id}"], check=True)
        print(f"[🗑️] PM2 process removed: {job_id}")
        logger.info("PM2 process removed")

        # Clean up logs
        await on_delete_file({
            "path": os.path.join(LOG_BASE_DIR, job_id),
            "is_folder": True
        })

        return {
            "status": "success",
            "log": "PM2 process removed"
        }

    except Exception as e:
        logger.exception("PM2 removal failed")
        print(f"[⛔ remove_pm2 error]: {e}")
        return {
            "status": "error",
            "log": f"Remove PM2 process failed: {e}"
        }

@sio.on("toggle_pm2")
async def on_toggle_pm2(data):
    script_id = data['script_id']
    job_id = data['job_id']
    action = data['action']  # "pause" or "play"
    logger = setup_logger(AGENT_ID, script_id, "pm2", job_id)

    try:
        if action == "pause":
            subprocess.run(["pm2", "stop", f"{PM2_PROCESS_PREFIX}_{job_id}"], check=True)
            logger.info("PM2 process paused")
            print(f"[⏸️] PM2 process paused: {job_id}")
        elif action == "play":
            subprocess.run(["pm2", "start", f"{PM2_PROCESS_PREFIX}_{job_id}"], check=True)
            logger.info("PM2 process resumed")
            print(f"[▶️] PM2 process resumed: {job_id}")
        else:
            return {
                "status": "error",
                "log": f"Unknown action '{action}'"
            }

        return {
            "status": "success",
            "log": f"PM2 process {action}d"
        }

    except Exception as e:
        logger.exception("Toggle PM2 failed")
        print(f"[⛔ toggle_pm2 error]: {e}")
        return {
            "status": "error",
            "log": f"Toggle PM2 failed: {e}"
        }



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
        return  {"status": "error", "message": str(e)}

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

        return {
            "status": "success",
            "columns": columns,
            "rows": rows,
            "table": table_name
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}

@sio.on("get_logs")
async def on_get_logs(data):
    try:
        script_id = data['script_id']
        mode = data.get('mode', 'run')
        log_file = os.path.join(LOG_BASE_DIR, AGENT_ID, script_id, f"{mode}.log")
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                content = f.read()
        else:
            content = "[!] Log file not found"
        print(f"[📜] Sending logs for script_id={script_id}")
        return {
            "status": "success",
            "log": content[-1000:]
        }
    except Exception as e:
        print(f"[⛔ get_logs error]: {e}")
        return {
            "status": "error",
            "log": f"Get logs failed: {e}"
        }


@sio.on("get_metrics")
async def on_get_metrics(data):
    try:
        metrics = {}
        is_exist = data['is_exist']
        if  is_exist:
            metrics = {
                "cpu": psutil.cpu_percent(interval=0),
                "memory": psutil.virtual_memory().percent,
                "disk": psutil.disk_usage("/").percent,
                "agent_id": AGENT_ID
            }
        else:
            metrics = {
                "cpu": psutil.cpu_percent(interval=0),
                "memory": psutil.virtual_memory().percent,
                "disk": psutil.disk_usage("/").percent,
                "agent_id": AGENT_ID,
                "root_dir": HOME_DIR,
                "script_dir": SCRIPT_DIR,
                "venv_base_dir": VENV_BASE_DIR,
                "log_base_dir": LOG_BASE_DIR
            }
        print("✅ Sent metrics")
        return metrics
    except Exception as e:
        print(f"[⛔ get_metrics error]: {e}")
        return {
            "status": "error",
            "log": f"Get metrics failed: {e}"
        }

# === START ===
async def start():
    try:
        await sio.connect(SERVER_URL)
        await sio.wait()
    except Exception as e:
        print(f"[🚫] Could not connect to server: {e}")

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
                await sio.emit("command_output", {
                    "agent_id": agent_id,
                    "line": f"Changed directory to {cwd}",
                    "cwd": cwd,
                    "done": True
                })
                return {"status": "success", "cwd": cwd}
            else:
                await sio.emit("command_output", {
                    "agent_id": agent_id,
                    "line": f"[⛔] No such directory: {new_dir}",
                    "cwd": cwd,
                    "done": True
                })
                return {"status": "error", "cwd": cwd}

        # Run subprocess
        process = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Stream stdout
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            await sio.emit("command_output", {
                "agent_id": agent_id,
                "line": line.decode().rstrip(),
                "cwd": cwd
            })

        # Stream stderr
        while True:
            line = await process.stderr.readline()
            if not line:
                break
            await sio.emit("command_output", {
                "agent_id": agent_id,
                "line": "[⛔] " + line.decode().rstrip(),
                "cwd": cwd
            })

        await process.wait()
        await sio.emit("command_output", {
            "agent_id": agent_id,
            "line": f"[✔] Command finished with code {process.returncode}",
            "cwd": cwd,
            "done": True
        })

        return {"status": "success", "cwd": cwd}

    except Exception as e:
        await sio.emit("command_output", {
            "agent_id": agent_id,
            "line": f"[⛔] {str(e)}",
            "cwd": cwd,
            "done": True
        })
        return {"status": "error", "cwd": cwd, "log": str(e)}


# === MAIN ===

if __name__ == "__main__":
    asyncio.run(start())
