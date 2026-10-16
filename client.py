import socket
import hashlib
import json
import sys
import os
import math
import queue
import struct
import threading
import time
import platform
import secrets
import sqlite3
import atexit
import shutil
import getpass
from datetime import datetime
from pathlib import PurePosixPath
import zlib
try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    zstd = None
    HAS_ZSTD = False

# Zero-Config Discovery & Dynamic Handshake Ports
DEFAULT_SERVER_PORT = 8080
DISCOVERY_UDP_PORT = 8082
CLIENT_PROBE_UDP_PORT = 8084
DEFAULT_INVITE_PORT = 8083

CHUNK_SIZE = 5 * 1024 * 1024


def detect_os():
    if sys.platform.startswith('win'):
        return 'windows'
    if 'ANDROID_ROOT' in os.environ or 'ANDROID_DATA' in os.environ or os.path.exists('/storage/emulated/0'):
        return 'android'
    return 'linux'


CLIENT_OS = detect_os()
CLIENT_HOSTNAME = platform.node() or socket.gethostname() or f"EFT-{CLIENT_OS.capitalize()}"
CLIENT_ID = f"{CLIENT_HOSTNAME}-{secrets.token_hex(3)}"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_HISTORY_DB_PATH = os.path.join(BASE_DIR, 'client_transfer_history.db')

# Client-controlled security state (configured at startup menu; never hardcoded)
CLIENT_PASSWORD_HASH = ""
REQUIRES_PASSWORD = False


def hash_password(raw_password):
    if not raw_password:
        return ""
    return hashlib.sha256(str(raw_password).encode('utf-8')).hexdigest()


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.'):
                return ip
    except Exception:
        pass
    return '127.0.0.1'


def get_default_browse_directory():
    if CLIENT_OS == 'android':
        return '/storage/emulated/0' if os.path.exists('/storage/emulated/0') else os.path.expanduser('~')
    return os.path.expanduser('~')


DEFAULT_BROWSE_DIR = get_default_browse_directory()

client_running = True
is_connected_to_server = False
active_server_ip = None
active_server_port = DEFAULT_SERVER_PORT
active_server_hostname = "EFT-Server"
active_server_os = "unknown"
bound_invite_port = DEFAULT_INVITE_PORT

transfer_active = False
transfer_lock = threading.Lock()
console_print_lock = threading.Lock()
work_queue = None
master_session_token = None
connect_trigger_event = threading.Event()


def normalize_rel_path(rel_path):
    """Ensure relative paths sent over the wire always use POSIX forward slashes."""
    cleaned = str(rel_path or '').replace('\\', '/').lstrip('/')
    parts = [p for p in PurePosixPath(cleaned).parts if p not in ('', '.', '..')]
    return '/'.join(parts)


def format_bytes_human(num_bytes):
    if not num_bytes or num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = min(int(math.log(num_bytes, 1024)), len(units) - 1)
    return f"{num_bytes / (1024 ** idx):.2f} {units[idx]}"


def format_ts_human(ts):
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "—"


# ==============================================================================
# CLIENT-SIDE TRANSFER HISTORY DATABASE (client_transfer_history.db)
# With automatic WAL -> DELETE mode cleanup so .db-wal and .db-shm never linger
# ==============================================================================
db_lock = threading.RLock()
history_conn = None


def init_client_db():
    global history_conn
    hconn = sqlite3.connect(CLIENT_HISTORY_DB_PATH, check_same_thread=False, isolation_level=None)
    hconn.execute('PRAGMA synchronous=NORMAL')
    hconn.execute("""
        CREATE TABLE IF NOT EXISTS transfer_sessions (
            session_token TEXT PRIMARY KEY,
            title TEXT,
            server_name TEXT,
            server_ip TEXT,
            server_os TEXT,
            client_id TEXT,
            client_name TEXT,
            client_ip TEXT,
            client_os TEXT,
            source_paths TEXT,
            destination_path TEXT,
            started_at REAL,
            updated_at REAL,
            completed_at REAL,
            total_files INTEGER DEFAULT 0,
            completed_files INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            transferred_bytes INTEGER DEFAULT 0,
            total_chunks INTEGER DEFAULT 0,
            received_chunks INTEGER DEFAULT 0,
            status TEXT DEFAULT 'idle'
        )
    """)
    hconn.execute("""
        CREATE TABLE IF NOT EXISTS transfer_history_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT,
            file_id INTEGER,
            relative_path TEXT,
            source_path TEXT,
            save_path TEXT,
            size INTEGER DEFAULT 0,
            mtime REAL,
            atime REAL,
            status TEXT DEFAULT 'pending',
            transferred_at REAL,
            UNIQUE(session_token, relative_path)
        )
    """)

    # Mark any previously active sessions as interrupted on startup
    hconn.execute("""
        UPDATE transfer_sessions
        SET status = 'interrupted', updated_at = ?
        WHERE status = 'active' AND received_chunks < total_chunks
    """, (time.time(),))

    hconn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    hconn.execute('PRAGMA journal_mode=DELETE')
    history_conn = hconn
    return hconn


def enable_db_wal():
    """Enable WAL journal mode during high-concurrency worker streaming."""
    with db_lock:
        if history_conn is not None:
            try:
                history_conn.execute('PRAGMA journal_mode=WAL')
                history_conn.execute('PRAGMA synchronous=NORMAL')
            except Exception:
                pass


def finalize_db_wal():
    """Checkpoint WAL and switch back to DELETE mode so .db-wal and .db-shm vanish immediately."""
    with db_lock:
        if history_conn is not None:
            try:
                history_conn.commit()
                history_conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                history_conn.execute('PRAGMA journal_mode=DELETE')
            except Exception:
                pass


def close_db_cleanly():
    """Guaranteed cleanup on client exit so .db-wal and .db-shm are completely removed."""
    global history_conn
    with db_lock:
        if history_conn is not None:
            try:
                history_conn.commit()
                history_conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                history_conn.execute('PRAGMA journal_mode=DELETE')
                history_conn.close()
            except Exception:
                pass
            history_conn = None


atexit.register(close_db_cleanly)
init_client_db()


def make_session_title(paths):
    if not paths:
        return "Transfer Session"
    first = os.path.basename(str(paths[0]).rstrip('/\\')) or str(paths[0])
    if len(paths) == 1:
        return first
    return f"{first} + {len(paths) - 1} more"


def record_client_session_init(token, title, target_paths, dest_path, srv_name, srv_ip, srv_os,
                               manifest, missing_map, already_completed, tot_chunks, recv_chunks):
    """Create or update the transfer session and file/empty-dir records in client_transfer_history.db."""
    now = time.time()
    c_ip = get_local_ip()
    files_list = manifest.get("files", [])
    dirs_list = manifest.get("dirs", [])
    total_files = len(files_list)
    total_bytes = manifest.get("total_bytes", 0)
    completed_set = set(already_completed or [])

    with db_lock:
        existing = history_conn.execute(
            "SELECT started_at FROM transfer_sessions WHERE session_token=?", (token,)
        ).fetchone()
        started_at = existing[0] if (existing and existing[0]) else now

        init_status = 'completed' if (total_files == 0 or not missing_map) else 'active'

        history_conn.execute("""
            INSERT OR REPLACE INTO transfer_sessions (
                session_token, title,
                server_name, server_ip, server_os,
                client_id, client_name, client_ip, client_os,
                source_paths, destination_path, started_at, updated_at, completed_at,
                total_files, completed_files, total_bytes, transferred_bytes,
                total_chunks, received_chunks, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        """, (
            token, title,
            srv_name or active_server_hostname, srv_ip or active_server_ip, srv_os or active_server_os,
            CLIENT_ID, CLIENT_HOSTNAME, c_ip, CLIENT_OS,
            json.dumps(target_paths), dest_path or "", started_at, now,
            now if init_status == 'completed' else None,
            total_files, len(completed_set), total_bytes,
            tot_chunks, recv_chunks, init_status
        ))

        # Log empty folders in history so the user sees what was created
        for dinfo in dirs_list:
            rel_d = dinfo["relative_path"].rstrip('/') + '/'
            src_d = dinfo.get("source_path") or rel_d
            save_d = os.path.join(dest_path or "", *rel_d.strip('/').split('/')) if dest_path else rel_d
            history_conn.execute("""
                INSERT INTO transfer_history_files (
                    session_token, file_id, relative_path, source_path, save_path,
                    size, mtime, atime, status, transferred_at
                ) VALUES (?, 0, ?, ?, ?, 0, ?, ?, 'completed', ?)
                ON CONFLICT(session_token, relative_path) DO UPDATE SET
                    status = 'completed',
                    transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
            """, (token, rel_d, src_d, save_d, dinfo.get("mtime", now), dinfo.get("atime", now), now))

        for finfo in files_list:
            rel_p = finfo["relative_path"]
            src_p = finfo.get("source_path") or rel_p
            m_entry = missing_map.get(rel_p, {})
            fid = m_entry.get("file_id", 0)
            save_p = m_entry.get("save_path", dest_path or "")
            is_done = (rel_p in completed_set) or (rel_p not in missing_map)
            f_status = 'completed' if is_done else 'pending'
            done_ts = now if is_done else None

            history_conn.execute("""
                INSERT INTO transfer_history_files (
                    session_token, file_id, relative_path, source_path, save_path,
                    size, mtime, atime, status, transferred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_token, relative_path) DO UPDATE SET
                    file_id = CASE WHEN excluded.file_id > 0 THEN excluded.file_id ELSE transfer_history_files.file_id END,
                    source_path = excluded.source_path,
                    save_path = CASE WHEN excluded.save_path != '' THEN excluded.save_path ELSE transfer_history_files.save_path END,
                    status = CASE WHEN transfer_history_files.status = 'completed' THEN 'completed' ELSE excluded.status END,
                    transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
            """, (
                token, fid, rel_p, src_p, save_p,
                finfo["size"], finfo["mtime"], finfo["atime"], f_status, done_ts
            ))

        sync_client_session_progress(token, recv_chunks, tot_chunks, override_status=init_status)


def sync_client_session_progress(token, received_chunks=None, total_chunks=None, override_status=None):
    """Synchronize session counters and status in client_transfer_history.db."""
    if not token:
        return
    now = time.time()
    with db_lock:
        s_row = history_conn.execute("""
            SELECT total_bytes, total_chunks, received_chunks, status
            FROM transfer_sessions WHERE session_token=?
        """, (token,)).fetchone()
        if not s_row:
            return
        total_bytes = s_row[0] or 0
        tot_c = total_chunks if total_chunks is not None else (s_row[1] or 0)
        recv_c = received_chunks if received_chunks is not None else (s_row[2] or 0)
        cur_status = s_row[3] or 'active'

        f_row = history_conn.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status='completed' THEN size ELSE 0 END)
            FROM transfer_history_files WHERE session_token=?
        """, (token,)).fetchone()
        tot_f = f_row[0] or 0
        comp_f = f_row[1] or 0
        comp_bytes = f_row[2] or 0

        if tot_c > 0 and recv_c < tot_c:
            approx_bytes = min(total_bytes, int((recv_c / tot_c) * total_bytes))
            trans_bytes = max(comp_bytes, approx_bytes)
        elif tot_c > 0 and recv_c >= tot_c:
            trans_bytes = total_bytes
        else:
            trans_bytes = comp_bytes

        new_status = override_status if override_status else cur_status
        completed_sql = ", completed_at = ?" if new_status == 'completed' else ""
        params = [now, tot_f, comp_f, trans_bytes, tot_c, recv_c, new_status]
        if new_status == 'completed':
            params.append(now)
        params.append(token)

        history_conn.execute(f"""
            UPDATE transfer_sessions
            SET updated_at = ?,
                total_files = ?,
                completed_files = ?,
                transferred_bytes = ?,
                total_chunks = ?,
                received_chunks = ?,
                status = ?
                {completed_sql}
            WHERE session_token = ?
        """, tuple(params))


def update_client_session_state_on_action(token, action_name):
    """Update client_transfer_history.db when pause, cancel, or rollback occurs."""
    target_token = token or master_session_token
    if not target_token:
        return
    now = time.time()
    with db_lock:
        if action_name == "pause_transfer":
            history_conn.execute(
                "UPDATE transfer_sessions SET status='paused', updated_at=? WHERE session_token=?",
                (now, target_token)
            )
        elif action_name == "cancel_transfer":
            history_conn.execute("""
                UPDATE transfer_history_files
                SET status='cancelled'
                WHERE session_token=? AND status != 'completed'
            """, (target_token,))
            sync_client_session_progress(target_token, override_status='cancelled')
        elif action_name == "rollback_transfer":
            history_conn.execute(
                "UPDATE transfer_history_files SET status='rolled_back' WHERE session_token=?",
                (target_token,)
            )
            history_conn.execute("""
                UPDATE transfer_sessions
                SET status='rolled_back', completed_files=0, transferred_bytes=0, received_chunks=0, updated_at=?
                WHERE session_token=?
            """, (now, target_token))
    finalize_db_wal()


# ==============================================================================
# DIRECTORY LISTING & MANIFEST BUILDER
# ==============================================================================
def list_directory(target_path):
    """Cross-platform directory listing supporting Windows drives, Linux, and Android."""
    if not target_path or not str(target_path).strip():
        target_path = DEFAULT_BROWSE_DIR
    else:
        target_path = os.path.expanduser(str(target_path).strip())

    if CLIENT_OS == 'windows' and target_path in ('/', '\\', 'DRIVES', 'drives'):
        drives = []
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            drive_root = f"{letter}:\\"
            if os.path.exists(drive_root):
                drives.append({
                    "name": f"Drive ({letter}:)",
                    "is_dir": True,
                    "path": drive_root,
                    "size": 0,
                    "mtime": 0
                })
        return {
            "status": "success",
            "os": CLIENT_OS,
            "current_path": "DRIVES",
            "parent_path": "DRIVES",
            "items": drives
        }

    if CLIENT_OS != 'windows' and target_path == '/':
        target_path = DEFAULT_BROWSE_DIR if CLIENT_OS == 'android' and not os.access('/', os.R_OK) else '/'

    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        return {"status": "error", "message": f"Path not found: {target_path}", "os": CLIENT_OS}
    if not os.path.isdir(target_path):
        target_path = os.path.dirname(target_path)

    parent_path = os.path.dirname(target_path.rstrip('/\\'))
    if CLIENT_OS == 'windows':
        drive, tail = os.path.splitdrive(target_path)
        if tail in ('\\', '/', ''):
            parent_path = 'DRIVES'
    else:
        if not parent_path:
            parent_path = '/'

    try:
        items = []
        with os.scandir(target_path) as entries:
            for entry in entries:
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    stat = entry.stat(follow_symlinks=False)
                    items.append({
                        "name": entry.name,
                        "is_dir": is_dir,
                        "path": entry.path,
                        "size": 0 if is_dir else stat.st_size,
                        "mtime": stat.st_mtime
                    })
                except (PermissionError, OSError):
                    continue
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return {
            "status": "success",
            "os": CLIENT_OS,
            "current_path": target_path,
            "parent_path": parent_path,
            "items": items
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "os": CLIENT_OS, "current_path": target_path}


def build_manifest(target_paths):
    manifest = {"files": [], "dirs": [], "total_bytes": 0}
    local_mapping = {}

    for raw_target in target_paths:
        target_path = os.path.abspath(os.path.expanduser(raw_target))
        if not os.path.exists(target_path):
            continue

        parent_dir = os.path.dirname(target_path.rstrip('/\\'))

        if os.path.isfile(target_path):
            try:
                stat = os.stat(target_path)
                rel_path = normalize_rel_path(os.path.basename(target_path))
                manifest["files"].append({
                    "relative_path": rel_path,
                    "source_path": target_path,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "atime": stat.st_atime
                })
                manifest["total_bytes"] += stat.st_size
                local_mapping[rel_path] = target_path
            except (PermissionError, OSError):
                continue

        elif os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path):
                # Track empty directories (no files and no subdirectories inside)
                if not files and not dirs:
                    try:
                        stat = os.stat(root)
                        rel_dir = normalize_rel_path(os.path.relpath(root, parent_dir))
                        if rel_dir:
                            manifest["dirs"].append({
                                "relative_path": rel_dir,
                                "source_path": root,
                                "mtime": stat.st_mtime,
                                "atime": stat.st_atime
                            })
                    except (PermissionError, OSError):
                        pass

                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        stat = os.stat(full_path)
                        rel_raw = os.path.relpath(full_path, parent_dir)
                        rel_path = normalize_rel_path(rel_raw)
                        manifest["files"].append({
                            "relative_path": rel_path,
                            "source_path": full_path,
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "atime": stat.st_atime
                        })
                        manifest["total_bytes"] += stat.st_size
                        local_mapping[rel_path] = full_path
                    except (PermissionError, OSError):
                        continue

    return manifest, local_mapping


def recv_json_line(sock, max_bytes=50 * 1024 * 1024):
    buf = bytearray()
    while len(buf) < max_bytes:
        try:
            chunk = sock.recv(4096)
        except Exception:
            return None
        if not chunk:
            break
        nl_idx = chunk.find(b'\n')
        if nl_idx != -1:
            buf.extend(chunk[:nl_idx])
            break
        buf.extend(chunk)
    if not buf:
        return None
    raw_str = buf.decode('utf-8', errors='replace').strip()
    try:
        return json.loads(raw_str)
    except Exception:
        return {"status": raw_str}


# ==============================================================================
# PRODUCER-CONSUMER CHUNK PIPELINE & LIVE CONSOLE PROGRESS LOGS
# ==============================================================================
def process_and_compress_chunks(local_mapping, manifest, chunk_queue, missing_map):
    global transfer_active
    cctx = zstd.ZstdCompressor(level=3) if HAS_ZSTD else None

    for file_info in manifest["files"]:
        if not transfer_active:
            break

        rel_path = file_info["relative_path"]
        if rel_path not in missing_map:
            continue

        file_id = missing_map[rel_path]["file_id"]
        missing_indices = sorted(missing_map[rel_path]["missing"])
        full_path = local_mapping.get(rel_path)
        if not full_path or not os.path.exists(full_path):
            continue

        try:
            with open(full_path, 'rb') as f:
                for chunk_index in missing_indices:
                    if not transfer_active:
                        break
                    f.seek(chunk_index * CHUNK_SIZE)
                    raw_bytes = f.read(CHUNK_SIZE)
                    if not raw_bytes and file_info["size"] > 0:
                        break
                    compressed = cctx.compress(raw_bytes) if HAS_ZSTD else zlib.compress(raw_bytes, level=1)
                    while transfer_active:
                        try:
                            chunk_queue.put({
                                "file_id": file_id,
                                "relative_path": rel_path,
                                "file_size": file_info["size"],
                                "chunk_index": chunk_index,
                                "data": compressed
                            }, timeout=0.5)
                            break
                        except queue.Full:
                            continue
        except (PermissionError, OSError):
            continue

    for _ in range(4):
        try:
            chunk_queue.put(None, timeout=1.0)
        except Exception:
            pass


def network_worker(worker_id, chunk_queue, session_token, server_ip, server_port, srv_name):
    global transfer_active
    worker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    worker_socket.settimeout(25.0)
    try:
        worker_socket.connect((server_ip, server_port))
        auth = {"action": "worker_auth", "session_token": session_token}
        worker_socket.sendall((json.dumps(auth) + "\n").encode('utf-8'))

        ack = worker_socket.recv(1024).decode('utf-8', errors='replace').strip()
        if "success" not in ack:
            return

        while transfer_active:
            try:
                chunk = chunk_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if chunk is None:
                chunk_queue.task_done()
                break

            meta = {
                "file_id": chunk["file_id"],
                "chunk_index": chunk["chunk_index"],
                "comp": "zstd" if HAS_ZSTD else "zlib"
            }
            meta_bytes = json.dumps(meta).encode('utf-8')
            chunk_data = chunk["data"]

            header = struct.pack('!II', len(meta_bytes), len(chunk_data))
            worker_socket.sendall(header + meta_bytes + chunk_data)

            ack_msg = recv_json_line(worker_socket)
            chunk_queue.task_done()
            if not ack_msg:
                break

            if isinstance(ack_msg, dict):
                rel_p = ack_msg.get("relative_path") or chunk.get("relative_path", "")
                f_size = ack_msg.get("file_size", chunk.get("file_size", 0))
                recv_c = ack_msg.get("received_chunks")
                tot_c = ack_msg.get("total_chunks")
                comp_f = ack_msg.get("completed_files", 0)
                tot_f = ack_msg.get("total_files", 0)
                sess_done = bool(ack_msg.get("session_completed", False))

                if ack_msg.get("file_completed"):
                    done_ts = ack_msg.get("transferred_at") or time.time()
                    with db_lock:
                        history_conn.execute("""
                            UPDATE transfer_history_files
                            SET status = 'completed', transferred_at = ?
                            WHERE session_token = ? AND relative_path = ?
                        """, (done_ts, session_token, rel_p))
                        sync_client_session_progress(
                            session_token,
                            received_chunks=recv_c,
                            total_chunks=tot_c,
                            override_status='completed' if sess_done else 'active'
                        )
                    pct = round((recv_c / tot_c * 100), 1) if (tot_c and recv_c is not None) else 100.0
                    ts_str = format_ts_human(done_ts)
                    with console_print_lock:
                        print(
                            f"[{ts_str}] ✓ Transferred {rel_p} ({format_bytes_human(f_size)}) "
                            f"[{comp_f}/{tot_f} files | {pct}%] -> Server {srv_name} ({server_ip})"
                        )
                elif recv_c is not None and tot_c is not None:
                    sync_client_session_progress(
                        session_token,
                        received_chunks=recv_c,
                        total_chunks=tot_c,
                        override_status='completed' if sess_done else None
                    )
    except Exception:
        pass
    finally:
        try:
            worker_socket.close()
        except Exception:
            pass


def stop_local_workers():
    global transfer_active, work_queue
    transfer_active = False
    if work_queue is not None:
        while not work_queue.empty():
            try:
                work_queue.get_nowait()
                work_queue.task_done()
            except Exception:
                break
        for _ in range(4):
            try:
                work_queue.put_nowait(None)
            except Exception:
                pass


def send_server_action(action_name):
    global master_session_token, active_server_ip, active_server_port
    if not active_server_ip:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((active_server_ip, active_server_port))
        s.sendall((json.dumps({"action": action_name, "session_token": master_session_token}) + "\n").encode('utf-8'))
        s.close()
    except Exception:
        pass


def execute_transfer(target_paths, requested_session_token=None, session_meta=None):
    global transfer_active, work_queue, master_session_token
    global active_server_ip, active_server_port, active_server_hostname, active_server_os
    if not active_server_ip:
        return
    stop_local_workers()
    session_meta = session_meta or {}

    with transfer_lock:
        transfer_active = True
        file_manifest, local_mapping = build_manifest(target_paths)

        # Notice: Even if file_manifest["files"] is empty, we STILL send the manifest to the server
        # so the server creates any empty directories and marks the session 'completed' instead of hanging!
        enable_db_wal()
        t_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t_sock.settimeout(30.0)
        try:
            t_sock.connect((active_server_ip, active_server_port))
            init_auth = {
                "password_hash": CLIENT_PASSWORD_HASH,
                "client_id": CLIENT_ID,
                "hostname": CLIENT_HOSTNAME,
                "os": CLIENT_OS
            }
            if requested_session_token:
                init_auth["session_token"] = requested_session_token
            t_sock.sendall((json.dumps(init_auth) + "\n").encode('utf-8'))

            resp = recv_json_line(t_sock)
            if not resp or resp.get("status") != "success":
                transfer_active = False
                finalize_db_wal()
                return
            token = resp.get("session_token")
            master_session_token = token

            srv_name = resp.get("server_hostname") or session_meta.get("server_hostname") or active_server_hostname
            srv_os = resp.get("server_os") or session_meta.get("server_os") or active_server_os
            srv_ip = resp.get("server_ip") or session_meta.get("server_ip") or active_server_ip
            dest_path = resp.get("destination_path") or session_meta.get("destination_path") or ""

            payload = {"action": "init_transfer", "session_token": token, "manifest": file_manifest}
            t_sock.sendall((json.dumps(payload) + "\n").encode('utf-8'))

            server_response = recv_json_line(t_sock) or {}
            missing_map = server_response.get("missing_map", {})
            already_completed = server_response.get("already_completed", [])
            dest_path = server_response.get("destination_path") or dest_path
            sess_title = server_response.get("session_title") or session_meta.get("session_title") or make_session_title(target_paths)
            srv_name = server_response.get("server_hostname") or srv_name
            srv_ip = server_response.get("server_ip") or srv_ip
            srv_os = server_response.get("server_os") or srv_os
            tot_chunks = server_response.get("total_chunks", 0)
            recv_chunks = server_response.get("received_chunks", 0)
        except Exception as e:
            print(f"[!] Transfer initialization error: {e}")
            transfer_active = False
            finalize_db_wal()
            return
        finally:
            try:
                t_sock.close()
            except Exception:
                pass

        record_client_session_init(
            token=token,
            title=sess_title,
            target_paths=target_paths,
            dest_path=dest_path,
            srv_name=srv_name,
            srv_ip=srv_ip,
            srv_os=srv_os,
            manifest=file_manifest,
            missing_map=missing_map,
            already_completed=already_completed,
            tot_chunks=tot_chunks,
            recv_chunks=recv_chunks
        )

        num_files = len(file_manifest.get("files", []))
        num_dirs = len(file_manifest.get("dirs", []))

        with console_print_lock:
            print(
                f"\n[*] Session '{sess_title}' ({token[:8]}) -> Server {srv_name} ({srv_ip}) [{srv_os.upper()}]\n"
                f"    Files: {num_files} ({format_bytes_human(file_manifest['total_bytes'])}) | "
                f"Empty Folders: {num_dirs} | Destination: {dest_path}"
            )
            for dinfo in file_manifest.get("dirs", []):
                ts_now = format_ts_human(time.time())
                print(f"[{ts_now}] 📁 Created empty directory '{dinfo['relative_path']}/' -> Server {srv_name} ({srv_ip})")

        if not missing_map:
            sync_client_session_progress(token, received_chunks=tot_chunks, total_chunks=tot_chunks, override_status='completed')
            finalize_db_wal()
            with console_print_lock:
                if num_files == 0 and num_dirs > 0:
                    print(f"[*] Session '{sess_title}' ({token[:8]}) COMPLETED: {num_dirs} empty folder(s) created on server.")
                else:
                    print(f"[*] Session '{sess_title}' ({token[:8]}) COMPLETED (all {num_files} file(s) already up-to-date on server).")
            transfer_active = False
            return

        work_queue = queue.Queue(maxsize=20)
        producer_thread = threading.Thread(
            target=process_and_compress_chunks,
            args=(local_mapping, file_manifest, work_queue, missing_map),
            daemon=True
        )
        producer_thread.start()

        workers = []
        for i in range(4):
            t = threading.Thread(
                target=network_worker,
                args=(i + 1, work_queue, token, active_server_ip, active_server_port, srv_name),
                daemon=True
            )
            t.start()
            workers.append(t)

        producer_thread.join()
        for t in workers:
            t.join()

        with db_lock:
            row = history_conn.execute(
                "SELECT status, completed_files, total_files, total_bytes FROM transfer_sessions WHERE session_token=?",
                (token,)
            ).fetchone()
            if row and row[0] == 'active':
                if row[1] >= row[2] and row[2] > 0:
                    sync_client_session_progress(token, override_status='completed')
                    with console_print_lock:
                        print(f"[*] Session '{sess_title}' ({token[:8]}) COMPLETED: {row[1]}/{row[2]} files ({format_bytes_human(row[3])}) transferred.")

        finalize_db_wal()
        transfer_active = False


# ==============================================================================
# ZERO-CONFIG WAITING, CLIENT-PASSWORD HANDSHAKE & AUTO-DISCOVERY ENGINE
# ==============================================================================
def handle_invite_payload(payload, sender_ip):
    """
    Validate an incoming connection invitation from an EFT Server Web UI click.
    Returns 'ok', 'auth_failed', or 'invalid'.
    """
    global active_server_ip, active_server_port, active_server_hostname, active_server_os
    if payload.get("action") != "connect_to_server":
        return "invalid"

    incoming_hash = (payload.get("password_hash") or "").strip()
    if REQUIRES_PASSWORD and incoming_hash != CLIENT_PASSWORD_HASH:
        print(f"[!] Rejected connection attempt from Server {sender_ip} (invalid client password).")
        return "auth_failed"

    target_ip = sender_ip
    preferred_ip = payload.get("preferred_server_ip")
    if target_ip in ('127.0.0.1', '0.0.0.0', '') and preferred_ip:
        target_ip = preferred_ip

    active_server_ip = target_ip
    active_server_port = int(payload.get("server_port") or DEFAULT_SERVER_PORT)
    active_server_hostname = payload.get("server_hostname") or "EFT-Server"
    active_server_os = (payload.get("server_os") or "unknown").lower()

    print(
        f"[*] Accepted connection invitation from Server {active_server_hostname} "
        f"({active_server_ip}:{active_server_port}) [OS: {active_server_os.upper()}]"
    )
    connect_trigger_event.set()
    return "ok"


def tcp_invite_listener_loop():
    """Listen on TCP invite port so the Server Web UI can click to connect and verify password."""
    global bound_invite_port
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    for candidate_port in range(DEFAULT_INVITE_PORT, DEFAULT_INVITE_PORT + 15):
        try:
            srv.bind(('0.0.0.0', candidate_port))
            bound_invite_port = candidate_port
            break
        except OSError:
            continue
    else:
        srv.bind(('0.0.0.0', 0))
        bound_invite_port = srv.getsockname()[1]

    srv.listen(5)
    srv.settimeout(1.0)
    while client_running:
        try:
            conn, addr = srv.accept()
            conn.settimeout(3.0)
            msg = recv_json_line(conn)
            result = handle_invite_payload(msg, addr[0]) if isinstance(msg, dict) else "invalid"
            if result == "ok":
                conn.sendall(b"connecting\n")
            elif result == "auth_failed":
                conn.sendall(b"auth_failed\n")
            else:
                conn.sendall(b"rejected\n")
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            continue
    try:
        srv.close()
    except Exception:
        pass


known_server_ips = set()


def get_client_broadcast_targets():
    targets = {
        ('255.255.255.255', DISCOVERY_UDP_PORT),
        ('127.0.0.1', DISCOVERY_UDP_PORT)
    }
    lip = get_local_ip()
    parts = lip.split('.')
    if len(parts) == 4 and not lip.startswith('127.'):
        targets.add((f"{parts[0]}.{parts[1]}.{parts[2]}.255", DISCOVERY_UDP_PORT))
    if active_server_ip:
        targets.add((active_server_ip, DISCOVERY_UDP_PORT))
    for sip in list(known_server_ips):
        targets.add((sip, DISCOVERY_UDP_PORT))
    return list(targets)


def udp_beacon_and_probe_loop():
    """
    Periodically broadcast waiting presence across all subnet broadcast addresses and known server IPs
    so the EFT Server always sees this client even when routers filter 255.255.255.255.
    """
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass

    try:
        udp_sock.bind(('0.0.0.0', CLIENT_PROBE_UDP_PORT))
    except Exception:
        try:
            udp_sock.bind(('0.0.0.0', 0))
        except Exception:
            pass

    udp_sock.settimeout(0.5)
    last_beacon = 0.0

    def send_beacon(target_addr=None):
        beacon = json.dumps({
            "type": "eft_client_beacon",
            "client_id": CLIENT_ID,
            "hostname": CLIENT_HOSTNAME,
            "os": CLIENT_OS,
            "ip": get_local_ip(),
            "invite_port": bound_invite_port,
            "requires_password": REQUIRES_PASSWORD,
            "waiting": not is_connected_to_server
        }).encode('utf-8')
        targets = [target_addr] if target_addr else get_client_broadcast_targets()
        for t in targets:
            try:
                udp_sock.sendto(beacon, t)
            except Exception:
                pass

    while client_running:
        now = time.time()
        interval = 1.2 if not is_connected_to_server else 3.0
        if now - last_beacon >= interval:
            send_beacon()
            last_beacon = now

        try:
            data, addr = udp_sock.recvfrom(4096)
            msg = json.loads(data.decode('utf-8'))
            if msg.get("type") == "eft_server_probe":
                disc_port = int(msg.get("discovery_port") or DISCOVERY_UDP_PORT)
                known_server_ips.add(addr[0])
                for sip in (msg.get("server_ips") or []):
                    known_server_ips.add(sip)
                send_beacon((addr[0], disc_port))
                for sip in (msg.get("server_ips") or []):
                    send_beacon((sip, disc_port))
            elif msg.get("action") == "connect_to_server":
                known_server_ips.add(addr[0])
                handle_invite_payload(msg, addr[0])
        except socket.timeout:
            continue
        except Exception:
            continue

    try:
        udp_sock.close()
    except Exception:
        pass


def run_control_session(server_ip, server_port):
    """Connect and maintain the authenticated control channel with the inviting server."""
    global is_connected_to_server, active_server_hostname, active_server_os, active_server_ip, master_session_token
    c_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c_sock.settimeout(10.0)
    try:
        c_sock.connect((server_ip, server_port))
    except Exception as e:
        print(f"[!] Could not connect to inviting server {server_ip}:{server_port} -> {e}")
        return

    auth_payload = {
        "action": "control_auth",
        "password_hash": CLIENT_PASSWORD_HASH,
        "client_id": CLIENT_ID,
        "hostname": CLIENT_HOSTNAME,
        "os": CLIENT_OS,
        "invite_port": bound_invite_port
    }
    try:
        c_sock.sendall((json.dumps(auth_payload) + "\n").encode('utf-8'))
        ack_resp = recv_json_line(c_sock)
        if not ack_resp or ack_resp.get("status") != "success":
            print("[!] Control authentication rejected by server.")
            c_sock.close()
            return
        if ack_resp.get("server_hostname"):
            active_server_hostname = ack_resp["server_hostname"]
        if ack_resp.get("server_os"):
            active_server_os = ack_resp["server_os"].lower()
    except Exception:
        try:
            c_sock.close()
        except Exception:
            pass
        return

    c_sock.settimeout(None)
    is_connected_to_server = True
    print(
        f"[*] Connected to EFT Server {active_server_hostname} ({server_ip}:{server_port}) "
        f"[Server OS: {active_server_os.upper()}] as {CLIENT_HOSTNAME} [{CLIENT_OS.upper()}]."
    )

    buffer = bytearray()
    try:
        while client_running:
            data = c_sock.recv(4096)
            if not data:
                break
            buffer.extend(data)

            while b'\n' in buffer:
                nl = buffer.find(b'\n')
                line_bytes = bytes(buffer[:nl]).strip()
                del buffer[:nl + 1]
                if not line_bytes:
                    continue

                cmd = json.loads(line_bytes.decode('utf-8'))
                action = cmd.get("action")

                if action == "list_dir":
                    res = list_directory(cmd.get("path"))
                    res["action"] = "dir_result"
                    c_sock.sendall((json.dumps(res) + "\n").encode('utf-8'))

                elif action == "start_transfer":
                    paths = cmd.get("paths", [])
                    req_tok = cmd.get("session_token")
                    session_meta = {
                        "session_title": cmd.get("session_title"),
                        "destination_path": cmd.get("destination_path"),
                        "server_hostname": cmd.get("server_hostname") or active_server_hostname,
                        "server_ip": cmd.get("server_ip") or server_ip,
                        "server_os": cmd.get("server_os") or active_server_os
                    }
                    if paths:
                        threading.Thread(
                            target=execute_transfer,
                            args=(paths, req_tok, session_meta),
                            daemon=True
                        ).start()

                elif action in ("cancel_transfer", "stop_transfer", "pause_transfer", "rollback_transfer"):
                    stop_local_workers()
                    update_client_session_state_on_action(cmd.get("session_token"), action)
                    with console_print_lock:
                        print(f"[*] Server requested '{action}' for session {cmd.get('session_token') or master_session_token}.")

                elif action == "disconnect_control":
                    stop_local_workers()
                    return
    except Exception:
        pass
    finally:
        stop_local_workers()
        is_connected_to_server = False
        if master_session_token:
            with db_lock:
                r = history_conn.execute(
                    "SELECT status, received_chunks, total_chunks FROM transfer_sessions WHERE session_token=?",
                    (master_session_token,)
                ).fetchone()
                if r and r[0] == 'active' and (r[1] or 0) < (r[2] or 0):
                    sync_client_session_progress(master_session_token, override_status='interrupted')
        finalize_db_wal()
        try:
            c_sock.close()
        except Exception:
            pass
        if client_running:
            print("[*] Disconnected from server. Ready and waiting for any EFT Server connection...")


# ==============================================================================
# INTERACTIVE TERMINAL UI (TUI) STARTUP MENU & NANO-STYLE HISTORY VIEWER
# ==============================================================================
def clear_terminal():
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    else:
        os.system('cls' if CLIENT_OS == 'windows' else 'clear')


def read_single_key():
    """
    Cross-platform single-keypress reader for nano-style terminal navigation.
    Works on Windows (msvcrt) and Linux / Android Termux (termios + tty).
    """
    if CLIENT_OS == 'windows':
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ('\x00', '\xe0'):
            ch2 = msvcrt.getwch()
            mapping = {
                'H': 'UP',
                'P': 'DOWN',
                'K': 'LEFT',
                'M': 'RIGHT',
                'I': 'PGUP',
                'Q': 'PGDN'
            }
            return mapping.get(ch2, '')
        if ch in ('\r', '\n'):
            return 'ENTER'
        if ch == '\x08':
            return 'BACKSPACE'
        if ch == '\x1b':
            return 'ESC'
        if ch == '\x03':
            raise KeyboardInterrupt
        return ch.lower()
    else:
        import termios
        import tty
        import select
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1)
            if not ch:
                return ''
            if ch == b'\x03':
                raise KeyboardInterrupt
            if ch in (b'\r', b'\n'):
                return 'ENTER'
            if ch in (b'\x7f', b'\x08'):
                return 'BACKSPACE'
            if ch == b'\x1b':
                rlist, _, _ = select.select([fd], [], [], 0.08)
                if rlist:
                    seq = os.read(fd, 3)
                    if seq.startswith(b'[A') or seq.startswith(b'OA'):
                        return 'UP'
                    if seq.startswith(b'[B') or seq.startswith(b'OB'):
                        return 'DOWN'
                    if seq.startswith(b'[C') or seq.startswith(b'OC'):
                        return 'RIGHT'
                    if seq.startswith(b'[D') or seq.startswith(b'OD'):
                        return 'LEFT'
                    if seq.startswith(b'[5'):
                        return 'PGUP'
                    if seq.startswith(b'[6'):
                        return 'PGDN'
                return 'ESC'
            return ch.decode('utf-8', errors='ignore').lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def interactive_history_viewer():
    """Nano/less-style interactive terminal viewer for client_transfer_history.db."""
    selected_idx = 0
    file_scroll_idx = 0
    viewing_session_token = None

    while True:
        term_cols, term_rows = shutil.get_terminal_size((110, 30))
        page_size = max(5, term_rows - 12)

        with db_lock:
            sessions = history_conn.execute("""
                SELECT session_token, title,
                       server_name, server_ip, server_os,
                       client_id, client_name, client_ip, client_os,
                       source_paths, destination_path, started_at, updated_at, completed_at,
                       total_files, completed_files, total_bytes, transferred_bytes,
                       total_chunks, received_chunks, status
                FROM transfer_sessions
                ORDER BY started_at DESC
            """).fetchall()
        finalize_db_wal()

        clear_terminal()
        border = "=" * min(term_cols - 1, 115)

        if viewing_session_token is None:
            print(border)
            print(" ⚡ EFT v2.4 CLIENT — NANO-STYLE TRANSFER HISTORY VIEWER (client_transfer_history.db)")
            print(border)

            if not sessions:
                print("\n   No transfer sessions recorded in client_transfer_history.db yet.\n")
                print(border)
                print(" Controls: [q / Esc / Enter] Return to Startup Menu")
                print(border)
                key = read_single_key()
                if key in ('q', 'ESC', 'ENTER', 'BACKSPACE'):
                    break
                continue

            selected_idx = max(0, min(selected_idx, len(sessions) - 1))
            start_idx = (selected_idx // page_size) * page_size
            end_idx = min(len(sessions), start_idx + page_size)

            print(f" Showing Sessions {start_idx + 1}-{end_idx} of {len(sessions)}:")
            print("-" * min(term_cols - 1, 115))
            header_fmt = f" {'#':<3} | {'STATUS':<11} | {'TITLE':<20} | {'FILES':<9} | {'DATA SIZE':<11} | {'SERVER (NAME / IP / OS)':<28} | {'STARTED AT':<19}"
            print(header_fmt[:term_cols - 1])
            print("-" * min(term_cols - 1, 115))

            for idx in range(start_idx, end_idx):
                s = sessions[idx]
                marker = "▶" if idx == selected_idx else " "
                status_str = (s[20] or 'idle').upper()[:11]
                title_str = (s[1] or 'Session')[:20]
                files_str = f"{s[15] or 0}/{s[14] or 0}"
                size_str = format_bytes_human(s[16] or 0)
                srv_peer = f"{s[2] or 'Server'} ({s[3] or '?'}) [{(s[4] or '?').upper()}]"[:28]
                started_str = format_ts_human(s[11])
                line = f"{marker}{idx + 1:<3} | {status_str:<11} | {title_str:<20} | {files_str:<9} | {size_str:<11} | {srv_peer:<28} | {started_str:<19}"
                if idx == selected_idx:
                    print(f"\033[7m{line[:term_cols - 1]}\033[0m")
                else:
                    print(line[:term_cols - 1])

            s_cur = sessions[selected_idx]
            print("-" * min(term_cols - 1, 115))
            print(f" Selected Session ID : {s_cur[0]}")
            print(f" Server Peer         : {s_cur[2] or 'Server'} ({s_cur[3] or 'N/A'}) [{(s_cur[4] or 'unknown').upper()}] | Server Dest: {s_cur[10] or 'N/A'}")
            print(f" Client Device       : {s_cur[6] or CLIENT_HOSTNAME} ({s_cur[7] or get_local_ip()}) [{(s_cur[8] or CLIENT_OS).upper()}]")
            print(border)
            print(" Controls: [↑/↓] Select Session  [←/→] Page  [Enter] Inspect Transferred Files  [q/Esc] Back to Menu")
            print(border)

            key = read_single_key()
            if key == 'UP':
                selected_idx = (selected_idx - 1) % len(sessions)
            elif key == 'DOWN':
                selected_idx = (selected_idx + 1) % len(sessions)
            elif key in ('LEFT', 'PGUP'):
                selected_idx = max(0, selected_idx - page_size)
            elif key in ('RIGHT', 'PGDN'):
                selected_idx = min(len(sessions) - 1, selected_idx + page_size)
            elif key == 'ENTER':
                viewing_session_token = sessions[selected_idx][0]
                file_scroll_idx = 0
            elif key in ('q', 'ESC', 'BACKSPACE'):
                break

        else:
            with db_lock:
                s_row = history_conn.execute("""
                    SELECT session_token, title,
                           server_name, server_ip, server_os,
                           client_id, client_name, client_ip, client_os,
                           source_paths, destination_path, started_at, updated_at, completed_at,
                           total_files, completed_files, total_bytes, transferred_bytes,
                           total_chunks, received_chunks, status
                    FROM transfer_sessions
                    WHERE session_token = ?
                """, (viewing_session_token,)).fetchone()

                f_rows = history_conn.execute("""
                    SELECT relative_path, source_path, save_path, size, status, transferred_at
                    FROM transfer_history_files
                    WHERE session_token = ?
                    ORDER BY id ASC
                """, (viewing_session_token,)).fetchall()
            finalize_db_wal()

            if not s_row:
                viewing_session_token = None
                continue

            print(border)
            print(f" 📂 CLIENT SESSION INSPECTOR: {s_row[1]}  [{(s_row[20] or 'idle').upper()}]")
            print(border)
            print(f" Session Token  : {s_row[0]}")
            print(f" Server Host    : {s_row[2] or 'Server'} | IP: {s_row[3] or 'N/A'} | OS: {(s_row[4] or 'unknown').upper()}")
            print(f" Client Device  : {s_row[6] or CLIENT_HOSTNAME} | IP: {s_row[7] or get_local_ip()} | OS: {(s_row[8] or CLIENT_OS).upper()}")
            print(f" Server Dest    : {s_row[10] or 'N/A'}")
            print(f" Started / Done : {format_ts_human(s_row[11])}  -->  {format_ts_human(s_row[13] or s_row[12])}")
            print(f" Progress       : {s_row[15] or 0}/{s_row[14] or 0} Files | {format_bytes_human(s_row[17] or 0)} / {format_bytes_human(s_row[16] or 0)} ({s_row[19] or 0}/{s_row[18] or 0} Chunks)")
            print("-" * min(term_cols - 1, 115))

            file_page_size = max(4, term_rows - 15)
            if not f_rows:
                print("\n   No file entries recorded for this session.\n")
            else:
                file_scroll_idx = max(0, min(file_scroll_idx, len(f_rows) - 1))
                f_start = (file_scroll_idx // file_page_size) * file_page_size
                f_end = min(len(f_rows), f_start + file_page_size)

                f_hdr = f" {'#':<4} | {'CLIENT RELATIVE PATH (SOURCE)':<44} | {'SIZE':<10} | {'STATUS':<11} | {'TRANSFERRED AT':<19}"
                print(f_hdr[:term_cols - 1])
                print("-" * min(term_cols - 1, 115))

                for f_idx in range(f_start, f_end):
                    fr = f_rows[f_idx]
                    marker = "▶" if f_idx == file_scroll_idx else " "
                    rel_p = (fr[0] or '')
                    if len(rel_p) > 44:
                        rel_p = "..." + rel_p[-41:]
                    sz_s = format_bytes_human(fr[3] or 0)
                    st_s = (fr[4] or 'pending').upper()[:11]
                    ts_s = format_ts_human(fr[5]) if fr[5] else "Pending"
                    line = f"{marker}{f_idx + 1:<4} | {rel_p:<44} | {sz_s:<10} | {st_s:<11} | {ts_s:<19}"
                    if f_idx == file_scroll_idx:
                        print(f"\033[7m{line[:term_cols - 1]}\033[0m")
                    else:
                        print(line[:term_cols - 1])

                cur_f = f_rows[file_scroll_idx]
                print("-" * min(term_cols - 1, 115))
                print(f" Client Relative Path : {cur_f[0]}")
                print(f" Client Source Path   : {cur_f[1]}")

            print(border)
            print(" Controls: [↑/↓] Scroll Files  [←/→] Page  [b / Backspace / Esc] Back to Sessions  [q] Main Menu")
            print(border)

            key = read_single_key()
            if key == 'UP' and f_rows:
                file_scroll_idx = (file_scroll_idx - 1) % len(f_rows)
            elif key == 'DOWN' and f_rows:
                file_scroll_idx = (file_scroll_idx + 1) % len(f_rows)
            elif key in ('LEFT', 'PGUP') and f_rows:
                file_scroll_idx = max(0, file_scroll_idx - file_page_size)
            elif key in ('RIGHT', 'PGDN') and f_rows:
                file_scroll_idx = min(len(f_rows) - 1, file_scroll_idx + file_page_size)
            elif key in ('b', 'BACKSPACE', 'ESC'):
                viewing_session_token = None
            elif key == 'q':
                break


def configure_client_password_interactive():
    """Prompt the client user to configure a password or continue with No Password."""
    global CLIENT_PASSWORD_HASH, REQUIRES_PASSWORD
    print("\n" + "-" * 68)
    print(" 🔒 CLIENT CONNECTION SECURITY CONFIGURATION")
    print("-" * 68)
    print("  1. Continue with No Password (Open — click to connect immediately)")
    print("  2. Set a Client Password (Server operator must enter this password in Web UI)")
    print("-" * 68)
    while True:
        try:
            sub = input("Select security mode [1-2, default=1]: ").strip()
        except (EOFError, KeyboardInterrupt):
            sub = '1'

        if sub in ('', '1'):
            CLIENT_PASSWORD_HASH = ""
            REQUIRES_PASSWORD = False
            print("[*] Security Mode: NO PASSWORD (Open Connection)")
            break
        elif sub == '2':
            try:
                pwd = getpass.getpass("Enter new client password (hidden): ").strip()
                if not pwd:
                    pwd = input("Enter new client password: ").strip()
            except Exception:
                pwd = input("Enter new client password: ").strip()

            if pwd:
                CLIENT_PASSWORD_HASH = hash_password(pwd)
                REQUIRES_PASSWORD = True
                print("[*] Security Mode: PASSWORD PROTECTED (SHA-256 handshake enabled)")
                break
            else:
                print("[!] Password cannot be empty. Please try again or choose 1 for No Password.")
        else:
            print("[!] Invalid choice. Enter 1 or 2.")


def main_client_loop():
    global client_running, active_server_ip, active_server_port
    client_running = True
    threading.Thread(target=tcp_invite_listener_loop, daemon=True).start()
    time.sleep(0.1)
    threading.Thread(target=udp_beacon_and_probe_loop, daemon=True).start()

    # Optional CLI argument support if user passes server IP explicitly: python client.py <server_ip>
    cli_args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if cli_args:
        arg = cli_args[0].strip()
        if ':' in arg:
            h, p = arg.rsplit(':', 1)
            active_server_ip = h
            active_server_port = int(p)
        else:
            active_server_ip = arg
        connect_trigger_event.set()

    auth_badge = "LOCKED (Password Required)" if REQUIRES_PASSWORD else "OPEN (No Password)"
    print("\n" + "=" * 76)
    print(f"[*] EFT Client v2.4 online ({CLIENT_OS.upper()} | {CLIENT_HOSTNAME})")
    print(f"[*] Local IP    : {get_local_ip()} | Invite Port: {bound_invite_port}")
    print(f"[*] Auth Mode   : {auth_badge}")
    print(f"[*] History DB  : {CLIENT_HISTORY_DB_PATH}")
    print("[*] Waiting for Server connection... (Click 'Connect' on this client in the Server Web UI)")
    print("=" * 76)

    try:
        while client_running:
            if connect_trigger_event.wait(timeout=1.0):
                connect_trigger_event.clear()
                if active_server_ip:
                    run_control_session(active_server_ip, active_server_port)
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C on client: stopping active workers and cleaning up WAL files...")
        client_running = False
        if transfer_active:
            stop_local_workers()
            update_client_session_state_on_action(master_session_token, "cancel_transfer")
            send_server_action("cancel_transfer")
        close_db_cleanly()


def run_startup_menu():
    """Interactive numerical startup menu for EFT Client v2.4."""
    if "--no-menu" in sys.argv:
        main_client_loop()
        return

    while True:
        print("\n" + "=" * 68)
        print(f" ⚡ EFFICIENT FILE TRANSFER (EFT) v2.4 — CLIENT ({CLIENT_HOSTNAME} | {CLIENT_OS.upper()})")
        print("=" * 68)
        print("  1. Start EFT Client (Configure Password / No Password & Wait for Server)")
        print("  2. Read Old Transfer History (Nano-Style Arrow-Key Viewer)")
        print("  3. Exit")
        print("-" * 68)
        try:
            choice = input("Select an option [1-3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting EFT Client.")
            close_db_cleanly()
            break

        if choice in ('1', ''):
            configure_client_password_interactive()
            main_client_loop()
            break
        elif choice == '2':
            try:
                interactive_history_viewer()
            except KeyboardInterrupt:
                pass
        elif choice == '3':
            print("[*] Exiting EFT Client.")
            close_db_cleanly()
            break
        else:
            print("[!] Invalid selection. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    run_startup_menu()
