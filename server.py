import socket
import threading
import hashlib
import json
import secrets
import sqlite3
import os
import sys
import math
import queue
import struct
import time
import signal
import atexit
import platform
import shutil
import subprocess
import ctypes
from datetime import datetime
from pathlib import PurePosixPath
import zlib
try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    zstd = None
    HAS_ZSTD = False

from flask import Flask, request, jsonify, render_template_string, Response
from werkzeug.serving import WSGIRequestHandler
import logging

# Completely silence Werkzeug 400 Bad Request binary/TLS probe garbage (e.g. \x16\x03 / \x78)
log = logging.getLogger('werkzeug')
log.setLevel(logging.CRITICAL)
log.disabled = True


class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        pass

    def log_error(self, format, *args):
        pass

    def log_message(self, format, *args):
        pass


HOST = '0.0.0.0'
PORT = 8080
WEB_PORT = 8081
DISCOVERY_UDP_PORT = 8082
CLIENT_PROBE_UDP_PORT = 8084
DEFAULT_CLIENT_INVITE_PORT = 8083

CHUNK_SIZE = 5 * 1024 * 1024


def detect_os():
    if sys.platform.startswith('win'):
        return 'windows'
    if 'ANDROID_ROOT' in os.environ or 'ANDROID_DATA' in os.environ or os.path.exists('/storage/emulated/0'):
        return 'android'
    return 'linux'


LOCAL_OS = detect_os()
LOCAL_HOSTNAME = platform.node() or socket.gethostname() or "EFT-Server"


def get_local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(('8.8.8.8', 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.'):
                ips.add(ip)
    except Exception:
        pass
    if not ips:
        ips.add('127.0.0.1')
    return sorted(ips)


def get_primary_local_ip():
    ips = get_local_ips()
    for ip in ips:
        if not ip.startswith('127.'):
            return ip
    return ips[0] if ips else '127.0.0.1'


def get_broadcast_targets():
    """Return 255.255.255.255, 127.0.0.1, directed subnet broadcasts (x.x.x.255), and active ARP table peers."""
    targets = {'255.255.255.255', '127.0.0.1'}
    for ip in get_local_ips():
        parts = ip.split('.')
        if len(parts) == 4 and not ip.startswith('127.'):
            targets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.255")
            targets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.1")
    # Also read the OS ARP table so hotspot/tethered peers receive direct unicast UDP probes
    try:
        arp_out = subprocess.check_output(['arp', '-a'], stderr=subprocess.DEVNULL, text=True, timeout=1.0)
        for token in arp_out.replace('(', ' ').replace(')', ' ').split():
            parts = token.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                if not token.startswith(('127.', '224.', '239.', '255.')):
                    targets.add(token)
    except Exception:
        pass
    return sorted(targets)


def get_default_save_directory():
    if LOCAL_OS == 'windows':
        if os.path.exists('D:\\'):
            return r'D:\File Transfer'
        return os.path.join(os.path.expanduser('~'), 'Downloads', 'File Transfer')
    elif LOCAL_OS == 'android':
        base = '/storage/emulated/0/Download' if os.path.exists('/storage/emulated/0') else os.path.expanduser('~')
        return os.path.join(base, 'File Transfer')
    else:
        return os.path.join(os.path.expanduser('~'), 'File Transfer')


SAVE_DIRECTORY = get_default_save_directory()
os.makedirs(SAVE_DIRECTORY, exist_ok=True)
REMOTE_ACTIVE_DIRECTORY = ""

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DB_PATH = os.path.join(BASE_DIR, 'transfer_state.db')
HISTORY_DB_PATH = os.path.join(BASE_DIR, 'transfer_history.db')
TEMPLATE_PATH = os.path.join(BASE_DIR, 'templates', 'index.html')
CLIENT_SCRIPT_PATH = os.path.join(BASE_DIR, 'client.py')

active_sessions = set()
current_active_token = None

file_locks = {}
file_lock_mutex = threading.Lock()

global_control_socket = None
connected_client_info = None
control_socket_lock = threading.Lock()

# Client-configured password hash tracking (no hardcoded password)
active_client_password_hash = ""
pending_client_password_hashes = {}
auth_state_lock = threading.Lock()
peer_connection_seq = 0

active_worker_connections = set()
worker_conn_lock = threading.Lock()

# Server-side PUSH (Server -> Client) producer pipeline state
push_transfer_active = False
push_transfer_lock = threading.Lock()
push_work_queue = None
console_print_lock = threading.Lock()

waiting_clients = {}
waiting_clients_lock = threading.Lock()

last_dir_result = None
dir_result_event = threading.Event()
server_running = True


def hash_password(raw_password):
    if not raw_password:
        return ""
    return hashlib.sha256(str(raw_password).encode('utf-8')).hexdigest()


def verify_client_password_hash(received_hash, client_ip=None, client_id=None):
    """Validate incoming client password hash against the negotiated handshake hash."""
    recv = (received_hash or "").strip()
    with auth_state_lock:
        if client_id and client_id in pending_client_password_hashes:
            expected = pending_client_password_hashes[client_id]
            if recv == expected:
                return True
        if client_ip and client_ip in pending_client_password_hashes:
            expected = pending_client_password_hashes[client_ip]
            if recv == expected:
                return True
        if recv == active_client_password_hash:
            return True
        if not active_client_password_hash and recv == "":
            return True
    return False


def get_file_lock(file_id):
    with file_lock_mutex:
        if file_id not in file_locks:
            file_locks[file_id] = threading.Lock()
        return file_locks[file_id]


def release_file_lock(file_id):
    with file_lock_mutex:
        file_locks.pop(file_id, None)


def normalize_rel_path(rel_path):
    """Always store relative paths in POSIX format across Windows, Linux, and Android."""
    cleaned = str(rel_path or '').replace('\\', '/').lstrip('/')
    parts = [p for p in PurePosixPath(cleaned).parts if p not in ('', '.', '..')]
    return '/'.join(parts)


def resolve_local_save_path(base_dir, rel_path):
    """Convert a normalized POSIX relative path into a safe native OS path."""
    norm = normalize_rel_path(rel_path)
    native_rel = os.path.join(*norm.split('/')) if norm else ''
    full_path = os.path.abspath(os.path.join(base_dir, native_rel))
    base_abs = os.path.abspath(base_dir)
    if not full_path.startswith(base_abs):
        raise ValueError("Invalid relative path outside target directory")
    return full_path


def format_remote_save_path(remote_base_dir, rel_path, remote_os='linux'):
    """Format a display destination path for files pushed to the remote client."""
    norm = normalize_rel_path(rel_path)
    base = str(remote_base_dir or '').rstrip('/\\')
    if (remote_os or '').lower() == 'windows' or '\\' in base or (len(base) >= 2 and base[1] == ':'):
        rel_win = norm.replace('/', '\\')
        return f"{base}\\{rel_win}" if base else rel_win
    return f"{base}/{norm}" if base else norm


def list_os_directory(target_path, default_path):
    """Cross-platform directory browser supporting Windows drives, Linux roots, and Android storage."""
    if not target_path or not str(target_path).strip():
        target_path = default_path
    else:
        target_path = os.path.expanduser(str(target_path).strip())

    if LOCAL_OS == 'windows' and target_path in ('/', '\\', 'DRIVES', 'drives'):
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
            "os": LOCAL_OS,
            "current_path": "DRIVES",
            "parent_path": "DRIVES",
            "items": drives
        }

    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        return {"status": "error", "message": f"Path does not exist: {target_path}", "os": LOCAL_OS}
    if not os.path.isdir(target_path):
        target_path = os.path.dirname(target_path)

    parent_path = os.path.dirname(target_path.rstrip('/\\'))
    if LOCAL_OS == 'windows':
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
            "os": LOCAL_OS,
            "current_path": target_path,
            "parent_path": parent_path,
            "items": items
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "os": LOCAL_OS, "current_path": target_path}


def build_local_manifest(target_paths):
    """Build a POSIX-normalized file & empty-folder manifest from local server paths for PUSH transfers."""
    manifest = {"files": [], "dirs": [], "total_bytes": 0}
    local_mapping = {}

    for raw_target in target_paths:
        target_path = os.path.abspath(os.path.expanduser(str(raw_target)))
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


# ==============================================================================
# DUAL SQLITE DATABASES:
# 1. transfer_state.db   -> Active chunk bitmaps & file locks (for both PULL & PUSH)
# 2. transfer_history.db -> Permanent session logs & per-file transfer history
# ==============================================================================
db_lock = threading.RLock()
db_conn = None
history_conn = None


def init_dbs():
    global db_conn, history_conn
    # 1. Initialize State Database (transfer_state.db)
    conn = sqlite3.connect(STATE_DB_PATH, check_same_thread=False, isolation_level=None)
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT,
            relative_path TEXT,
            source_path TEXT,
            save_path TEXT,
            size INTEGER,
            mtime REAL,
            atime REAL,
            pre_existed INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chunks (
            file_id INTEGER,
            chunk_index INTEGER,
            status TEXT,
            PRIMARY KEY (file_id, chunk_index)
        )
    """)

    cols = [r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()]
    if 'save_path' not in cols:
        conn.execute("ALTER TABLE files ADD COLUMN save_path TEXT")
    if 'source_path' not in cols:
        conn.execute("ALTER TABLE files ADD COLUMN source_path TEXT")
    if 'pre_existed' not in cols:
        conn.execute("ALTER TABLE files ADD COLUMN pre_existed INTEGER DEFAULT 0")

    # 2. Initialize Separate History Database (transfer_history.db)
    hconn = sqlite3.connect(HISTORY_DB_PATH, check_same_thread=False, isolation_level=None)
    hconn.execute('PRAGMA synchronous=NORMAL')
    hconn.execute("""
        CREATE TABLE IF NOT EXISTS transfer_sessions (
            session_token TEXT PRIMARY KEY,
            title TEXT,
            direction TEXT DEFAULT 'pull',
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
            pre_existed INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            transferred_at REAL,
            UNIQUE(session_token, relative_path)
        )
    """)

    # Safe schema migrations for existing v2.4 databases
    s_cols = [r[1] for r in hconn.execute("PRAGMA table_info(transfer_sessions)").fetchall()]
    for col_name, col_def in [
        ('direction', "TEXT DEFAULT 'pull'"),
        ('server_name', 'TEXT'),
        ('server_ip', 'TEXT'),
        ('server_os', 'TEXT'),
        ('client_id', 'TEXT')
    ]:
        if col_name not in s_cols:
            hconn.execute(f"ALTER TABLE transfer_sessions ADD COLUMN {col_name} {col_def}")

    hf_cols = [r[1] for r in hconn.execute("PRAGMA table_info(transfer_history_files)").fetchall()]
    if 'source_path' not in hf_cols:
        hconn.execute("ALTER TABLE transfer_history_files ADD COLUMN source_path TEXT")

    default_srv_ip = get_primary_local_ip()
    hconn.execute("""
        UPDATE transfer_sessions
        SET server_name = COALESCE(NULLIF(server_name, ''), ?),
            server_ip   = COALESCE(NULLIF(server_ip, ''), ?),
            server_os   = COALESCE(NULLIF(server_os, ''), ?),
            direction   = COALESCE(NULLIF(direction, ''), 'pull')
        WHERE server_name IS NULL OR server_name = '' OR direction IS NULL OR direction = ''
    """, (LOCAL_HOSTNAME, default_srv_ip, LOCAL_OS))

    # Mark any previously 'active' sessions that had pending chunks as 'interrupted' on startup
    hconn.execute("""
        UPDATE transfer_sessions
        SET status = 'interrupted', updated_at = ?
        WHERE status = 'active' AND received_chunks < total_chunks
    """, (time.time(),))

    # Create indexes so session_token and file_id lookups are O(log N) instead of full-table scans
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_session ON files(session_token)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_rel ON files(session_token, relative_path)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_file_status ON chunks(file_id, status)")
    hconn.execute("CREATE INDEX IF NOT EXISTS idx_hist_files_session ON transfer_history_files(session_token)")
    hconn.execute("CREATE INDEX IF NOT EXISTS idx_hist_files_status ON transfer_history_files(session_token, status)")

    # Reload any incomplete session tokens so they can be resumed
    for row in hconn.execute("SELECT session_token FROM transfer_sessions WHERE status IN ('paused', 'interrupted', 'completed')").fetchall():
        if row[0]:
            active_sessions.add(row[0])

    # Ensure both DBs start in clean DELETE journal mode (no lingering .db-wal / .db-shm files)
    for c in (conn, hconn):
        c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        c.execute('PRAGMA journal_mode=DELETE')

    db_conn = conn
    history_conn = hconn
    return conn, hconn


def enable_db_wal():
    """Enable WAL mode on both databases during high-concurrency chunk streaming."""
    with db_lock:
        for c in (db_conn, history_conn):
            if c is not None:
                try:
                    c.execute('PRAGMA journal_mode=WAL')
                    c.execute('PRAGMA synchronous=NORMAL')
                except Exception:
                    pass


def finalize_db_wal():
    """Flush WAL to main DB files and switch to DELETE mode so .db-wal and .db-shm vanish immediately."""
    with db_lock:
        for c in (db_conn, history_conn):
            if c is not None:
                try:
                    c.commit()
                    c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    c.execute('PRAGMA journal_mode=DELETE')
                except Exception:
                    pass


def close_db_cleanly():
    """Guaranteed cleanup on server stop so .db-wal and .db-shm are completely removed for both DBs."""
    global db_conn, history_conn
    with db_lock:
        for c in (db_conn, history_conn):
            if c is not None:
                try:
                    c.commit()
                    c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    c.execute('PRAGMA journal_mode=DELETE')
                    c.close()
                except Exception:
                    pass
        db_conn = None
        history_conn = None


atexit.register(close_db_cleanly)


def set_meta(key, value):
    with db_lock:
        db_conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, str(value)))


def get_meta(key, default=None):
    with db_lock:
        cursor = db_conn.execute("SELECT value FROM meta WHERE key=?", (key,))
        row = cursor.fetchone()
        return row[0] if row else default


init_dbs()


def make_session_title(paths):
    if not paths:
        return "Transfer Session"
    first = os.path.basename(str(paths[0]).rstrip('/\\')) or str(paths[0])
    if len(paths) == 1:
        return first
    return f"{first} + {len(paths) - 1} more"


def get_session_direction(session_token):
    if not session_token:
        return 'pull'
    with db_lock:
        row = history_conn.execute(
            "SELECT direction FROM transfer_sessions WHERE session_token=?", (session_token,)
        ).fetchone()
        return (row[0] or 'pull').lower() if row else 'pull'


def sync_session_metrics(session_token, override_status=None):
    """Synchronize chunk & file progress for a session between transfer_state.db and transfer_history.db."""
    if not session_token:
        return 0, 0, 0, 0
    now = time.time()
    with db_lock:
        cursor = db_conn.execute("""
            SELECT COUNT(*), SUM(CASE WHEN c.status='received' THEN 1 ELSE 0 END)
            FROM chunks c
            INNER JOIN files f ON c.file_id = f.file_id
            WHERE f.session_token = ?
        """, (session_token,))
        row = cursor.fetchone()
        total_chunks = row[0] or 0
        received_chunks = row[1] or 0

        f_cursor = history_conn.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END),
                   SUM(size),
                   SUM(CASE WHEN status='completed' THEN size ELSE 0 END)
            FROM transfer_history_files
            WHERE session_token = ?
        """, (session_token,))
        frow = f_cursor.fetchone()
        total_files = frow[0] or 0
        completed_files = frow[1] or 0
        total_bytes = frow[2] or 0
        completed_file_bytes = frow[3] or 0

        if total_chunks > 0 and received_chunks < total_chunks:
            approx_bytes = min(total_bytes, int((received_chunks / total_chunks) * total_bytes))
            transferred_bytes = max(completed_file_bytes, approx_bytes)
        elif total_chunks > 0 and received_chunks == total_chunks:
            transferred_bytes = total_bytes
        else:
            transferred_bytes = completed_file_bytes

        cur_status_row = history_conn.execute(
            "SELECT status FROM transfer_sessions WHERE session_token=?", (session_token,)
        ).fetchone()
        current_status = cur_status_row[0] if cur_status_row else 'idle'

        new_status = override_status if override_status else current_status
        completed_at_sql = ", completed_at = ?" if new_status == 'completed' else ""
        params = [
            now, total_files, completed_files, total_bytes, transferred_bytes,
            total_chunks, received_chunks, new_status
        ]
        if new_status == 'completed':
            params.append(now)
        params.append(session_token)

        history_conn.execute(f"""
            UPDATE transfer_sessions
            SET updated_at = ?,
                total_files = ?,
                completed_files = ?,
                total_bytes = ?,
                transferred_bytes = ?,
                total_chunks = ?,
                received_chunks = ?,
                status = ?
                {completed_at_sql}
            WHERE session_token = ?
        """, tuple(params))

        return completed_files, total_files, received_chunks, total_chunks


def is_client_connected():
    with control_socket_lock:
        if global_control_socket is not None:
            return True
    with worker_conn_lock:
        if len(active_worker_connections) > 0:
            return True
    return False


def send_control_command(payload):
    global global_control_socket, connected_client_info
    with control_socket_lock:
        if not global_control_socket:
            return False
        try:
            global_control_socket.sendall((json.dumps(payload) + "\n").encode('utf-8'))
            return True
        except Exception:
            try:
                global_control_socket.close()
            except Exception:
                pass
            global_control_socket = None
            connected_client_info = None
            return False


def stop_push_workers():
    """Stop the server-side PUSH chunk producer and drain push_work_queue."""
    global push_transfer_active, push_work_queue
    push_transfer_active = False
    if push_work_queue is not None:
        while not push_work_queue.empty():
            try:
                push_work_queue.get_nowait()
                push_work_queue.task_done()
            except Exception:
                break
        for _ in range(4):
            try:
                push_work_queue.put_nowait(None)
            except Exception:
                pass


def close_active_workers():
    stop_push_workers()
    with worker_conn_lock:
        conns = list(active_worker_connections)
    for c in conns:
        try:
            c.close()
        except Exception:
            pass


def disconnect_client_cleanly():
    """Disconnect the currently connected client so the next Ctrl+C shuts down the server."""
    global global_control_socket, connected_client_info, last_dir_result
    send_control_command({"action": "disconnect_control"})
    close_active_workers()
    with control_socket_lock:
        if global_control_socket:
            try:
                global_control_socket.close()
            except Exception:
                pass
            global_control_socket = None
        connected_client_info = None
    last_dir_result = None
    dir_result_event.clear()


def has_active_incomplete_transfer(session_token=None):
    """Return True ONLY if there is an actively running transfer with pending chunks."""
    tok = session_token or current_active_token or get_meta('session_token')
    if not tok:
        return False
    with db_lock:
        s_row = history_conn.execute(
            "SELECT status, received_chunks, total_chunks FROM transfer_sessions WHERE session_token=?", (tok,)
        ).fetchone()
        if not s_row or s_row[0] != 'active':
            return False
        c_row = db_conn.execute("""
            SELECT COUNT(*) FROM chunks c
            INNER JOIN files f ON c.file_id = f.file_id
            WHERE f.session_token = ? AND c.status = 'pending'
        """, (tok,)).fetchone()
        if c_row and (c_row[0] or 0) > 0:
            return True
        return (s_row[1] or 0) < (s_row[2] or 0)


def cleanup_empty_parent_dirs(file_path, base_dir):
    """Remove empty parent directories created during a transfer without deleting base_dir."""
    if not file_path or not base_dir:
        return
    base_abs = os.path.abspath(base_dir)
    parent = os.path.abspath(os.path.dirname(file_path))
    while parent.startswith(base_abs) and parent != base_abs:
        try:
            if os.path.exists(parent) and not os.listdir(parent):
                os.rmdir(parent)
                parent = os.path.abspath(os.path.dirname(parent))
            else:
                break
        except Exception:
            break


def perform_cancel(session_token=None, reason="User cancelled transfer"):
    """
    Cancel operation for a specific session (both PULL and PUSH):
    - For PULL: deletes incomplete partial files on the Server disk.
    - For PUSH: instructs the Client to delete incomplete partial files on the Client disk,
      while cleaning up pending chunk state in the Server databases.
    Completed files remain intact on disk and in history.
    """
    global current_active_token
    if not session_token:
        session_token = current_active_token or get_meta('session_token')
    if session_token:
        with db_lock:
            st_row = history_conn.execute(
                "SELECT status FROM transfer_sessions WHERE session_token=?", (session_token,)
            ).fetchone()
            if st_row and st_row[0] == 'completed':
                print(f"[*] Session {session_token[:8]} is already completed; skipping cancel.")
                return 0

    direction = get_session_direction(session_token)
    print(f"[*] Executing Cancel ({reason}) for {direction.upper()} session {session_token}: removing only partial files...")
    send_control_command({"action": "cancel_transfer", "session_token": session_token, "direction": direction})
    if session_token == current_active_token or not session_token:
        close_active_workers()
        time.sleep(0.15)

    removed_count = 0
    with db_lock:
        if session_token:
            cursor = db_conn.execute("""
                SELECT DISTINCT f.file_id, f.relative_path, f.save_path, f.pre_existed
                FROM files f
                INNER JOIN chunks c ON f.file_id = c.file_id
                WHERE f.session_token = ? AND c.status = 'pending'
            """, (session_token,))
            sess_row = history_conn.execute(
                "SELECT destination_path FROM transfer_sessions WHERE session_token=?", (session_token,)
            ).fetchone()
            base_save_dir = sess_row[0] if (sess_row and sess_row[0]) else SAVE_DIRECTORY
        else:
            cursor = db_conn.execute("""
                SELECT DISTINCT f.file_id, f.relative_path, f.save_path, f.pre_existed
                FROM files f
                INNER JOIN chunks c ON f.file_id = c.file_id
                WHERE c.status = 'pending'
            """)
            base_save_dir = SAVE_DIRECTORY

        incomplete_files = cursor.fetchall()
        for file_id, rel_path, save_path, pre_existed in incomplete_files:
            if direction == 'pull':
                target = save_path if save_path else resolve_local_save_path(base_save_dir, rel_path)
                flock = get_file_lock(file_id)
                with flock:
                    if target and os.path.exists(target) and not pre_existed:
                        try:
                            os.remove(target)
                            cleanup_empty_parent_dirs(target, base_save_dir)
                            removed_count += 1
                        except Exception as e:
                            print(f"[!] Could not remove partial file {target}: {e}")
                release_file_lock(file_id)
            else:
                removed_count += 1

            db_conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
            db_conn.execute("DELETE FROM files WHERE file_id=?", (file_id,))
            if session_token:
                history_conn.execute("""
                    UPDATE transfer_history_files
                    SET status='cancelled'
                    WHERE session_token=? AND relative_path=? AND status != 'completed'
                """, (session_token, rel_path))

        if session_token:
            history_conn.execute("""
                UPDATE transfer_history_files
                SET status='cancelled'
                WHERE session_token=? AND status != 'completed'
            """, (session_token,))
            sync_session_metrics(session_token, override_status='cancelled')
            if current_active_token == session_token:
                current_active_token = None
                set_meta('transfer_state', 'idle')
        else:
            set_meta('transfer_state', 'idle')

    finalize_db_wal()
    print(f"[*] Cancel complete. Cleaned up {removed_count} partial file(s). Completed files were kept.")
    return removed_count


def perform_rollback(session_token=None):
    """
    Rollback operation for a specific transfer session (both PULL and PUSH):
    - For PULL: deletes all non-pre-existing files & empty dirs created on the Server in that session.
    - For PUSH: instructs the Client to delete all non-pre-existing files & empty dirs created on the Client
      in that session, and updates Server state/history to 'rolled_back'.
    """
    global current_active_token
    if not session_token:
        session_token = current_active_token or get_meta('session_token')

    direction = get_session_direction(session_token)
    print(f"[*] Executing Rollback for {direction.upper()} session {session_token}: removing all files from this transfer...")
    send_control_command({"action": "rollback_transfer", "session_token": session_token, "direction": direction})
    if session_token == current_active_token:
        close_active_workers()
        time.sleep(0.15)

    removed_count = 0
    with db_lock:
        sess_row = history_conn.execute(
            "SELECT destination_path FROM transfer_sessions WHERE session_token=?", (session_token,)
        ).fetchone() if session_token else None
        base_save_dir = sess_row[0] if (sess_row and sess_row[0]) else SAVE_DIRECTORY

        files_to_remove = {}
        if session_token:
            for fid, rpath, spath, pre in db_conn.execute(
                "SELECT file_id, relative_path, save_path, pre_existed FROM files WHERE session_token=?",
                (session_token,)
            ).fetchall():
                files_to_remove[rpath] = (fid, spath, pre)

            for fid, rpath, spath, pre in history_conn.execute(
                "SELECT file_id, relative_path, save_path, pre_existed FROM transfer_history_files WHERE session_token=?",
                (session_token,)
            ).fetchall():
                if rpath not in files_to_remove:
                    files_to_remove[rpath] = (fid, spath, pre)
        else:
            for fid, rpath, spath, pre in db_conn.execute(
                "SELECT file_id, relative_path, save_path, pre_existed FROM files"
            ).fetchall():
                files_to_remove[rpath] = (fid, spath, pre)

        for rel_path, (file_id, save_path, pre_existed) in files_to_remove.items():
            if direction == 'pull':
                target = save_path if save_path else resolve_local_save_path(base_save_dir, rel_path)
                flock = get_file_lock(file_id) if file_id else threading.Lock()
                with flock:
                    if target and os.path.exists(target) and not pre_existed:
                        try:
                            if os.path.isdir(target):
                                if not os.listdir(target):
                                    os.rmdir(target)
                                    cleanup_empty_parent_dirs(target, base_save_dir)
                                    removed_count += 1
                            else:
                                os.remove(target)
                                cleanup_empty_parent_dirs(target, base_save_dir)
                                removed_count += 1
                        except Exception as e:
                            print(f"[!] Could not remove item during rollback {target}: {e}")
            else:
                if not pre_existed:
                    removed_count += 1

            if file_id:
                release_file_lock(file_id)
                db_conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
                db_conn.execute("DELETE FROM files WHERE file_id=?", (file_id,))

        if session_token:
            db_conn.execute("DELETE FROM chunks WHERE file_id IN (SELECT file_id FROM files WHERE session_token=?)", (session_token,))
            db_conn.execute("DELETE FROM files WHERE session_token=?", (session_token,))
            history_conn.execute("""
                UPDATE transfer_history_files
                SET status = 'rolled_back'
                WHERE session_token = ?
            """, (session_token,))
            history_conn.execute("""
                UPDATE transfer_sessions
                SET status = 'rolled_back',
                    completed_files = 0,
                    transferred_bytes = 0,
                    received_chunks = 0,
                    updated_at = ?
                WHERE session_token = ?
            """, (time.time(), session_token))
            active_sessions.discard(session_token)

        if current_active_token == session_token:
            current_active_token = None
            set_meta('transfer_state', 'idle')
            set_meta('session_token', '')

    finalize_db_wal()
    print(f"[*] Rollback complete. Removed {removed_count} transferred item(s).")
    return removed_count


def perform_pause(session_token=None):
    """
    Pause operation (both PULL and PUSH):
    Halts active transfer while keeping partial files and chunk records intact for per-session resumption.
    """
    global current_active_token
    target_token = session_token or current_active_token or get_meta('session_token')
    direction = get_session_direction(target_token)
    print(f"[*] Pausing {direction.upper()} transfer session {target_token}...")
    send_control_command({"action": "pause_transfer", "session_token": target_token, "direction": direction})
    close_active_workers()
    with db_lock:
        set_meta('transfer_state', 'paused')
        if target_token:
            sync_session_metrics(target_token, override_status='paused')
        current_active_token = None
    finalize_db_wal()


# ==============================================================================
# SERVER-SIDE PUSH ENGINE (Server -> Client Producer & Worker Stream Handler)
# ==============================================================================
def process_and_compress_push_chunks(local_mapping, manifest, chunk_queue, missing_map, use_zstd=False):
    """Server-side producer thread that reads & compresses local missing chunks for PUSH transfer."""
    global push_transfer_active
    can_use_zstd = bool(HAS_ZSTD and use_zstd)
    cctx = zstd.ZstdCompressor(level=3) if can_use_zstd else None
    comp_label = "zstd" if can_use_zstd else "zlib"

    for file_info in manifest.get("files", []):
        if not push_transfer_active:
            break

        rel_path = file_info["relative_path"]
        if rel_path not in missing_map:
            continue

        m_entry = missing_map[rel_path]
        client_file_id = m_entry["file_id"]
        server_file_id = m_entry.get("server_file_id", client_file_id)
        missing_indices = sorted(m_entry.get("missing", []))
        full_path = local_mapping.get(rel_path) or file_info.get("source_path")
        if not full_path or not os.path.exists(full_path):
            continue

        try:
            with open(full_path, 'rb') as f:
                for chunk_index in missing_indices:
                    if not push_transfer_active:
                        break
                    f.seek(chunk_index * CHUNK_SIZE)
                    raw_bytes = f.read(CHUNK_SIZE)
                    if not raw_bytes and file_info["size"] > 0:
                        break
                    compressed = cctx.compress(raw_bytes) if can_use_zstd else zlib.compress(raw_bytes, level=1)
                    while push_transfer_active:
                        try:
                            chunk_queue.put({
                                "client_file_id": client_file_id,
                                "server_file_id": server_file_id,
                                "relative_path": rel_path,
                                "file_size": file_info["size"],
                                "chunk_index": chunk_index,
                                "comp": comp_label,
                                "data": compressed
                            }, timeout=0.5)
                            break
                        except queue.Full:
                            continue
        except (PermissionError, OSError):
            continue

    for _ in range(12):
        try:
            chunk_queue.put(None, timeout=1.0)
        except Exception:
            pass


def start_push_session_on_server(session_token, paths, remote_dest_dir, is_resume=False):
    """Build the local manifest on the server, record history rows, and send start_push_transfer to client."""
    global current_active_token
    stop_push_workers()
    enable_db_wal()

    manifest, _ = build_local_manifest(paths)
    now = time.time()
    title = make_session_title(paths)
    c_id = (connected_client_info or {}).get("client_id", "")
    c_name = (connected_client_info or {}).get("hostname", "Remote Client")
    c_ip = (connected_client_info or {}).get("ip", "")
    c_os = (connected_client_info or {}).get("os", "linux")
    srv_ip = (connected_client_info or {}).get("server_ip") or get_primary_local_ip()

    with db_lock:
        active_sessions.add(session_token)
        current_active_token = session_token
        set_meta('target_paths', json.dumps(paths))
        set_meta('remote_destination', remote_dest_dir)
        set_meta('transfer_state', 'active')
        set_meta('session_token', session_token)

        existing = history_conn.execute(
            "SELECT started_at, title FROM transfer_sessions WHERE session_token=?", (session_token,)
        ).fetchone()
        started_at = existing[0] if (existing and existing[0]) else now
        if existing and existing[1]:
            title = existing[1]

        history_conn.execute("""
            INSERT OR REPLACE INTO transfer_sessions (
                session_token, title, direction,
                server_name, server_ip, server_os,
                client_id, client_name, client_ip, client_os,
                source_paths, destination_path, started_at, updated_at,
                total_files, completed_files, total_bytes, transferred_bytes,
                total_chunks, received_chunks, status
            ) VALUES (?, ?, 'push', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, 0, 0, 'active')
        """, (
            session_token, title,
            LOCAL_HOSTNAME, srv_ip, LOCAL_OS,
            c_id, c_name, c_ip, c_os,
            json.dumps(paths), remote_dest_dir, started_at, now,
            len(manifest.get("files", [])), manifest.get("total_bytes", 0)
        ))

    sent = send_control_command({
        "action": "start_push_transfer",
        "session_token": session_token,
        "session_title": title,
        "source_paths": paths,
        "destination_path": remote_dest_dir,
        "manifest": manifest,
        "server_hostname": LOCAL_HOSTNAME,
        "server_ip": srv_ip,
        "server_os": LOCAL_OS,
        "resume": is_resume
    })
    if not sent:
        finalize_db_wal()
    return sent


def handle_push_manifest_processed(msg):
    """
    Process the client's response after pre-allocating files for a PUSH transfer,
    populate server chunk tracking tables, and spawn the server-side chunk producer thread.
    """
    global push_transfer_active, push_work_queue
    token = msg.get("session_token")
    if not token or token not in active_sessions:
        return

    missing_map = msg.get("missing_map") or {}
    already_completed = set(msg.get("already_completed") or [])
    pre_existed_map = msg.get("pre_existed_map") or {}
    remote_dest_dir = msg.get("destination_path") or get_meta('remote_destination', '')
    now_ts = time.time()

    with db_lock:
        s_row = history_conn.execute(
            "SELECT source_paths, title, client_name, client_ip, client_os FROM transfer_sessions WHERE session_token=?",
            (token,)
        ).fetchone()
        if not s_row:
            return
        try:
            paths = json.loads(s_row[0] or '[]')
        except Exception:
            paths = []
        sess_title = s_row[1] or "Push Transfer"
        c_name = s_row[2] or "Remote Client"
        c_ip = s_row[3] or ""
        c_os = s_row[4] or "linux"

        if remote_dest_dir:
            history_conn.execute(
                "UPDATE transfer_sessions SET destination_path=? WHERE session_token=?",
                (remote_dest_dir, token)
            )

    manifest, local_mapping = build_local_manifest(paths)

    with db_lock:
        # Reset server-side file/chunk bitmap for this PUSH session and rebuild from client's missing_map
        db_conn.execute("DELETE FROM chunks WHERE file_id IN (SELECT file_id FROM files WHERE session_token=?)", (token,))
        db_conn.execute("DELETE FROM files WHERE session_token=?", (token,))

        for dinfo in manifest.get("dirs", []):
            norm_dir = normalize_rel_path(dinfo.get("relative_path", ""))
            if not norm_dir:
                continue
            dir_rel_display = norm_dir.rstrip('/') + '/'
            remote_dir_save = format_remote_save_path(remote_dest_dir, norm_dir, c_os)
            dir_pre = 1 if pre_existed_map.get(dir_rel_display) else 0
            history_conn.execute("""
                INSERT INTO transfer_history_files (
                    session_token, file_id, relative_path, source_path, save_path, size,
                    mtime, atime, pre_existed, status, transferred_at
                ) VALUES (?, 0, ?, ?, ?, 0, ?, ?, ?, 'completed', ?)
                ON CONFLICT(session_token, relative_path) DO UPDATE SET
                    save_path = excluded.save_path,
                    status = 'completed',
                    transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
            """, (
                token, dir_rel_display, dinfo.get("source_path") or norm_dir,
                remote_dir_save, dinfo.get("mtime", now_ts), dinfo.get("atime", now_ts),
                dir_pre, now_ts
            ))

        for finfo in manifest.get("files", []):
            norm_rel = normalize_rel_path(finfo["relative_path"])
            src_full = finfo.get("source_path") or local_mapping.get(norm_rel) or norm_rel
            m_entry = missing_map.get(norm_rel)
            remote_save = (m_entry.get("save_path") if m_entry else None) or format_remote_save_path(remote_dest_dir, norm_rel, c_os)
            pre_ex = 1 if (m_entry.get("pre_existed") if m_entry else pre_existed_map.get(norm_rel, 0)) else 0

            cur = db_conn.execute(
                """INSERT INTO files (session_token, relative_path, source_path, save_path, size, mtime, atime, pre_existed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (token, norm_rel, src_full, remote_save, finfo["size"], finfo["mtime"], finfo["atime"], pre_ex)
            )
            srv_file_id = cur.lastrowid
            if m_entry is not None:
                m_entry["server_file_id"] = srv_file_id

            total_f_chunks = 1 if finfo["size"] == 0 else max(1, math.ceil(finfo["size"] / CHUNK_SIZE))
            missing_set = set(m_entry.get("missing", [])) if m_entry else set()

            for idx in range(total_f_chunks):
                c_stat = 'pending' if idx in missing_set else 'received'
                db_conn.execute(
                    "INSERT INTO chunks (file_id, chunk_index, status) VALUES (?, ?, ?)",
                    (srv_file_id, idx, c_stat)
                )

            is_done = (norm_rel in already_completed) or (len(missing_set) == 0)
            f_status = 'completed' if is_done else 'pending'
            done_ts = now_ts if is_done else None

            history_conn.execute("""
                INSERT INTO transfer_history_files (
                    session_token, file_id, relative_path, source_path, save_path, size,
                    mtime, atime, pre_existed, status, transferred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_token, relative_path) DO UPDATE SET
                    file_id = excluded.file_id,
                    source_path = excluded.source_path,
                    save_path = excluded.save_path,
                    pre_existed = excluded.pre_existed,
                    status = CASE WHEN transfer_history_files.status = 'completed' THEN 'completed' ELSE excluded.status END,
                    transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
            """, (
                token, srv_file_id, norm_rel, src_full, remote_save, finfo["size"],
                finfo["mtime"], finfo["atime"], pre_ex, f_status, done_ts
            ))

        comp_f, tot_f, recv_c, tot_c = sync_session_metrics(
            token, override_status='completed' if not missing_map else 'active'
        )

    num_files = len(manifest.get("files", []))
    num_dirs = len(manifest.get("dirs", []))
    with console_print_lock:
        print(
            f"\n[*] PUSH Session '{sess_title}' ({token[:8]}) -> Client {c_name} ({c_ip}) [{c_os.upper()}]\n"
            f"    Files: {num_files} ({format_bytes_human(manifest.get('total_bytes', 0))}) | "
            f"Empty Folders: {num_dirs} | Client Dest: {remote_dest_dir}"
        )

    if not missing_map:
        set_meta('transfer_state', 'completed')
        finalize_db_wal()
        with console_print_lock:
            print(f"[*] PUSH Session '{sess_title}' ({token[:8]}) COMPLETED (all items up-to-date on client).")
        return

    client_has_zstd = bool(
        msg.get("has_zstd") if "has_zstd" in msg else (connected_client_info or {}).get("has_zstd", False)
    )
    with push_transfer_lock:
        push_transfer_active = True
        push_work_queue = queue.Queue(maxsize=20)
        threading.Thread(
            target=process_and_compress_push_chunks,
            args=(local_mapping, manifest, push_work_queue, missing_map, client_has_zstd),
            daemon=True
        ).start()

    # Notify client that the server's push_work_queue is ready AND spawn outbound server->client workers
    send_control_command({
        "action": "start_push_workers",
        "session_token": token
    })
    threading.Thread(target=spawn_server_outbound_workers, args=(token, "push"), daemon=True).start()


def handle_push_worker_stream(conn, worker_session_token):
    """Stream compressed chunks from server's push_work_queue to a client push_worker_auth socket with O(1) DB updates."""
    global push_transfer_active, push_work_queue
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    with worker_conn_lock:
        active_worker_connections.add(conn)
    try:
        while server_running and push_transfer_active:
            if push_work_queue is None:
                break
            try:
                chunk = push_work_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if chunk is None:
                push_work_queue.task_done()
                try:
                    conn.sendall(struct.pack('!II', 0, 0))
                except Exception:
                    pass
                break

            meta = {
                "file_id": chunk["client_file_id"],
                "chunk_index": chunk["chunk_index"],
                "comp": chunk.get("comp", "zlib")
            }
            meta_bytes = json.dumps(meta).encode('utf-8')
            chunk_data = chunk["data"]

            header = struct.pack('!II', len(meta_bytes), len(chunk_data))
            conn.sendall(header + meta_bytes + chunk_data)

            ack_msg = recv_json_line(conn)
            push_work_queue.task_done()
            if not ack_msg or not isinstance(ack_msg, dict):
                break

            srv_file_id = chunk.get("server_file_id")
            chunk_idx = chunk["chunk_index"]
            rel_p = ack_msg.get("relative_path") or chunk.get("relative_path", "")
            f_size = ack_msg.get("file_size", chunk.get("file_size", 0))
            file_done = bool(ack_msg.get("file_completed", False))
            sess_done = bool(ack_msg.get("session_completed", False))
            done_ts = ack_msg.get("transferred_at") or time.time()
            comp_f = ack_msg.get("completed_files", 0)
            tot_f = ack_msg.get("total_files", 0)
            recv_c = ack_msg.get("received_chunks", 0)
            tot_c = ack_msg.get("total_chunks", 0)

            with db_lock:
                if srv_file_id:
                    db_conn.execute(
                        "UPDATE chunks SET status='received' WHERE file_id=? AND chunk_index=?",
                        (srv_file_id, chunk_idx)
                    )
                if file_done:
                    history_conn.execute("""
                        UPDATE transfer_history_files
                        SET status = 'completed', transferred_at = ?
                        WHERE session_token = ? AND relative_path = ?
                    """, (done_ts, worker_session_token, rel_p))

                if sess_done:
                    set_meta('transfer_state', 'completed')
                    comp_f, tot_f, recv_c, tot_c = sync_session_metrics(worker_session_token, override_status='completed')
                    all_done = True
                else:
                    # O(1) primary-key update instead of scanning 11,000+ rows on every chunk!
                    history_conn.execute("""
                        UPDATE transfer_sessions
                        SET updated_at = ?,
                            completed_files = CASE WHEN ? > completed_files THEN ? ELSE completed_files END,
                            received_chunks = CASE WHEN ? > received_chunks THEN ? ELSE received_chunks + 1 END,
                            transferred_bytes = CASE WHEN ? > 0 THEN (total_bytes * ?) / ? ELSE transferred_bytes END
                        WHERE session_token = ?
                    """, (done_ts, comp_f, comp_f, recv_c, recv_c, tot_c, recv_c, tot_c, worker_session_token))
                    all_done = False

            if file_done and (tot_f <= 100 or f_size >= 1024 * 1024 or comp_f % 50 == 0 or all_done):
                pct = round((recv_c / tot_c * 100), 1) if tot_c else 100.0
                c_name = (connected_client_info or {}).get("hostname", "Client")
                c_ip = (connected_client_info or {}).get("ip", "")
                with console_print_lock:
                    print(
                        f"[{format_ts_human(done_ts)}] ➡ Pushed {rel_p} ({format_bytes_human(f_size)}) "
                        f"[{comp_f}/{tot_f} files | {pct}%] -> Client {c_name} ({c_ip})"
                    )

            if all_done:
                push_transfer_active = False
                finalize_db_wal()
                with console_print_lock:
                    print(f"[*] PUSH Session {worker_session_token[:8]} completed! WAL checkpointed and cleaned up.")
                break
    except Exception:
        pass
    finally:
        with worker_conn_lock:
            active_worker_connections.discard(conn)


# ==============================================================================
# ZERO-CONFIG CLIENT DISCOVERY & CLIENT-PASSWORD INVITATION ENGINE
# ==============================================================================
def discovery_listener_loop():
    """Listen for UDP beacons from waiting clients on the network."""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp_sock.bind((HOST, DISCOVERY_UDP_PORT))
    except Exception as e:
        print(f"[!] UDP Discovery listener could not bind port {DISCOVERY_UDP_PORT}: {e}")
        return

    udp_sock.settimeout(1.0)
    while server_running:
        try:
            data, addr = udp_sock.recvfrom(4096)
            msg = json.loads(data.decode('utf-8'))
            if msg.get("type") == "eft_client_beacon":
                cid = msg.get("client_id") or f"{addr[0]}:{msg.get('invite_port', DEFAULT_CLIENT_INVITE_PORT)}"
                reported_ip = msg.get("ip")
                effective_ip = addr[0]
                if effective_ip.startswith("127.") and reported_ip and not reported_ip.startswith("127."):
                    effective_ip = reported_ip

                with waiting_clients_lock:
                    waiting_clients[cid] = {
                        "client_id": cid,
                        "hostname": msg.get("hostname") or "Remote-Client",
                        "os": (msg.get("os") or "unknown").lower(),
                        "ip": effective_ip,
                        "source_ip": addr[0],
                        "udp_port": addr[1],
                        "invite_port": int(msg.get("invite_port") or DEFAULT_CLIENT_INVITE_PORT),
                        "requires_password": bool(msg.get("requires_password", False)),
                        "waiting": bool(msg.get("waiting", True)),
                        "last_seen": time.time()
                    }
        except socket.timeout:
            continue
        except Exception:
            continue
    try:
        udp_sock.close()
    except Exception:
        pass


def send_udp_probe():
    """Broadcast probe packets across all local NIC subnets so waiting clients on Wi-Fi/Hotspots respond immediately."""
    probe = json.dumps({
        "type": "eft_server_probe",
        "server_hostname": LOCAL_HOSTNAME,
        "server_os": LOCAL_OS,
        "server_ips": get_local_ips(),
        "discovery_port": DISCOVERY_UDP_PORT
    }).encode('utf-8')

    targets = set(get_broadcast_targets())
    with waiting_clients_lock:
        for v in waiting_clients.values():
            if v.get("ip"):
                targets.add(v["ip"])
            if v.get("source_ip"):
                targets.add(v["source_ip"])

    for local_ip in get_local_ips():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(0.15)
            try:
                if not local_ip.startswith('127.'):
                    s.bind((local_ip, 0))
            except Exception:
                pass
            for target_ip in targets:
                for port in (CLIENT_PROBE_UDP_PORT, DEFAULT_CLIENT_INVITE_PORT):
                    try:
                        s.sendto(probe, (target_ip, port))
                    except Exception:
                        pass
            s.close()
        except Exception:
            pass


def promote_socket_to_control_channel(conn, addr_ip, payload):
    """
    Promote an already-authenticated socket (either inbound on 8080 or outbound invite on 8083)
    into the persistent global_control_socket and start its reader thread.
    """
    global global_control_socket, connected_client_info, peer_connection_seq
    conn.settimeout(None)
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass

    try:
        routed_srv_ip = conn.getsockname()[0]
    except Exception:
        routed_srv_ip = get_primary_local_ip()
    if routed_srv_ip.startswith('127.') or routed_srv_ip == '0.0.0.0':
        routed_srv_ip = get_primary_local_ip()

    client_id = payload.get("client_id")
    recv_pwd_hash = payload.get("password_hash", "")
    c_info = {
        "client_id": client_id or f"{addr_ip}:{payload.get('invite_port', DEFAULT_CLIENT_INVITE_PORT)}",
        "hostname": payload.get("hostname") or "Remote-Client",
        "os": (payload.get("os") or "unknown").lower(),
        "ip": addr_ip,
        "server_ip": routed_srv_ip,
        "invite_port": payload.get("invite_port", DEFAULT_CLIENT_INVITE_PORT),
        "requires_password": bool(recv_pwd_hash),
        "has_zstd": bool(payload.get("has_zstd", False)),
        "connected_at": time.time()
    }
    with control_socket_lock:
        if global_control_socket and global_control_socket is not conn:
            try:
                global_control_socket.close()
            except Exception:
                pass
        global_control_socket = conn
        connected_client_info = c_info
        peer_connection_seq += 1

    print(f"[*] Client connected: {c_info['hostname']} ({addr_ip}) [OS: {c_info['os'].upper()}]")
    return c_info, routed_srv_ip

def process_pull_manifest_dict(manifest_payload, addr_ip):
    """
    Process a PULL manifest (either from control channel or dedicated socket),
    pre-allocate files in a single fast SQLite transaction, and return the response dict.
    """
    global current_active_token
    enable_db_wal()
    manifest_data = manifest_payload.get("manifest") or {}
    files = manifest_data.get("files", [])
    empty_dirs = manifest_data.get("dirs", [])
    token = manifest_payload.get("session_token") or current_active_token or secrets.token_hex(16)
    missing_map = {}
    already_completed_files = []
    now_ts = time.time()
    routed_srv_ip = (connected_client_info or {}).get("server_ip") or get_primary_local_ip()

    with db_lock:
        active_sessions.add(token)
        current_active_token = token
        set_meta('session_token', token)
        set_meta('transfer_state', 'active')

        db_conn.execute("BEGIN IMMEDIATE")
        history_conn.execute("BEGIN IMMEDIATE")
        sess_row = history_conn.execute(
            "SELECT destination_path, title FROM transfer_sessions WHERE session_token=?", (token,)
        ).fetchone()
        base_save_dir = sess_row[0] if (sess_row and sess_row[0]) else SAVE_DIRECTORY
        sess_title = sess_row[1] if (sess_row and sess_row[1]) else "Transfer Session"

        c_id = (connected_client_info or {}).get("client_id") or manifest_payload.get("client_id") or ""
        c_name = (connected_client_info or {}).get("hostname") or manifest_payload.get("hostname") or "Remote Client"
        c_ip = (connected_client_info or {}).get("ip") or addr_ip
        c_os = (connected_client_info or {}).get("os") or manifest_payload.get("os") or "unknown"

        if not sess_row:
            history_conn.execute("""
                INSERT INTO transfer_sessions (
                    session_token, title, direction,
                    server_name, server_ip, server_os,
                    client_id, client_name, client_ip, client_os,
                    source_paths, destination_path, started_at, updated_at, status
                ) VALUES (?, ?, 'pull', ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, 'active')
            """, (
                token, sess_title,
                LOCAL_HOSTNAME, routed_srv_ip, LOCAL_OS,
                c_id, c_name, c_ip, c_os,
                base_save_dir, now_ts, now_ts
            ))
        else:
            history_conn.execute("""
                UPDATE transfer_sessions
                SET direction = 'pull',
                    server_name = ?, server_ip = ?, server_os = ?,
                    client_id = COALESCE(NULLIF(?, ''), client_id),
                    client_name = COALESCE(NULLIF(?, ''), client_name),
                    client_ip = COALESCE(NULLIF(?, ''), client_ip),
                    client_os = COALESCE(NULLIF(?, ''), client_os)
                WHERE session_token = ?
            """, (LOCAL_HOSTNAME, routed_srv_ip, LOCAL_OS, c_id, c_name, c_ip, c_os, token))

        for dir_info in empty_dirs:
            norm_dir = normalize_rel_path(dir_info.get("relative_path", ""))
            if not norm_dir:
                continue
            dir_save_path = resolve_local_save_path(base_save_dir, norm_dir)
            dir_pre_existed = 1 if os.path.exists(dir_save_path) else 0
            os.makedirs(dir_save_path, exist_ok=True)
            try:
                os.utime(dir_save_path, (dir_info.get("atime", now_ts), dir_info.get("mtime", now_ts)))
            except Exception:
                pass

            dir_rel_display = norm_dir.rstrip('/') + '/'
            history_conn.execute("""
                INSERT INTO transfer_history_files (
                    session_token, file_id, relative_path, source_path, save_path, size,
                    mtime, atime, pre_existed, status, transferred_at
                ) VALUES (?, 0, ?, ?, ?, 0, ?, ?, ?, 'completed', ?)
                ON CONFLICT(session_token, relative_path) DO UPDATE SET
                    save_path = excluded.save_path,
                    status = 'completed',
                    transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
            """, (
                token, dir_rel_display, dir_info.get("source_path") or norm_dir,
                dir_save_path, dir_info.get("mtime", now_ts), dir_info.get("atime", now_ts),
                dir_pre_existed, now_ts
            ))

        for file_info in files:
            norm_rel = normalize_rel_path(file_info["relative_path"])
            src_full_path = file_info.get("source_path") or norm_rel
            final_path = resolve_local_save_path(base_save_dir, norm_rel)
            os.makedirs(os.path.dirname(final_path), exist_ok=True)

            cursor = db_conn.execute(
                'SELECT file_id, save_path, pre_existed FROM files WHERE session_token=? AND relative_path=? AND size=?',
                (token, norm_rel, file_info["size"])
            )
            existing = cursor.fetchone()
            if existing:
                file_id = existing[0]
                if existing[1]:
                    final_path = existing[1]
                pre_existed = existing[2]
            else:
                pre_existed = 1 if (os.path.exists(final_path) and os.path.getsize(final_path) == file_info["size"]) else 0
                cursor = db_conn.execute(
                    """INSERT INTO files (session_token, relative_path, source_path, save_path, size, mtime, atime, pre_existed)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (token, norm_rel, src_full_path, final_path, file_info["size"], file_info["mtime"], file_info["atime"], pre_existed)
                )
                file_id = cursor.lastrowid
                if file_info["size"] == 0:
                    db_conn.execute(
                        "INSERT INTO chunks (file_id, chunk_index, status) VALUES (?, 0, 'received')",
                        (file_id,)
                    )
                else:
                    total_chunks = max(1, math.ceil(file_info["size"] / CHUNK_SIZE))
                    for i in range(total_chunks):
                        db_conn.execute(
                            "INSERT INTO chunks (file_id, chunk_index, status) VALUES (?, ?, 'pending')",
                            (file_id, i)
                        )

            if not os.path.exists(final_path):
                with open(final_path, 'wb') as f:
                    if file_info["size"] > 0:
                        f.truncate(file_info["size"])
                if file_info["size"] == 0:
                    try:
                        os.utime(final_path, (file_info["atime"], file_info["mtime"]))
                    except Exception:
                        pass

            cursor = db_conn.execute(
                "SELECT chunk_index FROM chunks WHERE file_id=? AND status='pending'",
                (file_id,)
            )
            missing_chunks = [row[0] for row in cursor.fetchall()]
            file_status = 'completed' if len(missing_chunks) == 0 else 'pending'
            file_done_ts = now_ts if file_status == 'completed' else None

            history_conn.execute("""
                INSERT INTO transfer_history_files (
                    session_token, file_id, relative_path, source_path, save_path, size,
                    mtime, atime, pre_existed, status, transferred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_token, relative_path) DO UPDATE SET
                    file_id = excluded.file_id,
                    source_path = excluded.source_path,
                    save_path = excluded.save_path,
                    status = CASE WHEN transfer_history_files.status = 'completed' THEN 'completed' ELSE excluded.status END,
                    transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
            """, (
                token, file_id, norm_rel, src_full_path, final_path, file_info["size"],
                file_info["mtime"], file_info["atime"], pre_existed, file_status, file_done_ts
            ))

            if missing_chunks:
                missing_map[norm_rel] = {
                    "file_id": file_id,
                    "missing": missing_chunks,
                    "save_path": final_path
                }
            else:
                already_completed_files.append(norm_rel)

        cursor = db_conn.execute("""
            SELECT COUNT(*) FROM chunks c
            INNER JOIN files f ON c.file_id = f.file_id
            WHERE f.session_token = ? AND c.status = 'pending'
        """, (token,))
        if (cursor.fetchone()[0] or 0) == 0:
            set_meta('transfer_state', 'completed')
            comp_f, tot_f, recv_c, tot_c = sync_session_metrics(token, override_status='completed')
            db_conn.execute("COMMIT")
            history_conn.execute("COMMIT")
            finalize_db_wal()
        else:
            comp_f, tot_f, recv_c, tot_c = sync_session_metrics(token, override_status='active')
            db_conn.execute("COMMIT")
            history_conn.execute("COMMIT")

    return {
        "action": "pull_manifest_processed",
        "status": "manifest_processed",
        "session_token": token,
        "missing_map": missing_map,
        "already_completed": already_completed_files,
        "destination_path": base_save_dir,
        "session_title": sess_title,
        "server_hostname": LOCAL_HOSTNAME,
        "server_ip": routed_srv_ip,
        "server_os": LOCAL_OS,
        "server_has_zstd": HAS_ZSTD,
        "total_files": tot_f,
        "completed_files": comp_f,
        "total_chunks": tot_c,
        "received_chunks": recv_c
    }


def spawn_server_outbound_workers(session_token, mode="pull"):
    """
    Connect 4 worker sockets OUTBOUND from Server -> Client's invite_port (8083).
    Because Server -> Client (8083) is the exact direction that established the Control Channel,
    this guarantees 4 high-speed worker streams even if Windows Firewall or Android Hotspot blocks Server port 8080!
    """
    time.sleep(0.4)
    if session_token not in active_sessions:
        return
    with worker_conn_lock:
        if len(active_worker_connections) >= 2:
            return

    c_info = connected_client_info or {}
    client_ip = c_info.get("ip")
    invite_port = int(c_info.get("invite_port") or DEFAULT_CLIENT_INVITE_PORT)
    if not client_ip:
        return

    def _outbound_worker(wid):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10.0)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((client_ip, invite_port))
            req = {
                "action": "reverse_worker_connect",
                "mode": mode,
                "session_token": session_token,
                "password_hash": active_client_password_hash
            }
            s.sendall((json.dumps(req) + "\n").encode('utf-8'))
            ack = s.recv(1024).decode('utf-8', errors='replace').strip()
            if "success" not in ack:
                s.close()
                return
            s.settimeout(30.0)
            if mode == "push":
                handle_push_worker_stream(s, session_token)
            else:
                handle_worker_stream(s, session_token)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    for i in range(4):
        threading.Thread(target=_outbound_worker, args=(i + 1,), daemon=True).start()

def run_server_control_reader(conn, addr_ip):
    """Persistent reader loop for global_control_socket (resilient to malformed JSON lines)."""
    global global_control_socket, connected_client_info, last_dir_result, current_active_token
    buffer = bytearray()
    while server_running:
        try:
            data = conn.recv(65536)
            if not data:
                break
            buffer.extend(data)
            while b'\n' in buffer:
                nl = buffer.find(b'\n')
                line_bytes = bytes(buffer[:nl]).strip()
                del buffer[:nl + 1]
                if not line_bytes:
                    continue
                try:
                    msg = json.loads(line_bytes.decode('utf-8', errors='replace'))
                except Exception as je:
                    print(f"[!] Control channel ignored malformed JSON frame: {je}")
                    continue

                m_act = msg.get("action")
                if m_act == "dir_result":
                    last_dir_result = msg
                    dir_result_event.set()
                elif m_act == "init_transfer":
                    def _handle_ctrl_pull_init(m_payload):
                        resp_dict = process_pull_manifest_dict(m_payload, addr_ip)
                        send_control_command(resp_dict)
                        if resp_dict.get("missing_map"):
                            spawn_server_outbound_workers(resp_dict["session_token"], mode="pull")
                    threading.Thread(target=_handle_ctrl_pull_init, args=(msg,), daemon=True).start()
                elif m_act == "push_manifest_processed":
                    threading.Thread(
                        target=handle_push_manifest_processed,
                        args=(msg,),
                        daemon=True
                    ).start()
                elif m_act == "transfer_interrupted":
                    tok = msg.get("session_token") or current_active_token
                    stop_push_workers()
                    with db_lock:
                        set_meta('transfer_state', 'interrupted')
                        if tok:
                            sync_session_metrics(tok, override_status='interrupted')
                    finalize_db_wal()
        except Exception:
            break

    stop_push_workers()
    with control_socket_lock:
        if global_control_socket is conn:
            global_control_socket = None
            connected_client_info = None
    print(f"[*] Client control channel disconnected ({addr_ip}).")
    with db_lock:
        if current_active_token:
            cursor = db_conn.execute("""
                SELECT COUNT(*) FROM chunks c
                INNER JOIN files f ON c.file_id = f.file_id
                WHERE f.session_token = ? AND c.status = 'pending'
            """, (current_active_token,))
            if (cursor.fetchone()[0] or 0) > 0:
                set_meta('transfer_state', 'interrupted')
                sync_session_metrics(current_active_token, override_status='interrupted')
    finalize_db_wal()


def invite_waiting_client(client_ip, invite_port=DEFAULT_CLIENT_INVITE_PORT, udp_port=None, password_hash=""):
    """
    Invite a waiting client to connect to this server.
    UPGRADE: If the TCP connection to the client's invite_port succeeds and the client replies with
    'control_ready' JSON, we immediately promote THAT SAME TCP SOCKET into the persistent control channel!
    This completely bypasses any Windows Firewall or Android Hotspot routing blocks on port 8080!
    """
    invite_payload = {
        "action": "connect_to_server",
        "server_port": PORT,
        "server_hostname": LOCAL_HOSTNAME,
        "server_os": LOCAL_OS,
        "server_ips": get_local_ips(),
        "password_hash": password_hash or "",
        "upgrade_socket": True
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((client_ip, int(invite_port)))
        routed_server_ip = s.getsockname()[0]
        invite_payload["preferred_server_ip"] = routed_server_ip
        s.sendall((json.dumps(invite_payload) + "\n").encode('utf-8'))

        resp_line = s.recv(4096).decode('utf-8', errors='replace').strip()
        if "auth_failed" in resp_line or "rejected" in resp_line:
            s.close()
            return "auth_failed", "Incorrect password rejected by client."

        # Check if the client sent back a JSON control_auth upgrade on the same socket
        try:
            resp_json = json.loads(resp_line.splitlines()[0])
        except Exception:
            resp_json = None

        if isinstance(resp_json, dict) and resp_json.get("status") in ("control_ready", "connecting"):
            if resp_json.get("upgrade_control"):
                c_info, srv_ip = promote_socket_to_control_channel(s, client_ip, resp_json)
                auth_ack = {
                    "status": "success",
                    "server_hostname": LOCAL_HOSTNAME,
                    "server_os": LOCAL_OS,
                    "server_ip": srv_ip
                }
                s.sendall((json.dumps(auth_ack) + "\n").encode('utf-8'))
                threading.Thread(target=run_server_control_reader, args=(s, client_ip), daemon=True).start()
                return "upgraded", f"Connected directly to {c_info.get('hostname', client_ip)}"

        s.close()
        if "connecting" in resp_line or "success" in resp_line:
            return "ok", "Invitation accepted by client."
    except Exception:
        pass

    raw_msg = (json.dumps(invite_payload) + "\n").encode('utf-8')
    udp_sent = False
    for uport in filter(None, [udp_port, CLIENT_PROBE_UDP_PORT]):
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(0.5)
            u.sendto(raw_msg, (client_ip, int(uport)))
            u.close()
            udp_sent = True
        except Exception:
            pass

    if udp_sent:
        return "udp_sent", "UDP invitation sent."
    return "unreachable", f"Could not reach waiting client at {client_ip}:{invite_port}"

# ==============================================================================
# FLASK WEB UI & REST API
# ==============================================================================
app = Flask(__name__)


@app.route('/')
def serve_ui():
    try:
        with open(TEMPLATE_PATH, encoding='utf-8') as f:
            return render_template_string(f.read())
    except FileNotFoundError:
        return "Error: templates/index.html not found.", 404


@app.route('/download/client.py', methods=['GET'])
def download_client_script():
    """Allow fetching client.py via curl http://<server_ip>:8081/download/client.py -o client.py."""
    try:
        with open(CLIENT_SCRIPT_PATH, 'rb') as f:
            content = f.read()
        return Response(
            content,
            mimetype='text/x-python',
            headers={"Content-Disposition": "attachment; filename=client.py"}
        )
    except FileNotFoundError:
        return "Error: client.py not found on server.", 404


@app.route('/api/clients/waiting', methods=['GET'])
def api_waiting_clients():
    if request.args.get('probe', 'false').lower() == 'true':
        send_udp_probe()
        time.sleep(0.2)

    now = time.time()
    active_list = []
    with waiting_clients_lock:
        expired = [
            k for k, v in waiting_clients.items()
            if (now - v['last_seen'] > 30.0) and not (
                connected_client_info and connected_client_info.get("client_id") == v.get("client_id")
            )
        ]
        for k in expired:
            waiting_clients.pop(k, None)
        for v in waiting_clients.values():
            is_curr = bool(
                connected_client_info and
                (connected_client_info.get("client_id") == v["client_id"] or
                 connected_client_info.get("ip") in (v["ip"], v["source_ip"]))
            )
            item = dict(v)
            item["age_seconds"] = round(now - v["last_seen"], 1)
            item["is_connected"] = is_curr and (global_control_socket is not None)
            active_list.append(item)

    active_list.sort(key=lambda x: (not x["is_connected"], x["hostname"].lower()))
    return jsonify({
        "status": "success",
        "server_hostname": LOCAL_HOSTNAME,
        "server_os": LOCAL_OS,
        "server_ips": get_local_ips(),
        "server_port": PORT,
        "client_online": global_control_socket is not None,
        "connected_client": connected_client_info if global_control_socket is not None else None,
        "waiting_clients": active_list
    })

@app.route('/api/clients/connect', methods=['POST'])
def api_connect_client():
    global global_control_socket, connected_client_info, active_client_password_hash, last_dir_result
    data = request.json or {}
    client_id = data.get("client_id")
    ip = (data.get("ip") or "").strip()
    invite_port = int(data.get("invite_port") or DEFAULT_CLIENT_INVITE_PORT)
    raw_password = data.get("password")
    provided_hash = data.get("password_hash")
    udp_port = None
    requires_password = False

    if client_id:
        with waiting_clients_lock:
            cinfo = waiting_clients.get(client_id)
            if cinfo:
                ip = cinfo.get("source_ip") or cinfo.get("ip")
                invite_port = cinfo.get("invite_port", DEFAULT_CLIENT_INVITE_PORT)
                udp_port = cinfo.get("udp_port")
                requires_password = bool(cinfo.get("requires_password", False))

    if not ip:
        return jsonify({"status": "error", "message": "Client IP address is required."})

    if ':' in ip:
        parts = ip.rsplit(':', 1)
        ip = parts[0].strip()
        try:
            invite_port = int(parts[1].strip())
        except Exception:
            pass

    if requires_password and not raw_password and not provided_hash:
        return jsonify({
            "status": "password_required",
            "requires_password": True,
            "message": "This client is password-protected. Please enter the client's password."
        })

    pwd_hash = provided_hash if provided_hash is not None else hash_password(raw_password)

    with auth_state_lock:
        active_client_password_hash = pwd_hash
        pending_client_password_hashes[ip] = pwd_hash
        if client_id:
            pending_client_password_hashes[client_id] = pwd_hash

    with control_socket_lock:
        if global_control_socket is not None:
            try:
                global_control_socket.sendall((json.dumps({"action": "disconnect_control"}) + "\n").encode('utf-8'))
                global_control_socket.close()
            except Exception:
                pass
            global_control_socket = None
            connected_client_info = None
    last_dir_result = None
    dir_result_event.clear()

    prev_seq = peer_connection_seq
    invite_status, invite_msg = invite_waiting_client(ip, invite_port, udp_port, password_hash=pwd_hash)

    if invite_status == "upgraded" and global_control_socket is not None and connected_client_info:
        return jsonify({
            "status": "success",
            "message": invite_msg,
            "connected_client": connected_client_info
        })
    if invite_status == "auth_failed":
        return jsonify({
            "status": "auth_error",
            "requires_password": True,
            "message": invite_msg
        })
    if invite_status == "unreachable":
        return jsonify({"status": "error", "message": invite_msg})

    # Wait up to 7.0 seconds for fallback reverse connection if socket wasn't upgraded directly
    for _ in range(70):
        if global_control_socket is not None and connected_client_info and peer_connection_seq > prev_seq:
            return jsonify({
                "status": "success",
                "message": f"Connected to {connected_client_info.get('hostname', ip)}",
                "connected_client": connected_client_info
            })
        time.sleep(0.1)

    if global_control_socket is not None and connected_client_info:
        return jsonify({"status": "success", "connected_client": connected_client_info})

    if invite_status == "udp_sent":
        return jsonify({
            "status": "auth_error" if requires_password else "error",
            "message": "Client did not establish connection (verify client password or firewall settings)."
        })
    return jsonify({"status": "error", "message": "Invitation sent, but client did not establish control channel in time."})

@app.route('/api/clients/disconnect', methods=['POST'])
def api_disconnect_client():
    global global_control_socket, connected_client_info, last_dir_result
    send_control_command({"action": "disconnect_control"})
    close_active_workers()
    with control_socket_lock:
        if global_control_socket:
            try:
                global_control_socket.close()
            except Exception:
                pass
            global_control_socket = None
        connected_client_info = None
    last_dir_result = None
    dir_result_event.clear()
    return jsonify({"status": "success"})


@app.route('/api/local/browse', methods=['GET', 'POST'])
def browse_local():
    global SAVE_DIRECTORY
    if request.method == 'POST':
        data = request.json or {}
        target_path = data.get('path', '')
        update_save = data.get('set_save_dir', False)
    else:
        target_path = request.args.get('path', '')
        update_save = request.args.get('set_save_dir', 'false').lower() == 'true'

    res = list_os_directory(target_path, SAVE_DIRECTORY)
    if res.get("status") == "success" and update_save and res.get("current_path") != "DRIVES":
        SAVE_DIRECTORY = res["current_path"]
        set_meta('save_directory', SAVE_DIRECTORY)
    return jsonify(res)


@app.route('/api/remote/browse', methods=['POST'])
def browse_remote():
    global last_dir_result, REMOTE_ACTIVE_DIRECTORY
    if not is_client_connected() or global_control_socket is None:
        return jsonify({"status": "error", "message": "Remote client offline."})

    req_data = request.json or {}
    target_path = req_data.get('path', '')
    dir_result_event.clear()
    last_dir_result = None

    if not send_control_command({"action": "list_dir", "path": target_path}):
        return jsonify({"status": "error", "message": "Lost control connection to client."})

    if dir_result_event.wait(timeout=5.0) and last_dir_result is not None:
        if last_dir_result.get("status") == "success" and last_dir_result.get("current_path") and last_dir_result.get("current_path") != "DRIVES":
            REMOTE_ACTIVE_DIRECTORY = last_dir_result["current_path"]
        return jsonify(last_dir_result)
    return jsonify({"status": "error", "message": "Timeout waiting for remote device response."})


@app.route('/api/sessions', methods=['GET'])
def api_get_sessions():
    """Return all transfer sessions stored in transfer_history.db with Direction, Server & Client identification."""
    with db_lock:
        rows = history_conn.execute("""
            SELECT session_token, title, direction,
                   server_name, server_ip, server_os,
                   client_id, client_name, client_ip, client_os,
                   source_paths, destination_path, started_at, updated_at, completed_at,
                   total_files, completed_files, total_bytes, transferred_bytes,
                   total_chunks, received_chunks, status
            FROM transfer_sessions
            ORDER BY started_at DESC
        """).fetchall()

    default_srv_ip = get_primary_local_ip()
    sessions = []
    for r in rows:
        direction = (r[2] or 'pull').lower()
        total_c = r[19] or 0
        recv_c = r[20] or 0
        status = r[21] or 'idle'
        pct = round((recv_c / total_c * 100), 1) if total_c > 0 else (100.0 if status == 'completed' else 0.0)
        try:
            src_paths = json.loads(r[10] or '[]')
        except Exception:
            src_paths = []

        can_resume = status in ('paused', 'interrupted') and (total_c > 0 and recv_c < total_c)
        can_cancel = status in ('active', 'paused', 'interrupted') and (recv_c < total_c)
        can_rollback = status in ('active', 'paused', 'interrupted', 'completed', 'cancelled') and ((r[16] or 0) > 0 or recv_c > 0)

        sessions.append({
            "session_token": r[0],
            "title": r[1] or "Transfer Session",
            "direction": direction,
            "server_name": r[3] or LOCAL_HOSTNAME,
            "server_ip": r[4] or default_srv_ip,
            "server_os": r[5] or LOCAL_OS,
            "client_id": r[6] or "",
            "client_name": r[7] or "Remote Device",
            "client_ip": r[8] or "",
            "client_os": r[9] or "",
            "source_paths": src_paths,
            "destination_path": r[11] or (REMOTE_ACTIVE_DIRECTORY if direction == 'push' else SAVE_DIRECTORY),
            "started_at": r[12],
            "updated_at": r[13],
            "completed_at": r[14],
            "total_files": r[15] or 0,
            "completed_files": r[16] or 0,
            "total_bytes": r[17] or 0,
            "transferred_bytes": r[18] or 0,
            "total_chunks": total_c,
            "received_chunks": recv_c,
            "percent": pct,
            "status": status,
            "can_resume": can_resume,
            "can_cancel": can_cancel,
            "can_rollback": can_rollback
        })
    return jsonify({"status": "success", "sessions": sessions})


@app.route('/api/sessions/<session_token>', methods=['GET'])
def api_get_session_detail(session_token):
    """Return full metadata and paginated file history for a specific session so large sessions never lag the UI."""
    try:
        page = max(1, int(request.args.get('page', 1)))
    except Exception:
        page = 1
    try:
        per_page = min(500, max(10, int(request.args.get('per_page', 100))))
    except Exception:
        per_page = 100
    search_q = (request.args.get('search') or '').strip().lower()
    offset = (page - 1) * per_page

    with db_lock:
        r = history_conn.execute("""
            SELECT session_token, title, direction,
                   server_name, server_ip, server_os,
                   client_id, client_name, client_ip, client_os,
                   source_paths, destination_path, started_at, updated_at, completed_at,
                   total_files, completed_files, total_bytes, transferred_bytes,
                   total_chunks, received_chunks, status
            FROM transfer_sessions
            WHERE session_token = ?
        """, (session_token,)).fetchone()

        if not r:
            return jsonify({"status": "error", "message": "Session not found."}), 404

        if search_q:
            like_pat = f"%{search_q}%"
            total_log_rows = history_conn.execute("""
                SELECT COUNT(*) FROM transfer_history_files
                WHERE session_token = ? AND LOWER(relative_path) LIKE ?
            """, (session_token, like_pat)).fetchone()[0] or 0

            f_rows = history_conn.execute("""
                SELECT id, file_id, relative_path, source_path, save_path, size, mtime, status, transferred_at, pre_existed
                FROM transfer_history_files
                WHERE session_token = ? AND LOWER(relative_path) LIKE ?
                ORDER BY id ASC
                LIMIT ? OFFSET ?
            """, (session_token, like_pat, per_page, offset)).fetchall()
        else:
            total_log_rows = history_conn.execute("""
                SELECT COUNT(*) FROM transfer_history_files
                WHERE session_token = ?
            """, (session_token,)).fetchone()[0] or 0

            f_rows = history_conn.execute("""
                SELECT id, file_id, relative_path, source_path, save_path, size, mtime, status, transferred_at, pre_existed
                FROM transfer_history_files
                WHERE session_token = ?
                ORDER BY id ASC
                LIMIT ? OFFSET ?
            """, (session_token, per_page, offset)).fetchall()

        page_fids = [fr[1] for fr in f_rows if fr[1]]
        chunk_progress = {}
        if page_fids:
            placeholders = ",".join("?" for _ in page_fids)
            for fid, tot, done in db_conn.execute(f"""
                SELECT file_id, COUNT(*), SUM(CASE WHEN status='received' THEN 1 ELSE 0 END)
                FROM chunks
                WHERE file_id IN ({placeholders})
                GROUP BY file_id
            """, tuple(page_fids)).fetchall():
                chunk_progress[fid] = (tot or 0, done or 0)

        rollback_check = history_conn.execute("""
            SELECT 1 FROM transfer_history_files
            WHERE session_token = ? AND pre_existed = 0 AND status IN ('completed', 'pending')
            LIMIT 1
        """, (session_token,)).fetchone()

    default_srv_ip = get_primary_local_ip()
    direction = (r[2] or 'pull').lower()
    total_c = r[19] or 0
    recv_c = r[20] or 0
    status = r[21] or 'idle'
    pct = round((recv_c / total_c * 100), 1) if total_c > 0 else (100.0 if status == 'completed' else 0.0)
    try:
        src_paths = json.loads(r[10] or '[]')
    except Exception:
        src_paths = []

    files_list = []
    for fr in f_rows:
        fid = fr[1]
        f_status = fr[7]
        f_size = fr[5] or 0
        est_chunks = 1 if f_size == 0 else max(1, math.ceil(f_size / CHUNK_SIZE))
        tot_fc, done_fc = chunk_progress.get(fid, (est_chunks, est_chunks if f_status == 'completed' else 0))
        files_list.append({
            "id": fr[0],
            "file_id": fid,
            "relative_path": fr[2],
            "source_path": fr[3] or fr[2],
            "name": os.path.basename(fr[2].rstrip('/')),
            "save_path": fr[4],
            "size": f_size,
            "mtime": fr[6],
            "status": f_status,
            "transferred_at": fr[8],
            "pre_existed": bool(fr[9]),
            "chunks_total": tot_fc,
            "chunks_done": done_fc
        })

    total_pages = max(1, math.ceil(total_log_rows / per_page))
    can_resume = status in ('paused', 'interrupted') and (total_c > 0 and recv_c < total_c)
    can_cancel = status in ('active', 'paused', 'interrupted') and (recv_c < total_c)
    can_rollback = status in ('active', 'paused', 'interrupted', 'completed', 'cancelled') and bool(rollback_check)

    session_obj = {
        "session_token": r[0],
        "title": r[1] or "Transfer Session",
        "direction": direction,
        "server_name": r[3] or LOCAL_HOSTNAME,
        "server_ip": r[4] or default_srv_ip,
        "server_os": r[5] or LOCAL_OS,
        "client_id": r[6] or "",
        "client_name": r[7] or "Remote Device",
        "client_ip": r[8] or "",
        "client_os": r[9] or "",
        "source_paths": src_paths,
        "destination_path": r[11] or (REMOTE_ACTIVE_DIRECTORY if direction == 'push' else SAVE_DIRECTORY),
        "started_at": r[12],
        "updated_at": r[13],
        "completed_at": r[14],
        "total_files": r[15] or 0,
        "completed_files": r[16] or 0,
        "total_bytes": r[17] or 0,
        "transferred_bytes": r[18] or 0,
        "total_chunks": total_c,
        "received_chunks": recv_c,
        "percent": pct,
        "status": status,
        "can_resume": can_resume,
        "can_cancel": can_cancel,
        "can_rollback": can_rollback,
        "files": files_list,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "total_file_rows": total_log_rows
    }
    return jsonify({"status": "success", "session": session_obj})


@app.route('/api/action', methods=['POST'])
def api_action():
    global SAVE_DIRECTORY, REMOTE_ACTIVE_DIRECTORY, current_active_token
    data = request.json or {}
    cmd = data.get("action")
    req_token = data.get("session_token")

    if cmd == "cancel_transfer":
        removed = perform_cancel(session_token=req_token, reason="UI Cancel button")
        return jsonify({"status": "success", "state": get_meta('transfer_state', 'idle'), "removed_partial": removed})

    if cmd == "rollback_transfer":
        removed = perform_rollback(session_token=req_token)
        return jsonify({"status": "success", "state": "idle", "removed_files": removed})

    if cmd == "pause_transfer":
        perform_pause(session_token=req_token)
        return jsonify({"status": "success", "state": "paused"})

    if not global_control_socket:
        return jsonify({"status": "error", "message": "Remote client is not connected."})

    # 1. PULL Transfer (Client -> Server) or unified start_transfer with direction
    if cmd in ("start_transfer", "start_pull_transfer", "start_push_transfer"):
        direction = (data.get("direction") or ("push" if cmd == "start_push_transfer" else "pull")).lower()
        paths = data.get("paths", [])
        if not paths:
            return jsonify({"status": "error", "message": "No source files or directories selected."})

        if direction == "push":
            remote_dest = (data.get("remote_dest_path") or data.get("dest_path") or REMOTE_ACTIVE_DIRECTORY or "").strip()
            if remote_dest == "DRIVES":
                return jsonify({"status": "error", "message": "Cannot push files directly into DRIVES root. Open a folder on the client first."})
            if remote_dest:
                REMOTE_ACTIVE_DIRECTORY = remote_dest
            new_token = secrets.token_hex(16)
            if start_push_session_on_server(new_token, paths, REMOTE_ACTIVE_DIRECTORY, is_resume=False):
                return jsonify({"status": "success", "state": "active", "direction": "push", "session_token": new_token})
            return jsonify({"status": "error", "message": "Failed to send push transfer command to client."})

        # Default: PULL (Client -> Server)
        local_dest = (data.get("dest_path") or "").strip()
        if local_dest == "DRIVES":
            return jsonify({"status": "error", "message": "Cannot save files directly into DRIVES root. Open a local drive/folder first."})
        if local_dest and os.path.isdir(local_dest):
            SAVE_DIRECTORY = os.path.abspath(local_dest)

        new_token = secrets.token_hex(16)
        now = time.time()
        title = make_session_title(paths)
        c_id = (connected_client_info or {}).get("client_id", "")
        c_name = (connected_client_info or {}).get("hostname", "Remote Client")
        c_ip = (connected_client_info or {}).get("ip", "")
        c_os = (connected_client_info or {}).get("os", "")
        srv_ip = (connected_client_info or {}).get("server_ip") or get_primary_local_ip()

        with db_lock:
            active_sessions.add(new_token)
            current_active_token = new_token
            set_meta('target_paths', json.dumps(paths))
            set_meta('save_directory', SAVE_DIRECTORY)
            set_meta('transfer_state', 'active')
            set_meta('session_token', new_token)

            history_conn.execute("""
                INSERT OR REPLACE INTO transfer_sessions (
                    session_token, title, direction,
                    server_name, server_ip, server_os,
                    client_id, client_name, client_ip, client_os,
                    source_paths, destination_path, started_at, updated_at,
                    total_files, completed_files, total_bytes, transferred_bytes,
                    total_chunks, received_chunks, status
                ) VALUES (?, ?, 'pull', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 'active')
            """, (
                new_token, title,
                LOCAL_HOSTNAME, srv_ip, LOCAL_OS,
                c_id, c_name, c_ip, c_os,
                json.dumps(paths), SAVE_DIRECTORY, now, now
            ))

        if send_control_command({
            "action": "start_transfer",
            "direction": "pull",
            "paths": paths,
            "session_token": new_token,
            "session_title": title,
            "destination_path": SAVE_DIRECTORY,
            "server_hostname": LOCAL_HOSTNAME,
            "server_ip": srv_ip,
            "server_os": LOCAL_OS
        }):
            return jsonify({"status": "success", "state": "active", "direction": "pull", "session_token": new_token})
        return jsonify({"status": "error", "message": "Failed to send start command to client."})

    # 2. Resume Incomplete Session (Works for both PULL and PUSH)
    if cmd == "resume_transfer":
        target_token = req_token or get_meta('session_token')
        if not target_token:
            return jsonify({"status": "error", "message": "No session specified to resume."})

        with db_lock:
            row = history_conn.execute(
                "SELECT source_paths, destination_path, status, title, direction FROM transfer_sessions WHERE session_token=?",
                (target_token,)
            ).fetchone()
            if not row:
                return jsonify({"status": "error", "message": "Transfer session not found in history."})
            if row[2] not in ('paused', 'interrupted'):
                return jsonify({"status": "error", "message": f"Session is {row[2]} and cannot be resumed."})

            try:
                paths = json.loads(row[0] or '[]')
            except Exception:
                paths = []
            dest_dir = row[1] or ""
            title = row[3] or make_session_title(paths)
            direction = (row[4] or 'pull').lower()

        if direction == 'push':
            if start_push_session_on_server(target_token, paths, dest_dir, is_resume=True):
                return jsonify({"status": "success", "state": "active", "direction": "push", "session_token": target_token})
            return jsonify({"status": "error", "message": "Failed to resume PUSH transfer with client."})

        with db_lock:
            if dest_dir and os.path.isdir(dest_dir):
                SAVE_DIRECTORY = dest_dir
            srv_ip = (connected_client_info or {}).get("server_ip") or get_primary_local_ip()
            active_sessions.add(target_token)
            current_active_token = target_token
            set_meta('session_token', target_token)
            set_meta('target_paths', json.dumps(paths))
            set_meta('save_directory', SAVE_DIRECTORY)
            set_meta('transfer_state', 'active')
            history_conn.execute(
                "UPDATE transfer_sessions SET status='active', updated_at=? WHERE session_token=?",
                (time.time(), target_token)
            )

        if send_control_command({
            "action": "start_transfer",
            "direction": "pull",
            "paths": paths,
            "session_token": target_token,
            "session_title": title,
            "destination_path": SAVE_DIRECTORY,
            "server_hostname": LOCAL_HOSTNAME,
            "server_ip": srv_ip,
            "server_os": LOCAL_OS,
            "resume": True
        }):
            return jsonify({"status": "success", "state": "active", "direction": "pull", "session_token": target_token})
        return jsonify({"status": "error", "message": "Failed to send resume command to client."})

    return jsonify({"status": "error", "message": f"Unknown action: {cmd}"})


@app.route('/api/progress', methods=['GET'])
def get_progress():
    global current_active_token
    try:
        req_token = request.args.get('session_token') or current_active_token or get_meta('session_token')
        direction = 'pull'
        with db_lock:
            state = get_meta('transfer_state', 'idle')
            total_chunks = 0
            received_chunks = 0
            if req_token:
                s_row = history_conn.execute("""
                    SELECT status, direction, total_chunks, received_chunks
                    FROM transfer_sessions WHERE session_token=?
                """, (req_token,)).fetchone()
                if s_row:
                    state = s_row[0]
                    direction = (s_row[1] or 'pull').lower()
                    total_chunks = s_row[2] or 0
                    received_chunks = s_row[3] or 0
            pending_chunks = max(0, total_chunks - received_chunks)

            if state == 'active' and total_chunks > 0 and pending_chunks == 0:
                state = 'completed'
                set_meta('transfer_state', 'completed')
                if req_token:
                    sync_session_metrics(req_token, override_status='completed')
                finalize_db_wal()
            elif state == 'active' and not is_client_connected() and pending_chunks > 0:
                state = 'interrupted'
                set_meta('transfer_state', 'interrupted')
                if req_token:
                    sync_session_metrics(req_token, override_status='interrupted')
                finalize_db_wal()

            if req_token:
                cursor = db_conn.execute("""
                    SELECT f.relative_path,
                           (SELECT COUNT(*) FROM chunks c WHERE c.file_id = f.file_id),
                           (SELECT COUNT(*) FROM chunks c WHERE c.file_id = f.file_id AND c.status = 'received')
                    FROM files f
                    WHERE f.session_token = ?
                      AND f.size > 0 AND f.file_id IN (SELECT DISTINCT file_id FROM chunks WHERE status='pending')
                    LIMIT 4
                """, (req_token,))
            else:
                cursor = db_conn.execute("""
                    SELECT f.relative_path,
                           (SELECT COUNT(*) FROM chunks c WHERE c.file_id = f.file_id),
                           (SELECT COUNT(*) FROM chunks c WHERE c.file_id = f.file_id AND c.status = 'received')
                    FROM files f
                    WHERE f.file_id IN (SELECT DISTINCT file_id FROM chunks WHERE status='pending')
                    LIMIT 4
                """)
            active_files = [
                {"name": os.path.basename(r[0]), "relative_path": r[0], "total": r[1], "done": r[2]}
                for r in cursor.fetchall()
            ]

            if req_token:
                cursor = history_conn.execute(
                    "SELECT COUNT(*) FROM transfer_history_files WHERE session_token=? AND pre_existed=0 AND status IN ('completed', 'pending')",
                    (req_token,)
                )
            else:
                cursor = db_conn.execute("SELECT COUNT(*) FROM files WHERE pre_existed=0")
            rollback_eligible_count = cursor.fetchone()[0] or 0

        percent = (received_chunks / total_chunks * 100) if total_chunks > 0 else (100.0 if state == 'completed' else 0.0)
        can_resume = (state in ('paused', 'interrupted')) and (pending_chunks > 0)
        can_cancel = (state in ('active', 'paused', 'interrupted')) and (pending_chunks > 0)
        can_rollback = rollback_eligible_count > 0 and state in ('active', 'paused', 'interrupted', 'completed')

        return jsonify({
            "state": state,
            "direction": direction,
            "active_session_token": req_token or "",
            "server_hostname": LOCAL_HOSTNAME,
            "server_os": LOCAL_OS,
            "server_ips": get_local_ips(),
            "client_online": global_control_socket is not None,
            "connected_client": connected_client_info if global_control_socket is not None else None,
            "peer_seq": peer_connection_seq,
            "local_os": LOCAL_OS,
            "save_directory": SAVE_DIRECTORY,
            "remote_directory": REMOTE_ACTIVE_DIRECTORY,
            "percent": round(percent, 1),
            "total": total_chunks,
            "received": received_chunks,
            "active_files": active_files,
            "can_resume": can_resume,
            "can_cancel": can_cancel,
            "can_rollback": can_rollback,
            "rollback_files_count": rollback_eligible_count
        })
    except Exception as e:
        return jsonify({
            "state": "idle", "direction": "pull", "client_online": False, "percent": 0, "total": 0,
            "received": 0, "active_files": [], "can_resume": False,
            "can_cancel": False, "can_rollback": False, "error": str(e)
        })


def start_web_server():
    app.run(
        host=HOST,
        port=WEB_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
        request_handler=QuietWSGIRequestHandler
    )


# --- SOCKET FRAMING HELPERS ---
def recvall(sock, num_bytes):
    data = bytearray()
    while len(data) < num_bytes:
        try:
            packet = sock.recv(num_bytes - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def recv_json_line(sock, max_bytes=50 * 1024 * 1024):
    """Safely read a newline-delimited UTF-8 JSON line without splitting multi-byte characters."""
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
    return json.loads(buf.decode('utf-8').strip())


def handle_worker_stream(conn, worker_session_token):
    """Receive compressed chunks from client worker socket during a PULL (Client -> Server) transfer with O(1) DB updates."""
    global current_active_token
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    dctx = zstd.ZstdDecompressor() if HAS_ZSTD else None
    with worker_conn_lock:
        active_worker_connections.add(conn)
    try:
        while server_running:
            header = recvall(conn, 8)
            if not header:
                break

            meta_len, data_len = struct.unpack('!II', header)
            meta_bytes = recvall(conn, meta_len)
            if not meta_bytes:
                break
            meta = json.loads(meta_bytes.decode('utf-8'))

            compressed_payload = recvall(conn, data_len)
            if compressed_payload is None:
                break
            comp_type = meta.get("comp", "zstd")
            if comp_type == "zlib" or not HAS_ZSTD:
                raw_data = zlib.decompress(compressed_payload)
            else:
                raw_data = dctx.decompress(compressed_payload)
            file_id, chunk_index = meta["file_id"], meta["chunk_index"]

            with db_lock:
                row = db_conn.execute(
                    "SELECT session_token, relative_path, save_path, size, atime, mtime FROM files WHERE file_id=?",
                    (file_id,)
                ).fetchone()
                if not row:
                    break
                file_session_token, rel_path, saved_path, file_size, atime, mtime = (
                    row[0], row[1], row[2], row[3] or 0, row[4], row[5]
                )
                s_row = history_conn.execute(
                    "SELECT status, destination_path FROM transfer_sessions WHERE session_token=?",
                    (file_session_token,)
                ).fetchone()
                if s_row and s_row[0] not in ('active',):
                    break
                base_dir = s_row[1] if (s_row and s_row[1]) else SAVE_DIRECTORY
                final_path = saved_path if saved_path else resolve_local_save_path(base_dir, rel_path)

            flock = get_file_lock(file_id)
            with flock:
                if not os.path.exists(final_path):
                    break
                with open(final_path, 'r+b') as f:
                    f.seek(chunk_index * CHUNK_SIZE)
                    f.write(raw_data)

            all_done = False
            now_ts = time.time()
            with db_lock:
                upd = db_conn.execute(
                    "UPDATE chunks SET status='received' WHERE file_id=? AND chunk_index=? AND status!='received'",
                    (file_id, chunk_index)
                )
                chunk_newly_received = 1 if upd.rowcount > 0 else 0

                pending_count = db_conn.execute(
                    "SELECT COUNT(*) FROM chunks WHERE file_id=? AND status='pending'",
                    (file_id,)
                ).fetchone()[0]

                file_newly_completed = 0
                if pending_count == 0:
                    h_upd = history_conn.execute("""
                        UPDATE transfer_history_files
                        SET status = 'completed', transferred_at = ?
                        WHERE session_token = ? AND relative_path = ? AND status != 'completed'
                    """, (now_ts, file_session_token, rel_path))
                    file_newly_completed = 1 if h_upd.rowcount > 0 else 0

                # O(1) atomic counter increment on transfer_sessions (zero table scans!)
                history_conn.execute("""
                    UPDATE transfer_sessions
                    SET updated_at = ?,
                        received_chunks = received_chunks + ?,
                        completed_files = completed_files + ?,
                        transferred_bytes = transferred_bytes + ?
                    WHERE session_token = ?
                """, (
                    now_ts,
                    chunk_newly_received,
                    file_newly_completed,
                    file_size if file_newly_completed else 0,
                    file_session_token
                ))

                sc_row = history_conn.execute("""
                    SELECT completed_files, total_files, received_chunks, total_chunks
                    FROM transfer_sessions WHERE session_token = ?
                """, (file_session_token,)).fetchone()
                comp_f = sc_row[0] if sc_row else 0
                tot_f = sc_row[1] if sc_row else 0
                recv_c = sc_row[2] if sc_row else 0
                tot_c = sc_row[3] if sc_row else 0

                if tot_c > 0 and recv_c >= tot_c:
                    set_meta('transfer_state', 'completed')
                    comp_f, tot_f, recv_c, tot_c = sync_session_metrics(file_session_token, override_status='completed')
                    all_done = True

            if pending_count == 0:
                try:
                    os.utime(final_path, (atime, mtime))
                except Exception:
                    pass
                release_file_lock(file_id)
                if tot_f <= 100 or file_size >= 1024 * 1024 or comp_f % 50 == 0 or all_done:
                    with console_print_lock:
                        print(f"[*] ⬅ Completed PULL direct-write transfer ({comp_f}/{tot_f}): {rel_path}")

            if all_done:
                finalize_db_wal()
                with console_print_lock:
                    print(f"[*] PULL Session {file_session_token[:8]} completed! WAL checkpointed and cleaned up.")

            ack_payload = {
                "status": "ack",
                "file_completed": (pending_count == 0),
                "relative_path": rel_path,
                "file_size": file_size,
                "transferred_at": now_ts if pending_count == 0 else None,
                "completed_files": comp_f,
                "total_files": tot_f,
                "received_chunks": recv_c,
                "total_chunks": tot_c,
                "session_completed": all_done
            }
            conn.sendall((json.dumps(ack_payload) + "\n").encode('utf-8'))
    except Exception:
        pass
    finally:
        with worker_conn_lock:
            active_worker_connections.discard(conn)


def handle_client(conn, addr):
    global global_control_socket, connected_client_info, last_dir_result, current_active_token, peer_connection_seq
    try:
        conn.settimeout(15.0)
        payload = recv_json_line(conn)
        if not payload:
            return

        action = payload.get("action")
        client_id = payload.get("client_id")
        recv_pwd_hash = payload.get("password_hash", "")

        # 1. Persistent Control Channel from Client (Verified against Client-Configured Password Hash)
        if action == "control_auth":
            if not verify_client_password_hash(recv_pwd_hash, client_ip=addr[0], client_id=client_id):
                conn.sendall(b"auth_failed\n")
                print(f"[!] Control authentication failed from {addr[0]} (password mismatch).")
                return

            c_info, routed_srv_ip = promote_socket_to_control_channel(conn, addr[0], payload)
            auth_ack = {
                "status": "success",
                "server_hostname": LOCAL_HOSTNAME,
                "server_os": LOCAL_OS,
                "server_ip": routed_srv_ip
            }
            conn.sendall((json.dumps(auth_ack) + "\n").encode('utf-8'))
            run_server_control_reader(conn, addr[0])
            return

        # 2A. Data Worker Stream Channel for PULL (Client -> Server)
        if action == "worker_auth":
            tok = payload.get("session_token")
            if tok in active_sessions:
                conn.settimeout(30.0)
                conn.sendall(b"success\n")
                handle_worker_stream(conn, tok)
            return

        # 2B. Reverse Data Worker Stream Channel for PUSH (Server -> Client)
        if action == "push_worker_auth":
            tok = payload.get("session_token")
            if tok in active_sessions:
                conn.settimeout(30.0)
                conn.sendall(b"success\n")
                handle_push_worker_stream(conn, tok)
            return

        # 3. Client-initiated Cancel or Rollback
        if action == "cancel_transfer":
            perform_cancel(session_token=payload.get("session_token"), reason="Client requested cancel")
            return

        if action == "rollback_transfer":
            perform_rollback(payload.get("session_token"))
            return

        # 4. PULL Transfer Session Initialization & Manifest Sync
        if verify_client_password_hash(recv_pwd_hash, client_ip=addr[0], client_id=client_id):
            conn.settimeout(300.0)
            enable_db_wal()
            req_token = payload.get("session_token")
            routed_srv_ip = conn.getsockname()[0]
            if routed_srv_ip.startswith('127.') or routed_srv_ip == '0.0.0.0':
                routed_srv_ip = get_primary_local_ip()

            with db_lock:
                session_token = req_token or current_active_token or get_meta('session_token') or secrets.token_hex(16)
                active_sessions.add(session_token)
                current_active_token = session_token
                set_meta('session_token', session_token)
                set_meta('transfer_state', 'active')

            conn.sendall((json.dumps({
                "status": "success",
                "session_token": session_token,
                "server_hostname": LOCAL_HOSTNAME,
                "server_os": LOCAL_OS,
                "server_ip": routed_srv_ip,
                "server_has_zstd": HAS_ZSTD,
                "destination_path": SAVE_DIRECTORY
            }) + "\n").encode('utf-8'))

            manifest_payload = recv_json_line(conn)
            if manifest_payload and manifest_payload.get("session_token") in active_sessions:
                manifest_data = manifest_payload.get("manifest") or {}
                files = manifest_data.get("files", [])
                empty_dirs = manifest_data.get("dirs", [])
                token = manifest_payload.get("session_token")
                missing_map = {}
                already_completed_files = []
                now_ts = time.time()

                with db_lock:
                    db_conn.execute("BEGIN IMMEDIATE")
                    history_conn.execute("BEGIN IMMEDIATE")
                    sess_row = history_conn.execute(
                        "SELECT destination_path, title FROM transfer_sessions WHERE session_token=?", (token,)
                    ).fetchone()
                    base_save_dir = sess_row[0] if (sess_row and sess_row[0]) else SAVE_DIRECTORY
                    sess_title = sess_row[1] if (sess_row and sess_row[1]) else "Transfer Session"

                    c_id = (connected_client_info or {}).get("client_id") or payload.get("client_id") or ""
                    c_name = (connected_client_info or {}).get("hostname") or payload.get("hostname") or "Remote Client"
                    c_ip = (connected_client_info or {}).get("ip") or addr[0]
                    c_os = (connected_client_info or {}).get("os") or payload.get("os") or "unknown"

                    if not sess_row:
                        history_conn.execute("""
                            INSERT INTO transfer_sessions (
                                session_token, title, direction,
                                server_name, server_ip, server_os,
                                client_id, client_name, client_ip, client_os,
                                source_paths, destination_path, started_at, updated_at, status
                            ) VALUES (?, ?, 'pull', ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, 'active')
                        """, (
                            token, sess_title,
                            LOCAL_HOSTNAME, routed_srv_ip, LOCAL_OS,
                            c_id, c_name, c_ip, c_os,
                            base_save_dir, now_ts, now_ts
                        ))
                    else:
                        history_conn.execute("""
                            UPDATE transfer_sessions
                            SET direction = 'pull',
                                server_name = ?, server_ip = ?, server_os = ?,
                                client_id = COALESCE(NULLIF(?, ''), client_id),
                                client_name = COALESCE(NULLIF(?, ''), client_name),
                                client_ip = COALESCE(NULLIF(?, ''), client_ip),
                                client_os = COALESCE(NULLIF(?, ''), client_os)
                            WHERE session_token = ?
                        """, (LOCAL_HOSTNAME, routed_srv_ip, LOCAL_OS, c_id, c_name, c_ip, c_os, token))

                    for dir_info in empty_dirs:
                        norm_dir = normalize_rel_path(dir_info.get("relative_path", ""))
                        if not norm_dir:
                            continue
                        dir_save_path = resolve_local_save_path(base_save_dir, norm_dir)
                        dir_pre_existed = 1 if os.path.exists(dir_save_path) else 0
                        os.makedirs(dir_save_path, exist_ok=True)
                        try:
                            os.utime(dir_save_path, (dir_info.get("atime", now_ts), dir_info.get("mtime", now_ts)))
                        except Exception:
                            pass

                        dir_rel_display = norm_dir.rstrip('/') + '/'
                        history_conn.execute("""
                            INSERT INTO transfer_history_files (
                                session_token, file_id, relative_path, source_path, save_path, size,
                                mtime, atime, pre_existed, status, transferred_at
                            ) VALUES (?, 0, ?, ?, ?, 0, ?, ?, ?, 'completed', ?)
                            ON CONFLICT(session_token, relative_path) DO UPDATE SET
                                save_path = excluded.save_path,
                                status = 'completed',
                                transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
                        """, (
                            token, dir_rel_display, dir_info.get("source_path") or norm_dir,
                            dir_save_path, dir_info.get("mtime", now_ts), dir_info.get("atime", now_ts),
                            dir_pre_existed, now_ts
                        ))
                        print(f"[*] Created empty directory: {dir_rel_display}")

                    for file_info in files:
                        norm_rel = normalize_rel_path(file_info["relative_path"])
                        src_full_path = file_info.get("source_path") or norm_rel
                        final_path = resolve_local_save_path(base_save_dir, norm_rel)
                        os.makedirs(os.path.dirname(final_path), exist_ok=True)

                        cursor = db_conn.execute(
                            'SELECT file_id, save_path, pre_existed FROM files WHERE session_token=? AND relative_path=? AND size=?',
                            (token, norm_rel, file_info["size"])
                        )
                        existing = cursor.fetchone()
                        if existing:
                            file_id = existing[0]
                            if existing[1]:
                                final_path = existing[1]
                            pre_existed = existing[2]
                        else:
                            pre_existed = 1 if (os.path.exists(final_path) and os.path.getsize(final_path) == file_info["size"]) else 0
                            cursor = db_conn.execute(
                                """INSERT INTO files (session_token, relative_path, source_path, save_path, size, mtime, atime, pre_existed)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                (token, norm_rel, src_full_path, final_path, file_info["size"], file_info["mtime"], file_info["atime"], pre_existed)
                            )
                            file_id = cursor.lastrowid
                            if file_info["size"] == 0:
                                db_conn.execute(
                                    "INSERT INTO chunks (file_id, chunk_index, status) VALUES (?, 0, 'received')",
                                    (file_id,)
                                )
                            else:
                                total_chunks = max(1, math.ceil(file_info["size"] / CHUNK_SIZE))
                                for i in range(total_chunks):
                                    db_conn.execute(
                                        "INSERT INTO chunks (file_id, chunk_index, status) VALUES (?, ?, 'pending')",
                                        (file_id, i)
                                    )

                        if not os.path.exists(final_path):
                            with open(final_path, 'wb') as f:
                                if file_info["size"] > 0:
                                    f.truncate(file_info["size"])
                            if file_info["size"] == 0:
                                try:
                                    os.utime(final_path, (file_info["atime"], file_info["mtime"]))
                                except Exception:
                                    pass

                        cursor = db_conn.execute(
                            "SELECT chunk_index FROM chunks WHERE file_id=? AND status='pending'",
                            (file_id,)
                        )
                        missing_chunks = [row[0] for row in cursor.fetchall()]
                        file_status = 'completed' if len(missing_chunks) == 0 else 'pending'
                        file_done_ts = now_ts if file_status == 'completed' else None

                        history_conn.execute("""
                            INSERT INTO transfer_history_files (
                                session_token, file_id, relative_path, source_path, save_path, size,
                                mtime, atime, pre_existed, status, transferred_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(session_token, relative_path) DO UPDATE SET
                                file_id = excluded.file_id,
                                source_path = excluded.source_path,
                                save_path = excluded.save_path,
                                status = CASE WHEN transfer_history_files.status = 'completed' THEN 'completed' ELSE excluded.status END,
                                transferred_at = COALESCE(transfer_history_files.transferred_at, excluded.transferred_at)
                        """, (
                            token, file_id, norm_rel, src_full_path, final_path, file_info["size"],
                            file_info["mtime"], file_info["atime"], pre_existed, file_status, file_done_ts
                        ))

                        if missing_chunks:
                            missing_map[norm_rel] = {
                                "file_id": file_id,
                                "missing": missing_chunks,
                                "save_path": final_path
                            }
                        else:
                            already_completed_files.append(norm_rel)

                    cursor = db_conn.execute("""
                        SELECT COUNT(*) FROM chunks c
                        INNER JOIN files f ON c.file_id = f.file_id
                        WHERE f.session_token = ? AND c.status = 'pending'
                    """, (token,))
                    if (cursor.fetchone()[0] or 0) == 0:
                        set_meta('transfer_state', 'completed')
                        comp_f, tot_f, recv_c, tot_c = sync_session_metrics(token, override_status='completed')
                        db_conn.execute("COMMIT")
                        history_conn.execute("COMMIT")
                        finalize_db_wal()
                    else:
                        comp_f, tot_f, recv_c, tot_c = sync_session_metrics(token, override_status='active')
                        db_conn.execute("COMMIT")
                        history_conn.execute("COMMIT")

                conn.sendall((json.dumps({
                    "status": "manifest_processed",
                    "missing_map": missing_map,
                    "already_completed": already_completed_files,
                    "destination_path": base_save_dir,
                    "session_title": sess_title,
                    "server_hostname": LOCAL_HOSTNAME,
                    "server_ip": routed_srv_ip,
                    "server_os": LOCAL_OS,
                    "server_has_zstd": HAS_ZSTD,
                    "total_files": tot_f,
                    "completed_files": comp_f,
                    "total_chunks": tot_c,
                    "received_chunks": recv_c
                }) + "\n").encode('utf-8'))
        else:
            conn.sendall((json.dumps({"status": "auth_failed", "message": "Invalid password hash"}) + "\n").encode('utf-8'))
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ==============================================================================
# INTERACTIVE TERMINAL UI (TUI) STARTUP MENU & HISTORY VIEWER
# ==============================================================================
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


def clear_terminal():
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    else:
        os.system('cls' if LOCAL_OS == 'windows' else 'clear')


def read_single_key():
    """
    Cross-platform single-keypress reader for terminal navigation.
    Supports Arrow Keys (UP, DOWN, LEFT, RIGHT), PGUP, PGDN, ENTER, BACKSPACE, ESC, and letter keys
    on both Windows (msvcrt) and Linux / Android Termux (termios + tty).
    """
    if LOCAL_OS == 'windows':
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
    """Nano/less-style interactive terminal viewer for past transfer sessions and transferred files."""
    selected_idx = 0
    file_scroll_idx = 0
    viewing_session_token = None

    while True:
        term_cols, term_rows = shutil.get_terminal_size((110, 30))
        page_size = max(5, term_rows - 12)

        with db_lock:
            sessions = history_conn.execute("""
                SELECT session_token, title, direction,
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
            print(" ⚡ EFT v3.1 SERVER — TRANSFER HISTORY VIEWER (transfer_history.db)")
            print(border)

            if not sessions:
                print("\n   No transfer sessions recorded in transfer_history.db yet.\n")
                print(border)
                print(" Controls: [q / Esc / Enter] Return to Main Menu")
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
            header_fmt = f" {'#':<3} | {'DIR':<6} | {'STATUS':<11} | {'TITLE':<18} | {'FILES':<9} | {'DATA SIZE':<10} | {'CLIENT (NAME / IP / OS)':<25} | {'STARTED AT':<19}"
            print(header_fmt[:term_cols - 1])
            print("-" * min(term_cols - 1, 115))

            for idx in range(start_idx, end_idx):
                s = sessions[idx]
                marker = "▶" if idx == selected_idx else " "
                dir_str = "➡ PUSH" if (s[2] or 'pull').lower() == 'push' else "⬅ PULL"
                status_str = (s[21] or 'idle').upper()[:11]
                title_str = (s[1] or 'Session')[:18]
                files_str = f"{s[16] or 0}/{s[15] or 0}"
                size_str = format_bytes_human(s[17] or 0)
                c_peer = f"{s[7] or 'Client'} ({s[8] or '?'}) [{(s[9] or '?').upper()}]"[:25]
                started_str = format_ts_human(s[12])
                line = f"{marker}{idx + 1:<3} | {dir_str:<6} | {status_str:<11} | {title_str:<18} | {files_str:<9} | {size_str:<10} | {c_peer:<25} | {started_str:<19}"
                if idx == selected_idx:
                    print(f"\033[7m{line[:term_cols - 1]}\033[0m")
                else:
                    print(line[:term_cols - 1])

            s_cur = sessions[selected_idx]
            cur_dir = (s_cur[2] or 'pull').upper()
            flow_str = "Server ➔ Client (PUSH)" if cur_dir == 'PUSH' else "Client ➔ Server (PULL)"
            print("-" * min(term_cols - 1, 115))
            print(f" Selected Session ID : {s_cur[0]}  [{flow_str}]")
            print(f" Server Peer         : {s_cur[3] or LOCAL_HOSTNAME} ({s_cur[4] or get_primary_local_ip()}) [{(s_cur[5] or LOCAL_OS).upper()}]")
            print(f" Client Peer         : {s_cur[7] or 'Client'} ({s_cur[8] or 'N/A'}) [{(s_cur[9] or 'unknown').upper()}] | Dest: {s_cur[11] or SAVE_DIRECTORY}")
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
                    SELECT session_token, title, direction,
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

            dir_mode = (s_row[2] or 'pull').upper()
            flow_label = "SERVER ➔ CLIENT (PUSH)" if dir_mode == 'PUSH' else "CLIENT ➔ SERVER (PULL)"
            print(border)
            print(f" 📂 SESSION INSPECTOR: {s_row[1]}  [{flow_label} | {(s_row[21] or 'idle').upper()}]")
            print(border)
            print(f" Session Token  : {s_row[0]}")
            print(f" Server Host    : {s_row[3] or LOCAL_HOSTNAME} | IP: {s_row[4] or get_primary_local_ip()} | OS: {(s_row[5] or LOCAL_OS).upper()}")
            print(f" Client Device  : {s_row[7] or 'Remote'} | IP: {s_row[8] or 'N/A'} | OS: {(s_row[9] or 'unknown').upper()} | ID: {s_row[6] or 'N/A'}")
            print(f" Destination    : {s_row[11] or SAVE_DIRECTORY}")
            print(f" Started / Done : {format_ts_human(s_row[12])}  -->  {format_ts_human(s_row[14] or s_row[13])}")
            print(f" Progress       : {s_row[16] or 0}/{s_row[15] or 0} Files | {format_bytes_human(s_row[18] or 0)} / {format_bytes_human(s_row[17] or 0)} ({s_row[20] or 0}/{s_row[19] or 0} Chunks)")
            print("-" * min(term_cols - 1, 115))

            file_page_size = max(4, term_rows - 15)
            if not f_rows:
                print("\n   No file entries recorded for this session.\n")
            else:
                file_scroll_idx = max(0, min(file_scroll_idx, len(f_rows) - 1))
                f_start = (file_scroll_idx // file_page_size) * file_page_size
                f_end = min(len(f_rows), f_start + file_page_size)

                f_hdr = f" {'#':<4} | {'RELATIVE PATH':<44} | {'SIZE':<10} | {'STATUS':<11} | {'TRANSFERRED AT':<19}"
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
                if dir_mode == 'PUSH':
                    print(f" Server Source Path   : {cur_f[1] or cur_f[0]}")
                    print(f" Client Saved Path    : {cur_f[2]}")
                else:
                    print(f" Client Source Path   : {cur_f[1] or cur_f[0]}")
                    print(f" Server Saved Path    : {cur_f[2]}")

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


last_sigint_ts = 0.0


def handle_ctrl_c_interrupt():
    """
    Smart Ctrl+C handler:
    - If a client is connected:
        * If a transfer is actively running with pending chunks -> cancel partial files once.
        * If the transfer is already completed/idle/paused -> DO NOT overwrite status!
        * In both cases, disconnect the client immediately so the next Ctrl+C closes the server.
    - If no client is connected -> shut down the server cleanly.
    """
    global server_running, last_sigint_ts
    now = time.time()
    if now - last_sigint_ts < 0.8:
        return
    last_sigint_ts = now

    if is_client_connected():
        if has_active_incomplete_transfer(current_active_token):
            print("\n[!] Ctrl+C detected during active transfer -> Cancelling partial files & disconnecting client...")
            perform_cancel(
                session_token=current_active_token,
                reason="Ctrl+C on server during active transfer"
            )
        else:
            print("\n[*] Ctrl+C detected while client connected (no active transfer in progress) -> Disconnecting client...")
        disconnect_client_cleanly()
        print("[*] Client disconnected. Press Ctrl+C again to shut down the server.")
    else:
        print("\n[*] Ctrl+C detected with no client connected -> Shutting down server and cleaning up WAL files...")
        server_running = False


def ensure_os_network_and_av_readiness():
    """
    Cross-platform network & antivirus readiness helper:
    - Windows:
      1. Automatically switches any active 'Public' network profile to 'Private' via Set-NetConnectionProfile.
      2. Removes any pre-existing Windows Firewall 'Block' rules on python.exe (which override Allow rules!).
      3. Adds explicit Inbound Allow rules for TCP (8080, 8081), UDP (8082), and python.exe across all profiles.
    - Linux: Detects active UFW or firewalld and opens ports 8080-8084 if needed.
    - Android: Acquires termux-wake-lock if running inside Termux so Wi-Fi never sleeps mid-transfer.
    """
    if LOCAL_OS == 'windows':
        rule_name = "EFT_Server_v3_Inbound_Ready"
        py_exe = os.path.abspath(sys.executable)
        save_dir_clean = os.path.abspath(SAVE_DIRECTORY)

        needs_config = True
        try:
            chk_ps = (
                f'$r = Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue; '
                f'$pub = Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object {{ $_.NetworkCategory -eq "Public" }}; '
                f'$blk = Get-NetFirewallApplicationFilter -Program "{py_exe}" -ErrorAction SilentlyContinue | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $_.Action -eq "Block" }}; '
                f'if ($r -and (-not $pub) -and (-not $blk)) {{ Write-Output "READY" }}'
            )
            chk = subprocess.run(
                ["powershell", "-NoProfile", "-Command", chk_ps],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4.0
            )
            if "READY" in (chk.stdout or ""):
                needs_config = False
        except Exception:
            pass

        if needs_config:
            print("[*] Windows Network Security: Switching Public profile to Private & clearing Python firewall blocks...")
            ps_script = (
                "Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.NetworkCategory -eq 'Public' } | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue; "
                "Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'python' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
                f"Get-NetFirewallApplicationFilter -Program '{py_exe}' -ErrorAction SilentlyContinue | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $_.Action -eq 'Block' }} | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
                f"netsh advfirewall firewall delete rule name=\"{rule_name}\" >$null 2>&1; "
                f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=allow protocol=TCP localport={PORT},{WEB_PORT} profile=any enable=yes >$null 2>&1; "
                f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=allow protocol=UDP localport={DISCOVERY_UDP_PORT} profile=any enable=yes >$null 2>&1; "
                f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=allow program=\"{py_exe}\" profile=any enable=yes >$null 2>&1; "
                f"Add-MpPreference -ExclusionPath '{save_dir_clean}' -ErrorAction SilentlyContinue"
            )

            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False

            if is_admin:
                subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("[*] Windows Network Security: Wi-Fi set to Private, Block rules removed, and EFT ports opened.")
            else:
                print("[*] Windows Security: Please click 'Yes' on the UAC prompt to switch Wi-Fi to Private and unblock ports...")
                try:
                    ret = ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", "powershell.exe", f'-NoProfile -ExecutionPolicy Bypass -Command "{ps_script}"', None, 1
                    )
                    if int(ret) > 32:
                        time.sleep(2.2)
                        print("[*] Windows Network Security: Wi-Fi profile switched to Private and firewall rules applied.")
                    else:
                        print("[!] Windows Security: UAC declined. Incoming connections on Public Wi-Fi may time out.")
                except Exception as e:
                    print(f"[!] Windows Security auto-configuration skipped: {e}")

    elif LOCAL_OS == 'linux':
        try:
            if shutil.which("ufw"):
                ufw_st = subprocess.run("ufw status", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if "Status: active" in (ufw_st.stdout or "") and str(PORT) not in (ufw_st.stdout or ""):
                    print(f"[*] Linux UFW active: Opening EFT ports {PORT}:8084 (may prompt for sudo)...")
                    subprocess.run(f"sudo ufw allow {PORT}:8084/tcp && sudo ufw allow {PORT}:8084/udp", shell=True)
            elif shutil.which("firewall-cmd"):
                fw_st = subprocess.run("firewall-cmd --state", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if "running" in (fw_st.stdout or "").lower():
                    ports_chk = subprocess.run("firewall-cmd --list-ports", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if f"{PORT}/tcp" not in (ports_chk.stdout or ""):
                        print(f"[*] Linux firewalld active: Opening EFT ports {PORT}-8084...")
                        subprocess.run(f"sudo firewall-cmd --add-port={PORT}-8084/tcp --add-port={PORT}-8084/udp", shell=True)
        except Exception:
            pass

    elif LOCAL_OS == 'android':
        if shutil.which("termux-wake-lock"):
            try:
                subprocess.run("termux-wake-lock", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass


def start_server():
    global server_running
    server_running = True
    ensure_os_network_and_av_readiness()
    threading.Thread(target=start_web_server, daemon=True).start()
    threading.Thread(target=discovery_listener_loop, daemon=True).start()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(16)
    server_socket.settimeout(0.5)

    def sigint_handler(sig, frame):
        threading.Thread(target=handle_ctrl_c_interrupt, daemon=True).start()

    signal.signal(signal.SIGINT, sigint_handler)

    ips_str = ", ".join(get_local_ips())
    print("\n" + "=" * 78)
    print(f"[*] EFT Two-Way High-Speed Server v3.1 online ({LOCAL_OS.upper()} - {LOCAL_HOSTNAME})")
    print(f"[*] Server Local IPs : {ips_str}")
    print(f"[*] Socket Port      : {PORT} | Web UI: http://127.0.0.1:{WEB_PORT}")
    print(f"[*] Client curl URL  : curl http://{get_primary_local_ip()}:{WEB_PORT}/download/client.py -o client.py")
    print(f"[*] State DB         : {STATE_DB_PATH}")
    print(f"[*] History DB       : {HISTORY_DB_PATH}")
    print("=" * 78)
    send_udp_probe()

    try:
        while server_running:
            try:
                conn, addr = server_socket.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                handle_ctrl_c_interrupt()
            except OSError:
                break
    finally:
        server_running = False
        close_active_workers()
        try:
            server_socket.close()
        except Exception:
            pass
        close_db_cleanly()
        print("[*] Server stopped cleanly. SQLite WAL/SHM files removed for both State and History databases.")


def run_startup_menu():
    """Interactive numerical startup menu for EFT Server v3.1."""
    if "--no-menu" in sys.argv:
        start_server()
        return

    while True:
        print("\n" + "=" * 68)
        print(f" ⚡ EFFICIENT FILE TRANSFER (EFT) v3.1 — SERVER ({LOCAL_HOSTNAME} | {LOCAL_OS.upper()})")
        print("=" * 68)
        print("  1. Start EFT Server (Two-Way Engine + Web UI on port 8081)")
        print("  2. Read Old Transfer History (Arrow-Key Viewer)")
        print("  3. Exit")
        print("-" * 68)
        try:
            choice = input("Select an option [1-3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting EFT Server.")
            close_db_cleanly()
            break

        if choice in ('1', ''):
            start_server()
            break
        elif choice == '2':
            try:
                interactive_history_viewer()
            except KeyboardInterrupt:
                pass
        elif choice == '3':
            print("[*] Exiting EFT Server.")
            close_db_cleanly()
            break
        else:
            print("[!] Invalid selection. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    run_startup_menu()
