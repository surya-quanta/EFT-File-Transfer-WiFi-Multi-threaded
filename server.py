import socket
import threading
import hashlib
import json
import secrets
import sqlite3
import os
import sys
import math
import struct
import time
import signal
import atexit
import platform
import shutil
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
import logging

# Suppress noisy Flask per-second polling logs in console
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

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
        # If no password was configured on the client and no pending hash was set, allow empty hash
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


# ==============================================================================
# DUAL SQLITE DATABASES:
# 1. transfer_state.db   -> Active chunk bitmaps & file locks
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

    # Safe schema migrations for existing v3 databases
    s_cols = [r[1] for r in hconn.execute("PRAGMA table_info(transfer_sessions)").fetchall()]
    for col_name, col_def in [
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

    # Backfill any empty server metadata on older rows
    default_srv_ip = get_primary_local_ip()
    hconn.execute("""
        UPDATE transfer_sessions
        SET server_name = COALESCE(NULLIF(server_name, ''), ?),
            server_ip   = COALESCE(NULLIF(server_ip, ''), ?),
            server_os   = COALESCE(NULLIF(server_os, ''), ?)
        WHERE server_name IS NULL OR server_name = ''
    """, (LOCAL_HOSTNAME, default_srv_ip, LOCAL_OS))

    # Mark any previously 'active' sessions that had pending chunks as 'interrupted' on startup
    hconn.execute("""
        UPDATE transfer_sessions
        SET status = 'interrupted', updated_at = ?
        WHERE status = 'active' AND received_chunks < total_chunks
    """, (time.time(),))

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


def close_active_workers():
    with worker_conn_lock:
        conns = list(active_worker_connections)
    for c in conns:
        try:
            c.close()
        except Exception:
            pass


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
    Cancel operation for a specific session (or active session):
    Stops transfer and removes ONLY partial (incomplete) files for that session.
    Completed files remain intact on disk and in history.
    """
    global current_active_token
    if not session_token:
        session_token = current_active_token or get_meta('session_token')

    print(f"[*] Executing Cancel ({reason}) for session {session_token}: removing only partial files...")
    send_control_command({"action": "cancel_transfer", "session_token": session_token})
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
            db_conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
            db_conn.execute("DELETE FROM files WHERE file_id=?", (file_id,))
            if session_token:
                history_conn.execute("""
                    UPDATE transfer_history_files
                    SET status='cancelled'
                    WHERE session_token=? AND relative_path=? AND status != 'completed'
                """, (session_token, rel_path))

        if session_token:
            sync_session_metrics(session_token, override_status='cancelled')
            if current_active_token == session_token:
                current_active_token = None
                set_meta('transfer_state', 'idle')
        else:
            set_meta('transfer_state', 'idle')

    finalize_db_wal()
    print(f"[*] Cancel complete. Removed {removed_count} partial file(s). Completed files were kept.")
    return removed_count


def perform_rollback(session_token=None):
    """
    Rollback operation for a specific transfer session:
    Stops transfer (if active) and removes ALL files transferred in that particular transfer session
    (both completed and partial files created in that session).
    """
    global current_active_token
    if not session_token:
        session_token = current_active_token or get_meta('session_token')

    print(f"[*] Executing Rollback for session {session_token}: removing all files from this transfer...")
    send_control_command({"action": "rollback_transfer", "session_token": session_token})
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
    print(f"[*] Rollback complete. Removed {removed_count} transferred file(s).")
    return removed_count


def perform_pause(session_token=None):
    """
    Pause operation:
    Halts active transfer while keeping partial files and chunk records intact for per-session resumption.
    """
    global current_active_token
    target_token = session_token or current_active_token or get_meta('session_token')
    print(f"[*] Pausing transfer session {target_token}...")
    send_control_command({"action": "pause_transfer", "session_token": target_token})
    close_active_workers()
    with db_lock:
        set_meta('transfer_state', 'paused')
        if target_token:
            sync_session_metrics(target_token, override_status='paused')
        current_active_token = None
    finalize_db_wal()


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
    """Broadcast a probe packet so any waiting clients immediately announce themselves."""
    probe = json.dumps({
        "type": "eft_server_probe",
        "server_hostname": LOCAL_HOSTNAME,
        "server_os": LOCAL_OS,
        "discovery_port": DISCOVERY_UDP_PORT
    }).encode('utf-8')
    for target_ip in ('255.255.255.255', '127.0.0.1'):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(0.2)
            s.sendto(probe, (target_ip, CLIENT_PROBE_UDP_PORT))
            s.close()
        except Exception:
            pass


def invite_waiting_client(client_ip, invite_port=DEFAULT_CLIENT_INVITE_PORT, udp_port=None, password_hash=""):
    """
    Invite a waiting client to connect to this server using the client-configured password hash.
    Returns (status_code, message) where status_code is 'ok', 'auth_failed', or 'unreachable'.
    """
    invite_payload = {
        "action": "connect_to_server",
        "server_port": PORT,
        "server_hostname": LOCAL_HOSTNAME,
        "server_os": LOCAL_OS,
        "server_ips": get_local_ips(),
        "password_hash": password_hash or ""
    }

    # 1. Try TCP Invite to the client's invite listener port first (gives immediate auth verification)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((client_ip, int(invite_port)))
        routed_server_ip = s.getsockname()[0]
        invite_payload["preferred_server_ip"] = routed_server_ip
        s.sendall((json.dumps(invite_payload) + "\n").encode('utf-8'))
        resp = s.recv(1024).decode('utf-8', errors='replace').strip()
        s.close()

        if "auth_failed" in resp or "rejected" in resp:
            return "auth_failed", "Incorrect password rejected by client."
        if "connecting" in resp or "success" in resp:
            return "ok", "Invitation accepted by client."
    except Exception:
        pass

    # 2. Fallback: Send UDP Invite to client's UDP port & probe port if TCP port was filtered
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
        time.sleep(0.15)

    now = time.time()
    active_list = []
    with waiting_clients_lock:
        expired = [k for k, v in waiting_clients.items() if now - v['last_seen'] > 12.0]
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

    # If we know this client requires a password and the user hasn't entered one yet, tell the UI to prompt
    if requires_password and not raw_password and not provided_hash:
        return jsonify({
            "status": "password_required",
            "requires_password": True,
            "message": "This client is password-protected. Please enter the client's password."
        })

    pwd_hash = provided_hash if provided_hash is not None else hash_password(raw_password)

    # Register expected password hash for the upcoming handshake
    with auth_state_lock:
        active_client_password_hash = pwd_hash
        pending_client_password_hashes[ip] = pwd_hash
        if client_id:
            pending_client_password_hashes[client_id] = pwd_hash

    # If switching from a previously connected client, disconnect the old control channel cleanly first
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

    if invite_status == "auth_failed":
        return jsonify({
            "status": "auth_error",
            "requires_password": True,
            "message": invite_msg
        })
    if invite_status == "unreachable":
        return jsonify({"status": "error", "message": invite_msg})

    # Wait up to 3.5 seconds for the invited client to complete its control_auth connection
    for _ in range(35):
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
    global last_dir_result
    if not is_client_connected() or global_control_socket is None:
        return jsonify({"status": "error", "message": "Remote client offline."})

    target_path = (request.json or {}).get('path', '')
    dir_result_event.clear()
    last_dir_result = None

    if not send_control_command({"action": "list_dir", "path": target_path}):
        return jsonify({"status": "error", "message": "Lost control connection to client."})

    if dir_result_event.wait(timeout=5.0) and last_dir_result is not None:
        return jsonify(last_dir_result)
    return jsonify({"status": "error", "message": "Timeout waiting for remote device response."})


@app.route('/api/sessions', methods=['GET'])
def api_get_sessions():
    """Return all transfer sessions stored in transfer_history.db with Server & Client identification."""
    with db_lock:
        rows = history_conn.execute("""
            SELECT session_token, title,
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
        total_c = r[18] or 0
        recv_c = r[19] or 0
        status = r[20] or 'idle'
        pct = round((recv_c / total_c * 100), 1) if total_c > 0 else (100.0 if status == 'completed' else 0.0)
        try:
            src_paths = json.loads(r[9] or '[]')
        except Exception:
            src_paths = []

        can_resume = status in ('paused', 'interrupted') and (total_c > 0 and recv_c < total_c)
        can_cancel = status in ('active', 'paused', 'interrupted') and (recv_c < total_c)
        can_rollback = status in ('active', 'paused', 'interrupted', 'completed', 'cancelled') and ((r[15] or 0) > 0 or recv_c > 0)

        sessions.append({
            "session_token": r[0],
            "title": r[1] or "Transfer Session",
            "server_name": r[2] or LOCAL_HOSTNAME,
            "server_ip": r[3] or default_srv_ip,
            "server_os": r[4] or LOCAL_OS,
            "client_id": r[5] or "",
            "client_name": r[6] or "Remote Device",
            "client_ip": r[7] or "",
            "client_os": r[8] or "",
            "source_paths": src_paths,
            "destination_path": r[10] or SAVE_DIRECTORY,
            "started_at": r[11],
            "updated_at": r[12],
            "completed_at": r[13],
            "total_files": r[14] or 0,
            "completed_files": r[15] or 0,
            "total_bytes": r[16] or 0,
            "transferred_bytes": r[17] or 0,
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
    """Return full metadata (Server + Client identification) and file history for a specific session."""
    with db_lock:
        r = history_conn.execute("""
            SELECT session_token, title,
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

        f_rows = history_conn.execute("""
            SELECT id, file_id, relative_path, source_path, save_path, size, mtime, status, transferred_at, pre_existed
            FROM transfer_history_files
            WHERE session_token = ?
            ORDER BY id ASC
        """, (session_token,)).fetchall()

        chunk_progress = {}
        for fid, tot, done in db_conn.execute("""
            SELECT file_id, COUNT(*), SUM(CASE WHEN status='received' THEN 1 ELSE 0 END)
            FROM chunks
            WHERE file_id IN (SELECT file_id FROM files WHERE session_token=?)
            GROUP BY file_id
        """, (session_token,)).fetchall():
            chunk_progress[fid] = (tot or 0, done or 0)

    default_srv_ip = get_primary_local_ip()
    total_c = r[18] or 0
    recv_c = r[19] or 0
    status = r[20] or 'idle'
    pct = round((recv_c / total_c * 100), 1) if total_c > 0 else (100.0 if status == 'completed' else 0.0)
    try:
        src_paths = json.loads(r[9] or '[]')
    except Exception:
        src_paths = []

    files_list = []
    for fr in f_rows:
        fid = fr[1]
        f_status = fr[7]
        tot_fc, done_fc = chunk_progress.get(fid, (1, 1 if f_status == 'completed' else 0))
        files_list.append({
            "id": fr[0],
            "file_id": fid,
            "relative_path": fr[2],
            "source_path": fr[3] or fr[2],
            "name": os.path.basename(fr[2]),
            "save_path": fr[4],
            "size": fr[5] or 0,
            "mtime": fr[6],
            "status": f_status,
            "transferred_at": fr[8],
            "pre_existed": bool(fr[9]),
            "chunks_total": tot_fc,
            "chunks_done": done_fc
        })

    can_resume = status in ('paused', 'interrupted') and (total_c > 0 and recv_c < total_c)
    can_cancel = status in ('active', 'paused', 'interrupted') and (recv_c < total_c)
    can_rollback = status in ('active', 'paused', 'interrupted', 'completed', 'cancelled') and any(
        f["status"] in ('completed', 'pending') and not f["pre_existed"] for f in files_list
    )

    session_obj = {
        "session_token": r[0],
        "title": r[1] or "Transfer Session",
        "server_name": r[2] or LOCAL_HOSTNAME,
        "server_ip": r[3] or default_srv_ip,
        "server_os": r[4] or LOCAL_OS,
        "client_id": r[5] or "",
        "client_name": r[6] or "Remote Device",
        "client_ip": r[7] or "",
        "client_os": r[8] or "",
        "source_paths": src_paths,
        "destination_path": r[10] or SAVE_DIRECTORY,
        "started_at": r[11],
        "updated_at": r[12],
        "completed_at": r[13],
        "total_files": r[14] or 0,
        "completed_files": r[15] or 0,
        "total_bytes": r[16] or 0,
        "transferred_bytes": r[17] or 0,
        "total_chunks": total_c,
        "received_chunks": recv_c,
        "percent": pct,
        "status": status,
        "can_resume": can_resume,
        "can_cancel": can_cancel,
        "can_rollback": can_rollback,
        "files": files_list
    }
    return jsonify({"status": "success", "session": session_obj})


@app.route('/api/action', methods=['POST'])
def api_action():
    global SAVE_DIRECTORY, current_active_token
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

    if cmd == "start_transfer":
        paths = data.get("paths", [])
        local_dest = data.get("dest_path", "").strip()
        if local_dest and local_dest != "DRIVES" and os.path.isdir(local_dest):
            SAVE_DIRECTORY = os.path.abspath(local_dest)
        if not paths:
            return jsonify({"status": "error", "message": "No source files or directories selected."})

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
                    session_token, title,
                    server_name, server_ip, server_os,
                    client_id, client_name, client_ip, client_os,
                    source_paths, destination_path, started_at, updated_at,
                    total_files, completed_files, total_bytes, transferred_bytes,
                    total_chunks, received_chunks, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 'active')
            """, (
                new_token, title,
                LOCAL_HOSTNAME, srv_ip, LOCAL_OS,
                c_id, c_name, c_ip, c_os,
                json.dumps(paths), SAVE_DIRECTORY, now, now
            ))

        if send_control_command({
            "action": "start_transfer",
            "paths": paths,
            "session_token": new_token,
            "session_title": title,
            "destination_path": SAVE_DIRECTORY,
            "server_hostname": LOCAL_HOSTNAME,
            "server_ip": srv_ip,
            "server_os": LOCAL_OS
        }):
            return jsonify({"status": "success", "state": "active", "session_token": new_token})
        return jsonify({"status": "error", "message": "Failed to send start command to client."})

    if cmd == "resume_transfer":
        target_token = req_token or get_meta('session_token')
        if not target_token:
            return jsonify({"status": "error", "message": "No session specified to resume."})

        with db_lock:
            row = history_conn.execute(
                "SELECT source_paths, destination_path, status, title FROM transfer_sessions WHERE session_token=?",
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
            dest_dir = row[1] or SAVE_DIRECTORY
            title = row[3] or make_session_title(paths)
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
            "paths": paths,
            "session_token": target_token,
            "session_title": title,
            "destination_path": SAVE_DIRECTORY,
            "server_hostname": LOCAL_HOSTNAME,
            "server_ip": srv_ip,
            "server_os": LOCAL_OS,
            "resume": True
        }):
            return jsonify({"status": "success", "state": "active", "session_token": target_token})
        return jsonify({"status": "error", "message": "Failed to send resume command to client."})

    return jsonify({"status": "error", "message": f"Unknown action: {cmd}"})


@app.route('/api/progress', methods=['GET'])
def get_progress():
    global current_active_token
    try:
        req_token = request.args.get('session_token') or current_active_token or get_meta('session_token')
        with db_lock:
            if req_token:
                cursor = db_conn.execute("""
                    SELECT COUNT(*), SUM(CASE WHEN c.status='received' THEN 1 ELSE 0 END)
                    FROM chunks c
                    INNER JOIN files f ON c.file_id = f.file_id
                    WHERE f.session_token = ?
                """, (req_token,))
            else:
                cursor = db_conn.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN status='received' THEN 1 ELSE 0 END) FROM chunks"
                )
            row = cursor.fetchone()
            total_chunks = row[0] or 0
            received_chunks = row[1] or 0
            pending_chunks = total_chunks - received_chunks

            state = get_meta('transfer_state', 'idle')
            if req_token:
                s_row = history_conn.execute(
                    "SELECT status FROM transfer_sessions WHERE session_token=?", (req_token,)
                ).fetchone()
                if s_row:
                    state = s_row[0]

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
                      AND f.file_id IN (SELECT DISTINCT file_id FROM chunks WHERE status='pending')
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
            "active_session_token": req_token or "",
            "server_hostname": LOCAL_HOSTNAME,
            "server_os": LOCAL_OS,
            "server_ips": get_local_ips(),
            "client_online": global_control_socket is not None,
            "connected_client": connected_client_info if global_control_socket is not None else None,
            "peer_seq": peer_connection_seq,
            "local_os": LOCAL_OS,
            "save_directory": SAVE_DIRECTORY,
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
            "state": "idle", "client_online": False, "percent": 0, "total": 0,
            "received": 0, "active_files": [], "can_resume": False,
            "can_cancel": False, "can_rollback": False, "error": str(e)
        })


def start_web_server():
    app.run(host=HOST, port=WEB_PORT, debug=False, use_reloader=False, threaded=True)


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
    global current_active_token
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
                cursor = db_conn.execute(
                    "SELECT session_token, relative_path, save_path, size FROM files WHERE file_id=?", (file_id,)
                )
                row = cursor.fetchone()
                if not row:
                    break
                file_session_token, rel_path, saved_path, file_size = row[0], row[1], row[2], row[3] or 0
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
                db_conn.execute(
                    "UPDATE chunks SET status='received' WHERE file_id=? AND chunk_index=?",
                    (file_id, chunk_index)
                )
                cursor = db_conn.execute(
                    "SELECT COUNT(*) FROM chunks WHERE file_id=? AND status='pending'",
                    (file_id,)
                )
                pending_count = cursor.fetchone()[0]
                if pending_count == 0:
                    cursor = db_conn.execute("SELECT atime, mtime FROM files WHERE file_id=?", (file_id,))
                    atime, mtime = cursor.fetchone()
                    history_conn.execute("""
                        UPDATE transfer_history_files
                        SET status = 'completed', transferred_at = ?
                        WHERE session_token = ? AND relative_path = ?
                    """, (now_ts, file_session_token, rel_path))

                cursor = db_conn.execute("""
                    SELECT COUNT(*) FROM chunks c
                    INNER JOIN files f ON c.file_id = f.file_id
                    WHERE f.session_token = ? AND c.status = 'pending'
                """, (file_session_token,))
                total_pending = cursor.fetchone()[0]
                if total_pending == 0:
                    set_meta('transfer_state', 'completed')
                    comp_f, tot_f, recv_c, tot_c = sync_session_metrics(file_session_token, override_status='completed')
                    all_done = True
                else:
                    comp_f, tot_f, recv_c, tot_c = sync_session_metrics(file_session_token)

            if pending_count == 0:
                try:
                    os.utime(final_path, (atime, mtime))
                except Exception:
                    pass
                release_file_lock(file_id)
                print(f"[*] Completed direct-write transfer: {rel_path}")

            if all_done:
                finalize_db_wal()
                print(f"[*] Session {file_session_token[:8]} completed! WAL checkpointed and cleaned up.")

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

            conn.settimeout(None)
            routed_srv_ip = conn.getsockname()[0]
            if routed_srv_ip.startswith('127.') or routed_srv_ip == '0.0.0.0':
                routed_srv_ip = get_primary_local_ip()

            c_info = {
                "client_id": client_id or f"{addr[0]}:{payload.get('invite_port', DEFAULT_CLIENT_INVITE_PORT)}",
                "hostname": payload.get("hostname") or "Remote-Client",
                "os": (payload.get("os") or "unknown").lower(),
                "ip": addr[0],
                "server_ip": routed_srv_ip,
                "invite_port": payload.get("invite_port", DEFAULT_CLIENT_INVITE_PORT),
                "requires_password": bool(recv_pwd_hash),
                "connected_at": time.time()
            }
            with control_socket_lock:
                if global_control_socket:
                    try:
                        global_control_socket.close()
                    except Exception:
                        pass
                global_control_socket = conn
                connected_client_info = c_info
                peer_connection_seq += 1

            auth_ack = {
                "status": "success",
                "server_hostname": LOCAL_HOSTNAME,
                "server_os": LOCAL_OS,
                "server_ip": routed_srv_ip
            }
            conn.sendall((json.dumps(auth_ack) + "\n").encode('utf-8'))
            print(f"[*] Client connected: {c_info['hostname']} ({addr[0]}) [OS: {c_info['os'].upper()}]")

            buffer = bytearray()
            while server_running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    buffer.extend(data)
                    while b'\n' in buffer:
                        nl = buffer.find(b'\n')
                        line_bytes = bytes(buffer[:nl]).strip()
                        del buffer[:nl + 1]
                        if line_bytes:
                            msg = json.loads(line_bytes.decode('utf-8'))
                            if msg.get("action") == "dir_result":
                                last_dir_result = msg
                                dir_result_event.set()
                            elif msg.get("action") == "transfer_interrupted":
                                tok = msg.get("session_token") or current_active_token
                                with db_lock:
                                    set_meta('transfer_state', 'interrupted')
                                    if tok:
                                        sync_session_metrics(tok, override_status='interrupted')
                                finalize_db_wal()
                except Exception:
                    break

            with control_socket_lock:
                if global_control_socket is conn:
                    global_control_socket = None
                    connected_client_info = None
            print(f"[*] Client control channel disconnected ({addr[0]}).")
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
            return

        # 2. Data Worker Stream Channel
        if action == "worker_auth":
            tok = payload.get("session_token")
            if tok in active_sessions:
                conn.settimeout(30.0)
                conn.sendall(b"success\n")
                handle_worker_stream(conn, tok)
            return

        # 3. Client-initiated Cancel or Rollback
        if action == "cancel_transfer":
            perform_cancel(session_token=payload.get("session_token"), reason="Client requested cancel")
            return

        if action == "rollback_transfer":
            perform_rollback(payload.get("session_token"))
            return

        # 4. Transfer Session Initialization & Manifest Sync
        if verify_client_password_hash(recv_pwd_hash, client_ip=addr[0], client_id=client_id):
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
                                session_token, title,
                                server_name, server_ip, server_os,
                                client_id, client_name, client_ip, client_os,
                                source_paths, destination_path, started_at, updated_at, status
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, 'active')
                        """, (
                            token, sess_title,
                            LOCAL_HOSTNAME, routed_srv_ip, LOCAL_OS,
                            c_id, c_name, c_ip, c_os,
                            base_save_dir, now_ts, now_ts
                        ))
                    else:
                        history_conn.execute("""
                            UPDATE transfer_sessions
                            SET server_name = ?, server_ip = ?, server_os = ?,
                                client_id = COALESCE(NULLIF(?, ''), client_id),
                                client_name = COALESCE(NULLIF(?, ''), client_name),
                                client_ip = COALESCE(NULLIF(?, ''), client_ip),
                                client_os = COALESCE(NULLIF(?, ''), client_os)
                            WHERE session_token = ?
                        """, (LOCAL_HOSTNAME, routed_srv_ip, LOCAL_OS, c_id, c_name, c_ip, c_os, token))

                    # Create and log any empty directories included in the manifest
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
                        finalize_db_wal()
                    else:
                        comp_f, tot_f, recv_c, tot_c = sync_session_metrics(token, override_status='active')

                conn.sendall((json.dumps({
                    "status": "manifest_processed",
                    "missing_map": missing_map,
                    "already_completed": already_completed_files,
                    "destination_path": base_save_dir,
                    "session_title": sess_title,
                    "server_hostname": LOCAL_HOSTNAME,
                    "server_ip": routed_srv_ip,
                    "server_os": LOCAL_OS,
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
# INTERACTIVE TERMINAL UI (TUI) STARTUP MENU & NANO-STYLE HISTORY VIEWER
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
    Cross-platform single-keypress reader for nano-style terminal navigation.
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
                # Check for escape sequence (arrow keys)
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
            print(" ⚡ EFT SERVER — NANO-STYLE TRANSFER HISTORY VIEWER (transfer_history.db)")
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
            header_fmt = f" {'#':<3} | {'STATUS':<11} | {'TITLE':<20} | {'FILES':<9} | {'DATA SIZE':<11} | {'CLIENT (NAME / IP / OS)':<28} | {'STARTED AT':<19}"
            print(header_fmt[:term_cols - 1])
            print("-" * min(term_cols - 1, 115))

            for idx in range(start_idx, end_idx):
                s = sessions[idx]
                marker = "▶" if idx == selected_idx else " "
                status_str = (s[20] or 'idle').upper()[:11]
                title_str = (s[1] or 'Session')[:20]
                files_str = f"{s[15] or 0}/{s[14] or 0}"
                size_str = format_bytes_human(s[16] or 0)
                c_peer = f"{s[6] or 'Client'} ({s[7] or '?'}) [{(s[8] or '?').upper()}]"[:28]
                started_str = format_ts_human(s[11])
                line = f"{marker}{idx + 1:<3} | {status_str:<11} | {title_str:<20} | {files_str:<9} | {size_str:<11} | {c_peer:<28} | {started_str:<19}"
                if idx == selected_idx:
                    print(f"\033[7m{line[:term_cols - 1]}\033[0m")
                else:
                    print(line[:term_cols - 1])

            s_cur = sessions[selected_idx]
            print("-" * min(term_cols - 1, 115))
            print(f" Selected Session ID : {s_cur[0]}")
            print(f" Server Peer         : {s_cur[2] or LOCAL_HOSTNAME} ({s_cur[3] or get_primary_local_ip()}) [{(s_cur[4] or LOCAL_OS).upper()}]")
            print(f" Client Peer         : {s_cur[6] or 'Client'} ({s_cur[7] or 'N/A'}) [{(s_cur[8] or 'unknown').upper()}] | Dest: {s_cur[10] or SAVE_DIRECTORY}")
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
            print(f" 📂 SESSION INSPECTOR: {s_row[1]}  [{(s_row[20] or 'idle').upper()}]")
            print(border)
            print(f" Session Token  : {s_row[0]}")
            print(f" Server Host    : {s_row[2] or LOCAL_HOSTNAME} | IP: {s_row[3] or get_primary_local_ip()} | OS: {(s_row[4] or LOCAL_OS).upper()}")
            print(f" Client Device  : {s_row[6] or 'Remote'} | IP: {s_row[7] or 'N/A'} | OS: {(s_row[8] or 'unknown').upper()} | ID: {s_row[5] or 'N/A'}")
            print(f" Destination    : {s_row[10] or SAVE_DIRECTORY}")
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


def start_server():
    global server_running
    server_running = True
    threading.Thread(target=start_web_server, daemon=True).start()
    threading.Thread(target=discovery_listener_loop, daemon=True).start()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(16)
    server_socket.settimeout(0.5)

    def sigint_handler(sig, frame):
        global server_running
        if is_client_connected():
            print("\n[!] Ctrl+C detected while client is connected -> Executing Cancel (stopping transfer & deleting partial files)...")
            threading.Thread(
                target=perform_cancel,
                kwargs={"session_token": current_active_token, "reason": "Ctrl+C on server while client connected"},
                daemon=True
            ).start()
        else:
            print("\n[*] Ctrl+C detected with no client connected -> Shutting down server and cleaning up WAL files...")
            server_running = False

    signal.signal(signal.SIGINT, sigint_handler)

    ips_str = ", ".join(get_local_ips())
    print("\n" + "=" * 78)
    print(f"[*] EFT High-Speed Server online ({LOCAL_OS.upper()} - {LOCAL_HOSTNAME})")
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
                if is_client_connected():
                    perform_cancel(session_token=current_active_token, reason="Ctrl+C on server while client connected")
                else:
                    server_running = False
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
    """Interactive numerical startup menu for EFT Server v4."""
    if "--no-menu" in sys.argv:
        start_server()
        return

    while True:
        print("\n" + "=" * 68)
        print(f" ⚡ EFFICIENT FILE TRANSFER (EFT) v4 — SERVER ({LOCAL_HOSTNAME} | {LOCAL_OS.upper()})")
        print("=" * 68)
        print("  1. Start EFT Server (Engine + Web UI on port 8081)")
        print("  2. Read Old Transfer History (Nano-Style Arrow-Key Viewer)")
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