# 🛜 ⚡ Efficient File Transfer (EFT) — v3.1 (Two-Way Bi-Directional Engine)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Transport](https://img.shields.io/badge/Wi--Fi%20%2F%20LAN-Bi--Directional%20Multithreaded%20TCP%2FUDP-00A8E8.svg)](#)
[![Platform](https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20Android%20(Termux)-2ea44f.svg)](#)
[![Compression](https://img.shields.io/badge/Compression-Negotiated%20Zstandard%20%7C%20zlib-ff9800.svg)](#)
[![Security](https://img.shields.io/badge/Auth-HMAC--SHA256%20%2B%20Localhost%20Guard-blueviolet.svg)](#)

**Efficient File Transfer (EFT)** (paired with its web interface **Core Engine UI**) is a high-throughput, bi-directional (**Two-Way: `PULL` & `PUSH`**) multithreaded Wi-Fi/LAN file transfer engine built in Python. It is engineered from the ground up to bypass the severe protocol serialization and Queue Depth 1 (QD1) I/O bottlenecks of traditional USB Media Transfer Protocol (MTP), SMB, and standard OS file explorers.

By combining **lazy on-demand 5 MB direct-write disk pre-allocation**, **per-file open handle caching**, a **multi-core worker compression pipeline with automatic per-peer Zstandard/zlib negotiation**, **4x concurrent raw binary TCP socket streams with bidirectional `:8080` / `:8083` routing**, **consent-driven firewall & wake-lock state snapshotting with automatic reversion on exit**, and **O(1) indexed quadruple-SQLite WAL tracking**, EFT saturates local Wi-Fi and Ethernet links in both directions (`Client ➔ Server` and `Server ➔ Client`) while keeping host NVMe/SSD utilization near idle.

---

## 📑 Table of Contents
1. [📊 Real-World Benchmark: Wi-Fi EFT vs. USB MTP](#-1-real-world-benchmark-wi-fi-eft-vs-usb-mtp)
2. [✨ Key Features & Security Architecture (v3.1)](#-2-key-features--security-architecture-v31)
3. [📸 Visual Tour & Interface Gallery](#-3-visual-tour--interface-gallery)
4. [🚀 Step-by-Step Usage Guide (Python Setup, Server & Client)](#-4-step-by-step-usage-guide-python-setup-server--client)
5. [🧠 Under the Hood: Bi-Directional Architecture (PULL & PUSH)](#-5-under-the-hood-bi-directional-architecture-pull--push)
6. [🛜 Network Port Topology & Auto-Reverting Firewall Readiness](#-6-network-port-topology--auto-reverting-firewall-readiness)
7. [🖥️ Interactive Terminal UI (TUI) & Arrow-Key History Viewer](#️-7-interactive-terminal-ui-tui--arrow-key-history-viewer)
8. [⚙️ Scalability & Configuration Tuning](#️-8-scalability--configuration-tuning)
9. [📂 Repository Structure](#-9-repository-structure)
10. [📜 License](#-10-license)

---

## 📊 1. Real-World Benchmark: Wi-Fi EFT vs. USB MTP

Tested transferring a massive mixed directory (thousands of small source files, nested folders, documents, and large media payloads) between an Android device (running Termux) and a Windows PC over **Wi-Fi**:

| Benchmark Metric | Traditional USB MTP / Explorer | 🛜 ⚡ EFT Engine v3.1 (Wi-Fi) | Engineering Gain |
| :--- | :--- | :--- | :--- |
| **Workload Dataset** | 10,735 Files across 77 Folders (~1MB each) | 10,735 Files across 77 Folders (~1MB each) | **Identical Workload** |
| **Total Data Volume** | 4.60 GB (`4,947,399,050` bytes) | 4.60 GB (`4,947,399,050` bytes) | **100% Byte Parity** |
| **Transfer Direction** | One-Way Copy (Stalls on metadata) | **Bi-Directional (`⬅ PULL` & `➡ PUSH`)** | **Full Two-Way Parity** |
| **Total Elapsed Time** | ~8.5 Hours *(Projected)* | **2 Minutes 00 Seconds** | **~255x Faster** |
| **Sustained Throughput** | < 1.5 Mbps *(Stalls on small files)* | **363 Mbps (~45.4 MB/s)** | **Wire-Speed Saturation** |
| **Host NVMe Active Time (Task Manager)** | 100% *(QD1 metadata lockup)* | **2% Disk Active Time** | **Zero Disk Thrashing** |

---

## ✨ 2. Key Features & Security Architecture (v3.1)

**Full Bi-Directional (`⬅ PULL` & `➡ PUSH`) File Transfer with Dual-Path Worker Routing** allows operators to select files or folders on the **Remote Client** and pull them into the **Local Server** (`⬅ Pull to Local`), or select files and folders on the **Local Server** and push them directly into the active folder on the **Remote Client** (`➡ Push to Remote`). When the Server connects to a waiting Client on port `8083`, EFT immediately upgrades that working TCP socket into the persistent Control Channel (`upgrade_socket`) and negotiates manifests directly over it. During transfers, worker threads connect outbound to `:8080` and automatically fall back to reverse Server-to-Client worker streams on `:8083` (`reverse_worker_connect`), guaranteeing 100% connectivity across strict NATs, Windows Firewalls, and Android Hotspots.

**Zero-Config Multi-Subnet Discovery, `/proc/net/fib_trie` & ARP Peer Scanning** broadcasts lightweight UDP presence beacons (`eft_client_beacon`) and responds to server probes (`eft_server_probe`) across all local NICs and ARP table peers (`/proc/net/arp` and `arp -a`). On Android 11+ devices where SELinux blocks `ip addr` in Termux and Mobile Data (`LTE+`/`5G` CLAT `192.0.0.4`) is active alongside Wi-Fi or Hotspot (`ap0`/`wlan0`), `client.py` reads `/proc/net/fib_trie` and binds outbound sockets directly to the matching Wi-Fi/Hotspot subnet IP so traffic is never misrouted over cellular data.

**Consent-Driven Firewall Readiness & Automatic State Reversion on Exit** prompts the operator in the terminal before making any OS firewall changes (`1. Accept`, `2. Reject & Continue`, `3. Exit`, or `--no-system-tuning`). When accepted on **Windows**, EFT snapshots the exact pre-existing state (which interfaces were `Public`, whether EFT rules existed, and which inbound `Block` rules on `python.exe` were active), applies temporary session rules via a transparent `.ps1` script (compatible with Windows Defender and third-party AVs like Avast), and **automatically reverts the firewall, re-enables any original `Block` rules, and restores `Public` network profiles the moment the Server or Client exits (`Ctrl+C` / `atexit`)**. On **Linux**, EFT opens and reverts `ufw` / `firewalld` ports `8080`–`8098`. On **Android (Termux)**, EFT acquires `termux-wake-lock` and releases it via `termux-wake-unlock` on exit.

**HMAC-SHA256 Challenge-Response Authentication & Localhost Web UI Guard** protects against packet sniffing and unauthorized LAN access. Each client generates a cryptographic 16-byte `auth_nonce` (`secrets.token_hex(16)`) in its beacon and handshake; the server authenticates using `HMAC-SHA256(password_hash, auth_nonce)` (`hmac.compare_digest`) so the raw password hash never crosses the wire during invitations. Furthermore, the Flask server on `:8081` enforces a `@app.before_request` guard (`restrict_webui_to_localhost`): `/download/client.py` remains accessible to LAN peers via `curl`, while the Web UI (`/`) and all control APIs (`/api/*`) are locked strictly to `127.0.0.1` / `::1` unless `--allow-remote-ui` is passed.

**Multi-Core Worker Compression, Lazy Pre-Allocation & Open File Handle Caching** maximizes both large-file and small-file throughput. The producer thread performs pure sequential disk reads (`raw_bytes`), while all **4 worker threads compress chunks in parallel** (`zstandard` Level 3 or `zlib` Level 1), releasing the Python GIL across 4 CPU cores simultaneously. On the receiving end, 0-byte files and empty folders are created during manifest sync while non-empty files are pre-allocated lazily via `f.truncate(size)` on their first chunk write. Active `r+b` file descriptors are cached in memory per `file_id` (`open_file_handles`) and closed only when `pending_count == 0` (right before `os.utime()`), eliminating thousands of redundant `open()`/`close()` syscalls and antivirus file-close hooks.

**Pre-Flight Disk Space Check (`ENOSPC`), Modified-File Resume Detection & Automatic Chunk Re-Queueing** guarantee 100% byte accuracy. Before streaming chunks, EFT checks `shutil.disk_usage(dest_dir).free` against `required_missing_bytes` and rejects transfers immediately with a clean `disk_full` error if free space is insufficient. During manifest scan, `is_regular_readable_file()` (`os.lstat` + `S_ISREG`) filters out broken symlinks, Wine loops, and Unix domain sockets (`SingletonSocket`). If a worker socket drops mid-chunk, the unacknowledged chunk is automatically re-queued so another live worker delivers it. And if a user pauses a transfer, edits a source file (`size` or `mtime` change), and clicks **Resume**, EFT detects the mismatch, invalidates stale chunks for that file, and re-streams it cleanly from chunk `0`.

**O(1) Indexed Quadruple SQLite Databases, Paginated Web UI History & Automatic WAL Cleanup** maintain full state and audit logs across four databases: `transfer_state.db` and `transfer_history.db` on the Server, plus `client_transfer_state.db` and `client_transfer_history.db` on the Client. Manifest insertions are wrapped in batched `BEGIN IMMEDIATE ... COMMIT` transactions, per-chunk progress updates use O(1) indexed primary-key increments, and the Web UI Session Inspector paginates file logs (`100` items per page with live search) so sessions with 10,000+ files render instantaneously. All four databases checkpoint and switch from `WAL` to `DELETE` mode on completion or exit so `.db-wal` and `.db-shm` files vanish immediately.

---

## 📸 3. Visual Tour & Interface Gallery

### A. Zero-Config Client Discovery & HMAC-SHA256 Password Handshake
When the Web UI opens, it scans all local subnets and ARP tables for waiting clients without ever auto-connecting. Locked clients require password verification before the two-way control channel is established.

![EFT v3.1 Client Discovery and Password Authentication Modal](assets/screenshots/01-discovery-modal.png)

---

### B. Modern Dual-Pane Two-Way File Explorer
Navigate both the **Remote Client Device** (`Android` / `Linux` / `Windows`) and **Local Host Server** side-by-side with clickable path breadcrumbs, instant file filtering, and batch selection checkboxes in **both panes** for `⬅ Pull to Local` and `➡ Push to Remote`.

![EFT v3.1 Modern Dual-Pane File Explorer and Breadcrumb Navigation](assets/screenshots/02-dual-pane-browser.png)

---

### C. High-Speed Bi-Directional Transfer in Action
Watch real-time chunk streaming progress across concurrent workers for both `⬅ PULL` and `➡ PUSH` sessions, with instant access to **Pause**, **Cancel (Partial)**, and **Rollback** controls.

![EFT v3.1 Real-Time Multithreaded Chunk Streaming Progress](assets/screenshots/03-active-transfer-progress.png)

---

### D. Paginated Session History Inspector & Per-File Audit Log
Every session logs its transfer direction (`⬅ PULL` or `➡ PUSH`), full **Server Host** (`Name`, `IP`, `OS`) and **Client Device** (`Name`, `IP`, `OS`, `Client ID`) metadata, along with paginated per-file logs (`100` files per page + live search filter) showing relative path, source path, saved destination path, chunk progress, and completion timestamp.

![EFT v3.1 Session History Inspector and Per-File Audit Log](assets/screenshots/04-session-history-inspector.png)

![EFT Client v3.1 Session History Inspector and Per-File Audit Log](assets/screenshots/04-client-session-history-inspector.jpeg)

---

### E. Interactive Terminal UI (TUI) & Arrow-Key History Viewer
Both `server.py` and `client.py` include an interactive terminal startup menu (with explicit firewall consent prompts) and a keyboard-driven (`↑`/`↓`/`←`/`→`/`Enter`/`b`/`q`) history inspector displaying `⬅ PULL` and `➡ PUSH` session logs for headless or terminal workflows.

![EFT v3.1 Interactive Terminal Startup Menu and Nano-Style History Viewer](assets/screenshots/05-terminal-tui-viewer.png)

![EFT v3.1 Interactive Terminal Startup Menu Client](assets/screenshots/05-terminal-tui-client.jpeg)

---

## 🚀 4. Step-by-Step Usage Guide (Python Setup, Server & Client)

### Prerequisite: Install Python 3.8+ on Server & Client

#### 🪟 Windows
Download the latest Windows installer (`.exe`) from [python.org/downloads](https://www.python.org/downloads/). Run the installer, **check the box at the bottom that says `"Add python.exe to PATH"`**, and click **Install Now**.

#### 🍎 macOS
Download the official macOS installer (`.pkg`) from [python.org/downloads/macos](https://www.python.org/downloads/macos/), or install via Homebrew in Terminal:
```bash
brew install python
```

#### 🐧 Linux
Python 3 is pre-installed on most Linux distributions. To install or update Python 3 and `pip`:
```bash
# Ubuntu / Debian:
sudo apt update && sudo apt install python3 python3-pip

# Fedora:
sudo dnf install python3 python3-pip

# Arch Linux:
sudo pacman -S python python-pip
```

#### 🤖 Android (Termux)
Install **Termux** (from F-Droid, GitHub Releases, or Play Store), then run:
```bash
# 1. Grant storage access once so Termux can read/write /storage/emulated/0:
termux-setup-storage

# 2. Update packages & install Python (plus optional termux-api for wake-lock support):
pkg update && pkg install python termux-api
```

#### ✅ Verify Python Installation (All OS)
```bash
python --version
# OR
python3 --version
```

---

### Step 1: Install Dependencies
`server.py` requires `flask` (and optionally `zstandard` for maximum speed). `client.py` runs out of the box using **only the Python Standard Library** (installing `zstandard` is optional and automatically negotiated per session).

```bash
# On the Server Host (Windows / Linux / macOS):
pip install flask zstandard

# On the Client Device (Optional — automatically negotiates built-in zlib if omitted):
pip install zstandard
```

---

### Step 2: Start the Server (`server.py`)
On the computer where you want to host the Web UI:
```bash
python server.py
```
In the interactive terminal startup menu, press **`1`** (or hit `Enter`) to **Start EFT Server**. Next, EFT displays the **OS Firewall & Network Profile Configuration** prompt:
- Press **`1`** (or `Enter`, Default) to **Accept & Configure Temporary Firewall Rules** (switches `Public` Wi-Fi to `Private`, opens ports `8080`–`8098` + Ping, and **automatically reverts everything back to original state on exit**).
- Press **`2`** to **Reject & Continue Without Modifying Firewall** (or pass `--no-system-tuning` on the CLI).
- Press **`3`** to **Exit**.

Open your browser on the Server machine to **`http://127.0.0.1:8081`** (or pass `python server.py --allow-remote-ui` if you want to open the Web UI from a remote browser on the LAN) and note the **Client curl URL** printed in the console.

---

### Step 3: Download & Start the Client (`client.py`)
On your remote device (**Android Termux**, another **Windows PC**, or a **Linux** machine on the same Wi-Fi/Hotspot/LAN):

#### Option A: Fetch `client.py` Directly Over Wi-Fi via `curl` (No USB Cable Needed!)
```bash
# Download client.py directly from the running Server (be sure to include :8081):
curl http://<SERVER_LAN_IP>:8081/download/client.py -o client.py

# Run the client:
python client.py
```

#### Option B: Run Local `client.py` Directly
```bash
python client.py
```
In the client terminal menu, select **`1`** (`Start EFT Client`). On Windows or Linux clients, choose **`1`** (Accept temporary firewall rules, auto-reverted on exit) or **`2`** (Reject & Continue) at the firewall prompt. Next, choose your **Client Security Mode** by pressing **`1`** (or `Enter`) for **No Password (Open)** or **`2`** to **Set a Client Password** (protected via `HMAC-SHA256` challenge-response).

---

### Step 4: Connect & Transfer Files Bi-Directionally (`⬅ PULL` & `➡ PUSH`)
In the Server Web UI (`http://127.0.0.1:8081`), the **Client Discovery & Authentication** modal will display all waiting clients on your network (or click **↻ Scan for Waiting Clients**). Click **Click to Connect** (or **🔑 Enter Password & Connect** if locked).

**To PULL Files (`Client ➔ Server`):** Navigate to your desired save folder in the **Right Pane (Local Host Server)**, check the files or folders you want in the **Left Pane (Remote Client Device)**, and click **`⬅ Pull to Local (N)`** in the top toolbar.

**To PUSH Files (`Server ➔ Client`):** Navigate to the target destination folder in the **Left Pane (Remote Client Device)**, check the local files or folders you want to send in the **Right Pane (Local Host Server)**, and click **`➡ Push to Remote (N)`** in the top toolbar.

**Watch Live Progress:** Both the Web UI progress bar and the Server/Client terminals will display real-time directional transfer logs:
```text
[2026-10-18 21:04:12] ⬅ Pulled DCIM/Camera/VID_01.mp4 (124.50 MB) [12/45 files | 64.2%] -> Server QuantaPixel-SDS (10.211.79.3)
[2026-10-18 21:05:40] ➡ Pushed Movies/movie_1080p.mkv (757.70 MB) [1/1 files | 100.0%] -> Client linux27 (10.211.79.127)
```

---

## 🧠 5. Under the Hood: Bi-Directional Architecture (`PULL` & `PUSH`)

### Mode A: `⬅ PULL` Pipeline (`Client ➔ Server`)
```text
CLIENT (Sender: Android / Linux / Windows)                SERVER (Receiver: Windows / Linux / Android)
==========================================                ============================================
1. Scan selected paths (skip symlinks/sockets)  ───────►  2. Verify free disk space (shutil.disk_usage)
   Send init_transfer over Control Channel                3. Check transfer_state.db (invalidate if mtime/size changed)
                                                ◄───────  4. Return delta missing_map + server_has_zstd
5. Client Producer Thread:
   - Read raw 5 MB missing chunks sequentially
   - Push raw_bytes to bounded Queue(maxsize=20)
         │
         ├──► Worker 1..4 (Parallel Zstd/zlib Compress) ──►  Decompress -> Lock(file_id) -> Cached r+b Handle Write
         │    (Outbound :8080 or Reverse :8083)              O(1) SQLite chunk update; re-queue on socket drop
                                                                │
6. O(1) update on client_transfer_history.db    ◄───────  7. On final chunk: close handle, os.utime(atime, mtime),
   upon Server JSON ACK                                      checkpoint WAL -> DELETE mode
```

### Mode B: `➡ PUSH` Pipeline (`Server ➔ Client`)
```text
SERVER (Sender: Windows / Linux / Android)                CLIENT (Receiver: Android / Linux / Windows)
==========================================                ============================================
1. Scan local paths (skip symlinks/sockets)     ───────►  2. Verify free disk space (shutil.disk_usage)
   Send start_push_transfer over Control Channel          3. Check client_transfer_state.db (detect mtime/size changes)
                                                ◄───────  4. Reply push_manifest_processed (missing_map + has_zstd)
5. Server Producer Thread:
   - Read raw 5 MB missing chunks into push_work_queue
   - Signal start_push_workers & spawn fallback :8083 workers
         │
         ◄─── Client Worker 1..4 (:8080) or Server->Client (:8083)
         ├──► Worker 1..4 (Parallel Zstd/zlib Compress) ──►  Decompress -> Lock(file_id) -> Cached r+b Handle Write
                                                                │
6. Server updates transfer_state.db &           ◄───────  7. On final chunk: close handle, os.utime(atime, mtime),
   transfer_history.db upon Client JSON ACK                  checkpoint WAL -> DELETE mode & send JSON ACK
```

### Binary Wire Framing (`!II`)
Instead of slow text encoding, worker sockets stream raw binary packets prefixed with an 8-byte big-endian struct header:
```python
header = struct.pack('!II', len(meta_bytes), len(chunk_data))
worker_socket.sendall(header + meta_bytes + chunk_data)
```
Bytes `0..3` (`unsigned int`) specify the exact byte length of the UTF-8 JSON metadata (`{"file_id": 12, "chunk_index": 0, "comp": "zstd"}`), Bytes `4..7` (`unsigned int`) specify the exact byte length of the compressed chunk payload, and the payload immediately follows as `meta_bytes + chunk_data` (with `struct.pack('!II', 0, 0)` serving as the clean end-of-stream sentinel for `PUSH` workers).

---

## 🛜 6. Network Port Topology & Auto-Reverting Firewall Readiness

When the operator accepts firewall configuration at startup, EFT snapshots the pre-existing OS state, opens these ports for the active session, and **automatically reverts all firewall and network profile changes on exit**:

| Port | Protocol | Bound By | Role & Description |
| :--- | :--- | :--- | :--- |
| **`8080`** | TCP | `server.py` | Core socket server for control channels (`control_auth`), manifest negotiation (`init_transfer`), `PULL` chunk workers (`worker_auth`), and `PUSH` chunk workers (`push_worker_auth`). |
| **`8081`** | HTTP / TCP | `server.py` | Flask Web UI server (`127.0.0.1` localhost-guarded by default; pass `--allow-remote-ui` for LAN UI access) and `/download/client.py` distribution route (open to LAN `curl`). |
| **`8082`** | UDP | `server.py` | Server UDP discovery listener receiving `eft_client_beacon` broadcasts from waiting clients across all subnets. |
| **`8083`–`8098`** | TCP | `client.py` | Client TCP invite listener (`8083` with automatic `+15` port scan fallback) for direct socket-upgraded control channels (`upgrade_socket`) and reverse Server-to-Client worker streams (`reverse_worker_connect`). |
| **`8084`** | UDP | `client.py` | Client UDP probe listener for server broadcast/ARP scans (`eft_server_probe`) and UDP fallback invitations. |

---

## 🖥️ 7. Interactive Terminal UI (TUI) & Arrow-Key History Viewer

Both `server.py` and `client.py` feature a built-in terminal interface that works cross-platform on Windows (`msvcrt`) and Linux / Android Termux (`termios` + `tty`):

```text
====================================================================
 ⚡ EFFICIENT FILE TRANSFER (EFT) v3.1 — SERVER (QuantaPixel-SDS | WINDOWS)
====================================================================
  1. Start EFT Server (Two-Way Engine + Web UI on port 8081)
  2. Read Old Transfer History (Arrow-Key Viewer)
  3. Exit
--------------------------------------------------------------------
Select an option [1-3]:
```

When you select **`2. Read Old Transfer History`**, EFT launches a full-terminal interactive table showing `⬅ PULL` and `➡ PUSH` sessions. Use **`↑` / `↓` Arrow Keys** to move the selection highlight across past transfer sessions or individual transferred files, and **`←` / `→` or `PgUp` / `PgDn`** to jump across pages. Press **`Enter`** to open the **Session Inspector** for the highlighted session to view the transfer direction (`CLIENT ➔ SERVER (PULL)` or `SERVER ➔ CLIENT (PUSH)`), peer details, and every file's `relative_path`, `source_path`, `save_path`, size, status, and timestamp. Press **`b` / `Backspace` / `Esc`** to return from the File Inspector to the Sessions list, or **`q`** to exit back to the startup menu.

---

## ⚙️ 8. Scalability & Configuration Tuning

Developers and system administrators can tune EFT's CLI flags and concurrency constants at the top of `server.py` and `client.py`:

| Parameter / CLI Flag | Default Value | Description & Tuning Recommendation |
| :--- | :--- | :--- |
| `--no-menu` | Disabled | Skip the interactive startup menu and launch the Server/Client immediately using default settings. |
| `--no-system-tuning` | Disabled | Skip all OS firewall and network profile modifications on startup. |
| `--allow-remote-ui` | Disabled (`127.0.0.1` only) | Allow LAN devices to open the Flask Web UI (`:8081`) in a remote browser (by default, only `/download/client.py` is exposed to LAN peers). |
| `CHUNK_SIZE` | `5 * 1024 * 1024` (5 MB) | **Wi-Fi 5/6:** Keep at `5 MB`. **2.5GbE / 10GbE LAN:** Increase to `16 * 1024 * 1024` (16 MB). *(Must match on Server & Client).* |
| `work_queue` / `push_work_queue` | `20` chunks (~100 MB cap) | Controls the bounded memory buffer (`queue.Queue(maxsize=20)`). Increase to `40` on high-RAM desktops; lower to `8` on low-memory SBCs. |
| Worker Thread Count | `4` concurrent sockets | Configured in `execute_transfer()` (`PULL`) and `start_client_push_workers()` (`PUSH`). Each worker compresses/decompresses in parallel across CPU cores. |
| Compression Level | `zstd` Level `3` / `zlib` Level `1` | Dynamically negotiated per peer (`can_use_zstd`). Increase `zstd` to Level `6` for text/code datasets over slower Wi-Fi, or Level `1` on older mobile SoCs. |

---

## 📂 9. Repository Structure

```text
EFT-File-Transfer-WiFi-Multi-threaded/
├── server.py                   # Bi-Directional Host Engine, Parallel Worker Compressor, Auto-Reverting Firewall & Flask API
├── client.py                   # Bi-Directional Client Engine, Parallel Worker Compressor, Dual-SQLite WAL Manager & TUI Viewer
├── templates/
│   └── index.html              # Dual-Pane Two-Way Web UI (Pull & Push), Breadcrumb Explorer & Paginated Session Inspector
├── assets/
│   └── screenshots/            # UI & Terminal screenshots for documentation
├── LICENSE                     # Apache License 2.0
└── README.md                   # Architecture, Benchmark & Usage Documentation
```

---

## 📜 10. License

Copyright © 2026 Surya Pratap Singh.

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this project except in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
