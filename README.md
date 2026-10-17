# 🛜 ⚡ Efficient File Transfer (EFT) — v3.1 (Two-Way Bi-Directional Engine)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Transport](https://img.shields.io/badge/Wi--Fi%20%2F%20LAN-Bi--Directional%20Multithreaded%20TCP%2FUDP-00A8E8.svg)](#)
[![Platform](https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20Android%20(Termux)-2ea44f.svg)](#)
[![Compression](https://img.shields.io/badge/Compression-Negotiated%20Zstandard%20%7C%20zlib-ff9800.svg)](#)

**Efficient File Transfer (EFT)** (paired with its web interface **Core Engine UI**) is a high-throughput, bi-directional (**Two-Way: `PULL` & `PUSH`**) multithreaded Wi-Fi/LAN file transfer engine built in Python. It is engineered from the ground up to bypass the severe protocol serialization and Queue Depth 1 (QD1) I/O bottlenecks of traditional USB Media Transfer Protocol (MTP), SMB, and standard OS file explorers.

By combining **5 MB direct-write disk pre-allocation**, a **bounded producer-consumer compression pipeline with automatic per-peer Zstandard/zlib negotiation**, **4x concurrent raw binary TCP socket streams**, **automated cross-platform firewall & wake-lock management**, and **transactional dual-SQLite WAL state tracking** on both peers, EFT saturates local Wi-Fi and Ethernet links in both directions (`Client ➔ Server` and `Server ➔ Client`) while keeping host NVMe/SSD utilization near idle.

---

## 📑 Table of Contents
1. [📊 Real-World Benchmark: Wi-Fi EFT vs. USB MTP](#-1-real-world-benchmark-wi-fi-eft-vs-usb-mtp)
2. [✨ Key Features (v3.1)](#-2-key-features-v31)
3. [📸 Visual Tour & Interface Gallery](#-3-visual-tour--interface-gallery)
4. [🚀 Step-by-Step Usage Guide (Server & Client)](#-4-step-by-step-usage-guide-server--client)
5. [🧠 Under the Hood: Bi-Directional Architecture (PULL & PUSH)](#-5-under-the-hood-bi-directional-architecture-pull--push)
6. [🛜 Network Port Topology & Auto-Firewall Readiness](#-6-network-port-topology--auto-firewall-readiness)
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
| **Host NVMe Active Time (as seen in Task Manager)** | 100% *(QD1 metadata lockup)* | **2% Disk Active Time** | **Zero Disk Thrashing** |

---

## ✨ 2. Key Features (v3.1)

1. **Full Bi-Directional (`⬅ PULL` & `➡ PUSH`) File Transfer** allows operators to select files or folders on the **Remote Client** and pull them into the **Local Server** (`⬅ Pull to Local`), or select files and folders on the **Local Server** and push them directly into the active folder on the **Remote Client** (`➡ Push to Remote`) with identical multithreaded speed, pre-allocation, and audit logging. Firewall-friendly reverse worker streams ensure that even during a `PUSH` transfer (`Server ➔ Client`), the client initiates outbound TCP worker connections (`push_worker_auth`) to the server's port `8080`, traversing strict client NATs and firewalls effortlessly.

2. **Zero-Config Multi-Subnet Discovery & Android 464XLAT Filtering** broadcasts lightweight UDP presence beacons (`eft_client_beacon`) and responds to server probes (`eft_server_probe`) across all local NICs. On Android devices where Mobile Data (`LTE+`/`5G` CLAT `192.0.0.4`) and Wi-Fi are simultaneously active, `client.py` automatically enumerates routing tables and `ip -4 addr` interfaces to prioritize true RFC1918 Wi-Fi LAN addresses (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`).

3. **Automated OS Firewall, Windows Public-to-Private & Termux Wake-Lock Readiness** configures host security automatically at startup. On **Windows**, EFT requests a one-time UAC elevation to automatically switch `Public` Wi-Fi profiles to `Private`, strip pre-existing `Block` rules on `python.exe`, whitelist ports `8080`–`8084` across all profiles, and add the transfer directory to Windows Defender exclusions so `MsMpEng.exe` never throttles high-speed disk writes. On **Linux**, EFT detects active `ufw` or `firewalld` services and opens ports `8080`–`8098`. On **Android (Termux)**, EFT automatically acquires `termux-wake-lock` on startup so Android Doze Mode never drops background sockets, and guarantees `termux-wake-unlock` on `Ctrl+C` or exit (`atexit`).

4. **Client-Controlled Password & SHA-256 Handshake** ensures security is governed by the remote device (`client.py`). At startup, the client user chooses **No Password (Open)** or sets a **Client Password**. The Server Web UI displays `🔒 Password Protected` or `🔓 Open (No Password)` badges and verifies the SHA-256 hash before establishing the control channel. Sequential multi-peer flexibility allows connecting to one client, transferring files, disconnecting, and switching to another client or server without stale sockets.

5. **Direct-Write Pre-Allocation & Per-Peer Compression Negotiation** pre-allocates target files on disk via `f.truncate(size)` on the receiving peer and writes incoming 5 MB chunks directly to their byte offsets (`chunk_index * CHUNK_SIZE`) under per-file mutex locks (`get_file_lock`), eliminating `.part` files and post-transfer reassembly. During the handshake, both peers advertise `has_zstd` capability and dynamically negotiate **`zstandard` (Level 3)** when supported by both ends, or seamlessly fall back to built-in **`zlib` (Level 1)** in mixed environments (such as a Windows server with `zstandard` pushing to a Linux client without `zstandard`).

6. **Symmetric Pause, Per-Session Resume, Partial Cancel & Atomic Rollback** work identically for both `PULL` and `PUSH` sessions. **Pause** halts active workers while keeping partial files and chunk bitmaps intact. **Resume** is scoped strictly to `paused` or `interrupted` sessions and streams only missing 5 MB chunks. **Cancel** stops an active transfer and deletes **only incomplete partial files** (and empty parent directories) on the receiving peer while keeping completed files intact. **Rollback** atomically undoes an entire transfer session on either the Server (`PULL`) or the Client (`PUSH`), deleting all files and empty folders created in that session while protecting any pre-existing files (`pre_existed=1`).

7. **Quadruple SQLite Databases & Automatic WAL Cleanup** maintain complete state and history symmetry across both peers: `transfer_state.db` and `transfer_history.db` on the Server, paired with `client_transfer_state.db` and `client_transfer_history.db` on the Client. All four databases run in high-concurrency `PRAGMA journal_mode=WAL` during active streaming and automatically execute `PRAGMA wal_checkpoint(TRUNCATE)` + `PRAGMA journal_mode=DELETE` upon completion, pause, cancel, rollback, or exit so `.db-wal` and `.db-shm` files immediately vanish.

---

## 📸 3. Visual Tour & Interface Gallery

### A. Zero-Config Client Discovery & Password Handshake
When the Web UI opens, it scans all local subnets for waiting clients without ever auto-connecting. Locked clients require password verification before the two-way control channel is established.

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

### D. Session History Inspector & Per-File Audit Log
Every session logs its transfer direction (`⬅ PULL` or `➡ PUSH`), full **Server Host** (`Name`, `IP`, `OS`) and **Client Device** (`Name`, `IP`, `OS`, `Client ID`) metadata, along with each file's relative path, source path, saved destination path, chunk progress, and completion timestamp.

![EFT v3.1 Session History Inspector and Per-File Audit Log](assets/screenshots/04-session-history-inspector.png)

![EFT Client v3.1 Session History Inspector and Per-File Audit Log](assets/screenshots/04-client-session-history-inspector.jpeg)

---

### E. Interactive Terminal UI (TUI) & Arrow-Key History Viewer
Both `server.py` and `client.py` include an interactive terminal startup menu and a keyboard-driven (`↑`/`↓`/`←`/`→`/`Enter`/`b`/`q`) history inspector displaying `⬅ PULL` and `➡ PUSH` session logs for headless or terminal workflows.

![EFT v3.1 Interactive Terminal Startup Menu and Nano-Style History Viewer](assets/screenshots/05-terminal-tui-viewer.png)

![EFT v3.1 Interactive Terminal Startup Menu Client](assets/screenshots/05-terminal-tui-client.jpeg)

---

## 🚀 4. Step-by-Step Usage Guide (Server & Client)

### Install Python on client and server
#### Python Installation Guide

Here are quick instructions to install Python on all major operating systems.

## 🪟 Windows
1. Go to the official Python website: [python.org/downloads](https://www.python.org/downloads/)
2. Click **Download Python** (it will auto-detect the latest version for Windows).
3. Run the downloaded `.exe` installer.
4. **CRITICAL STEP:** At the bottom of the installer window, check the box that says **"Add python.exe to PATH"**.
5. Click **Install Now** and wait for the setup to complete.

## 🍎 macOS
**Option A: Official Installer (Recommended for beginners)**
1. Go to [python.org/downloads/macos](https://www.python.org/downloads/macos/).
2. Download the latest macOS installer (`.pkg` file).
3. Run the installer and follow the on-screen instructions.

**Option B: Using Homebrew (Recommended for developers)**
1. Open the Terminal.
2. Run the following command:
   ```bash
   brew install python
   ```

## 🐧 Linux
Python 3 is usually pre-installed on most Linux distributions. To install or update it, use your distribution's package manager. Open your terminal and run:

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip
```

**Fedora:**
```bash
sudo dnf install python3 python3-pip
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip
```

## 🤖 Android (Termux)
Install Termux from PlayStore or official .apk
```bash
# If using Android Termux for the first time, grant storage access once:
termux-setup-storage

# Optional on Termux: install termux-api so EFT can auto-manage wake-locks:
pkg install termux-api

#install Python
pkg install python

```
---

## ✅ Verify Installation (All OS)
To confirm Python was installed successfully, open your Terminal or Command Prompt and run:
```bash
python --version
# OR
python3 --version
```
*(It should print something like `Python 3.x.x`)*

### Step 1: Install Dependencies
**Python 3.8+** is required on both ends. `server.py` requires `flask` (and optionally `zstandard` for maximum speed), while `client.py` runs out of the box using **only the Python Standard Library** (installing `zstandard` is optional and automatically negotiated per session).

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
In the interactive terminal startup menu, press **`1`** (or hit `Enter`) to **Start EFT Server** (or pass `python server.py --no-menu` to skip the menu in automated setups). On Windows, if your Wi-Fi is set to `Public` or has firewall blocks on Python, click **Yes** on the one-time UAC prompt so EFT can automatically switch the network profile to `Private` and open ports `8080`–`8082`. Open your browser to **`http://127.0.0.1:8081`** and note the **Server Local IPs** printed in the console (e.g., `10.110.233.3` or `192.168.1.10`).

---


### Step 3: Download & Start the Client (`client.py`)
On your remote device (e.g., **Android Termux**, another Windows PC, or a Linux machine connected to the same Wi-Fi/Hotspot/LAN):

#### Option A: Fetch `client.py` Directly Over Wi-Fi via `curl` (No USB Cable Needed!)

#### To Run `client.py`
```bash
#(Optional) download zstandard
pip install zstandard

# Download client.py directly from the running Server:
curl http://<SERVER_LAN_IP>:8081/download/client.py -o client.py

# Run the client:
python client.py
```

#### Option B: Run Local `client.py` Directly
```bash
python client.py
```
In the client terminal menu, select **`1`** (`Start EFT Client`). Next, choose your security mode by pressing **`1`** (or `Enter`) for **No Password (Open)** for immediate one-click connection from the Server Web UI, or pressing **`2`** to **Set a Client Password** so the Server Web UI operator must authenticate before connecting.

---

### Step 4: Connect & Transfer Files Bi-Directionally (`⬅ PULL` & `➡ PUSH`)
In the Server Web UI (`http://127.0.0.1:8081`), the **Client Discovery & Authentication** modal will display your waiting client automatically (or click **↻ Scan for Waiting Clients**). Click **Click to Connect** (or **🔑 Enter Password & Connect** if locked).

**To PULL Files (`Client ➔ Server`):** Navigate to your desired save folder in the **Right Pane (Local Host Server)**, check the files or folders you want in the **Left Pane (Remote Client Device)**, and click **`⬅ Pull to Local (N)`** in the top toolbar.

**To PUSH Files (`Server ➔ Client`):** Navigate to the target destination folder in the **Left Pane (Remote Client Device)**, check the local files or folders you want to send in the **Right Pane (Local Host Server)**, and click **`➡ Push to Remote (N)`** in the top toolbar.

**Watch Live Progress:** Both the Web UI progress bar and the Server/Client terminals will display real-time directional transfer logs:
```text
[2026-10-17 16:14:22] ⬅ Pulled DCIM/Camera/VID_01.mp4 (124.50 MB) [12/45 files | 64.2%] -> Server QuantaPixel-SDS (10.110.233.3)
[2026-10-17 16:18:05] ➡ Pushed Movies/movie_1080p.mkv (757.70 MB) [1/1 files | 100.0%] -> Client linux27 (10.110.233.53)
```

---

## 🧠 5. Under the Hood: Bi-Directional Architecture (`PULL` & `PUSH`)

### Mode A: `⬅ PULL` Pipeline (`Client ➔ Server`)
```text
CLIENT (Sender: Android / Linux / Windows)                SERVER (Receiver: Windows / Linux / Android)
==========================================                ============================================
1. Scan selected paths -> Build POSIX Manifest  ───────►  2. Check transfer_state.db for existing chunks
   (Files + Empty Dirs + Sizes + Timestamps)              3. Pre-allocate missing files via f.truncate(size)
                                                ◄───────  4. Return delta missing_map (only missing chunks)
5. Client Producer Thread:
   - Seek & read 5 MB missing chunks
   - Compress via Zstd (L3) or zlib (L1)
   - Push to bounded Queue(maxsize=20)
         │
         ├──► Worker 1 (TCP :8080 worker_auth)  ───────►  Decompress -> Lock(file_id) -> Seek & Write r+b
         ├──► Worker 2 (TCP :8080 worker_auth)  ───────►  Decompress -> Lock(file_id) -> Seek & Write r+b
         ├──► Worker 3 (TCP :8080 worker_auth)  ───────►  Decompress -> Lock(file_id) -> Seek & Write r+b
         └──► Worker 4 (TCP :8080 worker_auth)  ───────►  Decompress -> Lock(file_id) -> Seek & Write r+b
                                                                │
6. Update client_transfer_history.db & print    ◄───────  7. On final chunk: os.utime(atime, mtime),
   live console log upon Server JSON ACK                     update transfer_history.db, checkpoint WAL
```

### Mode B: `➡ PUSH` Pipeline (`Server ➔ Client` via Reverse Outbound Workers)
```text
SERVER (Sender: Windows / Linux / Android)                CLIENT (Receiver: Android / Linux / Windows)
==========================================                ============================================
1. Scan local paths -> Build POSIX Manifest     ───────►  2. Check client_transfer_state.db for chunks
   Send via control channel (start_push_transfer)         3. Pre-allocate missing files via f.truncate(size)
                                                ◄───────  4. Reply push_manifest_processed (missing_map + has_zstd)
5. Server Producer Thread:
   - Negotiate compression (Zstd if both support, else zlib)
   - Read & compress 5 MB missing chunks into push_work_queue
   - Signal start_push_workers over control channel
         │
         ◄─── Client Worker 1 connects outbound (TCP :8080 push_worker_auth)
         ├──► Stream [!II Frame] chunk          ───────►  Decompress -> Lock(file_id) -> Seek & Write r+b
         ◄─── Client Worker 2..4 (TCP :8080)    ───────►  Decompress -> Lock(file_id) -> Seek & Write r+b
                                                                │
6. Server updates transfer_state.db &           ◄───────  7. Client restores os.utime(atime, mtime), updates
   transfer_history.db upon Client JSON ACK                  client_transfer_history.db & sends JSON ACK
```

### Binary Wire Framing (`!II`)
Instead of slow text encoding, worker sockets stream raw binary packets prefixed with an 8-byte big-endian struct header:
```python
header = struct.pack('!II', len(meta_bytes), len(chunk_data))
worker_socket.sendall(header + meta_bytes + chunk_data)
```
Bytes `0..3` (`unsigned int`) specify the exact byte length of the UTF-8 JSON metadata (`{"file_id": 12, "chunk_index": 0, "comp": "zstd"}`), Bytes `4..7` (`unsigned int`) specify the exact byte length of the compressed chunk payload, and the payload immediately follows as `meta_bytes + chunk_data` (with `struct.pack('!II', 0, 0)` serving as the clean end-of-stream sentinel for `PUSH` workers).

---

## 🛜 6. Network Port Topology & Auto-Firewall Readiness

EFT automatically configures these ports at startup on Windows (`netsh` + PowerShell profile/rule cleanup) and Linux (`ufw` / `firewalld`):

| Port | Protocol | Bound By | Role & Description |
| :--- | :--- | :--- | :--- |
| **`8080`** | TCP | `server.py` | Core socket server for persistent JSON control channels (`control_auth`), manifest negotiation (`init_transfer`), `PULL` chunk workers (`worker_auth`), and `PUSH` chunk workers (`push_worker_auth`). |
| **`8081`** | HTTP / TCP | `server.py` | Flask Web UI server (`templates/index.html`), REST API endpoints, and `/download/client.py` distribution route. |
| **`8082`** | UDP | `server.py` | Server UDP discovery listener receiving `eft_client_beacon` broadcasts from waiting clients across all subnets. |
| **`8083`** | TCP | `client.py` | Client TCP invite listener (with automatic `+15` port scan fallback `8083`–`8098`) for instant Web UI click-to-connect handshakes. |
| **`8084`** | UDP | `client.py` | Client UDP probe listener for server broadcast scans (`eft_server_probe`) and UDP fallback invitations. |

---

## 🖥️ 7. Interactive Terminal UI (TUI) & Arrow-Key History Viewer

Both `server.py` and `client.py` feature a built-in terminal interface that works cross-platform on Windows (`msvcrt`) and Linux / Android Termux (`termios` + `tty`):

```text
====================================================================
 ⚡ EFFICIENT FILE TRANSFER (EFT) v3.1 — CLIENT (localhost | ANDROID)
====================================================================
  1. Start EFT Client (Configure Password / No Password & Wait for Server)
  2. Read Old Transfer History (Arrow-Key Viewer)
  3. Exit
--------------------------------------------------------------------
Select an option [1-3]:
```

When you select **`2. Read Old Transfer History`**, EFT launches a full-terminal interactive table showing `⬅ PULL` and `➡ PUSH` sessions. Use **`↑` / `↓` Arrow Keys** to move the selection highlight across past transfer sessions or individual transferred files, and **`←` / `→` or `PgUp` / `PgDn`** to jump across pages. Press **`Enter`** to open the **Session Inspector** for the highlighted session to view the transfer direction (`CLIENT ➔ SERVER (PULL)` or `SERVER ➔ CLIENT (PUSH)`), peer details, and every file's `relative_path`, `source_path`, `save_path`, size, status, and timestamp. Press **`b` / `Backspace` / `Esc`** to return from the File Inspector to the Sessions list, or **`q`** to exit back to the startup menu.

---

## ⚙️ 8. Scalability & Configuration Tuning

Developers can tune EFT's concurrency and chunking parameters at the top of `server.py` and `client.py` to match specific hardware profiles:

| Constant / Parameter | Default Value | Tuning Recommendation |
| :--- | :--- | :--- |
| `CHUNK_SIZE` | `5 * 1024 * 1024` (5 MB) | **Wi-Fi 5/6:** Keep at `5 MB`. **2.5GbE / 10GbE LAN:** Increase to `16 * 1024 * 1024` (16 MB). **Slow/Congested Wi-Fi:** Lower to `2 * 1024 * 1024` (2 MB). *(Must match on Server & Client).* |
| `work_queue` / `push_work_queue` | `20` chunks (~100 MB cap) | Controls the bounded memory buffer (`queue.Queue(maxsize=20)`). Increase to `40` on high-RAM desktops; lower to `8` on low-memory single-board computers. |
| Worker Thread Count | `4` concurrent sockets | Configured in `execute_transfer()` (`PULL`) and `start_client_push_workers()` (`PUSH`). Scale to `6` or `8` threads to saturate multi-gigabit links. |
| Compression Level | `zstd` Level `3` / `zlib` Level `1` | Dynamically negotiated per peer (`can_use_zstd`). Increase `zstd` to Level `6` for text/code datasets over slower Wi-Fi, or Level `1` when CPU-bound on older mobile SoCs. |

---

## 📂 9. Repository Structure

```text
EFT-File-Transfer-WiFi-Multi-threaded/
├── server.py                   # Bi-Directional Host Engine, PUSH Producer, Dual-SQLite WAL Manager, Auto-Firewall & Flask API
├── client.py                   # Bi-Directional Client Engine, PULL Producer, PUSH Receiver, Dual-SQLite WAL Manager & TUI Viewer
├── templates/
│   └── index.html              # Dual-Pane Two-Way Web UI (Pull & Push), Breadcrumb Explorer & Session Inspector
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
