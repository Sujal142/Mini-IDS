# Mini Network Intrusion Detection System (IDS)

An educational, lightweight, and modular Network Intrusion Detection System (NIDS) designed for B.Tech Computer Engineering students, defensive cybersecurity labs, and network security enthusiasts.

---

## 🌟 Key Highlights

- **Dual Monitoring Modes:**
  - **Live Sniffer Mode:** Captures real Ethernet and Wi-Fi packets using Scapy and Npcap/libpcap.
  - **Safe Simulation Mode:** Generates realistic traffic and targeted attack vectors without needing administrative or root privileges.
- **Rule-Based Stateful Detection:**
  - **Rule 1:** Port Scan Detection (configurable unique port threshold per time window).
  - **Rule 2:** Excessive Request Burst / DoS-like traffic flood detection.
  - **Rule 3:** Unusual & Malformed Packets (TCP Xmas scan, Null scan, SYN+FIN illegal states).
  - **Rule 4:** Repeated Connection Attempts (SYN probing pattern).
  - **Alert Deduplication:** Prevents database flooding during high-speed traffic bursts.
- **Educational Machine Learning Component:**
  - Flow anomaly classification using Scikit-learn (RandomForestClassifier).
  - Includes dataset generator, train/test split (no data leakage), confusion matrix, and confidence scoring.
- **Modern Dark SOC Web Dashboard:**
  - Built with Flask, HTML5, CSS3, JavaScript, and Chart.js.
  - Real-time packet inspection table, alert feed, protocol charts, and CSV export.
- **Wireshark Verification Ready:**
  - Compare packet summaries directly against Wireshark packet captures.

---

## 📁 Project Structure

```
mini-network-ids/
│
├── app.py                     # Main Flask web application & REST API
├── config.py                  # Configurable thresholds, time windows, and paths
├── requirements.txt           # Python dependency specifications
├── README.md                  # Comprehensive installation & setup guide
│
├── detector/                  # Core Detection Engine
│   ├── __init__.py
│   ├── packet_capture.py      # Scapy live sniffer & simulated packet generator
│   ├── rules.py               # 4-tier stateful detection rules & deduplication
│   ├── traffic_analyzer.py    # Pipeline coordinating capture, rules, and DB
│   └── ml_detector.py         # Optional ML flow classifier & evaluation metrics
│
├── database/                  # Data Persistence Layer
│   ├── __init__.py
│   └── storage.py             # SQLite manager & CSV alert exporter
│
├── scripts/                   # CLI Testing & Utility Scripts
│   ├── generate_demo_data.py  # Seed database with sample packets and attacks
│   ├── train_model.py         # Train ML classifier and generate metrics
│   └── test_detector.py       # Automated detection rule test suite
│
├── templates/
│   └── index.html             # High-tech SOC dashboard web UI
│
├── static/
│   ├── css/style.css          # Dark cybersecurity UI theme
│   └── js/dashboard.js        # Real-time polling, Chart.js graphs, & controls
│
├── data/                      # Persistent SQLite DB & Model artifacts
│   ├── .gitkeep
│   ├── ids_alerts.db          # Auto-created SQLite database
│   └── model_metrics.json     # Saved ML performance metrics
│
├── tests/                     # Unit Tests
│   ├── __init__.py
│   ├── test_rules.py          # Unit tests for detection rules
│   └── test_storage.py        # Unit tests for SQLite storage & CSV export
│
└── docs/                      # Academic Submission Materials
    ├── project_report.md      # Full 20-section B.Tech mini-project report
    └── viva_questions.md      # 25+ detailed viva questions & answers
```

---

## 🚀 Beginner-Friendly Installation Guide

### Step 1: Check Python Installation
Open **Command Prompt (cmd)** on Windows or **Terminal** on Linux/macOS:
```bash
python --version
# Output should be Python 3.8.x, 3.10.x, 3.11.x, or 3.12.x
```

### Step 2: Navigate to Project Directory
```bash
cd mini-network-ids
```

### Step 3: Create and Activate a Virtual Environment

**On Windows (Command Prompt / PowerShell):**
```cmd
python -m venv venv
venv\Scripts\activate
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

*(You will see `(venv)` appear at the beginning of your terminal prompt).*

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

> **Note for Windows Users (For Live Sniffing Only):**  
> If you plan to capture live real packets from your Wi-Fi/Ethernet card, download and install **Npcap** from [https://npcap.com/](https://npcap.com/). During installation, ensure the checkbox **"Install Npcap in WinPcap API-compatible Mode"** is checked.  
> *(If you do not have administrative access, you can run Simulation Mode without installing Npcap!)*

---

## 🖥️ Running the Application

### 1. Launch the Flask Web Dashboard
```bash
python app.py
```
Terminal output:
```
============================================================
 Mini Network Intrusion Detection System (IDS) Server 
 Web Dashboard URL: http://127.0.0.1:5000
============================================================
```

### 2. Open in Your Browser
Open your browser and navigate to:
**`http://127.0.0.1:5000`**

---

## 🧪 College Lab Demonstration Workflow

Follow these steps for a complete, structured viva demonstration:

1. **Open the Dashboard:** Verify that the status shows `IDLE (Stopped)` with zero errors.
2. **Start Simulation Mode:** Click the blue **"▶ Start Demo Simulation"** button. The status indicator will turn green, and standard simulated network traffic (HTTPS, DNS, HTTP) will begin streaming into the packet table.
3. **Trigger Attack Scenarios:**
   - Click **"🔍 Rule 1: Port Scan Probe"**: Observe rapid probes to 16 distinct ports; a `HIGH` severity alert will appear immediately in the alert feed.
   - Click **"💥 Rule 2: Request Burst (DoS)"**: A burst of 45 packets will trigger a `MEDIUM` severity alert.
   - Click **"🎄 Rule 3: Xmas/Null Stealth Flags"**: Generates invalid TCP flag combinations (`FPU`, `0`, `SYN+FIN`) and raises an alert.
   - Click **"🔄 Rule 4: Repeated SYN Attempt"**: Triggers repeated pure connection probes.
4. **Inspect Visual Charts:** Watch the Traffic Rate line chart and the Protocol Distribution doughnut chart update in real time.
5. **Test the ML Anomaly Classifier:** In the ML panel, enter flow metrics (e.g., 48 pkts, 12 ports, 64 bytes avg length, 20 SYNs) and click **"Evaluate Flow Anomaly"** to see confidence scores and predictions.
6. **Export Alert Logs:** Click **"📥 Export CSV"** to download `ids_security_alerts.csv` for documentation.
7. **Run Automated Unit Tests:** In another terminal, run:
   ```bash
   python scripts/test_detector.py
   ```
   All 5 test assertions will output `[PASS]`.

---

## 🦈 Wireshark Independent Verification Guide

To compare IDS observations against Wireshark:

1. **Launch Wireshark.**
2. Select your active network adapter (e.g., `Wi-Fi` or `Ethernet` or `Npcap Loopback Adapter`).
3. Click the blue shark fin icon to start packet sniffing.
4. Apply the following display filters in Wireshark:
   - `tcp.flags.syn == 1 && tcp.flags.ack == 0` — Shows pure connection requests (matches Rule 1 & Rule 4).
   - `tcp.flags == 0x029` — Shows TCP Xmas scans with FIN, PSH, and URG active (matches Rule 3).
   - `ip.addr == 192.168.1.99` — Isolates the simulated attacker IP.
5. Observe how the timestamps and TCP flags in Wireshark match the IDS packet inspection table exactly.

---

## ⚙️ Configuration & Threshold Customization

All detection thresholds are cleanly organized in `config.py`:

```python
# config.py
PORT_SCAN_THRESHOLD = 8             # Number of distinct destination ports
PORT_SCAN_WINDOW_SEC = 15.0         # Observation time window in seconds
REQUEST_BURST_THRESHOLD = 40        # Total packets from single IP
REQUEST_BURST_WINDOW_SEC = 10.0     # Time window in seconds
REPEATED_CONN_THRESHOLD = 15        # Number of repeated SYN probes
ALERT_DEDUPLICATION_WINDOW_SEC = 5.0 # Suppression window
```

---

## ❓ Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `PermissionError: [Errno 1] Operation not permitted` | Running live capture without admin/root | Run Command Prompt/Terminal as Administrator, or simply click **"Start Demo Simulation"** (no privileges required). |
| `ModuleNotFoundError: No module named 'scapy'` | Virtual environment not activated or dependencies missing | Run `venv\Scripts\activate` followed by `pip install -r requirements.txt`. |
| `Address already in use (Port 5000)` | Another application (such as AirPlay or Docker) is using port 5000 | Open `config.py` and change `SERVER_PORT = 5001`. |
| Scapy cannot find interfaces on Windows | Missing Npcap driver | Download and install Npcap from https://npcap.com/ with WinPcap compatibility enabled. |

---

## 📜 Ethical & Authorized Monitoring Notice

This system is developed strictly for **educational and defensive cybersecurity research**. It must only be used to monitor:
1. `127.0.0.1` (Localhost loopback traffic).
2. Private academic lab subnets with explicit faculty authorization.
3. Private home networks owned by the operator.

*Do not scan or capture packets on public or unauthorized networks.*
