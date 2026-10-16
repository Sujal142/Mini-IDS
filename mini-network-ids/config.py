"""
Configuration settings for Mini Network Intrusion Detection System (IDS).
All detection thresholds, time windows, and server settings are managed here.
Students can adjust these values to test different detection sensitivities.
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Database configuration
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = str(DATA_DIR / "ids_alerts.db")
ML_MODEL_PATH = str(DATA_DIR / "ids_model.joblib")
ML_METRICS_PATH = str(DATA_DIR / "model_metrics.json")

# Server configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
DEBUG_MODE = False  # Keep False for security; only enable when debugging

# ==========================================
# Intrusion Detection Rule Thresholds
# ==========================================

# Rule 1: Port Scan Detection
# Trigger alert if a source IP scans more than PORT_SCAN_THRESHOLD distinct ports within PORT_SCAN_WINDOW_SEC
PORT_SCAN_THRESHOLD = 8             # Number of distinct destination ports
PORT_SCAN_WINDOW_SEC = 15.0         # Observation time window in seconds
PORT_SCAN_SEVERITY = "HIGH"

# Rule 2: Excessive Request / DoS-like Burst Detection
# Trigger alert if a source IP sends more than REQUEST_BURST_THRESHOLD packets within REQUEST_BURST_WINDOW_SEC
REQUEST_BURST_THRESHOLD = 40        # Total packets/requests from single IP
REQUEST_BURST_WINDOW_SEC = 10.0     # Time window in seconds
REQUEST_BURST_SEVERITY = "MEDIUM"

# Rule 3: Unusual & Malformed Packet Detection
# Flag suspicious or invalid TCP flag combinations (e.g., Xmas, Null scan, SYN+FIN)
UNUSUAL_PACKET_SEVERITY = "MEDIUM"
MALFORMED_PACKET_SEVERITY = "HIGH"

# Rule 4: Repeated Connection Attempts (SYN flood / probe)
# Repeated connection attempts without data transfer
REPEATED_CONN_THRESHOLD = 15        # Number of repeated SYN probes
REPEATED_CONN_WINDOW_SEC = 10.0     # Time window in seconds
REPEATED_CONN_SEVERITY = "MEDIUM"

# Alert Deduplication Window
# Prevent flooding the alert log with identical alerts within DEDUPLICATION_WINDOW_SEC
ALERT_DEDUPLICATION_WINDOW_SEC = 5.0

# Live Packet Capture Settings
DEFAULT_INTERFACE = None  # None selects default interface automatically
CAPTURE_BUFFER_SIZE = 1000  # Max recent packets kept in memory
