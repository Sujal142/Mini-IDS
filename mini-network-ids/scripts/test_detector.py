"""
Automated Test Suite for Mini Network Intrusion Detection System.
Tests each detection rule and verifies that normal traffic produces zero false alarms:
1. Normal browsing traffic -> 0 alerts
2. Port scan (distinct ports) -> Rule 1 fires
3. Request burst (high volume) -> Rule 2 fires
4. Malformed/illegal TCP flags (NULL, Xmas, SYN+FIN) -> Rule 3 fires
5. Repeated SYN connection probes -> Rule 4 fires
"""

import sys
import time
from pathlib import Path
from datetime import datetime

# Add root directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import DATABASE_PATH
from database.storage import DatabaseManager
from detector.rules import RuleEngine
from detector.traffic_analyzer import TrafficAnalyzer


def run_tests():
    print("=" * 70)
    print(" MINI NETWORK IDS - AUTOMATED DETECTION ENGINE TEST SUITE ")
    print("=" * 70)

    db = DatabaseManager(":memory:")  # Use in-memory SQLite for pristine test isolation
    rules = RuleEngine(
        port_scan_threshold=5,
        port_scan_window_sec=10.0,
        request_burst_threshold=15,
        request_burst_window_sec=5.0,
        repeated_conn_threshold=8,
        repeated_conn_window_sec=5.0,
        deduplication_window_sec=1.0
    )
    analyzer = TrafficAnalyzer(db, rules)

    passed_tests = 0
    total_tests = 5

    # -------------------------------------------------------------
    # Test 1: Normal Browsing Traffic
    # -------------------------------------------------------------
    print("\n[TEST 1] Testing Normal Web Browsing Traffic...")
    normal_ip = "192.168.1.10"
    normal_alerts = []
    for i in range(10):
        pkt = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": normal_ip,
            "dst_ip": "142.250.190.46",
            "src_port": 50000 + i,
            "dst_port": 443,  # Single destination port (HTTPS)
            "protocol": "TCP",
            "length": 800,
            "tcp_flags": "PA",
            "info": "Standard TLS payload",
            "is_simulated": True
        }
        res = analyzer.process_packet(pkt)
        normal_alerts.extend(res)

    if len(normal_alerts) == 0:
        print("  [PASS] Normal traffic produced 0 false positive alerts.")
        passed_tests += 1
    else:
        print(f"  [FAIL] Normal traffic generated unexpected alerts: {normal_alerts}")

    # -------------------------------------------------------------
    # Test 2: Port Scan Attack
    # -------------------------------------------------------------
    print("\n[TEST 2] Testing Port Scan Detection (Rule 1)...")
    scanner_ip = "192.168.1.88"
    scan_alerts = []
    # Contact 7 different ports (threshold is 5)
    for p in [21, 22, 23, 25, 80, 443, 8080]:
        pkt = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": scanner_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 60000,
            "dst_port": p,
            "protocol": "TCP",
            "length": 60,
            "tcp_flags": "S",
            "info": f"Scanning port {p}",
            "is_simulated": True
        }
        res = analyzer.process_packet(pkt)
        scan_alerts.extend(res)

    has_port_scan = any(a["rule_name"] == "Port Scan Detection" for a in scan_alerts)
    if has_port_scan:
        print(f"  [PASS] Port scan detected successfully ({len(scan_alerts)} alert triggered).")
        passed_tests += 1
    else:
        print("  [FAIL] Port scan was NOT detected.")

    # -------------------------------------------------------------
    # Test 3: Excessive Request Burst / DoS
    # -------------------------------------------------------------
    print("\n[TEST 3] Testing Excessive Request Burst Detection (Rule 2)...")
    flooder_ip = "192.168.1.77"
    burst_alerts = []
    # Send 18 packets in tight succession (threshold is 15)
    for i in range(18):
        pkt = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": flooder_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 70,
            "tcp_flags": "PA",
            "info": f"Flood packet #{i+1}",
            "is_simulated": True
        }
        res = analyzer.process_packet(pkt)
        burst_alerts.extend(res)

    has_burst = any(a["rule_name"] == "Excessive Requests Detection" for a in burst_alerts)
    if has_burst:
        print("  [PASS] Request burst / DoS pattern detected successfully.")
        passed_tests += 1
    else:
        print("  [FAIL] Excessive request burst was NOT detected.")

    # -------------------------------------------------------------
    # Test 4: Unusual & Malformed Packets (TCP Flags)
    # -------------------------------------------------------------
    print("\n[TEST 4] Testing Malformed & Unusual TCP Flags Detection (Rule 3)...")
    stealth_ip = "192.168.1.66"
    malformed_alerts = []
    test_cases = [
        ("FPU", "XMAS Scan"),
        ("0", "NULL Scan"),
        ("SF", "SYN+FIN Illegal")
    ]
    for flags, desc in test_cases:
        pkt = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": stealth_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 60,
            "tcp_flags": flags,
            "info": desc,
            "is_simulated": True
        }
        res = analyzer.process_packet(pkt)
        malformed_alerts.extend(res)

    has_malformed = any(a["rule_name"] == "Unusual Packet Detection" for a in malformed_alerts)
    if has_malformed:
        print(f"  [PASS] Malformed flag signatures detected successfully ({len(malformed_alerts)} alert triggered).")
        passed_tests += 1
    else:
        print("  [FAIL] Malformed TCP flags were NOT detected.")

    # -------------------------------------------------------------
    # Test 5: Repeated Connection Attempts (SYN Probing)
    # -------------------------------------------------------------
    print("\n[TEST 5] Testing Repeated Connection Attempts Detection (Rule 4)...")
    syn_ip = "192.168.1.55"
    syn_alerts = []
    # Send 10 pure SYN packets (threshold is 8)
    for i in range(10):
        pkt = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": syn_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 50000 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "length": 60,
            "tcp_flags": "S",
            "info": f"SYN attempt #{i+1}",
            "is_simulated": True
        }
        res = analyzer.process_packet(pkt)
        syn_alerts.extend(res)

    has_syn = any(a["rule_name"] == "Repeated Connection Attempts" for a in syn_alerts)
    if has_syn:
        print("  [PASS] Repeated SYN connection attempts detected successfully.")
        passed_tests += 1
    else:
        print("  [FAIL] Repeated connection attempts were NOT detected.")

    print("\n" + "=" * 70)
    print(f" TEST SUMMARY: {passed_tests}/{total_tests} Tests Passed Successfully! ")
    print("=" * 70)

    return passed_tests == total_tests


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
