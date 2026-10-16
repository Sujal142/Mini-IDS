"""
Script to populate the SQLite database with initial educational demo packets and alerts.
Useful for immediate testing of the web dashboard without needing live network access.
"""

import sys
import os
from pathlib import Path
from datetime import datetime, timedelta

# Ensure parent directory is in Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import DATABASE_PATH
from database.storage import DatabaseManager
from detector.rules import RuleEngine
from detector.traffic_analyzer import TrafficAnalyzer


def populate_demo_data():
    print(f"[*] Initializing database at: {DATABASE_PATH}")
    db = DatabaseManager(DATABASE_PATH)
    rules = RuleEngine()
    analyzer = TrafficAnalyzer(db, rules)

    print("[*] Clearing old records for clean demo state...")
    db.clear_all_data()

    print("[*] Generating simulated normal background traffic...")
    base_time = datetime.now() - timedelta(minutes=5)

    # 1. Normal web browsing packets
    for i in range(25):
        t = (base_time + timedelta(seconds=i * 2)).strftime("%Y-%m-%d %H:%M:%S")
        pkt = {
            "timestamp": t,
            "src_ip": "192.168.1.15",
            "dst_ip": "142.250.190.46",
            "src_port": 52140 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "length": 850,
            "tcp_flags": "PA",
            "info": "HTTPS TLS Application Data",
            "is_simulated": True
        }
        analyzer.process_packet(pkt)

    # 2. Normal DNS queries
    for i in range(10):
        t = (base_time + timedelta(seconds=i * 5)).strftime("%Y-%m-%d %H:%M:%S")
        pkt = {
            "timestamp": t,
            "src_ip": "192.168.1.22",
            "dst_ip": "1.1.1.1",
            "src_port": 53000 + i,
            "dst_port": 53,
            "protocol": "DNS",
            "length": 68,
            "tcp_flags": "",
            "info": "Standard query 0x2b4a A example.com",
            "is_simulated": True
        }
        analyzer.process_packet(pkt)

    print("[*] Simulating Attack Scenario 1: Port Scan (Rule 1)...")
    attacker_ip = "192.168.1.99"
    scan_time = datetime.now() - timedelta(minutes=2)
    # Contact 12 different ports
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 3306, 8080]):
        t = (scan_time + timedelta(milliseconds=i * 200)).strftime("%Y-%m-%d %H:%M:%S")
        pkt = {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "192.168.1.50",
            "src_port": 61200 + i,
            "dst_port": port,
            "protocol": "TCP",
            "length": 60,
            "tcp_flags": "S",
            "info": f"Port probe -> {port}",
            "is_simulated": True
        }
        analyzer.process_packet(pkt)

    print("[*] Simulating Attack Scenario 2: Request Burst / DoS (Rule 2)...")
    burst_attacker = "192.168.1.150"
    burst_time = datetime.now() - timedelta(minutes=1)
    for i in range(45):
        t = (burst_time + timedelta(milliseconds=i * 50)).strftime("%Y-%m-%d %H:%M:%S")
        pkt = {
            "timestamp": t,
            "src_ip": burst_attacker,
            "dst_ip": "192.168.1.50",
            "src_port": 55000 + (i % 5),
            "dst_port": 80,
            "protocol": "TCP",
            "length": 78,
            "tcp_flags": "S",
            "info": f"Rapid connection flood #{i+1}",
            "is_simulated": True
        }
        analyzer.process_packet(pkt)

    print("[*] Simulating Attack Scenario 3: Unusual & Malformed Packets (Rule 3)...")
    stealth_ip = "192.168.1.210"
    malformed_time = datetime.now() - timedelta(seconds=30)
    for flags, desc in [("FPU", "XMAS Scan probe"), ("0", "NULL Scan probe"), ("SF", "SYN+FIN probe")]:
        pkt = {
            "timestamp": malformed_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": stealth_ip,
            "dst_ip": "192.168.1.50",
            "src_port": 64000,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 60,
            "tcp_flags": flags,
            "info": desc,
            "is_simulated": True
        }
        analyzer.process_packet(pkt)

    stats = db.get_statistics()
    print("\n[+] Demo data successfully loaded!")
    print(f"    Total Packets: {stats['total_packets']}")
    print(f"    Total Alerts:  {stats['total_alerts']}")
    print(f"    Unique IPs:    {stats['unique_ips']}")
    print(f"    Severity Breakdown: {stats['severity_distribution']}")


if __name__ == "__main__":
    populate_demo_data()
