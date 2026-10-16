"""
Unit tests for DatabaseManager in Mini Network IDS.
Run via: python3 -m unittest tests/test_storage.py
"""

import unittest
import sys
from pathlib import Path

# Add root directory to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from database.storage import DatabaseManager


class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        # Use isolated in-memory DB for every test
        self.db = DatabaseManager(":memory:")

    def test_store_and_retrieve_packet(self):
        pkt = {
            "timestamp": "2026-10-16 12:00:00",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 128,
            "tcp_flags": "PA",
            "info": "HTTP GET",
            "is_simulated": True
        }
        row_id = self.db.store_packet(pkt)
        self.assertGreater(row_id, 0)

        packets = self.db.get_recent_packets(limit=10)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["src_ip"], "192.168.1.10")
        self.assertEqual(packets[0]["protocol"], "TCP")

    def test_store_and_retrieve_alert(self):
        alert = {
            "timestamp": "2026-10-16 12:00:05",
            "src_ip": "192.168.1.99",
            "dst_ip": "192.168.1.1",
            "dst_port": 22,
            "category": "Port Scanning",
            "severity": "HIGH",
            "reason": "Scanned 10 ports",
            "rule_name": "Port Scan Detection",
            "threshold_info": "10 >= 8",
            "is_simulated": True
        }
        alert_id = self.db.store_alert(alert)
        self.assertGreater(alert_id, 0)

        alerts = self.db.get_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["rule_name"], "Port Scan Detection")

    def test_csv_export(self):
        alert = {
            "timestamp": "2026-10-16 12:00:05",
            "src_ip": "192.168.1.99",
            "dst_ip": "192.168.1.1",
            "dst_port": 22,
            "category": "Port Scanning",
            "severity": "HIGH",
            "reason": "Scanned 10 ports",
            "rule_name": "Port Scan Detection",
            "threshold_info": "10 >= 8",
            "is_simulated": True
        }
        self.db.store_alert(alert)
        csv_data = self.db.export_alerts_to_csv()
        self.assertIn("Alert ID", csv_data)
        self.assertIn("Port Scanning", csv_data)
        self.assertIn("192.168.1.99", csv_data)

    def test_statistics_calculation(self):
        # Store packet and alert
        self.db.store_packet({
            "timestamp": "2026-10-16 12:00:00",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "length": 100
        })
        self.db.store_packet({
            "timestamp": "2026-10-16 12:00:01",
            "src_ip": "192.168.1.20",
            "dst_ip": "1.1.1.1",
            "protocol": "DNS",
            "length": 64
        })
        self.db.store_alert({
            "timestamp": "2026-10-16 12:00:02",
            "src_ip": "192.168.1.99",
            "category": "Port Scanning",
            "severity": "HIGH",
            "reason": "Test alert",
            "rule_name": "Test"
        })

        stats = self.db.get_statistics()
        self.assertEqual(stats["total_packets"], 2)
        self.assertEqual(stats["total_alerts"], 1)
        self.assertEqual(stats["unique_ips"], 2)
        self.assertEqual(stats["protocol_distribution"].get("TCP"), 1)
        self.assertEqual(stats["protocol_distribution"].get("DNS"), 1)
        self.assertEqual(stats["severity_distribution"].get("HIGH"), 1)


if __name__ == "__main__":
    unittest.main()
