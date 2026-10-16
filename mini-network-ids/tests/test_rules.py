"""
Unit tests for RuleEngine in Mini Network IDS.
Run via: python3 -m unittest tests/test_rules.py
"""

import unittest
import sys
from pathlib import Path

# Add root directory to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from detector.rules import RuleEngine


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        # Initialize with low thresholds for deterministic testing
        self.rules = RuleEngine(
            port_scan_threshold=3,
            port_scan_window_sec=5.0,
            request_burst_threshold=5,
            request_burst_window_sec=5.0,
            repeated_conn_threshold=4,
            repeated_conn_window_sec=5.0,
            deduplication_window_sec=0.1
        )

    def test_normal_traffic_no_alerts(self):
        """Verifies that standard repetitive HTTP requests to single port don't trigger port scans."""
        packet = {
            "timestamp": "2026-10-16 10:00:00",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 45000,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "PA",
            "length": 500,
            "is_simulated": True
        }
        alerts = self.rules.evaluate_packet(packet)
        self.assertEqual(len(alerts), 0)

    def test_port_scan_detection(self):
        """Verifies Rule 1 fires when port count reaches threshold."""
        src_ip = "10.0.0.50"
        alerts = []
        for port in [21, 22, 23, 80]:
            pkt = {
                "timestamp": "2026-10-16 10:00:00",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.2",
                "src_port": 50000,
                "dst_port": port,
                "protocol": "TCP",
                "tcp_flags": "S",
                "length": 60,
                "is_simulated": True
            }
            res = self.rules.evaluate_packet(pkt)
            alerts.extend(res)

        rule1_alerts = [a for a in alerts if a["rule_name"] == "Port Scan Detection"]
        self.assertGreaterEqual(len(rule1_alerts), 1)
        self.assertEqual(rule1_alerts[0]["severity"], "HIGH")

    def test_excessive_request_detection(self):
        """Verifies Rule 2 triggers upon high packet count."""
        src_ip = "10.0.0.99"
        alerts = []
        for _ in range(6):
            pkt = {
                "timestamp": "2026-10-16 10:00:00",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.2",
                "src_port": 50000,
                "dst_port": 80,
                "protocol": "TCP",
                "tcp_flags": "PA",
                "length": 80,
                "is_simulated": True
            }
            res = self.rules.evaluate_packet(pkt)
            alerts.extend(res)

        burst_alerts = [a for a in alerts if a["rule_name"] == "Excessive Requests Detection"]
        self.assertGreaterEqual(len(burst_alerts), 1)
        self.assertEqual(burst_alerts[0]["severity"], "MEDIUM")

    def test_malformed_tcp_flags(self):
        """Verifies Rule 3 flags Xmas scans and NULL scans."""
        # Xmas scan
        xmas_pkt = {
            "timestamp": "2026-10-16 10:00:00",
            "src_ip": "10.0.0.88",
            "dst_ip": "10.0.0.2",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "FPU",
            "length": 60,
            "is_simulated": True
        }
        alerts = self.rules.evaluate_packet(xmas_pkt)
        malformed = [a for a in alerts if a["rule_name"] == "Unusual Packet Detection"]
        self.assertEqual(len(malformed), 1)
        self.assertIn("Xmas", malformed[0]["reason"])

    def test_repeated_syn_connection_attempts(self):
        """Verifies Rule 4 catches repeated pure SYN attempts."""
        src_ip = "10.0.0.77"
        alerts = []
        for _ in range(5):
            pkt = {
                "timestamp": "2026-10-16 10:00:00",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.2",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "TCP",
                "tcp_flags": "S",
                "length": 60,
                "is_simulated": True
            }
            res = self.rules.evaluate_packet(pkt)
            alerts.extend(res)

        syn_alerts = [a for a in alerts if a["rule_name"] == "Repeated Connection Attempts"]
        self.assertGreaterEqual(len(syn_alerts), 1)


if __name__ == "__main__":
    unittest.main()
