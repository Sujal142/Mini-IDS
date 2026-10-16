"""
Database storage module for Mini Network Intrusion Detection System (IDS).
Manages SQLite storage for captured packets, security alerts, and supports CSV export.
"""

import sqlite3
import csv
import io
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple


class DatabaseManager:
    """
    Handles SQLite database interactions for storing and retrieving
    packet logs and security alerts with thread safety.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns the persistent database connection."""
        return self._conn

    def _init_database(self) -> None:
        """Initializes tables and indexes for packets and alerts."""
        with self._lock:
            cursor = self._conn.cursor()
            
            # Packets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    length INTEGER NOT NULL,
                    tcp_flags TEXT,
                    info TEXT,
                    is_simulated INTEGER DEFAULT 0
                )
            """)

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    threshold_info TEXT,
                    is_simulated INTEGER DEFAULT 0
                )
            """)

            # Useful indexes for fast querying & filtering
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip)")
            
            self._conn.commit()

    def store_packet(self, packet_dict: Dict[str, Any]) -> int:
        """Stores a parsed packet record."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO packets (
                    timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, length, tcp_flags, info, is_simulated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                packet_dict.get("timestamp", datetime.now().isoformat()),
                packet_dict.get("src_ip", "0.0.0.0"),
                packet_dict.get("dst_ip", "0.0.0.0"),
                packet_dict.get("src_port"),
                packet_dict.get("dst_port"),
                packet_dict.get("protocol", "OTHER"),
                packet_dict.get("length", 0),
                packet_dict.get("tcp_flags", ""),
                packet_dict.get("info", ""),
                1 if packet_dict.get("is_simulated", False) else 0
            ))
            conn.commit()
            return cursor.lastrowid

    def store_alert(self, alert_dict: Dict[str, Any]) -> int:
        """Stores a security alert record."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (
                    timestamp, src_ip, dst_ip, dst_port,
                    category, severity, reason, rule_name, threshold_info, is_simulated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_dict.get("timestamp", datetime.now().isoformat()),
                alert_dict.get("src_ip", "0.0.0.0"),
                alert_dict.get("dst_ip"),
                alert_dict.get("dst_port"),
                alert_dict.get("category", "General Anomaly"),
                alert_dict.get("severity", "LOW"),
                alert_dict.get("reason", "Suspicious traffic observed"),
                alert_dict.get("rule_name", "Unknown Rule"),
                alert_dict.get("threshold_info", ""),
                1 if alert_dict.get("is_simulated", False) else 0
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_packets(self, limit: int = 50, src_ip: Optional[str] = None, protocol: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves recent packets with optional filtering."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM packets"
            conditions = []
            params: List[Any] = []

            if src_ip:
                conditions.append("src_ip LIKE ?")
                params.append(f"%{src_ip}%")
            if protocol and protocol.upper() != "ALL":
                conditions.append("protocol = ?")
                params.append(protocol.upper())

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None,
                   category: Optional[str] = None, src_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves alerts with optional filters."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts"
            conditions = []
            params: List[Any] = []

            if severity and severity.upper() != "ALL":
                conditions.append("severity = ?")
                params.append(severity.upper())
            if category and category.upper() != "ALL":
                conditions.append("category = ?")
                params.append(category)
            if src_ip:
                conditions.append("src_ip LIKE ?")
                params.append(f"%{src_ip}%")

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        """Calculates dashboard summary statistics."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()

            # Total packets
            cursor.execute("SELECT COUNT(*) FROM packets")
            total_packets = cursor.fetchone()[0]

            # Total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            # Unique source IPs
            cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM packets")
            unique_ips = cursor.fetchone()[0]

            # Protocol breakdown
            cursor.execute("SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol ORDER BY count DESC")
            protocol_distribution = {row["protocol"]: row["count"] for row in cursor.fetchall()}

            # Severity breakdown
            cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            severity_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            for row in cursor.fetchall():
                severity_distribution[row["severity"]] = row["count"]

            return {
                "total_packets": total_packets,
                "total_alerts": total_alerts,
                "unique_ips": unique_ips,
                "protocol_distribution": protocol_distribution,
                "severity_distribution": severity_distribution,
            }

    def export_alerts_to_csv(self) -> str:
        """Exports all alerts to a CSV string."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY id ASC")
            rows = cursor.fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
            # Write Header
            writer.writerow([
                "Alert ID", "Timestamp", "Source IP", "Destination IP",
                "Destination Port", "Category", "Severity", "Reason",
                "Rule Name", "Threshold Info", "Is Simulated"
            ])
            for r in rows:
                writer.writerow([
                    r["id"], r["timestamp"], r["src_ip"], r["dst_ip"] or "N/A",
                    r["dst_port"] or "N/A", r["category"], r["severity"],
                    r["reason"], r["rule_name"], r["threshold_info"],
                    "Yes" if r["is_simulated"] else "No"
                ])
            return output.getvalue()

    def clear_all_data(self) -> None:
        """Clears all packet and alert records for fresh testing."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM packets")
            cursor.execute("DELETE FROM alerts")
            conn.commit()
