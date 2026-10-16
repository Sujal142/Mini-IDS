"""
Traffic Analyzer module for Mini Network IDS.
Coordinates packet processing, rule evaluation, database storage, and callback notifications.
"""

import threading
from typing import Dict, Any, List, Optional, Callable
from .rules import RuleEngine
try:
    from database.storage import DatabaseManager
except ImportError:
    from ..database.storage import DatabaseManager


class TrafficAnalyzer:
    """
    Central pipeline that ingests packets from live capture or simulation,
    evaluates them against the RuleEngine, saves records in SQLite,
    and invokes listeners/callbacks for live UI updates.
    """

    def __init__(self, db_manager: DatabaseManager, rule_engine: Optional[RuleEngine] = None):
        self.db = db_manager
        self.rule_engine = rule_engine or RuleEngine()
        self._lock = threading.Lock()
        self._packet_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_packet_callback(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        """Adds a callback invoked when a packet is processed."""
        self._packet_callbacks.append(cb)

    def register_alert_callback(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        """Adds a callback invoked when an alert is generated."""
        self._alert_callbacks.append(cb)

    def process_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Ingests a packet, saves it to SQLite, checks detection rules,
        saves alerts, and notifies callbacks.
        """
        # Save packet to DB
        packet_id = self.db.store_packet(packet)
        packet["id"] = packet_id

        # Evaluate rules
        alerts = self.rule_engine.evaluate_packet(packet)

        # Store alerts in DB and dispatch
        saved_alerts = []
        for alert in alerts:
            alert_id = self.db.store_alert(alert)
            alert["id"] = alert_id
            saved_alerts.append(alert)

            # Notify alert callbacks
            for cb in self._alert_callbacks:
                try:
                    cb(alert)
                except Exception as e:
                    print(f"[Error in alert callback]: {e}")

        # Notify packet callbacks
        for cb in self._packet_callbacks:
            try:
                cb(packet)
            except Exception as e:
                print(f"[Error in packet callback]: {e}")

        return saved_alerts

    def reset_analyzer(self) -> None:
        """Resets rule tracking history and database."""
        self.rule_engine.reset_state()
        self.db.clear_all_data()
