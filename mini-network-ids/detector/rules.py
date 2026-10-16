"""
Rule-Based Intrusion Detection Engine for Mini Network IDS.

Implements modular, transparent, and configurable detection rules:
- Rule 1: Port Scan Detection (multiple distinct destination ports from same source IP)
- Rule 2: Excessive Request / DoS-like Request Burst Detection
- Rule 3: Unusual & Malformed Packet Detection (illegal TCP flag combinations)
- Rule 4: Repeated Connection Attempts (SYN probing pattern)

Includes deduplication to prevent alert storms during high-frequency traffic.
"""

import time
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple, Set


class RuleEngine:
    def __init__(
        self,
        port_scan_threshold: int = 8,
        port_scan_window_sec: float = 15.0,
        request_burst_threshold: int = 40,
        request_burst_window_sec: float = 10.0,
        repeated_conn_threshold: int = 15,
        repeated_conn_window_sec: float = 10.0,
        deduplication_window_sec: float = 5.0
    ):
        # Configurable thresholds
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_sec = port_scan_window_sec
        self.request_burst_threshold = request_burst_threshold
        self.request_burst_window_sec = request_burst_window_sec
        self.repeated_conn_threshold = repeated_conn_threshold
        self.repeated_conn_window_sec = repeated_conn_window_sec
        self.deduplication_window_sec = deduplication_window_sec

        # State tracking (per source IP)
        # src_ip -> list of (timestamp, dst_port)
        self.port_access_history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)

        # src_ip -> list of timestamps
        self.request_history: Dict[str, List[float]] = defaultdict(list)

        # src_ip -> list of (timestamp, dst_ip, dst_port) for TCP SYN packets
        self.syn_attempt_history: Dict[str, List[Tuple[float, str, int]]] = defaultdict(list)

        # Alert deduplication: (src_ip, rule_name) -> last_alert_time
        self.last_alert_times: Dict[Tuple[str, str], float] = {}

    def _should_suppress_alert(self, src_ip: str, rule_name: str, current_time: float) -> bool:
        """Checks if an alert for this rule & IP should be suppressed to avoid flooding."""
        key = (src_ip, rule_name)
        last_time = self.last_alert_times.get(key, 0.0)
        if (current_time - last_time) < self.deduplication_window_sec:
            return True
        self.last_alert_times[key] = current_time
        return False

    def evaluate_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a single parsed packet against all detection rules.
        Returns a list of generated alert dictionaries (if any).
        """
        alerts: List[Dict[str, Any]] = []
        now = time.time()

        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port")
        protocol = packet.get("protocol", "").upper()
        tcp_flags = str(packet.get("tcp_flags") or "").upper()
        is_simulated = bool(packet.get("is_simulated", False))

        # Ignore loopback/invalid source if not simulated
        if not src_ip or src_ip == "0.0.0.0":
            return alerts

        # ---------------------------------------------------------
        # Rule 1: Port Scan Detection
        # ---------------------------------------------------------
        if dst_port is not None and protocol in ("TCP", "UDP"):
            history = self.port_access_history[src_ip]
            history.append((now, int(dst_port)))
            # Purge entries older than the window
            cutoff = now - self.port_scan_window_sec
            self.port_access_history[src_ip] = [item for item in history if item[0] >= cutoff]

            unique_ports: Set[int] = {item[1] for item in self.port_access_history[src_ip]}
            if len(unique_ports) >= self.port_scan_threshold:
                if not self._should_suppress_alert(src_ip, "Port Scan Detection", now):
                    alerts.append({
                        "timestamp": packet.get("timestamp"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "category": "Port Scanning",
                        "severity": "HIGH",
                        "reason": f"Source scanned {len(unique_ports)} distinct ports within {self.port_scan_window_sec}s",
                        "rule_name": "Port Scan Detection",
                        "threshold_info": f"Observed {len(unique_ports)} ports >= Threshold {self.port_scan_threshold}",
                        "is_simulated": is_simulated
                    })

        # ---------------------------------------------------------
        # Rule 2: Excessive Request / DoS-like Request Burst Detection
        # ---------------------------------------------------------
        req_hist = self.request_history[src_ip]
        req_hist.append(now)
        req_cutoff = now - self.request_burst_window_sec
        self.request_history[src_ip] = [t for t in req_hist if t >= req_cutoff]

        count = len(self.request_history[src_ip])
        if count >= self.request_burst_threshold:
            if not self._should_suppress_alert(src_ip, "Excessive Requests Detection", now):
                alerts.append({
                    "timestamp": packet.get("timestamp"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "category": "Traffic Burst / DoS",
                    "severity": "MEDIUM",
                    "reason": f"Suspicious packet burst: {count} packets sent in {self.request_burst_window_sec}s (Possible DoS attempt or rapid crawler)",
                    "rule_name": "Excessive Requests Detection",
                    "threshold_info": f"Observed {count} packets >= Threshold {self.request_burst_threshold}",
                    "is_simulated": is_simulated
                })

        # ---------------------------------------------------------
        # Rule 3: Unusual & Malformed Packet Detection
        # ---------------------------------------------------------
        if protocol == "TCP":
            flag_alert = self._inspect_tcp_flags(tcp_flags, packet, now, is_simulated)
            if flag_alert:
                alerts.append(flag_alert)

        # ---------------------------------------------------------
        # Rule 4: Repeated Connection Attempts (SYN Probing)
        # ---------------------------------------------------------
        if protocol == "TCP" and "S" in tcp_flags and "A" not in tcp_flags:
            # Pure SYN packet (connection initiation)
            syn_hist = self.syn_attempt_history[src_ip]
            syn_hist.append((now, dst_ip, dst_port or 0))
            syn_cutoff = now - self.repeated_conn_window_sec
            self.syn_attempt_history[src_ip] = [item for item in syn_hist if item[0] >= syn_cutoff]

            syn_count = len(self.syn_attempt_history[src_ip])
            if syn_count >= self.repeated_conn_threshold:
                if not self._should_suppress_alert(src_ip, "Repeated Connection Attempts", now):
                    alerts.append({
                        "timestamp": packet.get("timestamp"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "category": "Reconnaissance",
                        "severity": "MEDIUM",
                        "reason": f"High volume of repeated TCP SYN connection requests ({syn_count} attempts in {self.repeated_conn_window_sec}s)",
                        "rule_name": "Repeated Connection Attempts",
                        "threshold_info": f"Observed {syn_count} SYN attempts >= Threshold {self.repeated_conn_threshold}",
                        "is_simulated": is_simulated
                    })

        return alerts

    def _inspect_tcp_flags(self, flags: str, packet: Dict[str, Any], now: float, is_simulated: bool) -> Optional[Dict[str, Any]]:
        """
        Inspects TCP flags for signature scanning patterns:
        - NULL Scan: No flags set (used to bypass non-stateful firewalls)
        - XMAS Scan: FIN, PSH, URG all set (lit up like a Christmas tree)
        - SYN + FIN: Illegal combination
        - SYN + RST: Contradictory connection request and termination
        """
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port")

        reason = None
        severity = "MEDIUM"

        # Check for NULL flags
        if flags in ("NONE", "0", ""):
            reason = "TCP NULL packet detected (zero flags set; common stealth scan signature)"
            severity = "HIGH"
        # Check for XMAS flags (FIN, PSH, URG all present)
        elif "F" in flags and "P" in flags and "U" in flags:
            reason = "TCP Xmas Tree scan packet detected (FIN, PSH, URG flags active)"
            severity = "HIGH"
        # Check for SYN + FIN
        elif "S" in flags and "F" in flags:
            reason = "Illegal TCP flag combination detected: SYN + FIN set simultaneously"
            severity = "HIGH"
        # Check for SYN + RST
        elif "S" in flags and "R" in flags:
            reason = "Abnormal TCP flag combination detected: SYN + RST set simultaneously"
            severity = "MEDIUM"

        if reason and not self._should_suppress_alert(src_ip, "Unusual Packet Detection", now):
            return {
                "timestamp": packet.get("timestamp"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "category": "Malformed / Stealth Scan",
                "severity": severity,
                "reason": reason,
                "rule_name": "Unusual Packet Detection",
                "threshold_info": f"Observed flags: '{flags}'",
                "is_simulated": is_simulated
            }

        return None

    def reset_state(self) -> None:
        """Clears memory buffers and alert histories."""
        self.port_access_history.clear()
        self.request_history.clear()
        self.syn_attempt_history.clear()
        self.last_alert_times.clear()
