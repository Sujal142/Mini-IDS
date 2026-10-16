"""
Packet Capture Manager for Mini Network IDS.
Supports:
1. Live network packet capture via Scapy (when permissions and Npcap/libpcap exist).
2. Simulated packet generation for educational/demo environments where raw socket permissions are restricted.
3. Thread-safe background monitoring with graceful start/stop controls.
"""

import threading
import time
import random
from datetime import datetime
from typing import Optional, Callable, Dict, Any, List, Tuple

# Try importing Scapy; handle gracefully if not yet installed or unavailable
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketCaptureManager:
    def __init__(self, packet_handler: Callable[[Dict[str, Any]], None], interface: Optional[str] = None):
        self.packet_handler = packet_handler
        self.interface = interface
        self.is_running = False
        self.mode = "IDLE"  # "LIVE", "SIMULATED", "IDLE"
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self.last_error: Optional[str] = None

    def start_live_capture(self) -> Tuple[bool, str]:
        """Starts live packet sniffing in a background daemon thread."""
        if not SCAPY_AVAILABLE:
            self.last_error = "Scapy is not installed. Run 'pip install scapy' or use Demo/Simulation Mode."
            return False, self.last_error

        if self.is_running:
            return False, "Capture is already active."

        self.is_running = True
        self.mode = "LIVE"
        self._stop_event.clear()
        self.last_error = None

        self._worker_thread = threading.Thread(target=self._live_capture_worker, daemon=True)
        self._worker_thread.start()
        return True, "Live capture started successfully."

    def start_simulation(self) -> Tuple[bool, str]:
        """Starts synthetic traffic generation for demonstration without root/admin privileges."""
        if self.is_running:
            return False, "Monitoring is already active."

        self.is_running = True
        self.mode = "SIMULATED"
        self._stop_event.clear()
        self.last_error = None

        self._worker_thread = threading.Thread(target=self._simulation_worker, daemon=True)
        self._worker_thread.start()
        return True, "Simulated traffic mode started successfully."

    def stop_capture(self) -> Tuple[bool, str]:
        """Gracefully signals the worker thread to stop."""
        if not self.is_running:
            return False, "Capture is not currently running."

        self.is_running = False
        self.mode = "IDLE"
        self._stop_event.set()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.5)

        return True, "Capture stopped successfully."

    def _scapy_callback(self, scapy_pkt) -> None:
        """Parses a Scapy packet into a clean standardized dictionary."""
        if self._stop_event.is_set():
            return

        try:
            if not scapy_pkt.haslayer(IP):
                return

            ip_layer = scapy_pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = len(scapy_pkt)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            protocol = "OTHER"
            src_port = None
            dst_port = None
            tcp_flags = ""
            info = f"{src_ip} -> {dst_ip}"

            if scapy_pkt.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = scapy_pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                # Format flags (S, A, F, R, P, U)
                tcp_flags = str(tcp_layer.flags)
                info = f"{src_port} -> {dst_port} [{tcp_flags}] Seq={tcp_layer.seq}"
            elif scapy_pkt.haslayer(UDP):
                protocol = "UDP"
                udp_layer = scapy_pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                if scapy_pkt.haslayer(DNS):
                    protocol = "DNS"
                    info = f"DNS Query/Response on port {dst_port}"
                else:
                    info = f"{src_port} -> {dst_port} UDP Len={udp_layer.len}"
            elif scapy_pkt.haslayer(ICMP):
                protocol = "ICMP"
                icmp_layer = scapy_pkt[ICMP]
                info = f"ICMP Type={icmp_layer.type} Code={icmp_layer.code}"

            packet_dict = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "tcp_flags": tcp_flags,
                "info": info,
                "is_simulated": False
            }

            self.packet_handler(packet_dict)
        except Exception as e:
            # Prevent capture thread from terminating unexpectedly
            pass

    def _live_capture_worker(self) -> None:
        """Worker thread loop executing Scapy sniff."""
        try:
            # Sniff with stop_filter checking stop_event
            sniff(
                iface=self.interface,
                prn=self._scapy_callback,
                stop_filter=lambda x: self._stop_event.is_set(),
                store=False,
                timeout=None
            )
        except PermissionError:
            self.last_error = "Permission denied: Administrator or root privileges required for raw packet capture."
            self.is_running = False
            self.mode = "IDLE"
        except Exception as e:
            self.last_error = f"Capture error: {str(e)}"
            self.is_running = False
            self.mode = "IDLE"

    def _simulation_worker(self) -> None:
        """Generates realistic normal background traffic at paced intervals."""
        common_normal_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.22", "192.168.1.104",
            "10.0.0.5", "10.0.0.12"
        ]
        servers = [
            ("142.250.190.46", 443, "HTTPS - Google Web Services"),
            ("151.101.65.140", 80, "HTTP - Web Mirror"),
            ("1.1.1.1", 53, "DNS - Cloudflare Resolver"),
            ("8.8.8.8", 53, "DNS - Google DNS"),
            ("192.168.1.1", 80, "HTTP - Gateway Management"),
        ]

        while not self._stop_event.is_set():
            src = random.choice(common_normal_ips)
            dst, port, service = random.choice(servers)
            client_port = random.randint(49152, 65535)
            proto = "DNS" if port == 53 else ("TCP" if port in (80, 443) else "UDP")
            flags = "PA" if proto == "TCP" else ""
            length = random.randint(64, 1420)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            pkt = {
                "timestamp": timestamp,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": client_port,
                "dst_port": port,
                "protocol": proto,
                "length": length,
                "tcp_flags": flags,
                "info": f"Standard traffic: {src}:{client_port} -> {service}",
                "is_simulated": True
            }
            self.packet_handler(pkt)

            # Sleep between 0.3s and 0.8s
            time.sleep(random.uniform(0.3, 0.8))

    def inject_attack_scenario(self, scenario_type: str) -> List[Dict[str, Any]]:
        """
        Injects a specific simulated attack pattern for demonstration purposes.
        Scenarios:
        - 'port_scan': Rapid scan across multiple destination ports
        - 'burst': High volume burst of requests from single IP
        - 'malformed': Stealth / invalid TCP flag scans (NULL, XMAS, SYN+FIN)
        - 'repeated_syn': High frequency connection attempts to ports
        """
        generated_packets = []
        attacker_ip = "192.168.1.99"
        target_ip = "192.168.1.50"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if scenario_type == "port_scan":
            # Target ports 20 to 35
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 3306, 3389, 8080]
            for p in ports_to_scan:
                pkt = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(50000, 60000),
                    "dst_port": p,
                    "protocol": "TCP",
                    "length": 60,
                    "tcp_flags": "S",
                    "info": f"SYN Scan probe to port {p}",
                    "is_simulated": True
                }
                generated_packets.append(pkt)
                self.packet_handler(pkt)
                time.sleep(0.05)

        elif scenario_type == "burst":
            # 45 packets in rapid succession
            for i in range(45):
                pkt = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(50000, 60000),
                    "dst_port": 80,
                    "protocol": "TCP",
                    "length": 74,
                    "tcp_flags": "S",
                    "info": f"HTTP GET request burst probe #{i+1}",
                    "is_simulated": True
                }
                generated_packets.append(pkt)
                self.packet_handler(pkt)
                time.sleep(0.02)

        elif scenario_type == "malformed":
            # Send Xmas scan, Null scan, and SYN+FIN
            malformed_cases = [
                ("FPU", "XMAS scan probe (FIN+PSH+URG flags)"),
                ("0", "NULL scan probe (zero flags set)"),
                ("SF", "Illegal SYN+FIN flag combo"),
                ("SR", "Contradictory SYN+RST flag combo")
            ]
            for flags, desc in malformed_cases:
                pkt = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(50000, 60000),
                    "dst_port": 80,
                    "protocol": "TCP",
                    "length": 60,
                    "tcp_flags": flags,
                    "info": desc,
                    "is_simulated": True
                }
                generated_packets.append(pkt)
                self.packet_handler(pkt)
                time.sleep(0.1)

        elif scenario_type == "repeated_syn":
            # 18 connection attempts
            for i in range(18):
                pkt = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(50000, 60000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "length": 64,
                    "tcp_flags": "S",
                    "info": f"Repeated SYN connection attempt #{i+1}",
                    "is_simulated": True
                }
                generated_packets.append(pkt)
                self.packet_handler(pkt)
                time.sleep(0.04)

        return generated_packets
