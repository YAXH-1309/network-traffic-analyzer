from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime
from functools import lru_cache
import random
import socket
from threading import Event, Lock, Thread
import time
from typing import Any

import pandas as pd

try:
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, get_if_list, sniff
    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - depends on environment
    ARP = DNS = ICMP = IP = IPv6 = TCP = UDP = None  # type: ignore[assignment]
    get_if_list = None  # type: ignore[assignment]
    sniff = None  # type: ignore[assignment]
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(exc)


HTTP_PORTS = {80, 8000, 8080}
HTTPS_PORTS = {443, 8443}
DNS_PORTS = {53, 5353}

PACKET_COLUMNS = [
    "Timestamp",
    "Time",
    "Source",
    "Destination",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Source MAC",
    "Destination MAC",
    "Direction",
    "Size",
]


def _detect_local_ips() -> set[str]:
    """Return IPv4 addresses associated with this host for traffic direction tagging."""
    ips = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr:
                ips.add(addr)
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ips.add(sock.getsockname()[0])
    except OSError:
        pass

    return ips


@lru_cache(maxsize=512)
def resolve_hostname(ip: str) -> str:
    """Resolve an IP address to a hostname, returning the original IP on failure."""
    if not ip or ip in {"Unknown", "-"} or ":" in ip and ip.count(":") == 5:
        return ip
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ip


class NetworkAnalyzer:
    """Thread-safe packet capture, protocol analysis, bandwidth, and anomaly engine."""

    def __init__(self, max_packets: int = 5000) -> None:
        self.max_packets = max_packets
        self.packets: deque[dict[str, Any]] = deque(maxlen=max_packets)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=200)
        self.running = False
        self.mode = "idle"
        self.stop_event = Event()
        self.lock = Lock()
        self.thread: Thread | None = None
        self.error: str | None = None
        self.interface: str | None = None

        self.local_ips: set[str] = _detect_local_ips()
        self.total_packets = 0
        self.total_bytes = 0
        self.upload_bytes = 0
        self.download_bytes = 0
        self.protocol_counts: Counter[str] = Counter()

        # Sliding windows for anomaly detection
        self._port_probe_window: dict[tuple[str, str], deque[tuple[float, int | str]]] = defaultdict(deque)
        self._rate_window: dict[str, deque[float]] = defaultdict(deque)
        self._recent_alert_keys: dict[tuple[str, str], float] = {}

    def get_hostname(self, ip: str) -> str:
        """Resolve an IP address to a hostname safely."""
        return resolve_hostname(ip)

    def list_interfaces(self) -> list[str]:
        """Return available network interface names reported by Scapy."""
        if not SCAPY_AVAILABLE or get_if_list is None:
            return []
        try:
            return list(get_if_list())
        except Exception:
            return []

    def _classify_direction(self, src_ip: str, dst_ip: str) -> str:
        src_local = src_ip in self.local_ips
        dst_local = dst_ip in self.local_ips
        if src_local and dst_local:
            return "Local"
        if src_local:
            return "Upload"
        if dst_local:
            return "Download"
        return "External"

    def _classify_transport(
        self,
        sport: int | str,
        dport: int | str,
        is_tcp: bool,
        is_udp: bool,
        has_dns: bool = False,
    ) -> str:
        ports = {p for p in (sport, dport) if isinstance(p, int)}
        if has_dns or ports & DNS_PORTS:
            return "DNS"
        if is_tcp:
            if ports & HTTPS_PORTS:
                return "HTTPS"
            if ports & HTTP_PORTS:
                return "HTTP"
            return "TCP"
        if is_udp:
            return "UDP"
        return "OTHER"

    def _check_anomalies(self, record: dict[str, Any], now: float) -> None:
        src = str(record["Source"])
        dst = str(record["Destination"])
        dport = record["Destination Port"]
        if src in {"Unknown", "-"}:
            return

        # 1. Port scan detection: >= 10 distinct destination ports to same target within 10s
        if isinstance(dport, int):
            key = (src, dst)
            probe_q = self._port_probe_window[key]
            probe_q.append((now, dport))
            while probe_q and now - probe_q[0][0] > 10.0:
                probe_q.popleft()
            distinct_ports = {p for _, p in probe_q}
            if len(distinct_ports) >= 10:
                alert_key = ("Port Scan", f"{src}->{dst}")
                if now - self._recent_alert_keys.get(alert_key, 0.0) > 15.0:
                    self._recent_alert_keys[alert_key] = now
                    self.alerts.appendleft(
                        {
                            "Time": record["Time"],
                            "Severity": "High",
                            "Type": "Port Scan Detected",
                            "Source": src,
                            "Destination": dst,
                            "Details": f"{len(distinct_ports)} distinct destination ports probed within 10s",
                        }
                    )

        # 2. High packet burst detection: >= 200 packets from one source within 5s
        rate_q = self._rate_window[src]
        rate_q.append(now)
        while rate_q and now - rate_q[0] > 5.0:
            rate_q.popleft()
        if len(rate_q) >= 200:
            alert_key = ("Traffic Spike", src)
            if now - self._recent_alert_keys.get(alert_key, 0.0) > 15.0:
                self._recent_alert_keys[alert_key] = now
                self.alerts.appendleft(
                    {
                        "Time": record["Time"],
                        "Severity": "Medium",
                        "Type": "High Traffic Burst",
                        "Source": src,
                        "Destination": dst,
                        "Details": f"{len(rate_q)} packets from {src} in 5s",
                    }
                )

    def _record_metadata(self, record: dict[str, Any]) -> dict[str, Any]:
        now = float(record["Timestamp"])
        size = int(record["Size"])
        direction = record["Direction"]
        protocol = record["Protocol"]

        with self.lock:
            self.packets.append(record)
            self.total_packets += 1
            self.total_bytes += size
            if direction == "Upload":
                self.upload_bytes += size
            elif direction == "Download":
                self.download_bytes += size
            self.protocol_counts[protocol] += 1
            self._check_anomalies(record, now)

        return record

    def analyze_packet(self, packet: Any, timestamp: float | None = None) -> dict[str, Any]:
        """Extract metadata from a Scapy packet without retaining payload bytes."""
        now = time.time() if timestamp is None else float(timestamp)
        src_mac = getattr(packet, "src", "-") or "-"
        dst_mac = getattr(packet, "dst", "-") or "-"

        record: dict[str, Any] = {
            "Timestamp": now,
            "Time": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
            "Source": "Unknown",
            "Destination": "Unknown",
            "Protocol": "OTHER",
            "Source Port": "-",
            "Destination Port": "-",
            "Source MAC": src_mac,
            "Destination MAC": dst_mac,
            "Direction": "External",
            "Size": len(packet),
        }

        if SCAPY_AVAILABLE:
            if IP is not None and IP in packet:
                ip_layer = packet[IP]
                record["Source"] = ip_layer.src
                record["Destination"] = ip_layer.dst
            elif IPv6 is not None and IPv6 in packet:
                ip6_layer = packet[IPv6]
                record["Source"] = ip6_layer.src
                record["Destination"] = ip6_layer.dst
            elif ARP is not None and ARP in packet:
                arp_layer = packet[ARP]
                record["Source"] = arp_layer.psrc or src_mac
                record["Destination"] = arp_layer.pdst or dst_mac
                record["Protocol"] = "ARP"

            has_dns = DNS is not None and DNS in packet
            if TCP is not None and TCP in packet:
                tcp_layer = packet[TCP]
                record["Source Port"] = int(tcp_layer.sport)
                record["Destination Port"] = int(tcp_layer.dport)
                record["Protocol"] = self._classify_transport(
                    record["Source Port"],
                    record["Destination Port"],
                    is_tcp=True,
                    is_udp=False,
                    has_dns=has_dns,
                )
            elif UDP is not None and UDP in packet:
                udp_layer = packet[UDP]
                record["Source Port"] = int(udp_layer.sport)
                record["Destination Port"] = int(udp_layer.dport)
                record["Protocol"] = self._classify_transport(
                    record["Source Port"],
                    record["Destination Port"],
                    is_tcp=False,
                    is_udp=True,
                    has_dns=has_dns,
                )
            elif ICMP is not None and ICMP in packet:
                record["Protocol"] = "ICMP"
            elif IPv6 is not None and IPv6 in packet and getattr(packet[IPv6], "nh", None) == 58:
                record["Protocol"] = "ICMP"

        record["Direction"] = self._classify_direction(
            str(record["Source"]), str(record["Destination"])
        )
        return self._record_metadata(record)

    def _capture_worker(self, iface: str | None) -> None:
        try:
            sniff(
                iface=iface,
                prn=self.analyze_packet,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set(),
            )
        except Exception as exc:  # pragma: no cover - requires live driver/OS error
            self.error = (
                f"Live capture failed: {exc}. "
                "On Windows, ensure Npcap is installed and run with Administrator privileges; "
                "on Linux/macOS, run with sudo/CAP_NET_RAW. You can also test using Demo Simulation."
            )
        finally:
            self.running = False
            self.mode = "idle"

    def _simulation_worker(self) -> None:
        local_ip = next(
            (ip for ip in self.local_ips if not ip.startswith("127.") and ":" not in ip),
            "192.168.1.42",
        )
        remote_hosts = [
            "142.250.190.78",   # Google
            "151.101.1.69",     # Fastly CDN
            "104.16.132.229",   # Cloudflare
            "8.8.8.8",          # Google DNS
            "1.1.1.1",          # Cloudflare DNS
            "192.168.1.1",      # Gateway
            "52.94.236.248",    # AWS
        ]
        profiles = [
            ("HTTPS", 443, (120, 1460), 0.42),
            ("HTTP", 80, (100, 1200), 0.12),
            ("DNS", 53, (64, 240), 0.16),
            ("TCP", 22, (74, 900), 0.12),
            ("UDP", 51820, (80, 1100), 0.10),
            ("ICMP", "-", (64, 98), 0.05),
            ("ARP", "-", (42, 60), 0.03),
        ]
        protos = [p[0] for p in profiles]
        weights = [p[3] for p in profiles]
        profile_map = {p[0]: (p[1], p[2]) for p in profiles}

        tick = 0
        while not self.stop_event.is_set():
            burst = random.randint(2, 6)
            for _ in range(burst):
                if self.stop_event.is_set():
                    break
                now = time.time()
                proto = random.choices(protos, weights=weights, k=1)[0]
                service_port, size_range = profile_map[proto]
                is_upload = random.random() < 0.45
                remote_ip = random.choice(remote_hosts)

                if proto == "ARP":
                    src_ip = local_ip if is_upload else "192.168.1.1"
                    dst_ip = "192.168.1.1" if is_upload else local_ip
                    sport, dport = "-", "-"
                elif proto == "ICMP":
                    src_ip = local_ip if is_upload else remote_ip
                    dst_ip = remote_ip if is_upload else local_ip
                    sport, dport = "-", "-"
                else:
                    ephemeral = random.randint(49152, 65000)
                    if is_upload:
                        src_ip, dst_ip = local_ip, remote_ip
                        sport, dport = ephemeral, service_port
                    else:
                        src_ip, dst_ip = remote_ip, local_ip
                        sport, dport = service_port, ephemeral

                self._record_metadata(
                    {
                        "Timestamp": now,
                        "Time": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
                        "Source": src_ip,
                        "Destination": dst_ip,
                        "Protocol": proto,
                        "Source Port": sport,
                        "Destination Port": dport,
                        "Source MAC": "aa:bb:cc:11:22:33" if is_upload else "de:ad:be:ef:00:01",
                        "Destination MAC": "de:ad:be:ef:00:01" if is_upload else "aa:bb:cc:11:22:33",
                        "Direction": self._classify_direction(src_ip, dst_ip),
                        "Size": random.randint(*size_range),
                    }
                )

            # Periodically emit a realistic port scan sequence so anomaly UI can be exercised
            tick += 1
            if tick % 25 == 0:
                scanner_ip = "192.168.1.99"
                for probe_port in range(20, 32):
                    now = time.time()
                    self._record_metadata(
                        {
                            "Timestamp": now,
                            "Time": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
                            "Source": scanner_ip,
                            "Destination": local_ip,
                            "Protocol": "TCP",
                            "Source Port": 55000 + probe_port,
                            "Destination Port": probe_port,
                            "Source MAC": "00:11:22:33:44:55",
                            "Destination MAC": "aa:bb:cc:11:22:33",
                            "Direction": self._classify_direction(scanner_ip, local_ip),
                            "Size": 60,
                        }
                    )

            self.stop_event.wait(0.45)

        self.running = False
        self.mode = "idle"

    def start(self, iface: str | None = None) -> bool:
        """Start live packet capture using Scapy."""
        if self.running:
            return False
        if not SCAPY_AVAILABLE or sniff is None:
            self.error = (
                f"Scapy is unavailable ({SCAPY_IMPORT_ERROR}). "
                "Install dependencies or use Demo Simulation."
            )
            return False

        self.error = None
        self.interface = iface
        self.stop_event.clear()
        self.running = True
        self.mode = "live"
        self.thread = Thread(target=self._capture_worker, args=(iface,), daemon=True)
        self.thread.start()
        return True

    def start_simulation(self) -> bool:
        """Start simulated packet generation for environments without Npcap/root access."""
        if self.running:
            return False
        self.error = None
        self.interface = "Simulated NIC"
        self.stop_event.clear()
        self.running = True
        self.mode = "simulation"
        self.thread = Thread(target=self._simulation_worker, daemon=True)
        self.thread.start()
        return True

    def stop(self) -> None:
        """Stop any running capture or simulation thread."""
        self.stop_event.set()
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        self.running = False
        self.mode = "idle"

    def clear(self) -> None:
        """Reset all captured packets, alerts, and traffic counters."""
        with self.lock:
            self.packets.clear()
            self.alerts.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.upload_bytes = 0
            self.download_bytes = 0
            self.protocol_counts.clear()
            self._port_probe_window.clear()
            self._rate_window.clear()
            self._recent_alert_keys.clear()
            self.error = None

    def get_dataframe(self) -> pd.DataFrame:
        """Return a thread-safe DataFrame snapshot of captured packet metadata."""
        with self.lock:
            rows = list(self.packets)
        if not rows:
            return pd.DataFrame(columns=PACKET_COLUMNS)
        return pd.DataFrame(rows, columns=PACKET_COLUMNS)

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return a snapshot list of recent security/anomaly alerts."""
        with self.lock:
            return list(self.alerts)

    def get_stats(self, window_seconds: float = 5.0) -> dict[str, Any]:
        """Compute summary metrics and rolling upload/download throughput."""
        now = time.time()
        cutoff = now - window_seconds

        with self.lock:
            recent_upload = 0
            recent_download = 0
            src_ips: set[str] = set()
            dst_ips: set[str] = set()
            for pkt in self.packets:
                src = str(pkt["Source"])
                dst = str(pkt["Destination"])
                if src not in {"Unknown", "-"}:
                    src_ips.add(src)
                if dst not in {"Unknown", "-"}:
                    dst_ips.add(dst)
                if pkt["Timestamp"] >= cutoff:
                    if pkt["Direction"] == "Upload":
                        recent_upload += int(pkt["Size"])
                    elif pkt["Direction"] == "Download":
                        recent_download += int(pkt["Size"])

            return {
                "running": self.running,
                "mode": self.mode,
                "interface": self.interface or "Default",
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_mb": self.total_bytes / (1024 * 1024),
                "upload_mb": self.upload_bytes / (1024 * 1024),
                "download_mb": self.download_bytes / (1024 * 1024),
                "upload_kbps": (recent_upload / 1024.0) / max(window_seconds, 1.0),
                "download_kbps": (recent_download / 1024.0) / max(window_seconds, 1.0),
                "protocol_count": len(self.protocol_counts),
                "unique_sources": len(src_ips),
                "unique_destinations": len(dst_ips),
                "alert_count": len(self.alerts),
                "error": self.error,
            }


analyzer = NetworkAnalyzer()
