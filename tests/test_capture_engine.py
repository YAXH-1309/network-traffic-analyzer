import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, TCP, UDP

from capture_engine import NetworkAnalyzer, lookup_mac_vendor
from storage import TrafficDatabase


class TestNetworkAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_traffic.db"
        self.db = TrafficDatabase(self.db_path)
        self.analyzer = NetworkAnalyzer(max_packets=200, db=self.db)
        self.analyzer.local_ips = {"192.168.1.50", "127.0.0.1"}

    def tearDown(self) -> None:
        self.analyzer.stop()
        self.db.close()
        self.tmpdir.cleanup()

    def test_protocol_classification_direction_and_db(self) -> None:
        https_pkt = Ether(src="AA:BB:CC:11:22:33", dst="00:1A:11:44:55:66") / IP(
            src="192.168.1.50", dst="142.250.190.78"
        ) / TCP(sport=54321, dport=443)
        http_pkt = Ether(src="00:00:0C:77:88:99", dst="AA:BB:CC:11:22:33") / IP(
            src="93.184.216.34", dst="192.168.1.50"
        ) / TCP(sport=80, dport=54322)
        dns_pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=51000, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="example.com")
        )
        icmp_pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / ICMP()
        arp_pkt = Ether(src="DE:AD:BE:EF:00:01", dst="AA:BB:CC:11:22:33") / ARP(
            psrc="192.168.1.1", pdst="192.168.1.50"
        )

        r_https = self.analyzer.analyze_packet(https_pkt, timestamp=1000.0)
        r_http = self.analyzer.analyze_packet(http_pkt, timestamp=1000.5)
        r_dns = self.analyzer.analyze_packet(dns_pkt, timestamp=1001.0)
        r_icmp = self.analyzer.analyze_packet(icmp_pkt, timestamp=1001.5)
        r_arp = self.analyzer.analyze_packet(arp_pkt, timestamp=1002.0)

        self.assertEqual(r_https["Protocol"], "HTTPS")
        self.assertEqual(r_https["Direction"], "Upload")
        self.assertEqual(r_http["Protocol"], "HTTP")
        self.assertEqual(r_http["Direction"], "Download")
        self.assertEqual(r_dns["Protocol"], "DNS")
        self.assertEqual(r_icmp["Protocol"], "ICMP")
        self.assertEqual(r_arp["Protocol"], "ARP")
        self.assertEqual(r_arp["Direction"], "Download")

        df = self.analyzer.get_dataframe()
        self.assertEqual(len(df), 5)

        stats = self.analyzer.get_stats()
        self.assertEqual(stats["total_packets"], 5)
        self.assertEqual(stats["protocol_count"], 5)
        self.assertGreater(stats["upload_mb"], 0)
        self.assertGreater(stats["download_mb"], 0)

        db_summary = self.db.get_summary()
        self.assertEqual(db_summary["total_packets"], 5)

    def test_device_identification_and_mac_vendor(self) -> None:
        self.assertEqual(lookup_mac_vendor("00:1A:11:12:34:56"), "Google")
        self.assertEqual(lookup_mac_vendor("B8:27:EB:01:02:03"), "Raspberry Pi")
        self.assertEqual(lookup_mac_vendor("02:11:22:33:44:55"), "Private / Randomized MAC")

        pkt = Ether(src="B8:27:EB:AA:BB:CC", dst="00:1A:11:DD:EE:FF") / IP(
            src="192.168.1.105", dst="192.168.1.50"
        ) / TCP(sport=12345, dport=443)
        self.analyzer.analyze_packet(pkt, timestamp=time.time())

        devices = self.analyzer.get_devices_dataframe()
        self.assertEqual(len(devices), 2)
        pi_row = devices[devices["IP Address"] == "192.168.1.105"].iloc[0]
        self.assertEqual(pi_row["Vendor"], "Raspberry Pi")
        self.assertEqual(pi_row["Role"], "Remote / Peer")

    def test_configurable_alerts_port_scan_sensitive_port_and_burst(self) -> None:
        self.analyzer.update_alert_config(
            port_scan_threshold=5,
            burst_packet_threshold=15,
            suspicious_ports=(23, 3389),
            cooldown_s=0.0,
        )
        now = time.time()

        # Trigger port scan (5 distinct ports)
        for port in range(1000, 1005):
            pkt = Ether() / IP(src="10.0.0.99", dst="192.168.1.50") / TCP(sport=40000 + port, dport=port)
            self.analyzer.analyze_packet(pkt, timestamp=now)

        # Trigger sensitive port alert (Telnet 23)
        telnet_pkt = Ether() / IP(src="10.0.0.55", dst="192.168.1.50") / TCP(sport=51111, dport=23)
        self.analyzer.analyze_packet(telnet_pkt, timestamp=now)

        # Trigger traffic burst (15 packets)
        for idx in range(15):
            burst_pkt = Ether() / IP(src="10.0.0.77", dst="192.168.1.50") / UDP(sport=50000 + idx, dport=9999)
            self.analyzer.analyze_packet(burst_pkt, timestamp=now)

        alert_types = {a["Type"] for a in self.analyzer.get_alerts()}
        self.assertIn("Port Scan Detected", alert_types)
        self.assertIn("Sensitive Port Activity", alert_types)
        self.assertIn("High Traffic Burst", alert_types)

        db_alerts = self.db.query_alerts()
        self.assertGreaterEqual(len(db_alerts), 3)

    def test_clear_and_markdown_report(self) -> None:
        pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / ICMP()
        self.analyzer.analyze_packet(pkt)

        report = self.analyzer.generate_markdown_report()
        self.assertIn("# Network Traffic Analysis Report", report)
        self.assertIn("ICMP", report)

        self.analyzer.clear(clear_db=True)
        stats = self.analyzer.get_stats()
        self.assertEqual(stats["total_packets"], 0)
        self.assertEqual(self.db.get_summary()["total_packets"], 0)
        self.assertTrue(self.analyzer.get_dataframe().empty)

    def test_simulation_mode_generates_packets(self) -> None:
        started = self.analyzer.start_simulation()
        self.assertTrue(started)
        time.sleep(0.7)
        self.analyzer.stop()

        stats = self.analyzer.get_stats()
        self.assertFalse(stats["running"])
        self.assertGreater(stats["total_packets"], 0)


if __name__ == "__main__":
    unittest.main()
