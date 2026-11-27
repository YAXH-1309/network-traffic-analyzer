import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, TCP, UDP

from capture_engine import NetworkAnalyzer


class TestNetworkAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = NetworkAnalyzer(max_packets=100)
        self.analyzer.local_ips = {"192.168.1.50", "127.0.0.1"}

    def test_protocol_classification_and_direction(self) -> None:
        https_pkt = Ether() / IP(src="192.168.1.50", dst="142.250.190.78") / TCP(sport=54321, dport=443)
        http_pkt = Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=54322)
        dns_pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=51000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        icmp_pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / ICMP()
        arp_pkt = Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.50")

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

    def test_port_scan_detection(self) -> None:
        now = time.time()
        for port in range(100, 112):
            pkt = Ether() / IP(src="10.0.0.99", dst="192.168.1.50") / TCP(sport=40000 + port, dport=port)
            self.analyzer.analyze_packet(pkt, timestamp=now)

        alerts = self.analyzer.get_alerts()
        self.assertTrue(any(a["Type"] == "Port Scan Detected" for a in alerts))

    def test_clear_resets_state(self) -> None:
        pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / ICMP()
        self.analyzer.analyze_packet(pkt)
        self.analyzer.clear()

        stats = self.analyzer.get_stats()
        self.assertEqual(stats["total_packets"], 0)
        self.assertEqual(stats["total_bytes"], 0)
        self.assertTrue(self.analyzer.get_dataframe().empty)
        self.assertEqual(self.analyzer.get_alerts(), [])

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
