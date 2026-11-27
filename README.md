# Network Traffic Analyzer Using Python

A real-time network traffic monitoring and packet analysis dashboard built with **Python**, **Scapy**, **Streamlit**, **Pandas**, and **Plotly**.

## Features

- **Live Packet Capture**: Captures incoming and outgoing packets in real time using Scapy (without storing application payloads).
- **Demo Simulation Mode**: Built-in synthetic traffic generator so you can preview and test the dashboard even without Npcap or administrator privileges.
- **Protocol Analysis**: Detects `TCP`, `UDP`, `DNS`, `HTTP`, `HTTPS`, `ICMP`, `ARP`, and `OTHER`.
- **Bandwidth & Direction Monitoring**: Tracks upload, download, local, and external traffic volumes and rolling throughput (KB/s).
- **IP & MAC Monitoring**: Displays source/destination IP addresses, ports, MAC addresses, and optional cached hostname resolution.
- **Anomaly Detection**: Flags potential port scans and sudden packet bursts.
- **Interactive Filtering & Charts**: Filter by protocol, IP address, or direction and explore live Plotly visualizations.
- **CSV Export**: Download filtered traffic logs as a CSV report.

## Project Structure

```text
network-traffic-analyzer/
├── app.py                     # Streamlit interactive dashboard
├── capture_engine.py          # Scapy packet capture, analysis, and anomaly engine
├── requirements.txt           # Python dependencies
├── README.md                  # Documentation
└── tests/
    └── test_capture_engine.py # Unit tests for packet & anomaly analysis
```

## Installation

1. Create and activate a virtual environment (Python 3.10+):

   **Windows (PowerShell):**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

   **Linux / macOS:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

> **Note for Live Capture:**
> - **Windows**: Install [Npcap](https://npcap.com/) (enable WinPcap API-compatible mode) and run your terminal as Administrator.
> - **Linux/macOS**: Run with `sudo` or grant `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities.

## Run the Application

```bash
streamlit run app.py
```

Open the local URL printed in the terminal (usually `http://localhost:8501`).

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Security Notice

Only capture traffic on networks and devices you own or have explicit authorization to monitor. This application records packet header metadata only and does not store application payloads.
