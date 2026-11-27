# Network Traffic Analyzer Using Python

A real-time network traffic monitoring, device identification, and security analysis dashboard built with **Python**, **Scapy**, **Streamlit**, **Pandas**, **Plotly**, and **SQLite**.

## Roadmap Coverage

1. **Phase 1 – Basic Implementation**: Live Scapy packet capture, protocol detection (`TCP`, `UDP`, `DNS`, `HTTP`, `HTTPS`, `ICMP`, `ARP`), source/destination IP & port tracking, and an interactive Streamlit dashboard.
2. **Phase 2 – Advanced Monitoring**: Real-time upload/download throughput & timeline charts, offline MAC OUI vendor & device identification, and protocol/IP/direction traffic filtering.
3. **Phase 3 – Security Analysis**: Real-time detection of port scans, high-rate traffic bursts, and sensitive port access (`23`, `445`, `3389`, `4444`, `5900`) with configurable thresholds in the sidebar.
4. **Phase 4 – Final Project**: Persistent SQLite storage (`traffic_history.db`), downloadable CSV & Markdown summary reports, automated unit test suite, and complete documentation.

## Project Architecture

```text
Network Interface ──▶ Scapy Capture Engine (capture_engine.py)
                            │
                            ├──▶ Protocol, Port, Direction & MAC OUI Analysis
                            ├──▶ Configurable Anomaly & Port-Scan Detector
                            ├──▶ SQLite Persistence (storage.py / traffic_history.db)
                            └──▶ Streamlit + Plotly Dashboard (app.py)
```

## Project Structure

```text
network-traffic-analyzer/
├── app.py                     # Streamlit interactive dashboard (4 tabs)
├── capture_engine.py          # Packet capture, analysis, devices & alerts engine
├── storage.py                 # Thread-safe SQLite database persistence
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
└── tests/
    └── test_capture_engine.py # Unit tests for capture, devices, alerts & SQLite
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
> - **Windows**: Install [Npcap](https://npcap.com/) (with WinPcap API-compatible mode) and run your terminal as Administrator.
> - **Linux/macOS**: Run with `sudo` or grant `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities.
> - **No Driver / Demo Mode**: Click **🧪 Demo** in the dashboard sidebar to run the built-in synthetic traffic generator.

## Run the Application

```bash
streamlit run app.py
```

Open the local URL printed in the terminal (normally `http://localhost:8501`).

## Run Automated Tests

```bash
python -m unittest discover -s tests -v
```

## Security Notice

Only capture traffic on networks and devices you own or have explicit authorization to monitor. This application records packet header metadata only and does not store application payloads.
