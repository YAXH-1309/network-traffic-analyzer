# LABMENTIX Cybersecurity Training Program

## Cybersecurity Project Report — 15-Day Hands-On Project Submission

| Field | Details |
| :--- | :--- |
| **Project Title** | Network Traffic Analyzer Using Python |
| **Student Name** | `[Enter your full name]` |
| **Batch / Cohort** | `[Enter batch / cohort]` |
| **Domain** | Network Security / Cybersecurity |
| **Trainer Name** | Ganesh Kuche |
| **Submission Date** | `[Enter submission date]` |
| **Difficulty Level** | Intermediate |

---

## Section 1 — Project Abstract

The **Network Traffic Analyzer** is a Python-based application designed to capture and examine network packet metadata on an authorized interface. It uses **Scapy** for packet capture and header parsing, **Streamlit** for the interactive web dashboard, **Pandas** and **Plotly** for data processing and visualization, and **SQLite** for persistent history. The application classifies common network and transport protocols (`TCP`, `UDP`, `DNS`, `HTTP`, `HTTPS`, `ICMP`, `ARP`), tracks source and destination IP addresses and ports, summarizes upload/download bandwidth, identifies observed devices via MAC OUI vendor prefixes, and provides configurable security alerts for port scans, sensitive ports, and traffic bursts. A built-in **Demo Mode** allows the dashboard to be demonstrated and tested without live packet-capture privileges. Automated verification completed five unit tests successfully and validated a populated Streamlit dashboard smoke test without exceptions.

---

## Section 2 — Introduction

### 2.1 Background

Network security involves protecting networked systems, devices, and data from unauthorized access, misuse, and disruption. Monitoring network traffic helps administrators understand communication patterns, troubleshoot bandwidth or connectivity issues, and investigate suspicious activity. Analyzing packet header metadata—such as IP addresses, ports, MAC addresses, protocol types, and packet sizes—provides actionable network visibility without storing sensitive application payloads.

### 2.2 Problem Statement

Small networks and learning environments often lack a simple, consolidated view of live packet activity, protocol distribution, communicating IP addresses, and traffic volume trends. Manual packet inspection can be time-consuming, while anomalous patterns such as port scanning or sudden traffic bursts may go unnoticed without automated thresholds. This project addresses the need for an accessible, modular Python dashboard for authorized network monitoring, device tracking, and basic security analysis.

### 2.3 Objectives

- **Build** a Python application that captures and analyzes network packet metadata in real time without storing payloads.
- **Classify** common protocols (`TCP`, `UDP`, `DNS`, `HTTP`, `HTTPS`, `ICMP`, `ARP`) and summarize source/destination IP addresses, ports, MAC vendors, and traffic direction.
- **Visualize** live bandwidth timelines, protocol distributions, and top talkers with interactive filtering and downloadable CSV and Markdown reports.
- **Persist** captured packet metadata and alerts in SQLite and **detect** configurable suspicious patterns such as port scans, sensitive port connections, and traffic bursts.

---

## Section 3 — Tools & Environment Setup

| Tool / Software | Version / Platform | Purpose |
| :--- | :--- | :--- |
| **Python** | `3.14.10` (Windows) | Core application logic, threading, and analysis |
| **Scapy** | `2.8.0` | Packet capture and protocol/header inspection |
| **Streamlit** | `1.67.0` | Interactive web dashboard UI |
| **Pandas** | `3.1.1` | Tabular data aggregation and filtering |
| **Plotly** | `7.2.0` | Interactive bandwidth, protocol, and top-talker charts |
| **streamlit-autorefresh** | `1.0.1` | Periodic live UI refresh during active capture |
| **SQLite (`sqlite3`)** | Python standard library | Persistent packet metadata and security alert history |

### 3.1 Lab / Environment Description

The project was developed and verified on Windows using Python `3.14.10` inside an isolated virtual environment (`venv`) located in `network-traffic-analyzer/`. All third-party dependencies were installed from `requirements.txt`. Demo Mode was used to exercise the live dashboard and verify populated chart/table rendering. Live packet capture on Windows requires installing **Npcap** (with WinPcap API-compatible mode) and running the terminal with Administrator privileges; Npcap was not installed on the test machine at the time of verification.

---

## Section 4 — Methodology / Step-by-Step Process

### Step 1 — Project Workspace & Virtual Environment Setup
Created the `network-traffic-analyzer` project directory, initialized an isolated Python virtual environment, and installed all required packages from `requirements.txt`.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> `[Insert Screenshot 1: Project folder, virtual environment, and successful dependency installation]`
> **Figure 1:** Python project setup and dependency installation.

### Step 2 — Packet Capture, Protocol & Device Analysis Engine (`capture_engine.py`)
Implemented the thread-safe `NetworkAnalyzer` engine using Scapy. For each packet, `analyze_packet()` extracts header metadata (`Timestamp`, `Time`, `Source`, `Destination`, `Protocol`, `Source Port`, `Destination Port`, `Source MAC`, `Destination MAC`, `Direction`, and `Size`) without retaining application payloads. Added offline MAC OUI vendor identification (`lookup_mac_vendor`), rolling upload/download throughput calculation, configurable anomaly detection (`AlertConfig` for port scans, sensitive ports, and traffic bursts), Markdown summary report generation, and a built-in Demo Mode (`start_simulation`).

### Step 3 — Persistent SQLite History (`storage.py`)
Implemented `TrafficDatabase` using Python's built-in `sqlite3` module with Write-Ahead Logging (`WAL`) mode enabled. Stored packet metadata and security alerts in `traffic_history.db` with indexed timestamp, protocol, and source IP columns, along with summary, query, and clear operations.

### Step 4 — Interactive Streamlit Dashboard (`app.py`)
Built the dark-mode Streamlit + Plotly dashboard organized into four tabs (**Live Monitor**, **Devices**, **Security Alerts**, and **Database History**). Added sidebar controls for interface selection, Live/Demo/Stop/Clear actions, protocol/IP/direction filters, cached hostname resolution, configurable security alert thresholds, and downloadable CSV and Markdown reports.

### Step 5 — Automated Verification & Smoke Testing (`tests/test_capture_engine.py`)
Created unit tests covering protocol classification, traffic direction, SQLite persistence, MAC vendor/device identification, configurable security alerts, Markdown report export, and Demo Mode simulation, followed by a populated Streamlit `AppTest` dashboard smoke test.

```powershell
python -m unittest discover -s tests -v
streamlit run app.py
```

> `[Insert Screenshot 2: Streamlit dashboard running in Demo Mode with populated traffic]`
> **Figure 2:** Populated Network Traffic Analyzer dashboard.

---

## Section 5 — Results & Observations

### 5.1 Summary of Findings

| # | Finding / Observation | Details | Severity / Impact |
| :---: | :--- | :--- | :--- |
| 1 | Automated unit tests | All 5 unit tests in `tests/test_capture_engine.py` passed (`Ran 5 tests in 1.160s`, `OK`). | Info |
| 2 | Dashboard smoke test | Populated Streamlit `AppTest` completed (`STREAMLIT_POPULATED_OK`) with no exceptions or Arrow errors. | Info |
| 3 | Demo Mode | Simulated traffic exercises all dashboard charts, device identification, port-scan alerts, and exports without live capture privileges. | Low |
| 4 | Live capture prerequisite | Npcap was not installed (`C:\Windows\System32\Npcap` absent); live packet sniffing on Windows requires Npcap and Administrator privileges. | Medium |

### 5.2 Analysis

The five passing unit tests confirm that packet classification, direction tagging, MAC OUI device identification, configurable alert rules, SQLite persistence, report generation, and simulation mode function as expected. The populated Streamlit smoke test confirms that simulated traffic renders cleanly across all dashboard components without PyArrow serialization errors. While these results validate the application logic and UI paths, live network sniffing remains to be tested separately after installing Npcap and running with elevated permissions on an authorized network interface.

---

## Section 6 — Challenges Faced

| Challenge Faced | How I Solved It |
| :--- | :--- |
| Dependency & environment isolation | Created a project-specific virtual environment (`venv`) and pinned dependencies in `requirements.txt`. |
| PyArrow mixed-type port column error | Cast `Source Port` and `Destination Port` columns to `str` before rendering the Streamlit packet table so numeric ports and `"-"` serialize cleanly. |
| Npcap unavailable on Windows test machine | Implemented a built-in Demo Mode (`start_simulation`) for end-to-end dashboard testing and surfaced clear setup instructions when live capture drivers are missing. |

---

## Section 7 — Learning Outcomes

- Learned how to structure a modular Python project using virtual environments and reproducible `requirements.txt` dependencies.
- Learned how Scapy parses Ethernet, ARP, IP/IPv6, TCP, UDP, DNS, and ICMP packet headers without storing sensitive payloads.
- Learned how to classify application protocols (`HTTP`, `HTTPS`, `DNS`), compute rolling upload/download throughput, and map MAC OUI prefixes to device vendors.
- Learned how to build a real-time multi-tab monitoring dashboard with Streamlit, Pandas, and Plotly, including PyArrow-safe DataFrame formatting.
- Learned how to persist traffic and alert records in SQLite (`WAL` mode) and validate behavior with `unittest` and Streamlit `AppTest`.

---

## Section 8 — Conclusion & Future Scope

### 8.1 Conclusion

The project delivered a working Python-based Network Traffic Analyzer featuring a thread-safe packet analysis engine (`capture_engine.py`), SQLite persistence (`storage.py`), an interactive multi-tab Streamlit dashboard (`app.py`), and an automated unit test suite (`tests/test_capture_engine.py`). All implemented objectives—protocol classification, bandwidth monitoring, device identification, filtering, configurable security alerts, persistent history, and CSV/Markdown report exports—were verified through automated tests and a populated dashboard smoke test. The primary remaining validation step is live interface capture after installing Npcap.

### 8.2 Future Scope

- Validate live packet capture across wired, Wi-Fi, and VPN interfaces with Npcap installed.
- Add PCAP file import/export (`rdpcap` / `wrpcap`) for offline forensic analysis.
- Implement configurable database retention policies and scheduled report exports.
- Expand anomaly detection with baseline traffic profiling and DNS tunneling heuristics.
- Add user authentication and PDF report generation for deployment in shared lab environments.

---

## Section 9 — References

1. [Scapy Documentation](https://scapy.readthedocs.io/) — `https://scapy.readthedocs.io/`
2. [Streamlit Documentation](https://docs.streamlit.io/) — `https://docs.streamlit.io/`
3. [Pandas Documentation](https://pandas.pydata.org/docs/) — `https://pandas.pydata.org/docs/`
4. [Plotly Python Documentation](https://plotly.com/python/) — `https://plotly.com/python/`
5. [Npcap Official Site](https://npcap.com/) — `https://npcap.com/`

---

## Declaration

### Student Declaration

I hereby declare that this project report is my own original work, completed as part of the **Labmentix Cybersecurity Training Program**. The work presented in this report is genuine, and all external references have been duly acknowledged.

| Student Signature | Date of Submission |
| :--- | :--- |
| ___________________________ | ___________________________ |
