from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from capture_engine import analyzer

st.set_page_config(
    page_title="Network Traffic Analyzer",
    page_icon="🌐",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    div[data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 12px 16px;
    }
    .status-pill {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-bottom: 8px;
    }
    .status-live { background: #123d28; color: #3fb950; border: 1px solid #2ea043; }
    .status-sim { background: #1c2d4d; color: #58a6ff; border: 1px solid #388bfd; }
    .status-idle { background: #2d2124; color: #f85149; border: 1px solid #da3633; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🌐 Network Traffic Analyzer")
st.caption("Real-time packet capture, protocol inspection, bandwidth monitoring, device ID & security analytics")

# Sidebar: Control Panel
st.sidebar.header("Control Panel")
stats = analyzer.get_stats()

if stats["running"] and stats["mode"] == "live":
    st.sidebar.markdown(
        f'<span class="status-pill status-live">● Live Capture ({stats["interface"]})</span>',
        unsafe_allow_html=True,
    )
elif stats["running"] and stats["mode"] == "simulation":
    st.sidebar.markdown(
        '<span class="status-pill status-sim">● Demo Simulation Active</span>',
        unsafe_allow_html=True,
    )
else:
    st.sidebar.markdown(
        '<span class="status-pill status-idle">● Capture Stopped</span>',
        unsafe_allow_html=True,
    )

interfaces = analyzer.list_interfaces()
iface_choice = st.sidebar.selectbox(
    "Network Interface",
    options=["Default interface", *interfaces, "Custom..."],
    index=0,
)
if iface_choice == "Custom...":
    selected_iface = st.sidebar.text_input("Custom Interface Name", placeholder="e.g. Ethernet or eth0").strip() or None
elif iface_choice == "Default interface":
    selected_iface = None
else:
    selected_iface = iface_choice

col_start, col_sim = st.sidebar.columns(2)
if col_start.button("▶ Live", width="stretch", disabled=stats["running"]):
    analyzer.start(selected_iface)
    st.rerun()

if col_sim.button("🧪 Demo", width="stretch", disabled=stats["running"]):
    analyzer.start_simulation()
    st.rerun()

col_stop, col_clear = st.sidebar.columns(2)
if col_stop.button("⏹ Stop", width="stretch", disabled=not stats["running"]):
    analyzer.stop()
    st.rerun()

if col_clear.button("🗑 Clear", width="stretch"):
    analyzer.clear(clear_db=False)
    st.rerun()

# Sidebar: Traffic Filters
st.sidebar.divider()
st.sidebar.header("Traffic Filters")
auto_refresh = st.sidebar.checkbox("Auto-refresh dashboard", value=True)
refresh_ms = st.sidebar.slider("Refresh interval (ms)", min_value=500, max_value=5000, value=1000, step=500)

if auto_refresh and stats["running"]:
    st_autorefresh(interval=refresh_ms, key="traffic_refresh")

protocol_options = ["TCP", "UDP", "DNS", "HTTP", "HTTPS", "ICMP", "ARP", "OTHER"]
selected_protocols = st.sidebar.multiselect(
    "Protocols",
    options=protocol_options,
    default=[],
    placeholder="All protocols",
)
ip_filter = st.sidebar.text_input("Filter by IP (Source or Destination)", placeholder="e.g. 192.168.1.")
direction_filter = st.sidebar.selectbox(
    "Direction",
    options=["All", "Upload", "Download", "Local", "External"],
    index=0,
)
resolve_names = st.sidebar.checkbox("Resolve hostnames (cached)", value=False)
max_rows = st.sidebar.slider("Table rows to display", min_value=25, max_value=500, value=100, step=25)

# Sidebar: Configurable Security Alerts (Phase 3)
st.sidebar.divider()
with st.sidebar.expander("Configurable Security Alerts", expanded=False):
    cfg = analyzer.alert_config
    enable_scan = st.checkbox("Detect Port Scans", value=cfg.enable_port_scan)
    scan_ports = st.slider("Port scan threshold (ports)", min_value=3, max_value=50, value=cfg.port_scan_threshold)
    scan_window = st.slider("Port scan window (sec)", min_value=5, max_value=60, value=int(cfg.port_scan_window_s))

    enable_burst = st.checkbox("Detect Traffic Bursts", value=cfg.enable_traffic_burst)
    burst_pkts = st.slider("Burst threshold (packets)", min_value=20, max_value=1000, value=cfg.burst_packet_threshold, step=10)

    enable_sens = st.checkbox("Monitor Sensitive Ports", value=cfg.enable_suspicious_ports)
    sens_ports_text = st.text_input(
        "Sensitive ports (comma-separated)",
        value=",".join(str(p) for p in cfg.suspicious_ports),
    )
    parsed_ports: list[int] = []
    for token in sens_ports_text.split(","):
        token = token.strip()
        if token.isdigit():
            parsed_ports.append(int(token))

    analyzer.update_alert_config(
        enable_port_scan=enable_scan,
        port_scan_threshold=scan_ports,
        port_scan_window_s=float(scan_window),
        enable_traffic_burst=enable_burst,
        burst_packet_threshold=burst_pkts,
        enable_suspicious_ports=enable_sens,
        suspicious_ports=tuple(parsed_ports) if parsed_ports else cfg.suspicious_ports,
    )

# Surface capture errors clearly with quick Demo fallback
if stats["error"]:
    st.error(stats["error"])
    if not stats["running"] and st.button("Start Demo Simulation Instead"):
        analyzer.start_simulation()
        st.rerun()

# KPI Row
k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Total Packets", f"{stats['total_packets']:,}")
k2.metric(
    "Total Data",
    f"{stats['total_mb']:.2f} MB",
    delta=f"↑ {stats['upload_mb']:.2f} / ↓ {stats['download_mb']:.2f} MB",
)
k3.metric(
    "Live Throughput",
    f"{stats['upload_kbps'] + stats['download_kbps']:.1f} KB/s",
    delta=f"↑ {stats['upload_kbps']:.1f} | ↓ {stats['download_kbps']:.1f} KB/s",
)
k4.metric("Protocols", stats["protocol_count"])
k5.metric("Devices", stats["device_count"])
k6.metric("Alerts", stats["alert_count"])

df = analyzer.get_dataframe()
filtered_df = df.copy()
if not filtered_df.empty:
    if selected_protocols:
        filtered_df = filtered_df[filtered_df["Protocol"].isin(selected_protocols)]
    if ip_filter.strip():
        query = ip_filter.strip().lower()
        mask = (
            filtered_df["Source"].astype(str).str.lower().str.contains(query, regex=False)
            | filtered_df["Destination"].astype(str).str.lower().str.contains(query, regex=False)
        )
        filtered_df = filtered_df[mask]
    if direction_filter != "All":
        filtered_df = filtered_df[filtered_df["Direction"] == direction_filter]

alerts = analyzer.get_alerts()
devices_df = analyzer.get_devices_dataframe()

tab_live, tab_devices, tab_alerts, tab_db = st.tabs(
    [
        "📊 Live Monitor",
        f"💻 Devices ({len(devices_df)})",
        f"🚨 Security Alerts ({len(alerts)})",
        "🗄 Database History",
    ]
)

with tab_live:
    if filtered_df.empty:
        if df.empty:
            st.info(
                "No packets captured yet. Click **▶ Live** in the sidebar to capture from your network interface, "
                "or **🧪 Demo** to preview live analytics without Npcap/Administrator privileges."
            )
        else:
            st.warning("No packets match the active filters. Adjust or clear your sidebar filters.")
    else:
        c_left, c_right = st.columns([2, 1])

        with c_left:
            st.subheader("Bandwidth & Packet Timeline")
            timeline_df = (
                filtered_df.groupby(["Time", "Direction"], as_index=False)["Size"]
                .sum()
                .assign(KB=lambda d: d["Size"] / 1024.0)
            )
            fig_timeline = px.area(
                timeline_df,
                x="Time",
                y="KB",
                color="Direction",
                template="plotly_dark",
                labels={"KB": "Traffic (KB/s)", "Time": "Timestamp"},
                color_discrete_map={
                    "Download": "#3fb950",
                    "Upload": "#58a6ff",
                    "Local": "#d29922",
                    "External": "#bc8cff",
                },
            )
            fig_timeline.update_layout(margin=dict(l=10, r=10, t=20, b=10), height=320, legend_title_text="")
            st.plotly_chart(fig_timeline, width="stretch")

        with c_right:
            st.subheader("Protocol Distribution")
            proto_counts = filtered_df["Protocol"].value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Packets"]
            fig_pie = px.pie(
                proto_counts,
                names="Protocol",
                values="Packets",
                hole=0.45,
                template="plotly_dark",
            )
            fig_pie.update_layout(margin=dict(l=10, r=10, t=20, b=10), height=320)
            st.plotly_chart(fig_pie, width="stretch")

        c_src, c_ports = st.columns(2)
        with c_src:
            st.subheader("Top Source IP Addresses")
            top_src = (
                filtered_df.groupby("Source", as_index=False)
                .agg(Packets=("Size", "count"), KB=("Size", lambda s: s.sum() / 1024.0))
                .sort_values("Packets", ascending=False)
                .head(10)
            )
            fig_src = px.bar(
                top_src.sort_values("Packets", ascending=True),
                x="Packets",
                y="Source",
                orientation="h",
                text="Packets",
                hover_data={"KB": ":.2f"},
                template="plotly_dark",
                color="KB",
                color_continuous_scale="Blues",
            )
            fig_src.update_layout(margin=dict(l=10, r=10, t=20, b=10), height=320, coloraxis_showscale=False)
            st.plotly_chart(fig_src, width="stretch")

        with c_ports:
            st.subheader("Top Destination Ports")
            port_df = filtered_df[filtered_df["Destination Port"] != "-"].copy()
            if port_df.empty:
                st.info("No TCP/UDP port data in the current filtered traffic.")
            else:
                port_df["Port"] = port_df["Destination Port"].astype(str)
                top_ports = (
                    port_df.groupby(["Port", "Protocol"], as_index=False)
                    .size()
                    .rename(columns={"size": "Packets"})
                    .sort_values("Packets", ascending=False)
                    .head(10)
                )
                fig_ports = px.bar(
                    top_ports,
                    x="Port",
                    y="Packets",
                    color="Protocol",
                    template="plotly_dark",
                )
                fig_ports.update_layout(margin=dict(l=10, r=10, t=20, b=10), height=320)
                st.plotly_chart(fig_ports, width="stretch")

        st.subheader("Captured Packet Log")
        display_df = filtered_df.drop(columns=["Timestamp"]).iloc[::-1].head(max_rows).copy()
        display_df["Source Port"] = display_df["Source Port"].astype(str)
        display_df["Destination Port"] = display_df["Destination Port"].astype(str)
        if resolve_names:
            display_df["Source Host"] = display_df["Source"].map(analyzer.get_hostname)
            display_df["Destination Host"] = display_df["Destination"].map(analyzer.get_hostname)

        st.dataframe(display_df, width="stretch", hide_index=True)

        dl_col1, dl_col2, _ = st.columns([1, 1, 2])
        export_df = filtered_df.drop(columns=["Timestamp"])
        dl_col1.download_button(
            label="⬇ Export Traffic CSV",
            data=export_df.to_csv(index=False).encode("utf-8"),
            file_name="network_traffic_report.csv",
            mime="text/csv",
            width="stretch",
        )
        dl_col2.download_button(
            label="📄 Export Summary Report (.md)",
            data=analyzer.generate_markdown_report(filtered_df).encode("utf-8"),
            file_name="network_summary_report.md",
            mime="text/markdown",
            width="stretch",
        )

with tab_devices:
    st.subheader("Identified Network Devices & MAC Vendors")
    if devices_df.empty:
        st.info("No network devices observed yet.")
    else:
        view_devices = devices_df.copy()
        if resolve_names:
            view_devices["Hostname"] = view_devices["IP Address"].map(analyzer.get_hostname)
        st.dataframe(view_devices, width="stretch", hide_index=True)

        fig_dev = px.bar(
            devices_df.head(10),
            x="IP Address",
            y="Total KB",
            color="Vendor",
            template="plotly_dark",
            title="Top Devices by Traffic Volume (KB)",
        )
        fig_dev.update_layout(margin=dict(l=10, r=10, t=40, b=10), height=320)
        st.plotly_chart(fig_dev, width="stretch")

with tab_alerts:
    st.subheader("Real-Time Security & Anomaly Alerts")
    st.caption(
        f"Active Rules — Port Scan: {'On' if analyzer.alert_config.enable_port_scan else 'Off'} "
        f"({analyzer.alert_config.port_scan_threshold} ports / {analyzer.alert_config.port_scan_window_s:.0f}s) | "
        f"Traffic Burst: {'On' if analyzer.alert_config.enable_traffic_burst else 'Off'} "
        f"({analyzer.alert_config.burst_packet_threshold} pkts / {analyzer.alert_config.burst_window_s:.0f}s) | "
        f"Sensitive Ports: {'On' if analyzer.alert_config.enable_suspicious_ports else 'Off'}"
    )
    if alerts:
        alerts_df = pd.DataFrame(alerts)
        st.dataframe(alerts_df, width="stretch", hide_index=True)
        st.download_button(
            label="⬇ Export Alerts CSV",
            data=alerts_df.to_csv(index=False).encode("utf-8"),
            file_name="security_alerts_report.csv",
            mime="text/csv",
        )
    else:
        st.success("No suspicious port scans, sensitive port connections, or traffic bursts detected.")

with tab_db:
    st.subheader("SQLite Persistent Traffic History")
    if analyzer.db is None:
        st.warning("Database persistence is disabled.")
    else:
        db_summary = analyzer.db.get_summary()
        d1, d2, d3, d4 = st.columns(4)
        d1.metric("Stored Packets", f"{db_summary['total_packets']:,}")
        d2.metric("Stored Data", f"{db_summary['total_mb']:.2f} MB")
        d3.metric("Unique Sources", db_summary["unique_sources"])
        d4.metric("Stored Alerts", db_summary["total_alerts"])

        hist_packets = analyzer.db.query_packets(limit=250)
        hist_alerts = analyzer.db.query_alerts(limit=100)

        col_hist_dl, col_hist_clr, _ = st.columns([1, 1, 2])
        if not hist_packets.empty:
            col_hist_dl.download_button(
                label="⬇ Export Stored History CSV",
                data=hist_packets.to_csv(index=False).encode("utf-8"),
                file_name="sqlite_traffic_history.csv",
                mime="text/csv",
                width="stretch",
            )
        if col_hist_clr.button("🧹 Clear SQLite History", width="stretch"):
            analyzer.clear(clear_db=True)
            st.rerun()

        st.markdown("**Recent Stored Packets (SQLite)**")
        st.dataframe(hist_packets, width="stretch", hide_index=True)
        if not hist_alerts.empty:
            st.markdown("**Recent Stored Alerts (SQLite)**")
            st.dataframe(hist_alerts, width="stretch", hide_index=True)
