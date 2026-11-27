from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from capture_engine import analyzer

st.set_page_config(
    page_title="Network Traffic Analyzer",
    page_icon="🌐",
    layout="wide",
)

# Subtle dark dashboard styling
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
st.caption("Real-time packet capture, protocol inspection, bandwidth monitoring & anomaly detection")

# Sidebar Controls
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
    "Detected Network Interface",
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
if col_start.button("▶ Live Capture", use_container_width=True, disabled=stats["running"]):
    analyzer.start(selected_iface)
    st.rerun()

if col_sim.button("🧪 Demo Mode", use_container_width=True, disabled=stats["running"]):
    analyzer.start_simulation()
    st.rerun()

col_stop, col_clear = st.sidebar.columns(2)
if col_stop.button("⏹ Stop", use_container_width=True, disabled=not stats["running"]):
    analyzer.stop()
    st.rerun()

if col_clear.button("🗑 Clear", use_container_width=True):
    analyzer.clear()
    st.rerun()

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

# Surface capture errors clearly with quick fallback option
if stats["error"]:
    st.error(stats["error"])
    if not stats["running"] and st.button("Start Demo Simulation Instead"):
        analyzer.start_simulation()
        st.rerun()

# Refresh stats & data
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

# KPI Metrics Row
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total Packets", f"{stats['total_packets']:,}", help="All packets captured in current session")
k2.metric(
    "Total Data",
    f"{stats['total_mb']:.2f} MB",
    delta=f"↑ {stats['upload_mb']:.2f} / ↓ {stats['download_mb']:.2f} MB",
)
k3.metric(
    "Live Throughput (5s)",
    f"{stats['upload_kbps'] + stats['download_kbps']:.1f} KB/s",
    delta=f"↑ {stats['upload_kbps']:.1f} | ↓ {stats['download_kbps']:.1f} KB/s",
)
k4.metric("Detected Protocols", stats["protocol_count"])
k5.metric("Unique IPs", f"{stats['unique_sources']} src / {stats['unique_destinations']} dst")

st.divider()

if filtered_df.empty:
    if df.empty:
        st.info(
            "No packets captured yet. Click **▶ Live Capture** in the sidebar to sniff your network interface, "
            "or click **🧪 Demo Mode** to preview live traffic analytics without Npcap/Administrator privileges."
        )
    else:
        st.warning("No packets match the active filters. Adjust or clear your sidebar filters.")
else:
    # Row 1: Traffic Timeline & Protocol Distribution
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
        st.plotly_chart(fig_timeline, use_container_width=True)

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
        st.plotly_chart(fig_pie, use_container_width=True)

    # Row 2: Top Source IPs & Top Destination Ports
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
        st.plotly_chart(fig_src, use_container_width=True)

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
            st.plotly_chart(fig_ports, use_container_width=True)

# Security & Anomaly Alerts
alerts = analyzer.get_alerts()
st.subheader(f"Security & Anomaly Alerts ({len(alerts)})")
if alerts:
    st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
else:
    st.success("No suspicious port scans or traffic bursts detected.")

# Captured Packet Table & CSV Export
st.subheader("Captured Packet Log")
if not filtered_df.empty:
    display_df = filtered_df.drop(columns=["Timestamp"]).iloc[::-1].head(max_rows).copy()
    if resolve_names:
        display_df["Source Host"] = display_df["Source"].map(analyzer.get_hostname)
        display_df["Destination Host"] = display_df["Destination"].map(analyzer.get_hostname)

    st.dataframe(display_df, use_container_width=True, hide_index=True)

    export_df = filtered_df.drop(columns=["Timestamp"])
    csv_bytes = export_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇ Export Filtered Traffic as CSV",
        data=csv_bytes,
        file_name="network_traffic_report.csv",
        mime="text/csv",
        use_container_width=False,
    )
