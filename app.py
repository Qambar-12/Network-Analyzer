import streamlit as st
import os
import time
import threading
from dotenv import load_dotenv

from src.capture.manager import CaptureManager
from src.analysis.metrics_extractor import MetricsExtractor
from src.analysis.protocol_analyzer import ProtocolAnalyzer
from src.storage.influx_client import InfluxStorage
from src.logger import setup_logging
from src.config_loader import load_config

# Streamlit Setup
st.set_page_config(page_title="Network Analyzer", layout="wide")
load_dotenv()
logger = setup_logging("INFO")

CAPTURE_DIR = "data/captures"
METRIC_DIR = "data/metrics"

config = load_config("config/config.yaml")

# InfluxDB config
influx_cfg = {
    "token": os.getenv("INFLUX_TOKEN"),
    "url": os.getenv("INFLUX_URL", "http://localhost:8086"),
    "org": os.getenv("INFLUX_ORG", "networkorg"),
    "bucket": os.getenv("INFLUX_BUCKET", "network_metrics"),
}

# Shared state
if "capturing" not in st.session_state:
    st.session_state.capturing = False
if "capture_thread" not in st.session_state:
    st.session_state.capture_thread = None


# ----------------------------------------------------
# BACKGROUND THREAD
# ----------------------------------------------------
def run_capture(interface, backend, bpf, duration):
    cm = CaptureManager(
        interface=interface,
        backend=backend,
        out_dir=CAPTURE_DIR,
        bpf_filter=bpf
    )

    st.session_state.capturing = True
    pcap_file, pkt_count = cm.start(duration=duration)

    logger.info(f"Capture finished: {pcap_file} packets={pkt_count}")
    cm._write_to_influx(pcap_file)
    st.session_state.capturing = False


# ----------------------------------------------------
# SIDEBAR NAVIGATION
# ----------------------------------------------------
st.sidebar.title("📡 Network Analyzer")
selected = st.sidebar.radio(
    "Navigation",
    ["Capture", "Analyze", "Grafana Dashboard", "AI Assistant"],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.caption("Developed by QABH – Streamlit UI + Grafana Visualization")


# ----------------------------------------------------
# 1) CAPTURE TAB
# ----------------------------------------------------
if selected == "Capture":

    st.title("📥 Packet Capture")
    st.write("Capture live network packets from Scapy/PyShark backend.")

    iface = st.selectbox("Capture Interface", ["Wi-Fi", "Ethernet", "eth0"])
    backend = st.radio("Backend", ["scapy", "pyshark"], horizontal=True)
    bpf = st.text_input("BPF Filter", "tcp or udp")
    duration = st.number_input("Duration (seconds)", value=10, min_value=1)

    col1, col2 = st.columns([1, 1])

    with col1:
        if st.button("▶ Start Capture", disabled=st.session_state.capturing):
            st.session_state.capture_thread = threading.Thread(
                target=run_capture,
                args=(iface, backend, bpf, duration),
                daemon=True
            )
            st.session_state.capture_thread.start()

    with col2:
        if st.button("⏹ Force Stop"):
            st.session_state.capturing = False

    if st.session_state.capturing:
        st.info("🔴 Capture in progress...")
    else:
        st.success("🟢 Idle")

    st.divider()
    st.subheader("📄 Saved PCAP Files")

    # Auto-update only while capturing
    if st.session_state.capturing:
        time.sleep(1)
        st.experimental_rerun()
        
    pcaps = [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap")]
    st.write(pcaps if pcaps else "No captures available.")


# ----------------------------------------------------
# 2) ANALYSIS TAB
# ----------------------------------------------------
elif selected == "Analyze":

    st.title("📊 Packet Analysis")
    st.write("Run offline analysis on any captured PCAP file.")

    pcaps = [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap")]
    pcap_selected = st.selectbox("Choose PCAP File", pcaps)

    if st.button("Run Analysis"):
        metrics = MetricsExtractor(CAPTURE_DIR, influx_cfg=influx_cfg)
        analyzer = ProtocolAnalyzer(CAPTURE_DIR)

        pcap_path = os.path.join(CAPTURE_DIR, pcap_selected)

        m = metrics.extract_metrics(pcap_path)
        metrics._save_metrics(m)
        metrics._write_to_influx(m)

        proto_res = analyzer.analyze_protocols(pcap_path)

        st.json(m)
        st.write(proto_res)
    import json

    pcaps = sorted([f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap")])
    analyzed_jsons = sorted([f for f in os.listdir(CAPTURE_DIR) if f.endswith(".json")])

    options = []
    for p in pcaps:
        options.append(p)
    for j in analyzed_jsons:
        # show metric JSON files alongside pcaps
        options.append(j)

    if not options:
        st.write("No captures or analysis JSON files found.")
    else:
        selected = st.selectbox("Choose file (PCAP or analysis JSON)", options)

        # If a JSON metrics file is selected, offer to view it and (if possible) re-run analysis.
        if selected and selected.endswith(".json"):
            json_path = os.path.join(CAPTURE_DIR, selected)
            try:
                with open(json_path, "r", encoding="utf-8") as fh:
                    metrics_json = json.load(fh)
                st.subheader("Saved analysis JSON")
                st.json(metrics_json)
            except Exception:
                logger.exception("Failed to read analysis JSON %s", json_path)
                st.error(f"Could not open {selected}")

            # try to find a corresponding pcap to re-run analysis
            base = selected.replace("_metrics.json", "").replace(".metrics.json", "").replace(".json", "")
            corresponding_pcap = base + ".pcap"
            if os.path.exists(os.path.join(CAPTURE_DIR, corresponding_pcap)):
                if st.button("Re-run analysis on corresponding PCAP"):
                    metrics = MetricsExtractor(CAPTURE_DIR, influx_cfg=influx_cfg)
                    analyzer = ProtocolAnalyzer(CAPTURE_DIR)
                    pcap_path = os.path.join(CAPTURE_DIR, corresponding_pcap)
                    m = metrics.extract_metrics(pcap_path)
                    metrics._save_metrics(m)
                    metrics._write_to_influx(m)
                    proto_res = analyzer.analyze_protocols(pcap_path)
                    st.json(m)
                    st.write(proto_res)
            else:
                st.info("No corresponding PCAP found to re-run analysis.")

        # If a PCAP is selected, run analysis as before
        elif selected and selected.endswith(".pcap"):
            pcap_path = os.path.join(CAPTURE_DIR, selected)
            if st.button("Run Analysis"):
                metrics = MetricsExtractor(CAPTURE_DIR, influx_cfg=influx_cfg)
                analyzer = ProtocolAnalyzer(CAPTURE_DIR)
                m = metrics.extract_metrics(pcap_path)
                metrics._save_metrics(m)
                metrics._write_to_influx(m)
                proto_res = analyzer.analyze_protocols(pcap_path)
                st.json(m)
                st.write(proto_res)


# ----------------------------------------------------
# 3) GRAFANA DASHBOARD TAB
# ----------------------------------------------------
elif selected == "Grafana Dashboard":

    st.set_page_config(layout="wide")
    st.title("Grafana Dashboard Embedded in Streamlit")

    # ----------------------------
    # PANEL URLS (Your URLs)
    # ----------------------------

    row1 = [
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=2",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=4",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=5",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=6",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=4",
    ]

    row2 = [
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=8",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=9",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=10",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=11",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=12",
    ]

    row3 = [
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=14",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=15",
    ]

    row4 = [
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=14",
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=15",
    ]

    row5 = [
        "http://localhost:3000/d-solo/cf47q469kkxs0f/test?orgId=1&from=1763212325964&to=1763226494281&panelId=17",
    ]


    # ----------------------------
    # RENDER FUNCTION
    # ----------------------------
    def render_row(title, url_list, height=320):
        with st.expander(title, expanded=False):  
            cols = st.columns(len(url_list))
            for col, url in zip(cols, url_list):
                with col:
                    st.components.v1.iframe(url, height=height)


    # ----------------------------
    # SHOW COLLAPSIBLE ROWS
    # ----------------------------

    render_row("Row 1 — Traffic Overview", row1, height=280)
    render_row("Row 2 — Packet Metrics", row2, height=280)
    render_row("Row 3 — Time-Series Metrics", row3, height=330)
    render_row("Row 4 — Protocol Analytics", row4, height=330)
    render_row("Row 5 — Capture Metadata", row5, height=380)

# ============================================
# 4) AI NETWORK ASSISTANT
# ============================================
elif selected == "AI Assistant":
    from src.agent import crew

    st.header("🤖 NetSage AI – Intelligent Network Assistant")

    user_input = st.text_area("Enter your network analysis query:", height=150)
    if st.button("Ask NetSage AI"):
        if not user_input.strip():
            st.warning("Please enter a query.")
        else:
            with st.spinner("NetSage AI is analyzing..."):
                response = crew.kickoff(json.loads(user_input))
            st.subheader("Response:")
            st.markdown(response)