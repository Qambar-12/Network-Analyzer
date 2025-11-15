# src/cli.py
# The command-line entrypoint for running the analyzer. Parses arguments like --mode capture or --mode analyze and dispatches control to the relevant modules.
import argparse , os
from dotenv import load_dotenv
from src.logger import setup_logging
from src.config_loader import load_config
from src.capture.manager import CaptureManager
from src.analysis.metrics_extractor import MetricsExtractor
from src.analysis.protocol_analyzer import ProtocolAnalyzer
from src.analysis.summary_report import SummaryReport

def main():
    parser = argparse.ArgumentParser(prog="net-analyzer")
    parser.add_argument("--config", "-c", default="config/config.yaml")
    parser.add_argument("--mode", choices=["capture", "analyze", "summary", "streamlit"], default="all")
    parser.add_argument("--iface", "-i", default="Wi-Fi", help="Network interface to capture from")
    parser.add_argument("--backend", "-b", choices=["scapy", "pyshark"], default="scapy", help="Capture backend to use")
    parser.add_argument("--out", "-o", default="data/captures", help="Output directory for captures")
    parser.add_argument("--filter", "-f", default='tcp or udp', help="BPF filter for capture")
    parser.add_argument("--rotate-time", type=int, default=None, help="Rotate capture files every N seconds")
    parser.add_argument("--rotate-size", type=float, default=None, help="Rotate capture files every N MB")
    parser.add_argument("--duration", type=int, default=None, help="Total capture duration in seconds")
    parser.add_argument("--packet-count", type=int, default=None, help="Total number of packets to capture")
    args = parser.parse_args()
    logger = setup_logging("INFO")
    cfg = load_config(args.config)
    logger.info("Loaded configuration")
    capture_dir = "data/captures"
    load_dotenv()
    influx_cfg = {
        "token": os.getenv("INFLUX_TOKEN"),
        "url": os.getenv("INFLUX_URL", "http://localhost:8086"),
        "org": os.getenv("INFLUX_ORG", "networkorg"),
        "bucket": os.getenv("INFLUX_BUCKET", "network_metrics"),
    }

    # TODO: dispatch to modules
    if args.mode == "capture":
        cm = CaptureManager(interface=args.iface, backend=args.backend, out_dir=args.out, bpf_filter=args.filter,
                        rotate_time_sec=args.rotate_time, rotate_size_mb=args.rotate_size)
        pcap, pkt_count = cm.start(duration=args.duration, packet_count=args.packet_count)
        cm._write_to_influx(pcap)
        logger.info("Capture finished: {} packets: {}", pcap, pkt_count)
    elif args.mode in ("analyze"):
        logger.info("Starting analysis module (placeholder)")
        metrics = MetricsExtractor(capture_dir, influx_cfg=influx_cfg)
        analyzer = ProtocolAnalyzer(capture_dir)
        for file in os.listdir(capture_dir):
            if file.endswith(".pcap"):
                pcap_path = os.path.join(capture_dir, file)
                m = metrics.extract_metrics(pcap_path)
                metrics._save_metrics(m)
                metrics._write_to_influx(m)
                analyzer.analyze_protocols(pcap_path)
    elif args.mode == "summary":
        summary = SummaryReport(capture_dir)
        file = summary.generate_summary()
        print(f"Summary report generated: {file}")
if __name__ == "__main__":
    main()
