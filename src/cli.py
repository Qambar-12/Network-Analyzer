# src/cli.py
# The command-line entrypoint for running the analyzer. Parses arguments like --mode capture or --mode analyze and dispatches control to the relevant modules.
import argparse
from src.logger import setup_logging
from src.config_loader import load_config
from src.capture.manager import CaptureManager

def main():
    parser = argparse.ArgumentParser(prog="net-analyzer")
    parser.add_argument("--config", "-c", default="config/config.yaml")
    parser.add_argument("--mode", choices=["capture", "analyze", "all", "streamlit"], default="all")
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
    # TODO: dispatch to modules
    if args.mode == "capture":
        cm = CaptureManager(interface=args.iface, backend=args.backend, out_dir=args.out, bpf_filter=args.filter,
                        rotate_time_sec=args.rotate_time, rotate_size_mb=args.rotate_size)
        pcap, pkt_count = cm.start(duration=args.duration, packet_count=args.packet_count)
        logger.info("Capture finished: {} packets: {}", pcap, pkt_count)
    if args.mode in ("analyze", "all"):
        logger.info("Starting analysis module (placeholder)")

if __name__ == "__main__":
    main()
