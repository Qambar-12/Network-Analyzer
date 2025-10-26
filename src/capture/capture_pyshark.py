# src/capture/capture_pyshark.py
# Uses the PyShark library (a Python wrapper for Wireshark/TShark).
# Captures and decodes packets using TShark's engine, providing richer, pre-parsed protocol details.
# suitable for deeper packet-level dissection or remote captures.
import pyshark
from loguru import logger

# A BPF (Berkeley Packet Filter) is a method for capturing and filtering network packets at the operating system level to isolate specific traffic. It uses a specific syntax to define filters based on criteria like IP addresses, ports, and protocols, which allows applications to efficiently process only the data they need.
def capture_pyshark(interface: str, duration: int=60, bpf_filter: str=None, out_pcap: str="data/pyshark_capture.pcap"):
    logger.info("Starting pyshark capture: interface={}, duration={}, filter={}", interface, duration, bpf_filter)
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter, output_file=out_pcap)
    capture.sniff(timeout=duration)
    logger.info("Pyshark wrote capture to {}", out_pcap)
    return out_pcap
