# src/capture/capture_scapy.py
# Uses the Scapy library for packet capturing and crafting.
# Captures raw packets from the network interface. Scapy is powerful for low-level interaction and analysis.
from scapy.all import sniff, wrpcap
from typing import Optional
from loguru import logger


# A BPF (Berkeley Packet Filter) is a method for capturing and filtering network packets at the operating system level to isolate specific traffic. It uses a specific syntax to define filters based on criteria like IP addresses, ports, and protocols, which allows applications to efficiently process only the data they need.
def capture_packets(interface: str, duration: int=60, bpf_filter: Optional[str]=None, out_pcap: str="data/capture.pcap"):
    logger.info("Starting scapy capture: interface={}, duration={}, filter={}", interface, duration, bpf_filter)
    pkts = sniff(iface=interface, timeout=duration, filter=bpf_filter)
    logger.info("Captured {} packets, writing to {}", len(pkts), out_pcap)
    wrpcap(out_pcap, pkts)
    return out_pcap
