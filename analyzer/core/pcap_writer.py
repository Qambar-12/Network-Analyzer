from scapy.utils import wrpcap
import os
from datetime import datetime

PCAP_DIR = "/app/files"

def save_pcap(packets):
    """Save packets to a timestamped pcap file."""
    if not os.path.exists(PCAP_DIR):
        os.makedirs(PCAP_DIR)

    filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    path = os.path.join(PCAP_DIR, filename)

    wrpcap(path, packets)
    return path
