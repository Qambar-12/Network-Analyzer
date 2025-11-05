from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
import time
import json  # for safe string conversion if needed

def capture_traffic(duration=10, interface=None):
    """Capture packets for `duration` seconds and return list."""
    packets = sniff(timeout=duration, iface=interface)
    return packets

def analyze_packets(packets):
    total_packets = len(packets)
    if total_packets == 0:
        return {}

    first_time = packets[0].time
    last_time = packets[-1].time
    duration_sec = last_time - first_time if last_time > first_time else 0

    total_bytes = sum(len(pkt) for pkt in packets)
    throughput_bps = (total_bytes * 8 / duration_sec) if duration_sec > 0 else 0
    avg_pkt_size_bytes = total_bytes / total_packets

    # Protocol counts
    protocol_counts = Counter()
    src_ips = Counter()

    for pkt in packets:
        if IP in pkt:
            src_ips[pkt[IP].src] += 1
            if TCP in pkt:
                protocol_counts["TCP"] += 1
            elif UDP in pkt:
                protocol_counts["UDP"] += 1
            elif ICMP in pkt:
                protocol_counts["ICMP"] += 1
            else:
                protocol_counts["OTHER"] += 1

    top_talkers = src_ips.most_common(10)

    # Flatten protocol counts for InfluxDB
    flattened_protocol_counts = {f"protocol_{k.lower()}": v for k, v in protocol_counts.items()}

    # Optional: store top talkers as JSON string (for debugging/viewing only)
    top_talkers_str = json.dumps(top_talkers)

    return {
        "total_packets": total_packets,
        "duration_sec": duration_sec,
        "total_bytes": total_bytes,
        "throughput_bps": throughput_bps,
        "avg_pkt_size_bytes": avg_pkt_size_bytes,
        **flattened_protocol_counts,  # flattened TCP/UDP/ICMP counts
        "top_talkers": top_talkers_str,  # safe string
    }
