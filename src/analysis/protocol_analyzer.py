# src/analysis/protocol_analyzer.py

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
import os
import json

class ProtocolAnalyzer:
    def __init__(self, capture_dir: str):
        self.capture_dir = capture_dir

    def analyze_protocols(self, pcap_file: str):
        packets = rdpcap(pcap_file)
        protocol_stats = defaultdict(int)

        for pkt in packets:
            if IP in pkt:
                if TCP in pkt:
                    protocol_stats["TCP"] += 1
                elif UDP in pkt:
                    protocol_stats["UDP"] += 1
                elif ICMP in pkt:
                    protocol_stats["ICMP"] += 1
                else:
                    protocol_stats["Other_IP"] += 1
            else:
                protocol_stats["Non_IP"] += 1

        result = {"file_name": os.path.basename(pcap_file), "protocol_breakdown": dict(protocol_stats)}

        json_path = os.path.join(
            self.capture_dir, result["file_name"].replace(".pcap", "_protocols.json")
        )
        with open(json_path, "w") as f:
            json.dump(result, f, indent=4)

        return result
