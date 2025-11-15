# src/analysis/metrics_extractor.py

import os
import json
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from loguru import logger
from decimal import Decimal




class MetricsExtractor:
    def __init__(self, capture_dir: str, influx_cfg: dict = None):
        self.capture_dir = capture_dir
        self.influx_cfg = influx_cfg

    # -------------------- Helper Methods -------------------- #
    def _safe_rdpcap(self, path):
        """Read pcap safely; return packets list or empty on failure."""
        try:
            return rdpcap(path)
        except Exception as e:
            logger.exception(f"Failed to read {path}: {e}")
            return []

    def _compute_timestamps(self, pkts):
        """Return list of packet timestamps."""
        return [float(getattr(p, "time", 0.0)) for p in pkts]

    def _compute_interarrival_ms(self, timestamps):
        """Inter-arrival times (ms)."""
        if len(timestamps) < 2:
            return []
        return np.diff(np.array(timestamps)) * 1000.0

    def _compute_jitter_ms(self, iat_ms):
        """Compute jitter using RFC3550-like mean absolute difference."""
        if len(iat_ms) < 2:
            return 0.0
        diffs = np.abs(np.diff(np.array(iat_ms)))
        return float(np.mean(diffs))

    def _estimate_icmp_rtt_ms(self, pkts):
        """Estimate ICMP RTTs (ms) by matching echo request/reply pairs."""
        reqs, rtts = {}, []
        for p in pkts:
            if not (IP in p and ICMP in p):
                continue
            ip, icmp = p[IP], p[ICMP]
            ts = float(getattr(p, "time", 0.0))
            key = (ip.src, ip.dst, getattr(icmp, "id", None), getattr(icmp, "seq", None))
            if icmp.type == 8:  # echo-request
                reqs[key] = ts
            elif icmp.type == 0:  # echo-reply
                rev = (ip.dst, ip.src, getattr(icmp, "id", None), getattr(icmp, "seq", None))
                if rev in reqs:
                    rtt = (ts - reqs[rev]) * 1000.0
                    if rtt >= 0:
                        rtts.append(rtt)
        return rtts

    def _estimate_tcp_rtt_ms(self, pkts, max_window_seconds=10.0):
        """Estimate TCP RTTs from sequence/ack pairs."""
        outstanding = defaultdict(dict)
        rtts = []

        def fkey(src, dst, sport, dport):
            return (src, dst, sport, dport)

        for p in pkts:
            if IP not in p or TCP not in p:
                continue
            ts = float(getattr(p, "time", 0.0))
            ip, tcp = p[IP], p[TCP]
            src, dst, sport, dport = ip.src, ip.dst, tcp.sport, tcp.dport
            key_fwd = fkey(src, dst, sport, dport)
            key_rev = fkey(dst, src, dport, sport)
            seq, ack = int(tcp.seq), int(tcp.ack)
            payload_len = len(tcp.payload)

            if payload_len > 0 or (tcp.flags & 0x02):  # SYN or data
                if seq not in outstanding[key_fwd]:
                    outstanding[key_fwd][seq] = ts

            if tcp.flags & 0x10:  # ACK
                to_remove = []
                for s_seq, s_ts in list(outstanding[key_rev].items()):
                    if ack >= (s_seq + 1):
                        rtt = (ts - s_ts) * 1000.0
                        if 0 <= rtt <= (max_window_seconds * 1000.0):
                            rtts.append(rtt)
                            to_remove.append(s_seq)
                for s in to_remove:
                    outstanding[key_rev].pop(s, None)
        return rtts

    # -------------------- Main Metric Function -------------------- #
    def extract_metrics(self, pcap_file: str):
        """Compute all metrics, save JSON, and stream to InfluxDB if configured."""
        pkts = self._safe_rdpcap(pcap_file)
        total_packets = len(pkts)
        timestamps = self._compute_timestamps(pkts)

        duration = max(0.0, (max(timestamps) - min(timestamps))) if timestamps else 0.0
        total_bytes = sum(len(p) for p in pkts)
        throughput_bps = (total_bytes * 8 / duration) if duration > 0 else 0.0
        packet_rate_pps = (total_packets / duration) if duration > 0 else 0.0
        avg_pkt_size = (total_bytes / total_packets) if total_packets > 0 else 0.0

        # Jitter & inter-arrival
        iat_ms = self._compute_interarrival_ms(timestamps)
        jitter_rfc_ms = self._compute_jitter_ms(iat_ms)
        iat_mean_ms = float(np.mean(iat_ms)) if len(iat_ms) > 0 else 0.0

        # Protocol breakdown
        proto_counts = Counter()
        for p in pkts:
            if IP in p:
                if TCP in p:
                    proto_counts["TCP"] += 1
                elif UDP in p:
                    proto_counts["UDP"] += 1
                elif ICMP in p:
                    proto_counts["ICMP"] += 1
                else:
                    proto_counts["IP_OTHER"] += 1
            else:
                proto_counts["NON_IP"] += 1

        # Latency estimates
        icmp_rtts = self._estimate_icmp_rtt_ms(pkts)
        tcp_rtts = self._estimate_tcp_rtt_ms(pkts)
        icmp_rtt_mean = float(np.mean(icmp_rtts)) if icmp_rtts else 0.0
        tcp_rtt_mean = float(np.mean(tcp_rtts)) if tcp_rtts else 0.0

        # Build final metrics
        metrics = {
            "file_name": os.path.basename(pcap_file),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "capture_duration_sec": round(duration, 6),
            "throughput_bps": round(throughput_bps, 2),
            "packet_rate_pps": round(packet_rate_pps, 2),
            "avg_pkt_size_bytes": round(avg_pkt_size, 2),
            "interarrival_ms_mean": round(iat_mean_ms, 2),
            "jitter_rfc_ms": round(jitter_rfc_ms, 2),
            "icmp_rtt_mean_ms": round(icmp_rtt_mean, 2),
            "tcp_rtt_mean_ms": round(tcp_rtt_mean, 2),
            "protocol_counts": dict(proto_counts),
            "analyzed_at": datetime.utcnow().isoformat(),
        }

        # Save JSON
        json_path = self._save_metrics(metrics)

        # Optional InfluxDB write
        if self.influx_cfg:
            self._write_to_influx(metrics)

        return metrics

    # -------------------- Output Helpers -------------------- #
    def _save_metrics(self, metrics: dict):
        """Save metrics as JSON next to PCAP file."""
        json_path = os.path.join(
            self.capture_dir, metrics["file_name"].replace(".pcap", "_metrics.json")
        )
        def _json_default(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            return str(obj)
        try:
            with open(json_path, "w") as f:
                json.dump(metrics, f, indent=4, default=_json_default)
            logger.info(f"Wrote metrics to {json_path}")
        except Exception:
            logger.exception(f"Failed to write metrics JSON for {json_path}")
        return json_path

    def _write_to_influx(self, metrics: dict):
        """Write numeric fields to InfluxDB."""
        try:
            from src.storage.influx_client import InfluxStorage
            url = self.influx_cfg.get("url")
            token = self.influx_cfg.get("token")
            org = self.influx_cfg.get("org")
            bucket = self.influx_cfg.get("bucket")
            influx = InfluxStorage(url=url, token=token, org=org, bucket=bucket)
            influx.write_metrics(metrics)
        except Exception:
            logger.exception("Failed to write metrics to InfluxDB")
