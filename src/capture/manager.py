# src/capture/manager.py
import os
from pathlib import Path
from loguru import logger
from typing import Optional, Tuple
import time
import json

from .utils import timestamped_filename, ensure_dir, write_metadata, file_size_mb
from .backends.scapy_backend import ScapyBackend
from .backends.pyshark_backend import PysharkBackend

class CaptureManager:
    """
    High-level capture manager. Controls backend, rotation (time & size), metadata creation.
    """

    def __init__(self, interface: str = "Wi-Fi", backend: str = "scapy", out_dir: str = "data/captures",
                 bpf_filter: Optional[str]=None, rotate_time_sec: Optional[int]=None, rotate_size_mb: Optional[float]=None):
        self.interface = interface
        self.backend_name = backend.lower()
        self.out_dir = ensure_dir(out_dir)
        self.bpf_filter = bpf_filter
        self.rotate_time_sec = rotate_time_sec
        self.rotate_size_mb = rotate_size_mb
        self._backend = None
        self._current_pcap = None
        self._packets = 0
        self._start_ts = None

    def _create_backend(self, pcap_path: str):
        if self.backend_name == "scapy":
            return ScapyBackend(interface=self.interface, bpf_filter=self.bpf_filter, output_dir=str(self.out_dir), rotate_every_sec=self.rotate_time_sec)
        elif self.backend_name == "pyshark":
            return PysharkBackend(interface=self.interface, bpf_filter=self.bpf_filter, output_file=pcap_path)
        else:
            raise ValueError("Unsupported backend: " + self.backend_name)

    def start(self, duration: Optional[int]=None, packet_count: Optional[int]=None) -> Tuple[str, float]:
        """
        Start capture. Returns final pcap path and packets captured (if available).
        """
        fname = timestamped_filename("capture", "pcap")
        pcap_path = str(self.out_dir / fname)
        logger.info("Starting capture: backend={}, iface={}, out={}", self.backend_name, self.interface, pcap_path)
        self._start_ts = time.time()
        self._current_pcap = pcap_path
        backend = self._create_backend(pcap_path)
        if self.backend_name == "scapy":
            self._backend = backend.start(pcap_path,duration=duration, packet_count=packet_count)
        else:
            self._backend = backend.start(duration=duration, packet_count=packet_count)
        # Monitor for size-based rotation or completion
        try:
            while True:
                time.sleep(1)
                # size-based rotation
                if self.rotate_size_mb:
                    size = file_size_mb(self._current_pcap)
                    if size >= self.rotate_size_mb:
                        new_name = timestamped_filename("capture", "pcap").replace(".pcap", f".rot{int(time.time())}.pcap")
                        new_path = str(self.out_dir / new_name)
                        logger.info("Size threshold reached ({} MB). Rotating to {}", size, new_path)
                        # For scapy backend we can call internal rotate; for others, restart
                        if hasattr(self._backend, "_rotate"):
                            self._backend._rotate(new_path)  # scapy backend supports rotate
                            self._current_pcap = new_path
                        else:
                            # restart pyshark backend with new file
                            self._backend.stop()
                            self._backend = self._create_backend(new_path).start(duration=duration, packet_count=packet_count)
                            self._current_pcap = new_path
                # Check if backend stopped (thread ended)
                if hasattr(self._backend, "_running"):
                    running = getattr(self._backend, "_running")
                    if running is False:
                        logger.info("Backend reported stopped")
                        break
                # time-based duration handled by backend; if duration specified we will exit when backend stops
                # Add optional additional termination checks here
        except KeyboardInterrupt:
            logger.warning("KeyboardInterrupt received, stopping capture")
        finally:
            final_path, pkt_count = self._backend.stop()
            end_ts = time.time()
            meta = {
                "pcap": final_path,
                "interface": self.interface,
                "backend": self.backend_name,
                "filter": self.bpf_filter,
                "start_ts": int(self._start_ts),
                "end_ts": int(end_ts),
                "duration_sec": int(end_ts - self._start_ts),
                "packet_count": pkt_count
            }
            meta_file = write_metadata(final_path, meta)
            logger.info("Wrote metadata to {}", meta_file)
            return final_path, pkt_count
