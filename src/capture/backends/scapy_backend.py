# src/capture/backends/scapy_backend.py
from scapy.all import sniff, PcapWriter
from typing import Optional, Callable
from loguru import logger
import threading
import time

class ScapyBackend:
    """
    Simple Scapy backend that writes packets to a rotating PcapWriter.
    Exposes start/stop methods.
    """

    def __init__(self, interface: str, bpf_filter: Optional[str]=None, output_dir: str="data", rotate_every_sec: Optional[int]=None):
        self.interface = interface
        self.filter = bpf_filter
        self.output_dir = output_dir
        self.rotate_every_sec = rotate_every_sec
        self._running = False
        self._writer = None
        self._lock = threading.Lock()
        self._sniff_thread = None
        self._packet_count = 0
        self._current_file = None
        self._rotate_timer = None

    def _rotate(self, path):
        with self._lock:
            if self._writer:
                self._writer.close()
                logger.info("Closed pcap writer {}", self._current_file)
            # open new writer
            self._current_file = path
            self._writer = PcapWriter(self._current_file, append=True, sync=True)
            logger.info("Rotated to new pcap file {}", self._current_file)

    def _packet_handler(self, pkt):
        with self._lock:
            if self._writer:
                self._writer.write(pkt)
                self._packet_count += 1

    def _sniff_loop(self, duration: Optional[int], packet_count: Optional[int]):
        """
        Sniff until duration expires or packet_count reached or stop called.
        """
        start = time.time()
        while self._running:
            remaining = None
            if duration:
                elapsed = time.time() - start
                if elapsed >= duration:
                    logger.info("Duration reached, stopping sniff loop")
                    self._running = False
                    break
                remaining = max(1, int(duration - elapsed))
            # sniff for a smaller chunk to be responsive
            sniff(timeout=remaining if remaining else 1,
                  iface=self.interface,
                  filter=self.filter,
                  prn=self._packet_handler,
                  store=False)
            if packet_count and self._packet_count >= packet_count:
                logger.info("Packet count reached: {}", self._packet_count)
                break

    def start(self, initial_pcap_path: str, duration: Optional[int]=None, packet_count: Optional[int]=None):
        """
        Start capture: initial_pcap_path is full path for first pcap file.
        rotation if rotate_every_sec given.
        """
        logger.info("Starting ScapyBackend on iface={} filter={}", self.interface, self.filter)
        self._running = True
        self._packet_count = 0
        self._current_file = initial_pcap_path
        self._writer = PcapWriter(self._current_file, append=True, sync=True)

        # rotation timer thread
        if self.rotate_every_sec:
            def rotator():
                while self._running:
                    time.sleep(self.rotate_every_sec)
                    if not self._running:
                        break
                    new_path = initial_pcap_path.replace(".pcap", f".rot_{int(time.time())}.pcap")
                    self._rotate(new_path)
            self._rotate_timer = threading.Thread(target=rotator, daemon=True)
            self._rotate_timer.start()

        # sniff thread
        self._sniff_thread = threading.Thread(target=self._sniff_loop, args=(duration, packet_count), daemon=True)
        self._sniff_thread.start()
        return self

    def stop(self):
        logger.info("Stopping ScapyBackend")
        self._running = False
        if self._sniff_thread:
            self._sniff_thread.join(timeout=5)
        if self._rotate_timer:
            self._rotate_timer.join(timeout=1)
        with self._lock:
            if self._writer:
                self._writer.close()
                logger.info("Closed final writer {}", self._current_file)
                self._writer = None
        return self._current_file, self._packet_count
