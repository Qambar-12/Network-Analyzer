# # src/capture/backends/pyshark_backend.py
# import pyshark
# from typing import Optional
# from loguru import logger
# import threading
# import time

# class PysharkBackend:
#     """
#     Uses pyshark.LiveCapture to write to a pcap file via tshark.
#     This backend is ideal when you want richer per-packet fields or prefer tshark's filters.
#     """

#     def __init__(self, interface: str, bpf_filter: Optional[str]=None, output_file: str="data/pyshark_capture.pcap"):
#         self.interface = interface
#         self.filter = bpf_filter
#         self.output_file = output_file
#         self.capture = None
#         self._thread = None
#         self._running = False

#     def _run_capture(self, duration: Optional[int]=None, packet_count: Optional[int]=None):
#         self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.filter, output_file=self.output_file)
#         logger.info("PyShark starting capture to {}", self.output_file)
#         self._running = True
#         try:
#             # sniff will block until timeout; can't easily break early by packet_count here
#             self.capture.sniff(timeout=duration)
#         except Exception as e:
#             logger.error("PyShark capture error: {}", e)
#         finally:
#             self._running = False
#             logger.info("PyShark capture stopped")

#     def start(self, duration: Optional[int]=None, packet_count: Optional[int]=None):
#         #self._thread = threading.Thread(target=self._run_capture, args=(duration, packet_count), daemon=True)
#         #self._thread.start()
#         self._run_capture(duration, packet_count)
#         return self

#     def stop(self):
#         if self.capture:
#             try:
#                 self.capture.close()
#             except Exception:
#                 pass
#         if self._thread:
#             self._thread.join(timeout=3)
#         return self.output_file, None


import pyshark
from typing import Optional
from loguru import logger
import threading
import time

class PysharkBackend:
    """
    Pyshark backend similar in behaviour to ScapyBackend:
    - writes pcap via tshark (pyshark.LiveCapture with output_file)
    - supports start/stop
    - optional time-based rotation (best-effort: stops current capture and restarts to new file)
    - attempts to count packets by using apply_on_packets callback
    """

    def __init__(self, interface: str, bpf_filter: Optional[str]=None, output_file: str="data/pyshark_capture.pcap", rotate_every_sec: Optional[int]=None):
        self.interface = interface
        self.filter = bpf_filter
        self.output_file = output_file
        self.rotate_every_sec = rotate_every_sec

        self.capture: Optional[pyshark.LiveCapture] = None
        self._thread: Optional[threading.Thread] = None
        self._rotate_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._packet_count = 0

    def _packet_handler(self, pkt) -> None:
        with self._lock:
            self._packet_count += 1

    def _run_capture(self, duration: Optional[int]=None, packet_count: Optional[int]=None):
        """
        Run a single LiveCapture session writing to self.output_file.
        Uses apply_on_packets to count packets and will stop early if packet_count reached.
        """
        try:
            self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.filter, output_file=self.output_file)
            logger.info("PyShark starting capture to {}", self.output_file)
            self._running = True
            start = time.time()

            def cb(pkt):
                # callback invoked for each packet seen
                self._packet_handler(pkt)
                # if requested packet_count reached, close capture to stop
                if packet_count and self._packet_count >= packet_count:
                    try:
                        self.capture.close()
                    except Exception:
                        pass
                    # setting _running False signals other parts of code
                    self._running = False

            # apply_on_packets blocks until timeout or capture is closed
            # timeout passed in seconds; if duration is None apply_on_packets will run until externally stopped
            try:
                self.capture.apply_on_packets(cb, timeout=duration)
            except Exception as e:
                # apply_on_packets may raise on close - treat as normal stop
                logger.debug("pyshark apply_on_packets ended: {}", e)

        except Exception as e:
            logger.error("PyShark capture error: {}", e)
        finally:
            # ensure running flag cleared
            self._running = False
            # close capture handle if still open
            try:
                if self.capture:
                    self.capture.close()
            except Exception:
                pass
            logger.info("PyShark capture stopped for {}", self.output_file)

    def _rotate(self, new_path: str, duration: Optional[int]=None, packet_count: Optional[int]=None):
        """
        Stop current capture and start a new one writing to new_path.
        This is best-effort rotation: packet_count and duration timers are not precisely preserved across rotations.
        """
        logger.info("Rotating PyShark capture to {}", new_path)
        # stop current capture
        try:
            if self.capture:
                self.capture.close()
        except Exception:
            pass
        # wait briefly for thread to settle
        time.sleep(0.5)
        with self._lock:
            self.output_file = new_path
            self._packet_count = 0
            # start a new capture thread
            self._thread = threading.Thread(target=self._run_capture, args=(duration, packet_count), daemon=True)
            self._thread.start()

    def start(self, duration: Optional[int]=None, packet_count: Optional[int]=None):
        """
        Start capture in a background thread. If rotate_every_sec is set, start a rotation thread.
        """
        logger.info("Starting PysharkBackend on iface={} filter={} out={}", self.interface, self.filter, self.output_file)
        self._running = True
        self._packet_count = 0

        # main capture thread
        self._thread = threading.Thread(target=self._run_capture, args=(duration, packet_count), daemon=True)
        self._thread.start()

        # rotation thread (best-effort restart)
        if self.rotate_every_sec:
            def rotator():
                while self._running:
                    time.sleep(self.rotate_every_sec)
                    if not self._running:
                        break
                    # create a rotated filename using timestamp
                    ts = int(time.time())
                    new_path = str(self.output_file).replace(".pcap", f".rot_{ts}.pcap")
                    # perform rotation (stops and restarts capture)
                    self._rotate(new_path, duration=None, packet_count=None)
            self._rotate_thread = threading.Thread(target=rotator, daemon=True)
            self._rotate_thread.start()

        return self

    def stop(self):
        """
        Stop capture, join threads and return final file path and packet count (if available).
        """
        logger.info("Stopping PySharkBackend")
        self._running = False

        # close live capture to force apply_on_packets to exit
        try:
            if self.capture:
                self.capture.close()
        except Exception:
            pass

        if self._thread:
            self._thread.join(timeout=5)
        if self._rotate_thread:
            self._rotate_thread.join(timeout=1)

        # return last known output file and packet count
        return self.output_file, self._packet_count
