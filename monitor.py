import asyncio
import time
from collections import defaultdict, deque
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, Any
from scapy.all import AsyncSniffer, IP, TCP, Ether


def initialize_worker():
    """Initialize ML model here so it doesn't reload on every single packet."""
    global my_ml_model
    my_ml_model = None  # Change to ML model.


"""OLD Logic"""
# def process_worker_logic(packet_bytes):
#     """This handles CPU-BOUND heavy tasks and completely bypasses the Python GIL by having its own memomry space via running in an isolated CPU core/process"""
#     try:
#         # Reconstruct the Scapy packet from raw bytes.
#         packet = Ether(packet_bytes)
#
#         if IP in packet and TCP in packet:
#             # Feature extraction
#             packet_size = len(packet)
#             ttl = packet[IP].ttl
#             tcp_flags = int(packet[TCP].flags)
#
#             # Anomaly Inference
#             # features = [packet_size, ttl, tcp_flags]
#             # prediction = my_ml_model.predict([features])
#
#             # Detection
#             if packet_size > 1400:
#                 return {
#                     "anomaly": True,
#                     "src": packet[IP].src,
#                     "dst": packet[IP].dst,
#                     "reason": "Large Packet Size",
#                 }
#
#         return {"anomaly": False}
#     except Exception as e:
#         return {"anomaly": False, "error": str(e)}
#


def process_anomaly_inference(window_features):
    """
    CPU-BOUND WORK: This executes on isolated CPU cores.
    Receives pre-computed window metrics from the main thread.
    """
    # Anomaly Inference Engine
    # Unpack the metrics prepared by the sliding window
    pps = window_features["packets_per_sec"]
    unique_dsts = window_features["unique_dst_ips"]
    avg_len = window_features["avg_packet_len"]

    """Detection Engine"""
    # Example
    if pps > 1000 and unique_dsts > 20:
        return {
            "anomaly": True,
            "reason": f"High Rate: {pps} pps to {unique_dsts} unique IPs",
        }

    return {"anomaly": False}


class NetworkSlidingWindow:
    def __init__(self, window_duration_secs=5):
        self.duration = window_duration_secs
        # Maps Source IP -> deque([(timestamp, packet_len, dst_ip), ... ])
        self.history = defaultdict(deque)

    def add_packet(self, src_ip, dst_ip, packet_len):
        """Adds a packet to the window history and purges expired records."""
        now = time.time()
        self.history[src_ip].append((now, packet_len, dst_ip))
        self.prune(src_ip, now)

    def prune(self, src_ip, now):
        """Removes historical records older than the window duration."""
        cutoff = now - self.duration
        while self.history[src_ip] and self.history[src_ip][0][0] < cutoff:
            self.history[src_ip].popleft()

    def get_window_features(self, src_ip):
        """Calculates time-series mathematical metrics for the specific Source IP."""
        packets = self.history[src_ip]
        if not packets:
            return {"packets_per_sec": 0, "unique_dst_ips": 0, "avg_packet_len": 0}

        total_packets = len(packets)
        total_len = sum(p[1] for p in packets)
        unique_dsts = len(set(p[2] for p in packets))

        return {
            "src_ip": src_ip,
            "packets_per_sec": total_packets / self.duration,
            "unique_dst_ips": unique_dsts,
            "avg_packet_len": total_len / total_packets,
        }


# Multi Process Packet Capture
class AdvancedIDSPipeline:
    def __init__(self, max_processes=4, window_secs=5):
        self.packet_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self.window = NetworkSlidingWindow(window_duration_secs=window_secs)
        self.executor = ProcessPoolExecutor(
            max_workers=max_processes, initializer=initialize_worker
        )
        self.sniffer = None
        self.processing_task = None

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            # loop = asyncio.get_event_loop()
            # # Convert Scapy to raw bytes to safely cross process boundaries.
            # packet_bytes = bytes(packet)
            # loop.call_soon_threadsafe(self.packet_queue.put_nowait, packet_bytes)

            # New optimized version only requires the metadata for the sliding window.
            meta = {"src": packet[IP].src, "dst": packet[IP].dst, "len": len(packet)}
            loop = asyncio.get_event_loop()
            loop.call_soon_threadsafe(self.packet_queue.put_nowait, meta)

    async def start_capture(self, interface="eth0"):
        print(f"[*] Starting Multi-Process capture on {interface}...")
        self.sniffer = AsyncSniffer(iface=interface, prn=self.packet_callback, store=0)
        self.sniffer.start()
        self.processing_task = asyncio.create_task(self.packet_consumer_loop())

    async def packet_consumer_loop(self):
        loop = asyncio.get_running_loop()
        try:
            while True:
                # Non-blocking pull of raw bytes from async queue
                # packet_bytes = await self.packet_queue.get()

                # Offload to an independent CPU core process
                # result = await loop.run_in_executor(
                #    self.executor, process_worker_logic, packet_bytes
                # )

                packet_meta = await self.packet_queue.get()

                src = packet_meta["src"]
                dst = packet_meta["dst"]
                length = packet_meta["len"]

                # Update the centralized sliding window state
                self.window.add_packet(src, dst, length)

                # Extract statistical mathematical snapshot across the time window
                features = self.window.get_window_features(src)

                result = await loop.run_in_executor(
                    self.executor, process_anomaly_inference, features
                )

                if result.get("anomaly"):
                    await self.handle_alert(src, result)

                self.packet_queue.task_done()
        except asyncio.CancelledError:
            print("[*] Consumer pipeline cancelled.")

    async def handle_alert(self, culprit_ip, alert_data):
        """Asynchronous alert handler running on the main thread."""
        print(f"[!] IDS ALERT | Host: {culprit_ip} | Reason: {alert_data['reason']}")

    async def stop(self):
        print("[*] Shutting down multi-process system...")
        if self.sniffer:
            self.sniffer.stop()
        elif self.processing_task:
            self.processing_task.cancel()
            await asyncio.gather(self.processing_task, return_exceptions=True)

        # Terminate and clean up background processes
        self.executor.shutdown(wait=True)
        print("[*] System stopped cleanly.")


async def main():
    capture = AdvancedIDSPipeline(max_processes=4, window_secs=5)
    await capture.start_capture(interface="eth0")
    await asyncio.sleep(10)
    await capture.stop()


if __name__ == "__main__":
    asyncio.run(main())
