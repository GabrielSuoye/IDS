import asyncio
from concurrent.futures import ProcessPoolExecutor
from logging import shutdown
from uuid import main
from scapy.all import AsyncSniffer, IP, TCP, Ether, ifaces

def initialize_worker():
    """Initialize ML model here so it doesn't reload on every single packet."""
    global my_ml_model
    my_ml_model = None      # Change to ML model.

def process_worker_logic(packet_bytes):
    try:
        # Reconstruct the Scapy packet from raw bytes. 
        packet = Ether(packet_bytes)

        if IP in packet and TCP in packet:
            # Feature extraction
            packet_size = len(packet)
            ttl = packet[IP].ttl
            tcp_flags = int(packet[TCP].flags)

            # Anomaly Inference 
            features = [packet_size, ttl, tcp_flags]
            prediction = my_ml_model.predict([features])

            # Detection 
            if packet_size > 1400:
                return {"anomaly": True, "src": packet[IP].src, "dst": packet[IP].dst, "reason": "Large Packet Size"}

        return {"anomaly": False}
    except Exception as e:
        return {"anomaly": False, "error": str(e)}


class MultiProcessPacketCapture:
    def __init__(self, max_processes=4):
        self.packet_queue =asyncio.Queue()
        self.executor = ProcessPoolExecutor(
            max_workers=max_processes,
            initializer=initialize_worker
        )
        self.sniffer = None
        self.processing_task = None

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            loop = asyncio.get_event_loop()
            # Convert Scapy to raw bytes to safely cross process boundaries.
            packet_bytes = bytes(packet)
            loop.call_soon_threadsafe(self.packet_queue.put_nowait, packet_bytes)

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
            packet_bytes = await self.packet_queue.get()

            # Offload to an independent CPU core process 
            result = await loop.run_in_executor(
                self.executor,
                process_worker_logic,
                packet_bytes
            )

            if result.get("anomaly"):
                await self.handle_alert(result)

            self.packet_queue.task_done()
    except asyncio.CancelledError:
        print("[*] Consumer loop cancelled.")

async def handle_alert(self, alert_data):
    """Asynchronous alert handler running on the main thread."""
    print(f"[!] ANOMALY DETECTED by Process Pool: {alert_data['src']} -> {alert_data['dst']} | Reason: {alert_data['reason']")

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
    capture = MultiProcessPacketCapture(max_processes=4)
    await capture.start_capture(interface='eth0')
    await asyncio.sleep(10)
    await capture.stop()


if __name__ == "__main__":
    asyncio.run(main())
