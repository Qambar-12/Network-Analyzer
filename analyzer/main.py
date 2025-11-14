from fastapi import FastAPI
from analyzer.core.influx_client import write_data, query_data
from analyzer.core.packet_collector import capture_traffic, analyze_packets
from analyzer.core.scheduler import start_scheduler
from analyzer.core.pcap_writer import save_pcap

app = FastAPI()

@app.on_event("startup")
def startup_event():
    start_scheduler(interval_minutes=5)

@app.get("/")
def root():
    return {"status": "FastAPI + InfluxDB + Scheduler running"}

@app.get("/capture")
def capture_network(duration: int = 10):
    packets = capture_traffic(duration=duration)
    metrics = analyze_packets(packets)

    if not metrics:
        return {"message": "No packets captured"}

    # Save PCAP file
    pcap_path = save_pcap(packets)
    metrics["pcap_path"] = pcap_path  # (optional but useful)

    write_data("network_metrics", metrics)

    return {
        "message": "Metrics captured",
        "pcap_file": pcap_path,
        "data": metrics,
    }