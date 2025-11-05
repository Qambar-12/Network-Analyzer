from fastapi import FastAPI
from analyzer.core.influx_client import write_data, query_data
from analyzer.core.packet_collector import capture_traffic, analyze_packets

app = FastAPI()

@app.get("/")
def root():
    return {"status": "FastAPI + InfluxDB + Scapy connected"}

@app.get("/capture")
def capture_network(duration: int = 10):
    packets = capture_traffic(duration=duration)
    metrics = analyze_packets(packets)

    if not metrics:
        return {"message": "No packets captured"}

    # Push to InfluxDB
    write_data("network_metrics", metrics)
    return {"message": "Metrics captured", "data": metrics}
