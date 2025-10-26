# # src/tests/test_metrics.py
# import pytest
# from src.analysis.metrics import compute_throughput

# def test_throughput():
#     # small synthetic check
#     bytes_sent = 1000
#     seconds = 2
#     t = compute_throughput(bytes_sent, seconds)
#     assert round(t, 6) == 4000.0  # bits per second? depends on function
# Run a lightweight smoke script to check Influx connectivity
import os
from dotenv import load_dotenv
from influxdb_client import InfluxDBClient , Point, WriteOptions
from influxdb_client.client.write_api import SYNCHRONOUS
load_dotenv()
token = os.getenv("INFLUX_TOKEN")
url = "http://localhost:8086"
org = "networkorg"
bucket = "network_metrics"

with InfluxDBClient(url=url, token=token, org=org) as client:
    write_api = client.write_api(write_options=SYNCHRONOUS)
    point = Point("smoke_test").tag("host", "dev").field("value", 1.0)
    write_api.write(bucket=bucket, record=point)
    write_api.flush()

print("✅ Write complete.")