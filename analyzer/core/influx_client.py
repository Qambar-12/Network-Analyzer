from influxdb_client import InfluxDBClient, Point, WritePrecision
from analyzer.core.config_loader import settings
from influxdb_client.client.write_api import SYNCHRONOUS

client = InfluxDBClient(
    url=settings.influxdb_url,
    token=settings.influxdb_token,
    org=settings.influxdb_org
)

write_api = client.write_api(write_options=SYNCHRONOUS)

query_api = client.query_api()

def write_data(measurement: str, fields: dict, tags: dict = None):
    """Write a new point to InfluxDB."""
    point = Point(measurement)
    if tags:
        for k, v in tags.items():
            point = point.tag(k, v)
    for k, v in fields.items():
        point = point.field(k, v)
    write_api.write(bucket=settings.influxdb_bucket, record=point)

def query_data(query: str):
    """Run a Flux query and return results."""
    result = query_api.query(org=settings.influxdb_org, query=query)
    data = []
    for table in result:
        for record in table.records:
            data.append({
                "measurement": record.get_measurement(),
                "time": record.get_time(),
                "fields": record.values
            })
    return data
