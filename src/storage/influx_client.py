# src/storage/influx_client.py
# Storage module handles data persistence.
# Client for interacting with an InfluxDB time-series database.
# Handles pushing calculated metrics and results to a time-series database.
from influxdb_client import InfluxDBClient, Point, WriteOptions
from loguru import logger

class InfluxStorage:
    def __init__(self, url: str, token: str, org: str, bucket: str):
        """
        1. Parameters provide the essential connection details: the server address, the security token, the organization scope, and the target bucket (database) where data will be stored.
        2. self.client initializes the InfluxDB client using the provided connection details.
        3. self.bucket stores the name of the target bucket (database) for writing data.
        4. self.write_api creates a specialized WriteApi instance using WriteOptions. This API handles asynchronous writing and batching to improve performance and reduce overhead:
           batch_size=1000 tells the client to buffer up to 1,000 points before sending a batch request to InfluxDB.
           flush_interval=10000 ensures that buffered points are sent to the database at least every 10,000 milliseconds (10 seconds), even if the batch size hasn't been reached.
        """

        self.client = InfluxDBClient(url=url, token=token, org=org)
        self.bucket = bucket
        self.write_api = self.client.write_api(write_options=WriteOptions(batch_size=1000, flush_interval=10000))

    def write_metric(self, measurement: str, tags: dict, fields: dict, timestamp=None):
        """
            Writes a time-series data point (metric) to the configured InfluxDB bucket.

            This method formats the provided data into an InfluxDB Point, which is then
            passed to the asynchronous, batched WriteApi for efficient ingestion into the database.

            Args:
                measurement (str): The name of the measurement (table) to write the data to (e.g., 'network_traffic').
                    This is a key component for grouping related time-series data.
                tags (dict): A dictionary of indexed metadata for the point (e.g., {'host': 'server_1', 'protocol': 'tcp'}).
                    Tags are stored as strings and are crucial for fast filtering and querying.
                fields (dict): A dictionary of the actual time-series values (e.g., {'packet_count': 150, 'byte_rate': 20480}).
                    Fields are the values that change over time and are stored as floating-point numbers.
                timestamp (str, optional): The specific timestamp for the point (e.g., the time the packet was captured).
                    If None, InfluxDB will assign the timestamp upon ingestion. Defaults to None.

            Flow:
                1. A `Point` object is created with the given `measurement`.
                2. All items in the `tags` dictionary are added to the `Point` as string tags.
                3. All items in the `fields` dictionary are added to the `Point` as floating-point fields.
                4. If provided, the `timestamp` is set for the point.
                5. The resulting `Point` is written using the batched `self.write_api`, which buffers the data before sending it to the configured `bucket`.
                6. A debug log entry confirms the point has been prepared for writing.
            """
        p = Point(measurement)
        for k,v in tags.items(): p.tag(k, str(v))
        for k,v in fields.items(): p.field(k, float(v))
        if timestamp:
            p.time(timestamp)
        self.write_api.write(bucket=self.bucket, record=p)
        logger.debug("Wrote point to Influx: {} {} {}", measurement, tags, fields)
