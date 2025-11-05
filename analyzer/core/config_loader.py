import os
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

class Settings:
    def __init__(self):
        self.influxdb_url = os.getenv("INFLUXDB_URL")
        self.influxdb_token = os.getenv("INFLUXDB_TOKEN")
        self.influxdb_org = os.getenv("INFLUXDB_ORG")
        self.influxdb_bucket = os.getenv("INFLUXDB_BUCKET")

settings = Settings()
