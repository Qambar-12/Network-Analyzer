# src/config_loader.py
# Loads settings from config.yaml and .env. Merges environment variables (like Influx token) for runtime configuration.
import yaml
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()  # loads .env

def load_config(path: str = "config/config.yaml"):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with p.open() as f:
        cfg = yaml.safe_load(f)
    # merge env-overrides if required
    cfg['storage']['influx']['token'] = os.getenv("INFLUX_TOKEN", cfg['storage']['influx'].get('token'))
    return cfg
