# src/capture/utils.py
from datetime import datetime
from pathlib import Path
import json
import os
from typing import Dict

def timestamped_filename(prefix: str, ext: str = "pcap") -> str:
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}_{ts}.{ext}"

def ensure_dir(path: str):
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p

def write_metadata(pcap_path: str, meta: Dict):
    p = Path(pcap_path)
    meta_file = p.with_suffix(p.suffix + ".meta.json")
    with meta_file.open("w") as fh:
        json.dump(meta, fh, indent=2)
    return str(meta_file)

def file_size_mb(path: str) -> float:
    if not Path(path).exists():
        return 0.0
    return Path(path).stat().st_size / (1024 * 1024)
