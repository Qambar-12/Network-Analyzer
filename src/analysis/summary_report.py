# src/analysis/summary_report.py

import os
import json

class SummaryReport:
    def __init__(self, capture_dir: str):
        self.capture_dir = capture_dir

    def generate_summary(self):
        metrics_files = [
            f for f in os.listdir(self.capture_dir) if f.endswith("_metrics.json")
        ]

        summary = []
        for mf in metrics_files:
            with open(os.path.join(self.capture_dir, mf), "r") as f:
                summary.append(json.load(f))

        summary_file = os.path.join(self.capture_dir, "summary_report.json")
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=4)

        return summary_file
