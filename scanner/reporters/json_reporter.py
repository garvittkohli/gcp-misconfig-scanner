import json
import os
from pathlib import Path

from scanner.findings import ScanResult


class JSONReporter:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def write(self, result: ScanResult, filename: str = "findings.json") -> str:
        output = {
            "summary": result.summary(),
            "findings": [f.to_dict() for f in result.sorted_findings()],
        }
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2, default=str)
        return path
