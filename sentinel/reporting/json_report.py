"""Structured JSON report generator for Mobile Sentinel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.orchestrator.pipeline import ScanExecutionResult


class JsonReportGenerator:
    """Generates machine-readable report.json containing full structured evidence and AI report insights."""

    def generate(self, result: ScanExecutionResult | Any, output_path: Path | str) -> str:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        if hasattr(result, "to_dict"):
            data = result.to_dict()
        elif isinstance(result, dict):
            data = dict(result)
        else:
            data = {"scan_id": "UNKNOWN", "raw": str(result)}

        content = json.dumps(data, indent=2, default=str)

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)

        return content
