from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import EnrichmentResult


class ReportGenerator:
    def __init__(self, output_dir: str | Path = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def to_json(self, data: list[EnrichmentResult], filename: str = "ioc_report.json") -> str:
        payload = [self._serialize_result(result) for result in data]
        base_real = self.output_dir.resolve()
        target = (self.output_dir / filename).resolve()
        try:
            target.relative_to(base_real)
        except ValueError:
            raise Exception("Invalid file path")
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(target)

    def to_html(self, data: list[EnrichmentResult], filename: str = "ioc_report.html") -> str:
        rows = "\n".join(
            "<tr><td>{ip}</td><td>{score}</td><td>{level}</td><td>{country}</td><td>{ports}</td></tr>".format(
                ip=result.ip,
                score=result.risk_score,
                level=result.risk_level,
                country=result.country or "unknown",
                ports=", ".join(map(str, result.shodan_ports)) or "-",
            )
            for result in data
        )
        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset=\"utf-8\">
  <title>IOC Enrichment Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 0.75rem; text-align: left; }}
    th {{ background: #f2f2f2; }}
  </style>
</head>
<body>
  <h1>IOC Enrichment Report</h1>
  <table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Risk Score</th>
        <th>Risk Level</th>
        <th>Country</th>
        <th>Ports</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""
        base_real = self.output_dir.resolve()
        target = (self.output_dir / filename).resolve()
        try:
            target.relative_to(base_real)
        except ValueError:
            raise Exception("Invalid file path")
        target.write_text(html, encoding="utf-8")
        return str(target)

    def _serialize_result(self, result: EnrichmentResult) -> dict[str, Any]:
        return {
            "ip": result.ip,
            "country": result.country,
            "city": result.city,
            "org": result.org,
            "latitude": result.latitude,
            "longitude": result.longitude,
            "asn": result.asn,
            "shodan_ports": result.shodan_ports,
            "shodan_os": result.shodan_os,
            "shodan_org": result.shodan_org,
            "vt_detected": result.vt_detected,
            "vt_malicious": result.vt_malicious,
            "vt_score": result.vt_score,
            "vt_last_analysis": result.vt_last_analysis,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "sources": result.sources,
            "notes": result.notes,
            "metadata": result.metadata,
        }
