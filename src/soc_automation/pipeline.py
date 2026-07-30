from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .config import settings
from .enrichment import IOCEnricher
from .jira_client import JiraClient
from .log_parser import LogParser
from .reporting import ReportGenerator

logger = logging.getLogger(__name__)


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("logs/soc_automation.log", mode="a", encoding="utf-8"),
        ],
    )


class IOCPipeline:
    def __init__(self, input_file: str | Path, output_dir: str | Path = "reports") -> None:
        self.input_file = Path(input_file)
        self.output_dir = Path(output_dir)
        self.log_parser = LogParser()
        self.enricher = IOCEnricher()
        self.report_generator = ReportGenerator(self.output_dir)
        self.jira_client = JiraClient()

    def run(self) -> list[dict]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ips = self.log_parser.parse_file(self.input_file)
        logger.info("Identified %s IP addresses from input log", len(ips))

        results: list[dict] = []
        for ip in ips:
            enriched = self.enricher.enrich_ip(ip)
            results.append({
                "ip": ip,
                "risk_score": enriched.risk_score,
                "risk_level": enriched.risk_level,
                "country": enriched.country,
                "ports": enriched.shodan_ports,
                "vt_malicious": enriched.vt_malicious,
                "os": enriched.shodan_os,
            })
            logger.info("Processed IP %s with risk %s (%s)", ip, enriched.risk_score, enriched.risk_level)

            if enriched.risk_score >= settings.risk_threshold:
                ticket = self.jira_client.create_ticket_for_ioc(
                    ip=ip,
                    score=enriched.risk_score,
                    summary=f"High-risk IOC detected: {ip}",
                    description=(
                        f"IOC: {ip}\n"
                        f"Risk score: {enriched.risk_score}\n"
                        f"Country: {enriched.country or 'unknown'}\n"
                        f"Ports: {enriched.shodan_ports or 'none'}\n"
                        f"Notes: {'; '.join(enriched.notes) or 'none'}"
                    ),
                )
                logger.info("JIRA ticket result for %s: %s", ip, ticket)

        report_path = self.report_generator.to_json([self.enricher.enrich_ip(ip) for ip in ips], "ioc_report.json")
        html_path = self.report_generator.to_html([self.enricher.enrich_ip(ip) for ip in ips], "ioc_report.html")
        logger.info("Wrote JSON report to %s", report_path)
        logger.info("Wrote HTML report to %s", html_path)

        return results


def main() -> None:
    configure_logging(settings.log_level)
    parser = argparse.ArgumentParser(description="SOC IOC enrichment pipeline")
    parser.add_argument("--log-file", required=True, help="Path to suspicious log file")
    parser.add_argument("--output-dir", default=settings.default_output_dir, help="Directory for output reports")
    args = parser.parse_args()

    pipeline = IOCPipeline(args.log_file, args.output_dir)
    results = pipeline.run()

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
