# SOC Automation with Python Guide

## Overview

This guide walks through the design and implementation of a practical SOC automation project using Python. The goal is to show how an analyst or engineer can build a real-world pipeline for threat investigation, IOC enrichment, and incident response automation.

## 1. Why SOC automation matters

Security teams receive large volumes of alerts every day. Many signals are repetitive and require tasks such as:

- parsing raw logs
- extracting suspicious IPs
- checking external intelligence
- computing risk scores
- opening incident tickets

Python is a strong fit because it has a mature ecosystem, readable syntax, and productive libraries for automation.

## 2. Reading and parsing log data

SOC workflows often involve logs from multiple sources:

- JSON application logs
- CSV exports from SIEM tools
- Syslog from Linux systems
- Apache web server logs
- Windows Security event output

The `LogParser` class in this project extracts valid IP addresses from each line and normalizes them for enrichment.

## 3. Enriching suspicious IPs

Threat intelligence enrichment typically adds context such as:

- malicious reputation
- open ports
- network ownership or organization
- geolocation data
- risk score and confidence

This project demonstrates enrichment via VirusTotal, Shodan, and GeoIP.

## 4. Risk scoring model

A simple scoring model helps triage results:

- 40 points: malicious reputation from VirusTotal
- 25 points: open ports and exposed services
- 5 points: OS detection
- additional points for geolocation confidence and suspicious behavior

Thresholds can be tuned to match your environment.

## 5. Incident response automation with JIRA

Once risk is high enough, a ticket can be created automatically. The `JiraClient` wrapper uses the JIRA REST API and supports dry-run behavior when credentials are absent.

## 6. Report generation

The report generator creates:

- JSON for machine-readable ingestion
- HTML for analyst review

This is useful for both automation and human-facing triage reviews.

## 7. Best practices

- Never hardcode secrets in source files.
- Use `python-dotenv` and `.env` files locally.
- Log to a file and console with clear timestamping.
- Add retries for API requests and rate-limit handling.
- Validate external data before using it in downstream logic.

## 8. Extensions and future work

Consider extending this into a production-ready framework with:

- asyncio and aiohttp for parallel lookups
- Redis caching for repeated indicators
- Slack or Teams notifications
- cron or GitHub Actions scheduling
- Excel export and dashboard reporting
- integration with SIEM workflows

## 9. Example command

```bash
python -m soc_automation.pipeline --log-file sample_data/logs/suspicious_ips.log --output-dir reports
```

## 10. Summary

This project demonstrates how Python can automate meaningful SOC tasks while providing a strong foundation for a cybersecurity portfolio project.
