# Security Automation with Python

A practical Python-based SOC automation project for log parsing, IOC enrichment, incident response workflows, and threat intelligence collection.

This repository demonstrates how a Security Operations Center (SOC) engineer can automate repetitive investigations, enrich suspicious indicators, and raise incidents through APIs using production-friendly Python patterns.

## Learning Objectives

- Automate common SOC tasks in Python.
- Parse security logs in multiple formats: JSON, CSV, Syslog, Apache, and Windows Event logs.
- Extract and validate IP addresses from noisy telemetry.
- Search threat intel sources and collect reputation information.
- Perform GeoIP enrichment and service discovery through APIs.
- Create JIRA incident tickets for high-risk artifacts.
- Use OOP, logging, configuration, retries, and type hints in a real automation pipeline.
- Follow patterns inspired by chapters 12-15 of Automate the Boring Stuff with Python:
  - Working with files
  - Making web requests
  - Using APIs
  - Automating repeatable workflows

## Capstone Lab: IOC Enrichment Pipeline

The project implements an IOC enrichment pipeline that:

1. Reads a list of suspicious IP addresses from logs.
2. Extracts valid IP addresses automatically.
3. Queries VirusTotal for reputation data.
4. Queries Shodan for exposed services and organization metadata.
5. Performs IP geolocation lookups.
6. Calculates a risk score.
7. Generates structured JSON output.
8. Creates an HTML or PDF-friendly report.
9. Creates a JIRA incident ticket when risk is high.
10. Logs all activity and errors.

## Project Structure

```text
security-automation-with-python/
├── README.md
├── requirements.txt
├── pyproject.toml
├── config.yaml
├── .env.example
├── .gitignore
├── Dockerfile
├── src/
│   └── soc_automation/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── models.py
│       ├── log_parser.py
│       ├── enrichment.py
│       ├── jira_client.py
│       ├── reporting.py
│       ├── pipeline.py
│       └── utils.py
├── sample_data/
│   ├── logs/
│   │   └── suspicious_ips.log
│   └── outputs/
│       └── sample_ioc_report.json
├── tests/
│   ├── test_log_parser.py
│   └── test_pipeline.py
├── reports/
│   └── .gitkeep
├── docs/
│   └── soc_automation_guide.md
└── .github/
    └── workflows/
        └── ci.yml
```

## Quick Start

### 1. Create the environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure credentials

Copy the example file and add your secrets:

```bash
cp .env.example .env
```

Then update the variables for your environment:

```dotenv
VT_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
JIRA_URL=https://your-company.atlassian.net
JIRA_USER=your-email@example.com
JIRA_API_TOKEN=your-jira-token
GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
```

### 3. Run the IOC enrichment pipeline

```bash
python -m soc_automation.pipeline --log-file sample_data/logs/suspicious_ips.log --output-dir reports
```

### 4. View the generated report

```bash
ls reports/
```

The pipeline will generate:

- JSON report
- HTML report
- log file with pipeline output

## Core Workflow

The workflow is built around a modular design:

1. Parse suspicious IPs from raw logs.
2. Validate and normalize them.
3. Query external enrichment sources.
4. Compute a basic risk score.
5. Build a structured report.
6. Raise a JIRA ticket for high-risk findings.

## Security Log Parsing

The project covers multiple log styles that SOC teams commonly see.

### JSON logs

```json
{"timestamp":"2026-07-30T10:00:00Z","source_ip":"93.184.216.34","alert":"suspicious_login"}
```

### CSV logs

```csv
timestamp,source_ip,host,event
2026-07-30T10:00:00Z,198.51.100.25,web-01,failed_login
```

### Syslog

```text
Jul 30 10:00:00 host sshd[1234]: Failed password for invalid user root from 203.0.113.44 port 22
```

### Apache access logs

```text
203.0.113.10 - - [30/Jul/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123
```

### Windows Event-like data

```text
2026-07-30 10:00:00, Security, 4625, Logon Failure, 10.20.30.40
```

The parser extracts valid IPv4 and IPv6 addresses while ignoring malformed values.

## Threat Intelligence Enrichment

### VirusTotal

VirusTotal returns reputation metadata such as:

- detection ratio
- last analysis date
- suspicious status
- malicious confidence

Example:

```python
vt = VirusTotalClient(api_key=settings.vt_api_key)
result = vt.lookup("8.8.8.8")
```

### Shodan

Shodan provides:

- open ports
- service banners
- organization name
- operating system
- country and ISP information

Example:

```python
shodan_client = ShodanClient(api_key=settings.shodan_api_key)
result = shodan_client.lookup("8.8.8.8")
```

### GeoIP

GeoIP enrichment can help answer:

- country
- city
- ASN
- latitude/longitude
- timezone

Example:

```python
geo_client = GeoIPClient(db_path=settings.geoip_db_path)
geo = geo_client.lookup("1.1.1.1")
```

## Risk Scoring

A simple scoring model helps highlight high-risk IOCs. The basic approach is:

- suspicious reputation adds points
- malicious confidence adds points
- open services or risky ports adds points
- geolocation or ASN anomalies add points
- default high-risk threshold is 70

Example logic:

```python
risk_score = 0
if vt_result["malicious"]:
    risk_score += 40
if len(shodan_result["ports"]) >= 3:
    risk_score += 15
if geo_result["country"] not in {"US", "CA"}:
    risk_score += 10
```

## JIRA Automation

The project includes a JIRA client for creating structured incident tickets based on triage results.

Example:

```python
jira = JiraClient(url=settings.jira_url, username=settings.jira_user, api_token=settings.jira_api_token)
issue = jira.create_ticket_for_ioc(
    ip="198.51.100.25",
    score=89,
    summary="High-risk IOC identified",
    description="IOC enrichment identified multiple suspicious attributes."
)
```

If credentials are missing, the client can run in dry-run mode so the pipeline still executes safely without creating a ticket.

## Best Practices

- Store secrets in `.env` or a secret manager, not in source control.
- Use environment variables and config files instead of hard-coded keys.
- Add retries for transient API errors and rate limits.
- Log structured activity with timestamps and event codes.
- Validate all external inputs before processing.
- Avoid leaking sensitive data in logs.
- Keep API calls behind reusable wrappers for easier testing.
- Use dry-run or mock modes when developing locally.

## Secure API Key Management

Recommended practices:

- Use `.env` files in local development.
- Keep `.env` out of version control.
- Use GitHub Actions secrets or Vault for CI/CD.
- Rotate tokens regularly.
- Scope tokens to the minimum permissions required.
- Never log API keys or token values.

## Bonus Features

The project also includes guidance for production extensions:

- Async enrichment with asyncio and aiohttp
- Bulk IOC enrichment for large threat lists
- API response caching with Redis or local JSON cache
- Docker packaging for deployment
- Cron or GitHub Actions automation
- Slack or Microsoft Teams alerting
- Excel export using pandas
- CLI automation with Typer
- Packaging the project into a reusable Python module

## Suggested Extensions

This project can evolve into a broader SOC automation framework:

- Threat intel triage queue
- Automated phishing domain investigation
- Endpoint detection and response (EDR) enrichment
- Alert deduplication and correlation
- Weekly executive risk reporting
- SIEM integration via Elastic, Splunk, QRadar, or Sentinel

## Running the Example Pipeline

```bash
python -m soc_automation.pipeline --log-file sample_data/logs/suspicious_ips.log --output-dir reports
```

This will create JSON and HTML reports in the output directory.

## Testing

```bash
pytest -q
```

## Documentation

Additional walkthroughs and examples are available in [docs/soc_automation_guide.md](docs/soc_automation_guide.md).

## Production Notes

This repository is intentionally designed as a learning-and-portfolio project while still reflecting real SOC automation patterns. It is modular, readable, and extensible for real workflows.

## License

This project is intended for educational and portfolio use.
