FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY config.yaml ./config.yaml
COPY .env.example ./.env.example

CMD ["python", "-m", "soc_automation.cli", "run-pipeline", "--log-file", "sample_data/logs/suspicious_ips.log", "--output-dir", "reports"]
