from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


load_dotenv()


class Settings:
    def __init__(self, config_path: str | Path | None = None) -> None:
        base_dir = Path(__file__).resolve().parents[2]
        config_file = Path(config_path) if config_path else base_dir / "config.yaml"

        with config_file.open("r", encoding="utf-8") as file:
            self.config: dict[str, Any] = yaml.safe_load(file) or {}

        self.project_name = self.config.get("project", {}).get("name", "SOC Automation")
        self.risk_threshold = int(os.getenv("RISK_THRESHOLD", self.config.get("thresholds", {}).get("risk_score", 70)))

        self.vt_api_key = os.getenv("VT_API_KEY", "")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        self.jira_url = os.getenv("JIRA_URL", "")
        self.jira_user = os.getenv("JIRA_USER", "")
        self.jira_api_token = os.getenv("JIRA_API_TOKEN", "")
        self.geoip_db_path = os.getenv("GEOIP_DB_PATH", "")

        self.log_level = os.getenv("LOG_LEVEL", self.config.get("logging", {}).get("level", "INFO"))
        self.default_output_dir = self.config.get("pipeline", {}).get("default_output_dir", "reports")

    @property
    def config_path(self) -> Path:
        return Path(__file__).resolve().parents[2] / "config.yaml"


settings = Settings()
