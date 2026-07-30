from __future__ import annotations

import logging
from typing import Any

from jira import JIRA

from .config import settings

logger = logging.getLogger(__name__)


class JiraClient:
    def __init__(self, url: str | None = None, username: str | None = None, api_token: str | None = None) -> None:
        self.url = url or settings.jira_url
        self.username = username or settings.jira_user
        self.api_token = api_token or settings.jira_api_token
        self.client: JIRA | None = None

        if self.url and self.username and self.api_token:
            try:
                self.client = JIRA(server=self.url, basic_auth=(self.username, self.api_token))
            except Exception as exc:  # pragma: no cover - depends on network
                logger.warning("JIRA connection failed: %s", exc)
                self.client = None

    def create_ticket_for_ioc(self, ip: str, score: int, summary: str, description: str) -> dict[str, Any] | None:
        if not self.client:
            logger.info("JIRA client unavailable; skipping ticket creation for %s", ip)
            return None

        issue_dict = {
            "project": {"key": "SOC"},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Task"},
        }

        try:
            issue = self.client.create_issue(fields=issue_dict)
            logger.info("Created JIRA ticket: %s for IP %s", issue.key, ip)
            return {"key": issue.key, "url": f"{self.url}/browse/{issue.key}"}
        except Exception as exc:  # pragma: no cover - depends on network
            logger.warning("Ticket creation failed for %s: %s", ip, exc)
            return None
