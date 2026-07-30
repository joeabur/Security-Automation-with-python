from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .utils import dedupe_preserve_order, extract_ip_addresses


class LogParser:
    """Parse common SOC log types and return suspicious IPs."""

    def parse_file(self, file_path: str | Path) -> list[str]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file does not exist: {path}")

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        ips: list[str] = []

        for raw_line in lines:
            ips.extend(self.extract_ips_from_line(raw_line))

        return dedupe_preserve_order(ips)

    def extract_ips_from_line(self, line: str) -> list[str]:
        return extract_ip_addresses(line)

    def parse_json_log(self, path: str | Path) -> list[str]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        ips: list[str] = []

        if isinstance(data, list):
            for entry in data:
                ips.extend(self._search_dict_for_ips(entry))
        elif isinstance(data, dict):
            ips.extend(self._search_dict_for_ips(data))

        return dedupe_preserve_order(ips)

    def parse_csv_log(self, path: str | Path) -> list[str]:
        ips: list[str] = []
        with Path(path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                ips.extend(self._search_dict_for_ips(row))
        return dedupe_preserve_order(ips)

    def _search_dict_for_ips(self, data: dict[str, Any]) -> list[str]:
        found: list[str] = []
        for value in data.values():
            if isinstance(value, str):
                found.extend(extract_ip_addresses(value))
            elif isinstance(value, dict):
                found.extend(self._search_dict_for_ips(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        found.extend(extract_ip_addresses(item))
                    elif isinstance(item, dict):
                        found.extend(self._search_dict_for_ips(item))
        return found

    def parse_apache_log(self, path: str | Path) -> list[str]:
        pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips: list[str] = []
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            for match in re.findall(pattern, line):
                ips.append(match)
        return dedupe_preserve_order(ips)

    def parse_syslog(self, path: str | Path) -> list[str]:
        return self.parse_apache_log(path)

    def parse_windows_event_log(self, path: str | Path) -> list[str]:
        return self.parse_apache_log(path)
