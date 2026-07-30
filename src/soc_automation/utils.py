from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterable

IPV4_OR_IPV6_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}")


def extract_ip_addresses(text: str) -> list[str]:
    """Return candidate IP addresses from a text block."""
    matches = IPV4_OR_IPV6_PATTERN.findall(text)
    valid_ips: list[str] = []

    for candidate in matches:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        valid_ips.append(candidate)

    return valid_ips


def read_lines_from_file(path: str | Path) -> list[str]:
    """Read a file and return its lines as strings."""
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered
