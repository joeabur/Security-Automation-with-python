from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrichmentResult:
    ip: str
    country: str | None = None
    city: str | None = None
    org: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    shodan_ports: list[int] = field(default_factory=list)
    shodan_services: list[str] = field(default_factory=list)
    shodan_os: str | None = None
    shodan_org: str | None = None
    vt_detected: bool = False
    vt_malicious: bool = False
    vt_score: int = 0
    vt_last_analysis: str | None = None
    risk_score: int = 0
    risk_level: str = "low"
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IOCFinding:
    ip: str
    source: str
    risk_score: int
    risk_level: str
    metadata: dict[str, Any] = field(default_factory=dict)
