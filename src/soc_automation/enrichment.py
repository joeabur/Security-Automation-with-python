from __future__ import annotations

import json
import logging
from typing import Any

import requests

from .config import settings
from .models import EnrichmentResult

logger = logging.getLogger(__name__)


class VirusTotalClient:
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.vt_api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    def lookup(self, ip: str) -> dict[str, Any]:
        if not self.api_key:
            return {"error": "missing API key", "malicious": False, "score": 0}

        url = f"{self.base_url}/ip_addresses/{ip}"
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            score = int((malicious + suspicious) / total * 100)
            return {
                "malicious": malicious > 0 or suspicious > 0,
                "score": score,
                "last_analysis": data.get("last_analysis_date"),
                "raw": payload,
            }
        except requests.RequestException as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", ip, exc)
            return {"error": str(exc), "malicious": False, "score": 0}


class ShodanClient:
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.shodan_api_key

    def lookup(self, ip: str) -> dict[str, Any]:
        if not self.api_key:
            return {"error": "missing API key", "ports": [], "organization": None, "os": None}

        url = "https://api.shodan.io/shodan/host/{ip}?key={key}".format(ip=ip, key=self.api_key)
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            payload = response.json()
            return {
                "ports": payload.get("ports", []),
                "organization": payload.get("org"),
                "os": payload.get("os"),
                "country": payload.get("country_name"),
                "isp": payload.get("isp"),
                "data": payload,
            }
        except requests.RequestException as exc:
            logger.warning("Shodan lookup failed for %s: %s", ip, exc)
            return {"error": str(exc), "ports": [], "organization": None, "os": None}


class GeoIPClient:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or settings.geoip_db_path

    def lookup(self, ip: str) -> dict[str, Any]:
        if not self.db_path:
            return {"country": None, "city": None, "org": None, "latitude": None, "longitude": None, "asn": None}

        try:
            import geoip2.database
            from geoip2.errors import GeoIp2Error

            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.city(ip)
                return {
                    "country": response.country.name,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "asn": getattr(response.traits, "autonomous_system_organization", None),
                    "org": getattr(response.traits, "organization", None),
                }
        except (ImportError, OSError, GeoIp2Error, ValueError) as exc:
            logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
            return {"country": None, "city": None, "org": None, "latitude": None, "longitude": None, "asn": None}


class IOCEnricher:
    def __init__(self, vt_client: VirusTotalClient | None = None, shodan_client: ShodanClient | None = None, geo_client: GeoIPClient | None = None) -> None:
        self.vt_client = vt_client or VirusTotalClient()
        self.shodan_client = shodan_client or ShodanClient()
        self.geo_client = geo_client or GeoIPClient()

    def enrich_ip(self, ip: str) -> EnrichmentResult:
        vt_data = self.vt_client.lookup(ip)
        shodan_data = self.shodan_client.lookup(ip)
        geo_data = self.geo_client.lookup(ip)

        risk_score = 0
        notes: list[str] = []
        sources: list[str] = []

        if vt_data.get("malicious"):
            risk_score += 40
            notes.append("VirusTotal reports malicious behavior")
            sources.append("VirusTotal")
        elif vt_data.get("score"):
            risk_score += min(vt_data["score"], 25)
            notes.append("VirusTotal reputation score is elevated")

        ports = shodan_data.get("ports", [])
        if ports:
            risk_score += min(len(ports) * 5, 25)
            sources.append("Shodan")
            notes.append(f"Exposed services on ports: {ports}")

        os_name = shodan_data.get("os")
        if os_name:
            risk_score += 5
            notes.append(f"Operating system identified: {os_name}")

        if geo_data.get("country"):
            sources.append("GeoIP")
            notes.append(f"Country enrichment: {geo_data['country']}")

        if risk_score >= 70:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"

        return EnrichmentResult(
            ip=ip,
            country=geo_data.get("country"),
            city=geo_data.get("city"),
            org=geo_data.get("org"),
            latitude=geo_data.get("latitude"),
            longitude=geo_data.get("longitude"),
            asn=geo_data.get("asn"),
            shodan_ports=ports,
            shodan_services=[],
            shodan_os=os_name,
            shodan_org=shodan_data.get("organization"),
            vt_detected=vt_data.get("malicious", False),
            vt_malicious=vt_data.get("malicious", False),
            vt_score=vt_data.get("score", 0),
            vt_last_analysis=vt_data.get("last_analysis"),
            risk_score=risk_score,
            risk_level=risk_level,
            sources=sources,
            notes=notes,
            metadata={
                "vt_raw": vt_data.get("raw", {}),
                "shodan_raw": shodan_data.get("data", {}),
            },
        )
