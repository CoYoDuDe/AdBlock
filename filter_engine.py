"""Hilfsfunktionen zum Parsen von Domains und zum Bewerten von Listen.

Dieses Modul validiert Host-Listen, extrahiert g\xc3\xbcltige Domains und
berechnet Metriken, um die Quelllisten zu beurteilen.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterator

import idna
from config import DOMAIN_PATTERN, DOMAIN_VALIDATOR


LOGGER = logging.getLogger(__name__)


def ist_gueltige_domain(domain: str) -> bool:
    """Validate domain name."""
    try:
        try:
            domain = idna.encode(domain).decode("ascii")
        except idna.core.IDNAError as exc:
            LOGGER.debug("Ungültige IDN-Domain %s: %s", domain, exc)
            return False
        match = DOMAIN_VALIDATOR.match(domain)
        if match:
            return True
        LOGGER.debug("Domain %s ist ungültig", domain)
        return False
    except Exception as exc:
        LOGGER.error("Fehler beim Validieren der Domain %s: %s", domain, exc)
        return False


def parse_domains(content: str, url: str) -> Iterator[str]:
    """Yield valid domains from list content."""
    try:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!")):
                continue
            match = DOMAIN_PATTERN.match(line)
            if match:
                domain = (match.group(1) or match.group(2) or match.group(3)).lower()
                if ist_gueltige_domain(domain) and not domain.startswith("*"):
                    yield domain
    except Exception as exc:
        LOGGER.error("Fehler beim Parsen der Domains aus %s: %s", url, exc)


def categorize_list(url: str) -> str:
    """Categorize list URL."""
    try:
        url_lower = url.lower()
        if any(x in url_lower for x in ["malware", "phishing", "crypto"]):
            return "malware"
        if any(x in url_lower for x in ["ads", "ad", "tracking"]):
            return "ads"
        if any(x in url_lower for x in ["porn", "adult"]):
            return "adult"
        return "unknown"
    except Exception as exc:
        LOGGER.error("Fehler beim Kategorisieren der URL %s: %s", url, exc)
        return "unknown"


def evaluate_lists(statistics: Dict, config: Dict) -> None:
    """Evaluate list statistics and update metrics."""
    try:
        list_stats = statistics.get("list_stats", {})
        for url, stats in list_stats.items():
            stats.setdefault("total", 0)
            stats.setdefault("unique", 0)
            stats.setdefault("subdomains", 0)
            stats.setdefault("reachable", 0)
            stats.setdefault("unreachable", 0)
            duplicates = stats.get("duplicates")
            if duplicates is None:
                duplicates = stats["total"] - stats["unique"]
            stats["duplicates"] = max(duplicates, 0)
            stats["category"] = categorize_list(url)
            if stats["total"] > 0:
                unique_ratio = stats["unique"] / stats["total"]
                reachable_ratio = (
                    stats["reachable"] / (stats["reachable"] + stats["unreachable"])
                    if stats["reachable"] + stats["unreachable"] > 0
                    else 0
                )
                category_weight = config["category_weights"].get(stats["category"], 1.0)
                subdomain_ratio = (
                    stats["subdomains"] / stats["total"] if stats["total"] > 0 else 0
                )
                stats["score"] = (
                    unique_ratio * 0.4
                    + reachable_ratio * 0.3
                    + (1 if url in config["priority_lists"] else 0) * 0.1
                    - subdomain_ratio * 0.1
                ) * category_weight
            else:
                stats["score"] = 0.0
    except Exception as exc:
        LOGGER.error("Fehler beim Bewerten der Listen: %s", exc)
