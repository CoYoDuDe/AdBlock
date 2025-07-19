from __future__ import annotations

from typing import List, Tuple, Set
import os
import logging

from filter_engine import ist_gueltige_domain


def load_hosts_sources(
    config: dict, script_dir: str, logger: logging.Logger
) -> List[str]:
    """Load source URLs from configuration file."""
    sources_path = os.path.join(script_dir, "hosts_sources.conf")
    try:
        if not os.path.exists(sources_path):
            logger.warning(
                "Quell-URLs-Datei %s nicht gefunden, erstelle Standarddatei",
                sources_path,
            )
            with open(sources_path, "w", encoding="utf-8") as f:
                f.write(
                    "\n".join(
                        [
                            "https://adaway.org/hosts.txt",
                            "https://v.firebog.net/hosts/Easyprivacy.txt",
                        ]
                    )
                )
        with open(sources_path, "r", encoding="utf-8") as f:
            sources = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
        priority = config["priority_lists"]
        if config["prioritize_lists"]:
            sources = sorted(sources, key=lambda x: 0 if x in priority else 1)
        logger.debug("Geladene Quell-URLs: %d", len(sources))
        return sources
    except Exception as exc:
        logger.error("Fehler beim Laden der Quell-URLs: %s", exc)
        return []


def load_whitelist_blacklist(
    script_dir: str, logger: logging.Logger
) -> Tuple[Set[str], Set[str]]:
    """Load whitelist and blacklist files."""
    try:
        whitelist: Set[str] = set()
        blacklist: Set[str] = set()
        for file, target in [
            ("whitelist.txt", whitelist),
            ("blacklist.txt", blacklist),
        ]:
            filepath = os.path.join(script_dir, file)
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        domain = line.strip().lower()
                        if (
                            domain
                            and not domain.startswith("#")
                            and ist_gueltige_domain(domain)
                        ):
                            target.add(domain)
        logger.debug(
            "Whitelist: %d Einträge, Blacklist: %d Einträge",
            len(whitelist),
            len(blacklist),
        )
        return whitelist, blacklist
    except Exception as exc:
        logger.error("Fehler beim Laden von Whitelist/Blacklist: %s", exc)
        return set(), set()
