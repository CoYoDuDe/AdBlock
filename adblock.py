#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

try:
    import aiohttp
    import aiodns
    import psutil
    import aiofiles
except ImportError:
    print(
        "Bitte ./setup_env.sh ausführen oder 'pip install -r requirements.txt'",
        file=sys.stderr,
    )
    sys.exit(1)

import logging
import os
import gc
import hashlib
import json
import subprocess
import time
import shutil
from argparse import ArgumentParser
import argparse
from collections import defaultdict
import socket
import asyncio
import backoff
from enum import Enum
from typing import Any, Dict, Sequence, Set

from caching import (
    CacheManager,
    DomainTrie,
    cleanup_temp_files,
    sanitize_tmp_identifier,
)
import config
from config import (
    DB_PATH,
    DEFAULT_CONFIG,
    DEFAULT_HOST_SOURCES,
    LOG_FORMAT,
    REACHABLE_FILE,
    SCRIPT_DIR,
    TMP_DIR,
    UNREACHABLE_FILE,
    CONFIG,
    DNS_CACHE,
    dns_cache_lock,
    logged_messages,
    console_logged_messages,
)
from filter_engine import evaluate_lists, parse_domains
from monitoring import get_system_resources, monitor_resources
from networking import (
    is_ipv6_supported,
    select_best_dns_server,
    send_email,
    setup_git,
    test_domain_batch,
    upload_to_github,
)
from source_loader import load_hosts_sources, load_whitelist_blacklist
from writer import safe_save, export_statistics_csv, export_prometheus_metrics


class SystemMode(Enum):
    NORMAL = "normal"
    LOW_MEMORY = "low_memory"
    EMERGENCY = "emergency"


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = ArgumentParser(description="AdBlock hosts generator")
    parser.add_argument(
        "--config",
        default=os.path.join(SCRIPT_DIR, "config.json"),
        help="Pfad zur Konfigurationsdatei",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Aktiviere Debug-Logging",
    )
    return parser.parse_args(args)


def _is_console_handler(handler: logging.Handler) -> bool:
    if not isinstance(handler, logging.StreamHandler):
        return False
    stream = getattr(handler, "stream", None)
    stdout = getattr(sys, "stdout", None)
    stderr = getattr(sys, "stderr", None)
    return stream is stdout or stream is stderr


class _LogOncePerCallFilter(logging.Filter):
    """Filter, der pro log_once-Aufruf den Handler-Zugriff steuert."""

    __slots__ = ("_allow", "_is_console", "_state", "_marker")

    def __init__(
        self,
        allow: bool,
        is_console: bool,
        state: dict[str, bool],
        marker: object,
    ) -> None:
        super().__init__(name="adblock.log_once")
        self._allow = allow
        self._is_console = is_console
        self._state = state
        self._marker = marker

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "_log_once_marker", None) is not self._marker:
            return True
        if not self._allow:
            return False
        if self._is_console:
            self._state["console"] = True
        else:
            self._state["file"] = True
        return True


def log_once(level, message, console=True):
    log_to_file = message not in logged_messages
    log_to_console = console and message not in console_logged_messages

    if not (log_to_file or log_to_console):
        return

    if not logger.isEnabledFor(level):
        return

    handlers_with_scope: list[tuple[logging.Handler, bool]] = []
    seen_handlers: set[int] = set()
    current_logger = logger
    while current_logger:
        for handler in current_logger.handlers:
            handler_id = id(handler)
            if handler_id in seen_handlers:
                continue
            seen_handlers.add(handler_id)
            handlers_with_scope.append((handler, _is_console_handler(handler)))
        if not current_logger.propagate:
            break
        current_logger = current_logger.parent

    dispatch_state = {"file": False, "console": False}
    filters_attached: list[tuple[logging.Handler, _LogOncePerCallFilter]] = []

    if handlers_with_scope:
        marker = object()
        for handler, is_console in handlers_with_scope:
            allow_logging = log_to_console if is_console else log_to_file
            filter_obj = _LogOncePerCallFilter(allow_logging, is_console, dispatch_state, marker)
            handler.createLock()
            handler.acquire()
            try:
                handler.addFilter(filter_obj)
            finally:
                handler.release()
            filters_attached.append((handler, filter_obj))

        try:
            try:
                fn, lno, func, sinfo = logger.findCaller(stack_info=False, stacklevel=3)
            except TypeError:
                fn, lno, func = logger.findCaller(stack_info=False)
                sinfo = None
            record = logger.makeRecord(
                logger.name,
                level,
                fn,
                lno,
                message,
                args=(),
                exc_info=None,
                func=func,
                extra=None,
                sinfo=sinfo,
            )
            setattr(record, "_log_once_marker", marker)
            logger.handle(record)
        finally:
            for handler, filter_obj in filters_attached:
                handler.acquire()
                try:
                    handler.removeFilter(filter_obj)
                finally:
                    handler.release()
    else:
        logger.log(level, message, stacklevel=3)
        # Wenn es keine aktiven Handler gibt, markieren wir den Logeintrag nicht als
        # verarbeitet. Dadurch werden Bootmeldungen erneut ausgegeben, sobald später
        # echte Handler zur Verfügung stehen.

    if log_to_file and dispatch_state["file"]:
        logged_messages.add(message)
    if log_to_console and dispatch_state["console"]:
        console_logged_messages.add(message)


def create_default_list_stats_entry() -> Dict[str, Any]:
    """Erzeugt den Standarddatensatz für eine Listenstatistik."""

    return {
        "total": 0,
        "unique": 0,
        "reachable": 0,
        "unreachable": 0,
        "duplicates": 0,
        "subdomains": 0,
        "score": 0.0,
        "category": "unknown",
    }


STATISTICS = {
    "total_domains": 0,
    "unique_domains": 0,
    "reachable_domains": 0,
    "unreachable_domains": 0,
    "duplicates": 0,
    "failed_lists": 0,
    "cache_hits": 0,
    "cache_flushes": 0,
    "trie_cache_hits": 0,
    "list_stats": defaultdict(create_default_list_stats_entry),
    "list_recommendations": [],
    "error_message": "",
    "run_failed": False,
    "domain_sources": {},
}


def calculate_unique_domains(
    url_counts: Dict[str, Dict[str, int]],
    global_unique_domains: Set[str],
) -> int:
    """Berechnet die Anzahl einzigartiger Domains über alle Listen."""

    if global_unique_domains:
        return len(global_unique_domains)
    if any(counts.get("unique", 0) for counts in url_counts.values()):
        # Alle potentiellen Domains wurden herausgefiltert (z. B. durch die Whitelist)
        # und tauchen daher nicht in den exportierten Ergebnissen auf.
        return 0
    return sum(counts.get("unique", 0) for counts in url_counts.values())


# Die Standardkonfiguration und das Log-Format werden zentral in config.py
# verwaltet. Die hier zuvor vorhandenen Duplikate führten zu Ruff-Fehlern
# (F811). Durch das Importieren der Werte vermeiden wir abweichende Angaben
# zwischen den Modulen und stellen sicher, dass Konfigurationsänderungen nur an
# einer Stelle erfolgen müssen.

logger = logging.getLogger(__name__)


def deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Führt zwei Dictionaries rekursiv zusammen."""

    merged: Dict[str, Any] = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = deep_merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def sanitize_url_for_tmp(url: str) -> str:
    """Gibt einen sicheren Dateinamen für die zwischengespeicherte URL zurück."""

    return sanitize_tmp_identifier(url)


def ensure_list_stats_entry(
    url: str,
    *,
    total: int | None = None,
    unique: int | None = None,
    subdomains: int | None = None,
    duplicates: int | None = None,
) -> Dict[str, Any]:
    """Stellt sicher, dass für die URL ein Statistik-Eintrag existiert und aktualisiert ihn."""

    entry = STATISTICS["list_stats"].setdefault(url, create_default_list_stats_entry())
    if total is not None:
        entry["total"] = total
    if unique is not None:
        entry["unique"] = unique
    if subdomains is not None:
        entry["subdomains"] = subdomains
    if duplicates is not None:
        entry["duplicates"] = max(duplicates, 0)
    else:
        total_value = entry.get("total", 0)
        unique_value = entry.get("unique", 0)
        subdomain_value = entry.get("subdomains", 0)
        entry["duplicates"] = max(total_value - unique_value - subdomain_value, 0)
    entry.setdefault("reachable", 0)
    entry.setdefault("unreachable", 0)
    entry.setdefault("score", 0.0)
    entry.setdefault("category", "unknown")
    return entry


async def deduplicate_unreachable_domains() -> list[str]:
    """Liest die unerreichbaren Domains ein, dedupliziert sie und aktualisiert die Statistik."""

    if not os.path.exists(UNREACHABLE_FILE):
        STATISTICS["unreachable_domains"] = 0
        return []

    async with aiofiles.open(UNREACHABLE_FILE, "r", encoding="utf-8") as file:
        raw_unreachable = [line.strip() async for line in file if line.strip()]

    unique_unreachable = sorted(dict.fromkeys(raw_unreachable))

    async with aiofiles.open(UNREACHABLE_FILE, "w", encoding="utf-8") as file:
        await file.write("\n".join(unique_unreachable))

    STATISTICS["unreachable_domains"] = len(unique_unreachable)
    return unique_unreachable


def sync_cache_flush_statistics(cache_manager: CacheManager | None) -> None:
    """Synchronisiert den Cache-Flush-Zähler mit den globalen Statistiken."""

    if cache_manager is None:
        return

    STATISTICS["cache_flushes"] = cache_manager.flush_count


async def load_unique_sorted_domains(file_path: str) -> list[str]:
    """Liest Domains aus einer Datei, entfernt Duplikate und sortiert deterministisch."""

    async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
        domains = [
            line.strip() async for line in f if line.strip() and line.strip() != ""
        ]
    unique_domains = dict.fromkeys(domains)
    return sorted(unique_domains)


async def load_sorted_domains_with_statistics(file_path: str) -> list[str]:
    """Lädt sortierte Domains und aktualisiert die Statistik der erreichbaren Domains."""

    sorted_domains = await load_unique_sorted_domains(file_path)
    STATISTICS["reachable_domains"] = len(sorted_domains)
    return sorted_domains


def build_dnsmasq_lines(
    domains: Sequence[str], config_values: Dict[str, Any], include_ipv6: bool
) -> list[str]:
    """Erzeugt dnsmasq-Einträge für die angegebenen Domains."""

    dnsmasq_lines: list[str] = []
    if config_values.get("use_ipv4_output", False):
        dnsmasq_lines.extend(
            f"address=/{domain}/{config_values['web_server_ipv4']}"
            for domain in domains
        )
    if config_values.get("use_ipv6_output", False) and include_ipv6:
        dnsmasq_lines.extend(
            f"address=/{domain}/{config_values['web_server_ipv6']}"
            for domain in domains
        )
    return dnsmasq_lines


def build_hosts_content(domains: Sequence[str], config_values: Dict[str, Any]) -> str:
    """Erzeugt den Inhalt der hosts.txt für die angegebenen Domains."""

    lines = [f"{config_values['hosts_ip']} {domain}" for domain in domains if domain]
    return "\n".join(lines).strip()


def load_config(config_path: str | None = None):
    if config_path is None:
        config_path = os.path.join(SCRIPT_DIR, "config.json")
    logger.debug(f"Versuche, Konfigurationsdatei zu laden: {config_path}")
    try:
        custom_config: Dict[str, Any] = {}
        if not os.path.exists(config_path):
            logger.warning(
                f"Konfigurationsdatei {config_path} nicht gefunden, erstelle Standardkonfiguration"
            )
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
                f.write("\n")
        else:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    custom_config = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(
                    f"Fehler beim Parsen von config.json: {e}. Verwende Standardkonfiguration."
                )
                custom_config = {}
            except Exception as e:
                logger.error(
                    f"Fehler beim Laden von config.json: {e}. Verwende Standardkonfiguration."
                )
                custom_config = {}
        CONFIG.clear()
        CONFIG.update(deep_merge_dicts(DEFAULT_CONFIG, custom_config))
        for key in [
            "log_file",
            "hosts_ip",
            "use_smtp",
            "send_email",
            "resource_thresholds",
            "dns_servers",
            "cache_flush_interval",
            "category_weights",
            "http_timeout",
        ]:
            if key not in CONFIG:
                CONFIG[key] = DEFAULT_CONFIG[key]
                logger.warning(
                    f"'{key}' nicht in Konfiguration gefunden, verwende Standard: {CONFIG[key]}"
                )
        valid_dns_servers = []
        for server in CONFIG["dns_servers"]:
            try:
                socket.inet_pton(socket.AF_INET, server)
                valid_dns_servers.append(server)
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, server)
                    valid_dns_servers.append(server)
                except socket.error:
                    logger.warning(f"Ungültige DNS-Server-Adresse: {server}")
        if not valid_dns_servers:
            logger.warning(
                "Keine gültigen DNS-Server angegeben, verwende Fallback: 8.8.8.8, 1.1.1.1"
            )
            CONFIG["dns_servers"] = ["8.8.8.8", "1.1.1.1"]
        else:
            CONFIG["dns_servers"] = valid_dns_servers
        if (
            not isinstance(CONFIG["cache_flush_interval"], (int, float))
            or CONFIG["cache_flush_interval"] <= 0
        ):
            logger.warning("Ungültiges cache_flush_interval, verwende Standard: 300")
            CONFIG["cache_flush_interval"] = 300
        if (
            not isinstance(CONFIG["http_timeout"], (int, float))
            or CONFIG["http_timeout"] <= 0
        ):
            logger.warning("Ungültiges http_timeout, verwende Standard: 60")
            CONFIG["http_timeout"] = 60
        if not isinstance(CONFIG["category_weights"], dict):
            logger.warning("Ungültige category_weights, verwende Standard")
            CONFIG["category_weights"] = DEFAULT_CONFIG["category_weights"]
        CONFIG["smtp_password"] = os.environ.get(
            "SMTP_PASSWORD", CONFIG.get("smtp_password", "")
        )
        if CONFIG["send_email"] and CONFIG["use_smtp"]:
            if not all(
                [
                    CONFIG.get(k)
                    for k in [
                        "smtp_server",
                        "smtp_port",
                        "smtp_user",
                        "smtp_password",
                        "email_recipient",
                        "email_sender",
                    ]
                ]
            ):
                logger.warning(
                    "Ungültige SMTP-Konfiguration, deaktiviere E-Mail-Benachrichtigungen"
                )
                CONFIG["send_email"] = False
        persisted_config: Dict[str, Any] = dict(CONFIG)
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(persisted_config, f, indent=4)
                f.write("\n")
            logger.debug(f"Konfigurationsdatei aktualisiert: {config_path}")
        except Exception as e:
            logger.error(f"Fehler beim Speichern der Konfigurationsdatei: {e}")
        logger.info(f"Verwendete DNS-Server: {', '.join(CONFIG['dns_servers'])}")
    except Exception as e:
        logger.error(
            f"Kritischer Fehler in load_config: {e}. Verwende Standardkonfiguration."
        )
        CONFIG.clear()
        CONFIG.update(deep_merge_dicts(DEFAULT_CONFIG, {}))


def setup_logging():
    try:
        if "log_file" not in CONFIG:
            CONFIG["log_file"] = DEFAULT_CONFIG["log_file"]
            logger.warning(
                f"'log_file' nicht in Konfiguration gefunden, verwende Standard: {CONFIG['log_file']}"
            )

        log_dir = os.path.dirname(CONFIG["log_file"])
        if log_dir:
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError as e:
                logger.error(
                    f"Fehler beim Erstellen des Log-Verzeichnisses {log_dir}: {e}"
                )
                sys.exit(1)
            if not os.access(log_dir, os.W_OK):
                logger.error(
                    f"Keine Schreibrechte für Log-Verzeichnis {log_dir}, beende Skript"
                )
                sys.exit(1)

        level = getattr(
            logging, CONFIG.get("logging_level", "INFO").upper(), logging.INFO
        )
        if CONFIG.get("detailed_log", False):
            level = logging.DEBUG
        elif config.global_mode == SystemMode.EMERGENCY:
            level = logging.ERROR

        logger.handlers.clear()

        handler = logging.FileHandler(CONFIG["log_file"], mode="w")
        if CONFIG.get("log_format") == "json":
            handler.setFormatter(
                logging.Formatter(
                    '{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", '
                    '"operation": "%(funcName)s"}'
                )
            )
        else:
            handler.setFormatter(logging.Formatter(LOG_FORMAT))
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)

        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(handler.formatter)
        logger.addHandler(stream_handler)

        logger.setLevel(level)

        logger.debug(f"Logging konfiguriert mit Level {logging.getLevelName(level)}")
        logger.info("Logging erfolgreich konfiguriert")
    except Exception as e:
        logger.error(f"Fehler beim Einrichten des Loggings: {e}")
        sys.exit(1)


def calculate_md5(content: str) -> str:
    try:
        return hashlib.md5(content.encode("utf-8")).hexdigest()
    except Exception as e:
        logger.error(f"Fehler beim Berechnen des MD5-Hash: {e}")
        return ""


def initialize_directories_and_files():
    try:
        os.makedirs(TMP_DIR, exist_ok=True)
        files = [
            ("config.json", DEFAULT_CONFIG, True),
            (
                "hosts_sources.conf",
                "\n".join(DEFAULT_HOST_SOURCES),
                False,
            ),
            ("whitelist.txt", "# Whitelist für Domains, eine pro Zeile\n", False),
            ("blacklist.txt", "# Blacklist für Domains, eine pro Zeile\n", False),
            (os.path.join(TMP_DIR, "statistics.json"), {}, True),
        ]
        for path, content, is_json in files:
            filepath = os.path.join(SCRIPT_DIR, path)
            if not os.path.exists(filepath):
                safe_save(filepath, content, logger, is_json=is_json)
                logger.info(f"Erstellt: {filepath}")
        logger.debug("Verzeichnisse und Dateien initialisiert")
    except Exception as e:
        logger.error(f"Fehler beim Initialisieren der Verzeichnisse und Dateien: {e}")
        raise


def restart_dnsmasq(config_values: dict) -> bool:
    """Restart the DNSMasq service if possible."""
    systemctl_available = shutil.which("systemctl") is not None
    service_available = shutil.which("service") is not None

    if systemctl_available:
        try:
            subprocess.run(["systemctl", "restart", "dnsmasq"], check=True)
            logger.info("DNSMasq erfolgreich neu gestartet")
            return True
        except subprocess.CalledProcessError as exc:
            logger.warning("Fehler beim Neustarten von DNSMasq via systemctl: %s", exc)

    if service_available:
        try:
            subprocess.run(["service", "dnsmasq", "restart"], check=True)
            logger.info("DNSMasq erfolgreich via service neu gestartet")
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Fehler beim Neustarten von DNSMasq via service: %s", exc)
            if config.global_mode != SystemMode.EMERGENCY:
                send_email(
                    "Fehler im AdBlock-Skript",
                    f"DNSMasq-Neustart fehlgeschlagen: {exc}",
                    config_values,
                )
            return False

    if not systemctl_available and not service_available:
        logger.warning(
            "Weder systemctl noch service verfügbar, DNSMasq kann nicht neu gestartet werden"
        )

    return False


# Die Funktionen zum Laden der Quelllisten sowie von White- und Blacklist sind
# bereits im Modul ``source_loader`` implementiert und werden hier nur noch
# importiert. Dadurch vermeiden wir doppelte Logik innerhalb des Projekts.


# =============================================================================
# 12. HAUPTLOGIK
# =============================================================================


@backoff.on_exception(
    backoff.expo, (aiohttp.ClientError, asyncio.TimeoutError), max_tries=3
)
async def process_list(
    url: str, cache_manager: CacheManager, session: aiohttp.ClientSession
) -> tuple[int, int, int, int]:
    """Verarbeitet eine Blockliste und extrahiert Domains"""
    try:
        if config.global_mode == SystemMode.EMERGENCY:
            log_once(
                logging.WARNING,
                f"Emergency-Mode: Liste {url} wird übersprungen, um Ressourcen zu sparen",
                console=True,
            )
            return 0, 0, 0, 0

        logger.debug(f"Verarbeite Liste: {url}")
        async with session.get(url, timeout=CONFIG["http_timeout"]) as response:
            logger.debug(f"HTTP-Status für {url}: {response.status}")
            if response.status == 404:
                logger.error(f"Liste {url} nicht gefunden (404)")
                raise aiohttp.ClientError("Liste nicht gefunden (404)")
            if response.status >= 400:
                logger.error(
                    f"Fehler beim Abrufen der Liste {url}: HTTP-Status {response.status}, Grund: {response.reason}"
                )
                raise aiohttp.ClientError(
                    f"HTTP-Fehler: {response.status} {response.reason}"
                )
            response.raise_for_status()
            content = await response.text()
        logger.debug(f"Inhalt von {url} heruntergeladen, Länge: {len(content)} Zeichen")
        if not content.strip():
            logger.warning(f"Liste {url} ist leer")
            return 0, 0, 0, 0
        sample_lines = "\n".join(content.splitlines()[:5])
        logger.debug(f"Erste Zeilen von {url}:\n{sample_lines}")
        current_md5 = calculate_md5(content)
        cached_entry = cache_manager.get_list_cache_entry(url)
        sanitized_url = sanitize_url_for_tmp(url)
        temp_file = os.path.join(TMP_DIR, f"{sanitized_url}.tmp")
        filtered_file = os.path.join(TMP_DIR, f"{sanitized_url}.filtered")
        if cached_entry and cached_entry["md5"] == current_md5:
            cached_stats_available = all(
                cached_entry.get(field) is not None
                for field in (
                    "total_domains",
                    "unique_domains",
                    "subdomains",
                    "duplicates",
                )
            )
            filtered_exists = os.path.exists(filtered_file)
            if cached_stats_available and filtered_exists:
                total_domains = int(cached_entry.get("total_domains", 0) or 0)
                unique_domains = int(cached_entry.get("unique_domains", 0) or 0)
                subdomain_count = int(cached_entry.get("subdomains", 0) or 0)
                cached_duplicates = cached_entry.get("duplicates")
                if cached_duplicates is None:
                    cached_duplicates = max(total_domains - unique_domains, 0)
                else:
                    cached_duplicates = max(int(cached_duplicates), 0)
                previous_stats = STATISTICS["domain_sources"].get(url, {})
                previous_duplicates = previous_stats.get("duplicates", 0)
                delta_duplicates = max(cached_duplicates - previous_duplicates, 0)
                if delta_duplicates:
                    STATISTICS["duplicates"] += delta_duplicates
                STATISTICS["domain_sources"].setdefault(url, {})
                STATISTICS["domain_sources"][url]["duplicates"] = cached_duplicates
                STATISTICS["domain_sources"][url]["subdomains"] = subdomain_count
                STATISTICS["cache_hits"] += 1
                logger.info(f"Liste {url} unverändert, verwende Cache")
                return total_domains, unique_domains, subdomain_count, cached_duplicates
            if not cached_stats_available:
                logger.debug(
                    "Cache-Eintrag für %s ohne vollständige Statistik, führe Verarbeitung erneut durch",
                    url,
                )
            elif not filtered_exists:
                logger.debug(
                    "Cache-Eintrag für %s vorhanden, aber gefilterte Datei %s fehlt – verarbeite Liste erneut",
                    url,
                    filtered_file,
                )
        trie = DomainTrie(url, cache_manager.config)
        domain_count = 0
        unique_count = 0
        subdomain_count = 0
        duplicate_count = 0
        batch = []
        async with aiofiles.open(
            temp_file, "w", encoding="utf-8"
        ) as f_temp, aiofiles.open(filtered_file, "w", encoding="utf-8") as f_filtered:

            async def flush_batch(reason: str | None = None) -> int:
                nonlocal batch, unique_count, subdomain_count
                if reason:
                    logger.debug(reason)
                if batch:
                    for d in batch:
                        if CONFIG["remove_redundant_subdomains"] and trie.has_parent(d):
                            subdomain_count += 1
                        else:
                            await f_filtered.write(d + "\n")
                            unique_count += 1
                    await f_temp.write("\n".join(batch) + "\n")
                    batch.clear()
                trie.flush()
                gc.collect()
                new_free_memory = psutil.virtual_memory().available
                logger.debug(
                    "Batch verarbeitet%s, Speicher nach GC: %.2f MB",
                    f" ({reason})" if reason else "",
                    new_free_memory / (1024 * 1024),
                )
                return new_free_memory

            for domain in parse_domains(content, url):
                domain_count += 1
                free_memory = psutil.virtual_memory().available
                trie.storage.update_threshold()
                _, batch_size, _ = get_system_resources()
                batch_size = min(
                    batch_size,
                    10 if config.global_mode == SystemMode.EMERGENCY else 20,
                )
                if (
                    free_memory
                    < CONFIG["resource_thresholds"]["emergency_memory_mb"] * 1024 * 1024
                ):
                    log_once(
                        logging.WARNING,
                        (
                            "Kritischer Speicherstand: %s MB frei, leere Batch und aktiviere "
                            "Emergency-Mode"
                        )
                        % (free_memory / (1024 * 1024)),
                        console=True,
                    )
                    if batch:
                        free_memory = await flush_batch(
                            "Emergency-Flush wegen kritischem Speicher"
                        )
                    else:
                        free_memory = await flush_batch(
                            "Emergency-Flush ohne Batch-Inhalt"
                        )
                    previous_mode = config.global_mode
                    config.global_mode = SystemMode.EMERGENCY
                    batch_size = max(1, min(batch_size, 5))
                    if previous_mode != SystemMode.EMERGENCY:
                        logger.warning(
                            "Schalte in den Emergency-Mode um und reduziere Batch-Größe auf %s",
                            batch_size,
                        )
                    else:
                        logger.debug(
                            "Emergency-Mode bleibt aktiv, Batch-Größe auf %s begrenzt",
                            batch_size,
                        )
                    if (
                        free_memory
                        < CONFIG["resource_thresholds"]["emergency_memory_mb"]
                        * 1024
                        * 1024
                    ):
                        logger.debug(
                            "Speicher nach Emergency-Flush weiterhin kritisch: %.2f MB",
                            free_memory / (1024 * 1024),
                        )
                if not trie.insert(domain):
                    duplicate_count += 1
                    continue
                batch.append(domain)
                if len(batch) >= batch_size:
                    await flush_batch(f"Regulärer Batch-Flush mit {len(batch)} Domains")
                if domain_count % 1000 == 0:
                    memory = psutil.Process().memory_info().rss / (1024 * 1024)
                    logger.debug(
                        f"Verarbeite {url}: {domain_count} Domains, Speicher: {memory:.2f} MB"
                    )
                    trie.flush()
                    gc.collect()
            if batch:
                await flush_batch(f"Finaler Batch-Flush mit {len(batch)} Domains")
        cache_manager.upsert_list_cache(
            url,
            current_md5,
            total_domains=domain_count,
            unique_domains=unique_count,
            subdomains=subdomain_count,
            duplicates=duplicate_count,
        )
        trie.close()
        STATISTICS["duplicates"] += duplicate_count
        STATISTICS["domain_sources"].setdefault(url, {})
        STATISTICS["domain_sources"][url]["duplicates"] = duplicate_count
        STATISTICS["domain_sources"][url]["subdomains"] = subdomain_count
        gc.collect()
        logger.info(
            f"Extrahierte {domain_count} Domains aus {url}, {unique_count} einzigartig, {duplicate_count} Duplikate"
        )
        return domain_count, unique_count, subdomain_count, duplicate_count
    except aiohttp.ClientError as e:
        logger.warning(f"Netzwerkfehler beim Verarbeiten der Liste {url}: {e}")
        raise
    except asyncio.TimeoutError as e:
        logger.warning(f"Netzwerk-Timeout bei der Liste {url}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unbekannter Fehler beim Verarbeiten der Liste {url}: {e}")
        raise


async def main(config_path: str | None = None, debug: bool = False):
    """Hauptfunktion des Skripts."""
    cache_flush_lock = asyncio.Lock()
    cache_flush_task = None
    resource_monitor_task = None
    try:
        start_time = time.time()
        logger.info("Starte AdBlock-Skript")
        free_memory = psutil.virtual_memory().available / (1024 * 1024)
        logger.debug(f"Freier Speicher: {free_memory:.2f} MB")

        logger.debug("Lade Konfiguration...")
        load_config(config_path)
        if debug:
            CONFIG["detailed_log"] = True
            CONFIG["logging_level"] = "DEBUG"
        logger.debug("Konfiguration geladen")

        if free_memory < CONFIG["resource_thresholds"]["emergency_memory_mb"]:
            log_once(
                logging.WARNING,
                f"Kritischer Speicherstand vor Start: {free_memory:.2f} MB frei, aktiviere Emergency-Mode",
                console=True,
            )
            config.global_mode = SystemMode.EMERGENCY
        elif free_memory < CONFIG["resource_thresholds"]["low_memory_mb"]:
            log_once(
                logging.WARNING,
                f"Niedriger Speicherstand vor Start: {free_memory:.2f} MB frei, aktiviere Low-Memory-Mode",
                console=True,
            )
            config.global_mode = SystemMode.LOW_MEMORY
        else:
            config.global_mode = SystemMode.NORMAL

        logger.debug("Richte Logging ein...")
        setup_logging()
        logger.debug("Logging eingerichtet")

        logger.debug(f"Erstelle temporäres Verzeichnis: {TMP_DIR}")
        os.makedirs(TMP_DIR, exist_ok=True)
        logger.debug("Temporäres Verzeichnis erstellt")

        logger.debug("Initialisiere CacheManager...")
        config.cache_manager = CacheManager(
            DB_PATH, CONFIG["cache_flush_interval"], config=CONFIG
        )
        if config.cache_manager is None:
            raise ValueError("CacheManager konnte nicht initialisiert werden")
        logger.debug("CacheManager initialisiert")

        logger.debug("Initialisiere Verzeichnisse und Dateien...")
        initialize_directories_and_files()
        logger.debug("Verzeichnisse und Dateien initialisiert")

        logger.debug("Bereinige temporäre Dateien...")
        cleanup_temp_files(config.cache_manager)
        logger.debug("Temporäre Dateien bereinigt")

        memory = psutil.Process().memory_info().rss / (1024 * 1024)
        logger.info(f"Initialer Speicherverbrauch: {memory:.2f} MB")

        logger.debug("Starte Cache-Flush- und Ressourcenüberwachungs-Tasks...")
        cache_flush_task = asyncio.create_task(
            config.cache_manager.flush_cache_periodically()
        )
        resource_monitor_task = asyncio.create_task(
            monitor_resources(config.cache_manager, CONFIG)
        )
        logger.debug("Cache-Flush- und Ressourcenüberwachungs-Tasks gestartet")

        if CONFIG["github_upload"]:
            logger.debug("Git-Upload aktiviert, verwende manuelle Git-Konfiguration")
            if not setup_git():
                logger.warning("Git-Setup fehlgeschlagen, deaktiviere Git-Upload")
                CONFIG["github_upload"] = False
        else:
            logger.debug("Git-Upload deaktiviert")

        logger.debug("Lade Quell-URLs...")
        sources = load_hosts_sources(CONFIG, SCRIPT_DIR, logger)
        if not sources:
            logger.error("Keine Quell-URLs in hosts_sources.conf gefunden")
            if config.global_mode != SystemMode.EMERGENCY:
                send_email(
                    "Fehler im AdBlock-Skript",
                    "Keine Quell-URLs in hosts_sources.conf gefunden",
                    CONFIG,
                )
            raise ValueError("Keine Quell-URLs gefunden")
        logger.debug(f"Geladene Quell-URLs: {len(sources)}")

        logger.debug("Lade Whitelist und Blacklist...")
        whitelist, blacklist = load_whitelist_blacklist(SCRIPT_DIR, logger)
        logger.debug(
            f"Whitelist: {len(whitelist)} Einträge, Blacklist: {len(blacklist)} Einträge"
        )

        url_counts = {}
        global_unique_domains: Set[str] = set()
        processed_urls = []
        logger.debug("Starte Verarbeitung der Blocklisten...")
        async with aiohttp.ClientSession() as session:
            logger.debug("Wähle beste DNS-Server...")
            dns_servers = await select_best_dns_server(CONFIG["dns_servers"])
            resolver = aiodns.DNSResolver(
                nameservers=dns_servers, timeout=CONFIG["domain_timeout"]
            )
            logger.debug("DNS-Server ausgewählt")
            max_jobs, _, _ = get_system_resources()
            for i in range(0, len(sources), max_jobs):
                batch = sources[i : i + max_jobs]
                tasks = [
                    process_list(url, config.cache_manager, session) for url in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for url, result in zip(batch, results):
                    if isinstance(result, Exception):
                        if isinstance(
                            result, (aiohttp.ClientError, asyncio.TimeoutError)
                        ):
                            message = f"Netzwerkfehler bei {url}: {result}"
                            logger.warning(message)
                        else:
                            message = f"Fehler bei {url}: {result}"
                            logger.error(message)
                        STATISTICS["failed_lists"] += 1
                        STATISTICS["error_message"] = message
                        continue
                    total, unique, subdomains, duplicates = result
                    filtered_path = os.path.join(
                        TMP_DIR, f"{sanitize_url_for_tmp(url)}.filtered"
                    )
                    if os.path.exists(filtered_path):
                        processed_urls.append(url)
                        url_counts[url] = {
                            "total": total,
                            "unique": unique,
                            "subdomains": subdomains,
                            "duplicates": duplicates,
                        }
                        ensure_list_stats_entry(
                            url,
                            total=total,
                            unique=unique,
                            subdomains=subdomains,
                            duplicates=duplicates,
                        )
                    logger.info(f"Verarbeitet {url}: {unique} Domains")
                    memory = psutil.Process().memory_info().rss / (1024 * 1024)
                    logger.debug(f"Speicherverbrauch nach {url}: {memory:.2f} MB")
                    gc.collect()
        if not processed_urls:
            logger.warning("Keine gültigen Domains gefunden")
            STATISTICS["error_message"] = (
                "Alle Listen konnten nicht geladen werden. Bitte "
                "Netzwerkverbindung überprüfen."
            )
            STATISTICS["run_failed"] = True
            if config.global_mode != SystemMode.EMERGENCY:
                send_email(
                    "Fehler im AdBlock-Skript",
                    "Keine gültigen Domains gefunden",
                    CONFIG,
                )
            processed_urls = []
        STATISTICS["total_domains"] = sum(
            counts["total"] for counts in url_counts.values()
        )
        max_jobs, batch_size, max_concurrent_dns = get_system_resources()
        if os.path.exists(REACHABLE_FILE):
            os.remove(REACHABLE_FILE)
        if os.path.exists(UNREACHABLE_FILE):
            os.remove(UNREACHABLE_FILE)
        async with aiofiles.open(
            REACHABLE_FILE, "a", encoding="utf-8"
        ) as f_reachable, aiofiles.open(
            UNREACHABLE_FILE, "a", encoding="utf-8"
        ) as f_unreachable:
            for url in processed_urls:
                stats_entry = ensure_list_stats_entry(
                    url,
                    total=url_counts.get(url, {}).get("total", 0),
                    unique=url_counts.get(url, {}).get("unique", 0),
                    subdomains=url_counts.get(url, {}).get("subdomains", 0),
                    duplicates=url_counts.get(url, {}).get("duplicates"),
                )
                stats_entry["reachable"] = 0
                stats_entry["unreachable"] = 0
                filtered_file = os.path.join(
                    TMP_DIR, f"{sanitize_url_for_tmp(url)}.filtered"
                )
                if not os.path.exists(filtered_file):
                    continue
                domains = []
                async with aiofiles.open(filtered_file, "r", encoding="utf-8") as f:
                    async for line in f:
                        domain = line.strip()
                        if not domain:
                            continue
                        domain_lower = domain.lower()
                        if domain_lower in whitelist:
                            continue
                        global_unique_domains.add(domain)
                        free_memory = psutil.virtual_memory().available
                        config.cache_manager.domain_cache.update_threshold()
                        _, batch_size, max_concurrent_dns = get_system_resources()
                        domains.append(domain)
                        if len(domains) >= batch_size:
                            results = await test_domain_batch(
                                domains,
                                url,
                                resolver,
                                config.cache_manager,
                                whitelist,
                                blacklist,
                                DNS_CACHE,
                                dns_cache_lock,
                                max_concurrent_dns,
                                CONFIG,
                            )
                            for domain, reachable in results:
                                domain_lower = domain.lower()
                                if domain_lower in whitelist:
                                    continue
                                if not isinstance(reachable, bool):
                                    logger.error(
                                        f"Ungültiges Ergebnis für Domain {domain}: {reachable}"
                                    )
                                    continue
                                if reachable:
                                    await f_reachable.write(domain + "\n")
                                    STATISTICS["reachable_domains"] += 1
                                    stats_entry["reachable"] += 1
                                else:
                                    await f_unreachable.write(domain + "\n")
                                    STATISTICS["unreachable_domains"] += 1
                                    stats_entry["unreachable"] += 1
                            domains = []
                            memory = psutil.Process().memory_info().rss / (1024 * 1024)
                            logger.debug(
                                f"Speicherverbrauch nach Batch ({url}): {memory:.2f} MB"
                            )
                            gc.collect()
                            if (
                                free_memory
                                < CONFIG["resource_thresholds"]["emergency_memory_mb"]
                                * 1024
                                * 1024
                            ):
                                log_once(
                                    logging.WARNING,
                                    f"Kritischer Speicherstand: {free_memory/(1024*1024):.2f} MB frei, "
                                    f"reduziere Cache",
                                    console=True,
                                )
                                config.cache_manager.current_cache_size = max(
                                    2, config.cache_manager.current_cache_size // 2
                                )
                                config.cache_manager.adjust_cache_size()
                                config.cache_manager.domain_cache.use_ram = False
                    if domains:
                        results = await test_domain_batch(
                            domains,
                            url,
                            resolver,
                            config.cache_manager,
                            whitelist,
                            blacklist,
                            DNS_CACHE,
                            dns_cache_lock,
                            max_concurrent_dns,
                            CONFIG,
                        )
                        for domain, reachable in results:
                            domain_lower = domain.lower()
                            if domain_lower in whitelist:
                                continue
                            if not isinstance(reachable, bool):
                                logger.error(
                                    f"Ungültiges Ergebnis für Domain {domain}: {reachable}"
                                )
                                continue
                            if reachable:
                                await f_reachable.write(domain + "\n")
                                STATISTICS["reachable_domains"] += 1
                                stats_entry["reachable"] += 1
                            else:
                                await f_unreachable.write(domain + "\n")
                                STATISTICS["unreachable_domains"] += 1
                                stats_entry["unreachable"] += 1
        existing_domain_lowers = {domain.lower() for domain in global_unique_domains}
        blacklist_domains_to_add: list[str] = []
        for domain in sorted(blacklist):
            if not domain:
                continue
            if domain in whitelist:
                continue
            if domain.lower() in existing_domain_lowers:
                continue
            blacklist_domains_to_add.append(domain)
            existing_domain_lowers.add(domain.lower())
        if blacklist_domains_to_add:
            async with aiofiles.open(
                REACHABLE_FILE, "a", encoding="utf-8"
            ) as blacklist_handle:
                for domain in blacklist_domains_to_add:
                    await blacklist_handle.write(domain + "\n")
                    global_unique_domains.add(domain)
            additional_blacklist_count = len(blacklist_domains_to_add)
            STATISTICS["reachable_domains"] += additional_blacklist_count
            blacklist_stats_entry = ensure_list_stats_entry("blacklist.txt")
            blacklist_stats_entry["total"] += additional_blacklist_count
            blacklist_stats_entry["unique"] += additional_blacklist_count
            blacklist_stats_entry["reachable"] += additional_blacklist_count
            blacklist_stats_entry["duplicates"] = max(
                blacklist_stats_entry["total"]
                - blacklist_stats_entry["unique"]
                - blacklist_stats_entry.get("subdomains", 0),
                0,
            )
            STATISTICS["unique_domains"] = len(global_unique_domains)
        STATISTICS["unique_domains"] = calculate_unique_domains(
            url_counts, global_unique_domains
        )
        logger.debug("Statistiken berechnet")
        evaluate_lists(STATISTICS, CONFIG)
        logger.debug("Listen bewertet")
        sorted_domains = await load_sorted_domains_with_statistics(REACHABLE_FILE)
        logger.debug(f"Anzahl der erreichbaren Domains: {len(sorted_domains)}")
        logger.debug(f"Erste 5 erreichbare Domains (Beispiel): {sorted_domains[:5]}")
        ipv6_supported = False
        if CONFIG["use_ipv6_output"]:
            ipv6_supported = await is_ipv6_supported(CONFIG)
        dnsmasq_lines = build_dnsmasq_lines(sorted_domains, CONFIG, ipv6_supported)
        if CONFIG["use_ipv4_output"]:
            logger.debug(
                f"IPv4-Ausgabe aktiviert, {len(sorted_domains)} Einträge für dnsmasq.conf mit IPv4"
            )
        if CONFIG["use_ipv6_output"] and ipv6_supported:
            logger.debug(
                f"IPv6-Ausgabe aktiviert, {len(dnsmasq_lines)} Einträge für dnsmasq.conf mit IPv6"
            )
        dnsmasq_content = "\n".join(dnsmasq_lines)
        hosts_content = build_hosts_content(sorted_domains, CONFIG)
        logger.debug(
            f"Schreibe {len(sorted_domains)} Domains in hosts.txt mit IP {CONFIG['hosts_ip']}"
        )
        async with aiofiles.open(
            os.path.join(SCRIPT_DIR, CONFIG["dns_config_file"]), "w", encoding="utf-8"
        ) as f:
            await f.write(dnsmasq_content)
        async with aiofiles.open(
            os.path.join(SCRIPT_DIR, CONFIG["hosts_file"]), "w", encoding="utf-8"
        ) as f:
            await f.write(hosts_content)
        unreachable_domains = await deduplicate_unreachable_domains()
        if CONFIG["save_unreachable"] and os.path.exists(UNREACHABLE_FILE):
            async with aiofiles.open(
                os.path.join(TMP_DIR, "unreachable.txt"), "w", encoding="utf-8"
            ) as f:
                await f.write("\n".join(unreachable_domains))
        if CONFIG["github_upload"] and config.global_mode != SystemMode.EMERGENCY:
            upload_to_github(CONFIG)
        safe_save(
            os.path.join(TMP_DIR, "statistics.json"),
            STATISTICS,
            logger,
            is_json=True,
        )
        if config.global_mode != SystemMode.EMERGENCY:
            sync_cache_flush_statistics(config.cache_manager)
            export_statistics_csv(TMP_DIR, STATISTICS, logger)
            if CONFIG["export_prometheus"]:
                cache_size = 0
                if config.cache_manager and config.cache_manager.domain_cache:
                    cache_size = config.cache_manager.domain_cache.total_items()
                export_prometheus_metrics(
                    TMP_DIR,
                    STATISTICS,
                    start_time,
                    cache_size,
                    logger,
                )
        recommendations = (
            "\n".join(STATISTICS["list_recommendations"])
            if STATISTICS["list_recommendations"]
            else "Keine Empfehlungen"
        )
        sync_cache_flush_statistics(config.cache_manager)
        summary = f"""
AdBlock-Skript Zusammenfassung (Laufzeit: {time.time() - start_time:.2f}s):
+-----------------------+-----------------+
| Metrik                | Wert            |
+-----------------------+-----------------+
| Total Domains         | {STATISTICS['total_domains']:<15} |
| Einzigartige Domains  | {STATISTICS['unique_domains']:<15} |
| Erreichbare Domains   | {STATISTICS['reachable_domains']:<15} |
| Nicht erreichbare     | {STATISTICS['unreachable_domains']:<15} |
| Duplikate             | {STATISTICS['duplicates']:<15} |
| Cache-Hits            | {STATISTICS['cache_hits']:<15} |
| Cache-Flushes         | {STATISTICS['cache_flushes']:<15} |
| Trie-Cache-Hits       | {STATISTICS['trie_cache_hits']:<15} |
| Fehlgeschlagene Listen| {STATISTICS['failed_lists']:<15} |
+-----------------------+-----------------+
Empfehlungen:
{recommendations}
"""
        logger.info("Zusammenfassung erfolgreich erstellt")
        logger.info(summary)
        if (
            CONFIG.get("send_email", False)
            and config.global_mode != SystemMode.EMERGENCY
        ):
            send_email("AdBlock-Skript Bericht", summary, CONFIG)
        restart_dnsmasq(CONFIG)
        logger.info("Skript erfolgreich abgeschlossen")
    except Exception as e:
        logger.error(f"Kritischer Fehler in der Hauptfunktion: {e}")
        if config.global_mode != SystemMode.EMERGENCY:
            send_email(
                "Kritischer Fehler im AdBlock-Skript",
                f"Skript fehlgeschlagen: {e}",
                CONFIG,
            )
        sys.exit(1)
    finally:
        if cache_flush_task:
            cache_flush_task.cancel()
            try:
                await cache_flush_task
            except asyncio.CancelledError:
                logger.debug("cache_flush_task erfolgreich abgebrochen")
        if resource_monitor_task:
            resource_monitor_task.cancel()
            try:
                await resource_monitor_task
            except asyncio.CancelledError:
                logger.debug("resource_monitor_task erfolgreich abgebrochen")
        if config.cache_manager:
            async with cache_flush_lock:
                flush_performed = config.cache_manager.save_domain_cache()
                if flush_performed:
                    logger.debug("Finaler Cache-Flush erfolgreich ausgeführt")
                sync_cache_flush_statistics(config.cache_manager)


def cli_main(cli_args: list[str] | None = None) -> None:
    """Entry point for the command-line interface."""
    args = parse_args(cli_args)
    try:
        logger.debug("Skript wird gestartet")
        asyncio.run(main(config_path=args.config, debug=args.debug))
    except KeyboardInterrupt:
        logger.info("Skript durch Benutzer abgebrochen")
        sys.exit(0)
    except MemoryError:
        logger.error("Skript abgebrochen: Nicht genügend Speicher verfügbar")
        if config.global_mode != SystemMode.EMERGENCY:
            send_email(
                "Kritischer Fehler im AdBlock-Skript",
                "Skript abgebrochen: Nicht genügend Speicher verfügbar",
                CONFIG,
            )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Kritischer Fehler beim Start des Skripts: {e}")
        if config.global_mode != SystemMode.EMERGENCY:
            send_email(
                "Kritischer Fehler im AdBlock-Skript",
                f"Skript fehlgeschlagen: {e}",
                CONFIG,
            )
        sys.exit(1)


if __name__ == "__main__":
    cli_main()
