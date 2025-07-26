#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import gc
import hashlib
import json
import subprocess
import time
import shutil
from argparse import ArgumentParser
import argparse
from collections import defaultdict
from datetime import datetime
from threading import Lock
import socket
import aiodns

import aiofiles
import aiohttp
import asyncio
import backoff
import psutil
from enum import Enum

from caching import (
    CacheManager,
    DomainTrie,
    cleanup_temp_files,
)
from config import (
    DB_PATH,
    DEFAULT_CONFIG,
    DEFAULT_HOST_SOURCES,
    LOG_FORMAT,
    REACHABLE_FILE,
    SCRIPT_DIR,
    TMP_DIR,
    UNREACHABLE_FILE,
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


CONFIG = {}
DNS_CACHE = {}
dns_cache_lock = Lock()
cache_flush_lock = asyncio.Lock()
cache_manager = None
global_mode = SystemMode.NORMAL

logged_messages = set()
console_logged_messages = set()


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


def log_once(level, message, console=True):
    if message not in logged_messages:
        logger.log(level, message)
        logged_messages.add(message)
    if console and message not in console_logged_messages:
        if level >= logging.ERROR:
            logger.error(message)
        else:
            logger.info(message)
        console_logged_messages.add(message)


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
    "list_stats": defaultdict(
        lambda: {
            "total": 0,
            "unique": 0,
            "reachable": 0,
            "unreachable": 0,
            "duplicates": 0,
            "subdomains": 0,
            "score": 0.0,
            "category": "unknown",
        }
    ),
    "list_recommendations": [],
    "error_message": "",
    "run_failed": False,
    "domain_sources": {},
}


# Die Standardkonfiguration und das Log-Format werden zentral in config.py
# verwaltet. Die hier zuvor vorhandenen Duplikate führten zu Ruff-Fehlern
# (F811). Durch das Importieren der Werte vermeiden wir abweichende Angaben
# zwischen den Modulen und stellen sicher, dass Konfigurationsänderungen nur an
# einer Stelle erfolgen müssen.

logger = logging.getLogger(__name__)


def load_config(config_path: str | None = None):
    if config_path is None:
        config_path = os.path.join(SCRIPT_DIR, "config.json")
    logger.debug(f"Versuche, Konfigurationsdatei zu laden: {config_path}")
    try:
        CONFIG.clear()
        CONFIG.update(DEFAULT_CONFIG)
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
                    CONFIG.update(custom_config)
            except json.JSONDecodeError as e:
                logger.error(
                    f"Fehler beim Parsen von config.json: {e}. Verwende Standardkonfiguration."
                )
                CONFIG.update(DEFAULT_CONFIG)
            except Exception as e:
                logger.error(
                    f"Fehler beim Laden von config.json: {e}. Verwende Standardkonfiguration."
                )
                CONFIG.update(DEFAULT_CONFIG)
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
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(
                    {k: v for k, v in CONFIG.items() if k != "smtp_password"},
                    f,
                    indent=4,
                )
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
        CONFIG.update(DEFAULT_CONFIG)


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
        elif global_mode == SystemMode.EMERGENCY:
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


def restart_dnsmasq(config: dict) -> bool:
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
            if global_mode != SystemMode.EMERGENCY:
                send_email(
                    "Fehler im AdBlock-Skript",
                    f"DNSMasq-Neustart fehlgeschlagen: {exc}",
                    config,
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
) -> tuple[int, int, int]:
    """Verarbeitet eine Blockliste und extrahiert Domains"""
    try:
        if global_mode == SystemMode.EMERGENCY:
            log_once(
                logging.WARNING,
                f"Emergency-Mode: Liste {url} wird übersprungen, um Ressourcen zu sparen",
                console=True,
            )
            return 0, 0, 0

        logger.debug(f"Verarbeite Liste: {url}")
        async with session.get(url, timeout=CONFIG["http_timeout"]) as response:
            logger.debug(f"HTTP-Status für {url}: {response.status}")
            if response.status == 404:
                logger.error(f"Liste {url} nicht gefunden (404)")
                STATISTICS["failed_lists"] += 1
                return 0, 0, 0
            if response.status >= 400:
                logger.error(
                    f"Fehler beim Abrufen der Liste {url}: HTTP-Status {response.status}, Grund: {response.reason}"
                )
                STATISTICS["failed_lists"] += 1
                raise aiohttp.ClientError(
                    f"HTTP-Fehler: {response.status} {response.reason}"
                )
            response.raise_for_status()
            content = await response.text()
        logger.debug(f"Inhalt von {url} heruntergeladen, Länge: {len(content)} Zeichen")
        if not content.strip():
            logger.warning(f"Liste {url} ist leer")
            return 0, 0, 0
        sample_lines = "\n".join(content.splitlines()[:5])
        logger.debug(f"Erste Zeilen von {url}:\n{sample_lines}")
        current_md5 = calculate_md5(content)
        list_cache = cache_manager.load_list_cache()
        temp_file = os.path.join(
            TMP_DIR, f"{url.replace('://', '__').replace('/', '__')}.tmp"
        )
        filtered_file = os.path.join(
            TMP_DIR, f"{url.replace('://', '__').replace('/', '__')}.filtered"
        )
        if url in list_cache and list_cache[url]["md5"] == current_md5:
            logger.info(f"Liste {url} unverändert, verwende Cache")
            if os.path.exists(filtered_file):
                async with aiofiles.open(filtered_file, "r", encoding="utf-8") as f:
                    unique_count = sum(1 for _ in await f.readlines() if _.strip())
                return unique_count, unique_count, 0
        trie = DomainTrie(url)
        domain_count = 0
        unique_count = 0
        subdomain_count = 0
        duplicate_count = 0
        seen_domains = set()
        batch = []
        async with aiofiles.open(
            temp_file, "w", encoding="utf-8"
        ) as f_temp, aiofiles.open(filtered_file, "w", encoding="utf-8") as f_filtered:
            for domain in parse_domains(content, url):
                free_memory = psutil.virtual_memory().available
                trie.storage.update_threshold()
                _, batch_size, _ = get_system_resources()
                batch_size = min(
                    batch_size, 10 if global_mode == SystemMode.EMERGENCY else 20
                )
                if (
                    free_memory
                    < CONFIG["resource_thresholds"]["emergency_memory_mb"] * 1024 * 1024
                ):
                    log_once(
                        logging.WARNING,
                        f"Kritischer Speicherstand: {free_memory/(1024*1024):.2f} MB frei, pausiere Verarbeitung",
                        console=True,
                    )
                    await asyncio.sleep(5)
                if domain in seen_domains:
                    duplicate_count += 1
                    continue
                seen_domains.add(domain)
                trie.insert(domain)
                batch.append(domain)
                domain_count += 1
                if len(batch) >= batch_size:
                    free_memory = psutil.virtual_memory().available
                    logger.debug(
                        f"Verarbeite Batch von {len(batch)} Domains, Speicher: {free_memory/(1024*1024):.2f} MB"
                    )
                    for d in batch:
                        if CONFIG["remove_redundant_subdomains"] and trie.has_parent(d):
                            subdomain_count += 1
                        else:
                            await f_filtered.write(d + "\n")
                            unique_count += 1
                    await f_temp.write("\n".join(batch) + "\n")
                    batch = []
                    trie.flush()
                    gc.collect()
                    logger.debug(
                        f"Batch gespeichert, Speicher nach GC: {psutil.virtual_memory().available/(1024*1024):.2f} MB"
                    )
                if domain_count % 1000 == 0:
                    memory = psutil.Process().memory_info().rss / (1024 * 1024)
                    logger.debug(
                        f"Verarbeite {url}: {domain_count} Domains, Speicher: {memory:.2f} MB"
                    )
                    trie.flush()
                    gc.collect()
            if batch:
                free_memory = psutil.virtual_memory().available
                logger.debug(
                    f"Verarbeite finalen Batch von {len(batch)} Domains, Speicher: {free_memory/(1024*1024):.2f} MB"
                )
                for d in batch:
                    if CONFIG["remove_redundant_subdomains"] and trie.has_parent(d):
                        subdomain_count += 1
                    else:
                        await f_filtered.write(d + "\n")
                        unique_count += 1
                await f_temp.write("\n".join(batch) + "\n")
                gc.collect()
                logger.debug(
                    "Finaler Batch gespeichert, Speicher nach GC: "
                    f"{psutil.virtual_memory().available/(1024*1024):.2f} MB"
                )
        list_cache[url] = {
            "md5": current_md5,
            "last_checked": datetime.now().isoformat(),
        }
        cache_manager.save_list_cache(list_cache)
        trie.close()
        STATISTICS["duplicates"] += duplicate_count
        gc.collect()
        logger.info(
            f"Extrahierte {domain_count} Domains aus {url}, {unique_count} einzigartig, {duplicate_count} Duplikate"
        )
        return domain_count, unique_count, subdomain_count
    except aiohttp.ClientError as e:
        msg = f"Netzwerkfehler beim Verarbeiten der Liste {url}: {e}"
        logger.warning(msg)
        STATISTICS["failed_lists"] += 1
        STATISTICS["error_message"] = msg
        return 0, 0, 0
    except asyncio.TimeoutError as e:
        msg = f"Netzwerk-Timeout bei der Liste {url}: {e}"
        logger.warning(msg)
        STATISTICS["failed_lists"] += 1
        STATISTICS["error_message"] = msg
        return 0, 0, 0
    except Exception as e:
        logger.error(f"Unbekannter Fehler beim Verarbeiten der Liste {url}: {e}")
        STATISTICS["failed_lists"] += 1
        return 0, 0, 0


async def main(config_path: str | None = None, debug: bool = False):
    """Hauptfunktion des Skripts."""
    cache_flush_task = None
    resource_monitor_task = None
    global cache_manager, global_mode
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
            global_mode = SystemMode.EMERGENCY
        elif free_memory < CONFIG["resource_thresholds"]["low_memory_mb"]:
            log_once(
                logging.WARNING,
                f"Niedriger Speicherstand vor Start: {free_memory:.2f} MB frei, aktiviere Low-Memory-Mode",
                console=True,
            )
            global_mode = SystemMode.LOW_MEMORY
        else:
            global_mode = SystemMode.NORMAL

        logger.debug("Richte Logging ein...")
        setup_logging()
        logger.debug("Logging eingerichtet")

        logger.debug(f"Erstelle temporäres Verzeichnis: {TMP_DIR}")
        os.makedirs(TMP_DIR, exist_ok=True)
        logger.debug("Temporäres Verzeichnis erstellt")

        logger.debug("Initialisiere CacheManager...")
        cache_manager = CacheManager(DB_PATH, CONFIG["cache_flush_interval"])
        if cache_manager is None:
            raise ValueError("CacheManager konnte nicht initialisiert werden")
        logger.debug("CacheManager initialisiert")

        logger.debug("Initialisiere Verzeichnisse und Dateien...")
        initialize_directories_and_files()
        logger.debug("Verzeichnisse und Dateien initialisiert")

        logger.debug("Bereinige temporäre Dateien...")
        cleanup_temp_files(cache_manager)
        logger.debug("Temporäre Dateien bereinigt")

        memory = psutil.Process().memory_info().rss / (1024 * 1024)
        logger.info(f"Initialer Speicherverbrauch: {memory:.2f} MB")

        logger.debug("Starte Cache-Flush- und Ressourcenüberwachungs-Tasks...")
        cache_flush_task = asyncio.create_task(cache_manager.flush_cache_periodically())
        resource_monitor_task = asyncio.create_task(
            monitor_resources(cache_manager, CONFIG)
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
            if global_mode != SystemMode.EMERGENCY:
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
                tasks = [process_list(url, cache_manager, session) for url in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for url, result in zip(batch, results):
                    if isinstance(result, (aiohttp.ClientError, asyncio.TimeoutError)):
                        logger.warning(f"Netzwerkfehler bei {url}: {result}")
                        STATISTICS["failed_lists"] += 1
                        continue
                    if isinstance(result, Exception):
                        logger.error(f"Fehler bei {url}: {result}")
                        STATISTICS["failed_lists"] += 1
                        continue
                    total, unique, subdomains = result
                    if os.path.exists(
                        os.path.join(
                            TMP_DIR,
                            f"{url.replace('://', '__').replace('/', '__')}.filtered",
                        )
                    ):
                        processed_urls.append(url)
                        url_counts[url] = {
                            "total": total,
                            "unique": unique,
                            "subdomains": subdomains,
                        }
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
            if global_mode != SystemMode.EMERGENCY:
                send_email(
                    "Fehler im AdBlock-Skript",
                    "Keine gültigen Domains gefunden",
                    CONFIG,
                )
            processed_urls = []
        STATISTICS["total_domains"] = sum(
            counts["total"] for counts in url_counts.values()
        )
        STATISTICS["unique_domains"] = sum(
            counts["unique"] for counts in url_counts.values()
        )
        logger.debug("Statistiken berechnet")
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
                filtered_file = os.path.join(
                    TMP_DIR, f"{url.replace('://', '__').replace('/', '__')}.filtered"
                )
                if not os.path.exists(filtered_file):
                    continue
                domains = []
                async with aiofiles.open(filtered_file, "r", encoding="utf-8") as f:
                    async for line in f:
                        domain = line.strip()
                        if domain:
                            free_memory = psutil.virtual_memory().available
                            cache_manager.domain_cache.update_threshold()
                            _, batch_size, max_concurrent_dns = get_system_resources()
                            domains.append(domain)
                            if len(domains) >= batch_size:
                                results = await test_domain_batch(
                                    domains,
                                    url,
                                    resolver,
                                    cache_manager,
                                    whitelist,
                                    blacklist,
                                    max_concurrent_dns,
                                )
                                for domain, reachable in results:
                                    if not isinstance(reachable, bool):
                                        logger.error(
                                            f"Ungültiges Ergebnis für Domain {domain}: {reachable}"
                                        )
                                        continue
                                    if reachable:
                                        await f_reachable.write(domain + "\n")
                                        STATISTICS["reachable_domains"] += 1
                                    else:
                                        await f_unreachable.write(domain + "\n")
                                        STATISTICS["unreachable_domains"] += 1
                                domains = []
                                memory = psutil.Process().memory_info().rss / (
                                    1024 * 1024
                                )
                                logger.debug(
                                    f"Speicherverbrauch nach Batch ({url}): {memory:.2f} MB"
                                )
                                gc.collect()
                                if (
                                    free_memory
                                    < CONFIG["resource_thresholds"][
                                        "emergency_memory_mb"
                                    ]
                                    * 1024
                                    * 1024
                                ):
                                    log_once(
                                        logging.WARNING,
                                        f"Kritischer Speicherstand: {free_memory/(1024*1024):.2f} MB frei, "
                                        f"reduziere Cache",
                                        console=True,
                                    )
                                    cache_manager.current_cache_size = max(
                                        2, cache_manager.current_cache_size // 2
                                    )
                                    cache_manager.adjust_cache_size()
                                    cache_manager.domain_cache.use_ram = False
                    if domains:
                        results = await test_domain_batch(
                            domains,
                            url,
                            resolver,
                            cache_manager,
                            whitelist,
                            blacklist,
                            max_concurrent_dns,
                        )
                        for domain, reachable in results:
                            if not isinstance(reachable, bool):
                                logger.error(
                                    f"Ungültiges Ergebnis für Domain {domain}: {reachable}"
                                )
                                continue
                            if reachable:
                                await f_reachable.write(domain + "\n")
                                STATISTICS["reachable_domains"] += 1
                            else:
                                await f_unreachable.write(domain + "\n")
                                STATISTICS["unreachable_domains"] += 1
        evaluate_lists(url_counts, STATISTICS, CONFIG)
        logger.debug("Listen bewertet")
        sorted_domains = []
        async with aiofiles.open(REACHABLE_FILE, "r", encoding="utf-8") as f:
            sorted_domains = sorted(
                [
                    line.strip()
                    async for line in f
                    if line.strip() and line.strip() != ""
                ]
            )
        logger.debug(f"Anzahl der erreichbaren Domains: {len(sorted_domains)}")
        logger.debug(f"Erste 5 erreichbare Domains (Beispiel): {sorted_domains[:5]}")
        dnsmasq_lines = []
        if CONFIG["use_ipv4_output"]:
            dnsmasq_lines.extend(
                f"address=/{domain}/{CONFIG['web_server_ipv4']}"
                for domain in sorted_domains
            )
            logger.debug(
                f"IPv4-Ausgabe aktiviert, {len(dnsmasq_lines)} Einträge für dnsmasq.conf mit IPv4"
            )
        if CONFIG["use_ipv6_output"] and await is_ipv6_supported(CONFIG):
            dnsmasq_lines.extend(
                f"address=/{domain}/{CONFIG['web_server_ipv6']}"
                for domain in sorted_domains
            )
            logger.debug(
                f"IPv6-Ausgabe aktiviert, {len(dnsmasq_lines)} Einträge für dnsmasq.conf mit IPv6"
            )
        dnsmasq_content = "\n".join(dnsmasq_lines)
        hosts_content = "\n".join(
            f"{CONFIG['hosts_ip']} {domain}" for domain in sorted_domains if domain
        ).strip()
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
        if CONFIG["save_unreachable"] and os.path.exists(UNREACHABLE_FILE):
            async with aiofiles.open(UNREACHABLE_FILE, "r", encoding="utf-8") as f:
                unreachable_domains = sorted(
                    [line.strip() async for line in f if line.strip()]
                )
            async with aiofiles.open(
                os.path.join(TMP_DIR, "unreachable.txt"), "w", encoding="utf-8"
            ) as f:
                await f.write("\n".join(unreachable_domains))
        if CONFIG["github_upload"] and global_mode != SystemMode.EMERGENCY:
            upload_to_github(CONFIG)
        safe_save(
            os.path.join(TMP_DIR, "statistics.json"),
            STATISTICS,
            logger,
            is_json=True,
        )
        if global_mode != SystemMode.EMERGENCY:
            export_statistics_csv(TMP_DIR, STATISTICS, logger)
            if CONFIG["export_prometheus"]:
                export_prometheus_metrics(
                    TMP_DIR,
                    STATISTICS,
                    start_time,
                    len(cache_manager.domain_cache.ram_storage),
                    logger,
                )
        recommendations = (
            "\n".join(STATISTICS["list_recommendations"])
            if STATISTICS["list_recommendations"]
            else "Keine Empfehlungen"
        )
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
        if CONFIG.get("send_email", False) and global_mode != SystemMode.EMERGENCY:
            send_email("AdBlock-Skript Bericht", summary, CONFIG)
        restart_dnsmasq(CONFIG)
        logger.info("Skript erfolgreich abgeschlossen")
    except Exception as e:
        logger.error(f"Kritischer Fehler in der Hauptfunktion: {e}")
        if global_mode != SystemMode.EMERGENCY:
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
        if cache_manager:
            async with cache_flush_lock:
                cache_manager.save_domain_cache()


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
        if global_mode != SystemMode.EMERGENCY:
            send_email(
                "Kritischer Fehler im AdBlock-Skript",
                "Skript abgebrochen: Nicht genügend Speicher verfügbar",
                CONFIG,
            )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Kritischer Fehler beim Start des Skripts: {e}")
        if global_mode != SystemMode.EMERGENCY:
            send_email(
                "Kritischer Fehler im AdBlock-Skript",
                f"Skript fehlgeschlagen: {e}",
                CONFIG,
            )
        sys.exit(1)


if __name__ == "__main__":
    cli_main()
