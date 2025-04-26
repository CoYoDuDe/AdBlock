#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# AdBlock-Skript zur Verarbeitung von Blocklisten, DNS-Validierung und Hosts-Datei-Erstellung
# Optimiert für dynamische Ressourcennutzung, asynchrone Operationen und Speichereffizienz

import logging
import os
import sys

# Frühes Logging direkt in /var/log/adblock.log
LOG_FILE = '/var/log/adblock.log'
LOG_DIR = os.path.dirname(LOG_FILE)
if LOG_DIR and not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)
if not os.access(LOG_DIR, os.W_OK):
    print(f"Keine Schreibrechte für {LOG_DIR}, beende Skript")
    sys.exit(1)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.debug("Skript beginnt")

# Prüfe, ob alle benötigten Module verfügbar sind
try:
    import logging
    import os
    import sys
    import gc
    import psutil
    import time
    import subprocess
    import hashlib
    import requests
    import re
    import json
    from collections import defaultdict
    import asyncio
    import aiodns
    from datetime import datetime, timedelta
    from threading import Lock
    import aiohttp
    import smtplib
    from email.mime.text import MIMEText
    import sqlite3
    import socket
    import shelve
    from typing import Dict, List, Optional, Iterator, Any
    from dataclasses import dataclass
    import csv
    import pickle
    import zlib
    import backoff
    from urllib.parse import quote
    import aiofiles
    from logging.handlers import RotatingFileHandler
    from bloom_filter import BloomFilter
except ImportError as e:
    logger.error(f"Fehler beim Importieren der Module: {e}")
    print(f"Fehler beim Importieren der Module: {e}")
    print(f"Bitte installiere die benötigten Abhängigkeiten mit:")
    print(f"sudo pip3 install -r {os.path.join(os.path.dirname(os.path.realpath(__file__)), 'requirements.txt')} --break-system-packages")
    sys.exit(1)

# =============================================================================
# 1. GLOBALE KONFIGURATION UND INITIALISIERUNG
# =============================================================================

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TMP_DIR = os.path.join(SCRIPT_DIR, 'tmp')
DB_PATH = os.path.join(TMP_DIR, 'adblock_cache.db')
HOSTS_HASH_PATH = os.path.join(TMP_DIR, 'hosts_hash.txt')
TRIE_CACHE_PATH = os.path.join(TMP_DIR, 'trie_cache.pkl')
TRIE_DB_PATH = os.path.join(TMP_DIR, 'trie_cache.db')
REACHABLE_FILE = os.path.join(TMP_DIR, 'reachable.txt')
UNREACHABLE_FILE = os.path.join(TMP_DIR, 'unreachable.txt')

CONFIG = {}
DNS_CACHE = {}
dns_cache_lock = Lock()
cache_flush_lock = asyncio.Lock()
MAX_DNS_CACHE_SIZE = 10000  # Begrenze DNS-Cache auf 10.000 Einträge

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
    "list_stats": defaultdict(lambda: {
        "total": 0,
        "unique": 0,
        "reachable": 0,
        "unreachable": 0,
        "duplicates": 0,
        "subdomains": 0,
        "score": 0.0,
        "category": "unknown"
    }),
    "list_recommendations": [],
    "error_message": "",
    "run_failed": False
}

DEFAULT_CONFIG = {
    "log_file": "/var/log/adblock.log",
    "log_format": "text",
    "max_retries": 3,
    "retry_delay": 2,
    "dns_retry_strategy": "exponential",
    "dns_config_file": "dnsmasq.conf",
    "hosts_file": "hosts.txt",
    "hosts_ip": "0.0.0.0",
    "web_server_ipv4": "127.0.0.1",
    "web_server_ipv6": "::1",
    "use_ipv4_output": True,
    "use_ipv6_output": False,
    "github_upload": False,
    "github_repo": "git@github.com:example/repo.git",
    "github_branch": "main",
    "git_user": "",
    "git_email": "",
    "dns_servers": [
        "8.8.8.8", "8.8.4.4",
        "1.1.1.1", "1.0.0.1",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2606:4700:4700::1111", "2606:4700:4700::1001"
    ],
    "logging_level": "INFO",
    "detailed_log": False,
    "save_unreachable": True,
    "prioritize_lists": True,
    "domain_timeout": 3,
    "domain_cache_validity_days": 7,
    "cache_flush_interval": 300,
    "cache_trie": True,
    "always_check_all_domains": False,
    "priority_lists": [],
    "send_email": False,
    "use_smtp": True,
    "email_recipient": "example@example.com",
    "email_sender": "no-reply@example.com",
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "remove_redundant_subdomains": True,
    "export_prometheus": False,
    "category_weights": {
        "malware": 1.5,
        "adult": 1.2,
        "ads": 1.0,
        "unknown": 0.8
    },
    "use_bloom_filter": True,
    "bloom_filter_capacity": 1000000,
    "bloom_filter_error_rate": 0.01
}

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logger.debug("Globale Variablen initialisiert")

# Cache für Regex
DOMAIN_PATTERN = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|\S+:+\S+)\s+(\S+)|^\s*(\S+)$')
DOMAIN_VALIDATOR = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$')
logger.debug("Regex-Muster kompiliert")

# =============================================================================
# 2. HYBRIDE SPEICHERSTRATEGIE
# =============================================================================

class HybridStorage:
    """Hybride Speicherstrategie für RAM- und Plattenbasierten Cache"""
    def __init__(self, db_path: str):
        logger.debug(f"Initializing HybridStorage with db_path: {db_path}")
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
                logger.debug(f"Alte Datenbank {db_path} gelöscht")
            except Exception as e:
                logger.warning(f"Fehler beim Löschen der alten Datenbank {db_path}: {e}")
        self.db = shelve.open(db_path, writeback=True)
        logger.debug(f"shelve-Datenbank {db_path} erfolgreich geöffnet")
        self.ram_storage = {}
        self.ram_threshold = self.calculate_threshold()
        self.use_ram = self.should_use_ram()
        logger.debug(f"HybridStorage initialisiert: RAM-Speicher={self.use_ram}, Pfad={db_path}, Schwellwert={self.ram_threshold/(1024*1024):.2f} MB")

    def calculate_threshold(self) -> int:
        try:
            free_memory = psutil.virtual_memory().available
            threshold = max(20 * 1024 * 1024, min(512 * 1024 * 1024, int(free_memory * 0.1)))
            logger.debug(f"Schwellwert berechnet: {threshold/(1024*1024):.2f} MB (freier RAM: {free_memory/(1024*1024):.2f} MB)")
            return threshold
        except Exception as e:
            logger.warning(f"Fehler bei Schwellwertberechnung: {e}, verwende Fallback: 20 MB")
            return 20 * 1024 * 1024

    def update_threshold(self):
        old_threshold = self.ram_threshold
        self.ram_threshold = self.calculate_threshold()
        if old_threshold != self.ram_threshold:
            logger.debug(f"Schwellwert aktualisiert: {self.ram_threshold/(1024*1024):.2f} MB")
        self.use_ram = self.should_use_ram()

    def should_use_ram(self) -> bool:
        try:
            free_memory = psutil.virtual_memory().available
            logger.debug(f"Freier RAM: {free_memory/(1024*1024):.2f} MB, Schwellwert: {self.ram_threshold/(1024*1024):.2f} MB")
            return free_memory > self.ram_threshold
        except Exception as e:
            logger.warning(f"Fehler beim Überprüfen des freien RAM: {e}, verwende plattenbasierten Speicher")
            return False

    def flush_to_disk(self):
        if self.use_ram:
            for key, value in self.ram_storage.items():
                self.db[key] = value
            self.db.sync()
            logger.debug("RAM-Daten auf Platte geschrieben")

    def __setitem__(self, key: str, value: Any):
        try:
            if self.use_ram:
                self.ram_storage[key] = value
            else:
                try:
                    self.db[key] = value
                    self.db.sync()
                except Exception as e:
                    logger.error(f"Fehler beim Schreiben in shelve-Datenbank: key={key}, value_type={type(value)}, error={e}")
                    raise
        except Exception as e:
            logger.error(f"Kritischer Fehler beim Schreiben in HybridStorage: key={key}, value_type={type(value)}, error={e}")
            raise

    def __getitem__(self, key: str) -> Any:
        if self.use_ram:
            return self.ram_storage[key]
        return self.db[key]

    def __contains__(self, key: str) -> bool:
        if self.use_ram:
            return key in self.ram_storage
        return key in self.db

    def __delitem__(self, key: str):
        if self.use_ram:
            del self.ram_storage[key]
        else:
            del self.db[key]
            self.db.sync()

    def items(self):
        if self.use_ram:
            return self.ram_storage.items()
        return self.db.items()

    def __len__(self):
        if self.use_ram:
            return len(self.ram_storage)
        return len(self.db)

    def clear(self):
        self.flush_to_disk()
        if self.use_ram:
            self.ram_storage.clear()
        else:
            self.db.clear()
        self.db.sync()

    def close(self):
        try:
            self.db.close()
            logger.debug("HybridStorage-Datenbank geschlossen")
        except Exception as e:
            logger.warning(f"Fehler beim Schließen der HybridStorage-Datenbank: {e}")

# =============================================================================
# 3. TRIE FÜR SUBDOMAIN-OPTIMIERUNG
# =============================================================================

@dataclass
class TrieNode:
    children: Dict[str, str]
    is_end: bool = False

    def __init__(self):
        self.children = {}
        self.is_end = False

    def __getstate__(self):
        return {'children': self.children, 'is_end': self.is_end}

    def __setstate__(self, state):
        self.children = state['children']
        self.is_end = state['is_end']

class DomainTrie:
    """Trie-Struktur zur Optimierung von Subdomain-Prüfungen mit optionalem Bloom-Filter"""
    def __init__(self):
        self.storage = HybridStorage(TRIE_DB_PATH)
        self.root_key = 'root'
        self.bloom_filter = None
        if CONFIG['use_bloom_filter'] and BloomFilter:
            self.bloom_filter = BloomFilter(
                max_elements=CONFIG['bloom_filter_capacity'],
                error_rate=CONFIG['bloom_filter_error_rate']
            )
        elif CONFIG['use_bloom_filter'] and not BloomFilter:
            logger.warning("Bloom-Filter aktiviert, aber bloom-filter nicht installiert. Deaktiviere Bloom-Filter.")
            CONFIG['use_bloom_filter'] = False
        if self.root_key not in self.storage:
            self.storage[self.root_key] = TrieNode()
        logger.debug("DomainTrie initialisiert")

    def insert(self, domain: str):
        try:
            logger.debug(f"Inserting domain: {domain}")
            if self.bloom_filter and domain in self.bloom_filter:
                logger.debug(f"Domain {domain} bereits im Bloom-Filter")
                return
            node = self.storage[self.root_key]
            logger.debug(f"Root node retrieved: {node}")
            node_key = self.root_key
            parts = domain.split('.')[::-1]
            for i, part in enumerate(parts):
                logger.debug(f"Processing part {part} at level {i}")
                if part not in node.children:
                    new_key = f"{node_key}:{part}:{i}"
                    node.children[part] = new_key
                    self.storage[new_key] = TrieNode()
                    logger.debug(f"Created new node with key {new_key}")
                node_key = node.children[part]
                node = self.storage[node_key]
                logger.debug(f"Moved to node with key {node_key}")
            node.is_end = True
            self.storage[node_key] = node
            if self.bloom_filter:
                self.bloom_filter.add(domain)
            logger.debug(f"Domain {domain} successfully inserted")
        except Exception as e:
            logger.error(f"Fehler beim Einfügen der Domain {domain} in den Trie: {e}")
            raise

    def has_parent(self, domain: str) -> bool:
        try:
            logger.debug(f"Checking parent for domain: {domain}")
            if self.bloom_filter and domain not in self.bloom_filter:
                logger.debug(f"Domain {domain} not in Bloom-Filter")
                return False
            parts = domain.split('.')[::-1]
            node = self.storage[self.root_key]
            logger.debug(f"Root node retrieved: {node}")
            node_key = self.root_key
            for i, part in enumerate(parts):
                logger.debug(f"Checking part {part} at level {i}")
                if part not in node.children:
                    logger.debug(f"Part {part} not found in children")
                    return False
                node_key = node.children[part]
                node = self.storage[node_key]
                logger.debug(f"Moved to node with key {node_key}")
                if node.is_end and i < len(parts) - 1:
                    logger.debug(f"Parent domain found at level {i}")
                    return True
            logger.debug(f"No parent domain found for {domain}")
            return False
        except Exception as e:
            logger.error(f"Fehler beim Prüfen der Eltern-Domain für {domain}: {e}")
            return False

    def flush(self):
        try:
            self.storage.clear()
            self.storage[self.root_key] = TrieNode()
            logger.debug("DomainTrie Speicher geflusht")
        except Exception as e:
            logger.warning(f"Fehler beim Flushen des DomainTrie: {e}")

    def close(self):
        self.storage.close()
        logger.debug("DomainTrie geschlossen")

def save_trie_cache(trie: DomainTrie, all_domains_hash: str):
    if not CONFIG['cache_trie']:
        return
    try:
        data = {'hash': all_domains_hash, 'version': '1.0'}
        compressed = zlib.compress(pickle.dumps(data))
        with open(TRIE_CACHE_PATH, 'wb') as f:
            f.write(compressed)
        logger.info(f"Trie-Cache gespeichert: {TRIE_CACHE_PATH}")
    except Exception as e:
        logger.warning(f"Fehler beim Speichern des Trie-Caches: {e}")

def load_trie_cache(all_domains_hash: str) -> Optional[DomainTrie]:
    if not CONFIG['cache_trie'] or not os.path.exists(TRIE_CACHE_PATH):
        logger.debug("Trie-Cache nicht verfügbar oder deaktiviert")
        return None
    try:
        with open(TRIE_CACHE_PATH, 'rb') as f:
            compressed = f.read()
        data = pickle.loads(zlib.decompress(compressed))
        if data.get('version') != '1.0':
            logger.debug("Trie-Cache-Version inkompatibel")
            return None
        if data['hash'] == all_domains_hash:
            STATISTICS['trie_cache_hits'] += 1
            logger.info("Trie-Cache geladen")
            return DomainTrie()
        logger.debug("Trie-Cache ungültig (Hash geändert)")
        return None
    except Exception as e:
        logger.warning(f"Fehler beim Laden des Trie-Caches: {e}")
        return None

# =============================================================================
# 4. CACHE-MANAGEMENT
# =============================================================================

class CacheManager:
    def __init__(self, db_path: str, flush_interval: int):
        self.db_path = db_path
        self.flush_interval = flush_interval
        self.domain_cache = HybridStorage(os.path.join(TMP_DIR, 'domain_cache.db'))
        self.list_cache = {}
        self.last_flush = time.time()
        self.current_cache_size = self.calculate_dynamic_cache_size()
        self.init_database()
        logger.info(f"CacheManager initialisiert: Initiale Cache-Größe={self.current_cache_size}")

    def calculate_dynamic_cache_size(self) -> int:
        try:
            free_memory = psutil.virtual_memory().available
            estimated_cache_size = int(free_memory * 0.05 / (1024 * 1024) * 100)
            dynamic_size = max(2, min(100000, estimated_cache_size))
            if free_memory < 150 * 1024 * 1024:  # Reduzierte Schwelle auf 150 MB
                dynamic_size = 2
                logger.warning("Low-Memory-Modus aktiviert: Cache-Größe auf 2 reduziert")
            logger.debug(f"Dynamische Cache-Größe berechnet: {dynamic_size} (freier RAM: {free_memory/(1024*1024):.2f} MB)")
            return dynamic_size
        except Exception as e:
            logger.warning(f"Fehler bei Cache-Größenberechnung: {e}, verwende Fallback: 2")
            return 2

    def adjust_cache_size(self):
        try:
            new_size = self.calculate_dynamic_cache_size()
            if new_size != self.current_cache_size:
                self.current_cache_size = new_size
                logger.info(f"Cache-Größe angepasst: {self.current_cache_size}")
                if len(self.domain_cache.ram_storage) > self.current_cache_size and self.domain_cache.use_ram:
                    sorted_items = sorted(self.domain_cache.ram_storage.items(), key=lambda x: x[1]['checked_at'])
                    self.domain_cache.ram_storage = dict(sorted_items[-self.current_cache_size:])
                    logger.debug(f"Domain-Cache beschnitten auf {self.current_cache_size} Einträge")
        except Exception as e:
            logger.warning(f"Fehler beim Anpassen der Cache-Größe: {e}")

    def init_database(self):
        try:
            os.makedirs(TMP_DIR, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS list_cache (
                    url TEXT PRIMARY KEY,
                    md5 TEXT,
                    last_checked TEXT
                )
            ''')
            conn.commit()
            conn.close()
            logger.debug("SQLite-Datenbank initialisiert")
        except Exception as e:
            logger.error(f"Fehler beim Initialisieren der SQLite-Datenbank: {e}")
            raise

    async def flush_cache_periodically(self):
        while True:
            try:
                await asyncio.sleep(5)
                memory = psutil.Process().memory_info().rss / (1024 * 1024)
                free_memory = psutil.virtual_memory().available / (1024 * 1024)
                cpu_usage = psutil.cpu_percent(interval=0.1)
                if free_memory < 50 or psutil.virtual_memory().percent > 90:
                    logger.warning(f"Kritischer Speicherstand: {free_memory:.2f} MB frei, Auslastung: {psutil.virtual_memory().percent}%, reduziere Cache")
                    self.current_cache_size = max(2, self.current_cache_size // 2)
                    self.adjust_cache_size()
                    self.domain_cache.use_ram = False
                elif free_memory > 512 and psutil.virtual_memory().percent < 50:
                    self.adjust_cache_size()
                    self.domain_cache.use_ram = True
                if cpu_usage > 90:
                    logger.warning(f"Hohe CPU-Auslastung: {cpu_usage}%, reduziere parallele Aufgaben")
                logger.debug(f"Speicherverbrauch: {memory:.2f} MB, CPU: {cpu_usage}%, Cache-Größe: {self.current_cache_size}, RAM-Speicher: {self.domain_cache.use_ram}")
                if time.time() - self.last_flush > self.flush_interval:
                    async with cache_flush_lock:
                        self.save_domain_cache()
                        self.last_flush = time.time()
            except asyncio.CancelledError:
                async with cache_flush_lock:
                    self.save_domain_cache()
                break
            except Exception as e:
                logger.warning(f"Fehler im Cache-Flush-Task: {e}")

    def load_domain_cache(self):
        try:
            return self.domain_cache
        except Exception as e:
            logger.warning(f"Fehler beim Zugriff auf Domain-Cache: {e}")
            return {}

    def save_domain_cache(self):
        try:
            if len(self.domain_cache.ram_storage) > self.current_cache_size and self.domain_cache.use_ram:
                sorted_items = sorted(self.domain_cache.ram_storage.items(), key=lambda x: x[1]['checked_at'])
                self.domain_cache.ram_storage = dict(sorted_items[-self.current_cache_size:])
                logger.debug(f"Domain-Cache beschnitten auf {self.current_cache_size} Einträge")
            STATISTICS['cache_flushes'] += 1
            logger.debug(f"Domain-Cache geflusht (Flush #{STATISTICS['cache_flushes']})")
        except Exception as e:
            logger.warning(f"Fehler beim Speichern des Domain-Caches: {e}")

    def save_domain(self, domain: str, reachable: bool, source_url: str):
        try:
            self.domain_cache[domain] = {
                "reachable": reachable,
                "checked_at": datetime.now().isoformat(),
                "source": source_url
            }
            if len(self.domain_cache.ram_storage) > self.current_cache_size and self.domain_cache.use_ram:
                oldest_domain = min(self.domain_cache.ram_storage, key=lambda k: self.domain_cache.ram_storage[k]['checked_at'])
                del self.domain_cache[oldest_domain]
                logger.debug(f"Älteste Domain {oldest_domain} aus Cache entfernt")
        except Exception as e:
            logger.warning(f"Fehler beim Speichern der Domain {domain}: {e}")

    def load_list_cache(self) -> Dict[str, Dict]:
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            c.execute("SELECT url, md5, last_checked FROM list_cache")
            self.list_cache = {row[0]: {"md5": row[1], "last_checked": row[2]} for row in c.fetchall()}
            conn.close()
            logger.debug("List-Cache geladen")
            return self.list_cache
        except Exception as e:
            logger.warning(f"Fehler beim Zugriff auf List-Cache: {e}")
            return {}

    def save_list_cache(self, cache: Dict[str, Dict]):
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            c.execute("DELETE FROM list_cache")
            for url, data in cache.items():
                c.execute('''
                    INSERT INTO list_cache (url, md5, last_checked)
                    VALUES (?, ?, ?)
                ''', (url, data['md5'], data['last_checked']))
            conn.commit()
            conn.close()
            logger.debug("List-Cache gespeichert")
        except Exception as e:
            logger.warning(f"Fehler beim Speichern des List-Caches: {e}")

    def cleanup(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            expiry = (datetime.now() - timedelta(days=CONFIG['domain_cache_validity_days'])).isoformat()
            c.execute("DELETE FROM domain_cache WHERE checked_at < ?", (expiry,))
            conn.commit()
            conn.close()
            logger.debug("Cache bereinigt")
        except Exception as e:
            logger.warning(f"Fehler beim Bereinigen der Datenbank: {e}")

# =============================================================================
# 5. HILFSFUNKTIONEN
# =============================================================================

def load_config():
    config_path = os.path.join(SCRIPT_DIR, 'config.json')
    logger.debug(f"Versuche, Konfigurationsdatei zu laden: {config_path}")
    try:
        CONFIG.update(DEFAULT_CONFIG)
        if not os.path.exists(config_path):
            logger.warning(f"Konfigurationsdatei {config_path} nicht gefunden, erstelle Standardkonfiguration")
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
        with open(config_path, 'r', encoding='utf-8') as f:
            custom_config = json.load(f)
            CONFIG.update(custom_config)
        logger.debug("Konfigurationsdatei erfolgreich geladen")
    except json.JSONDecodeError as e:
        logger.error(f"Fehler beim Parsen von config.json: {e}. Verwende Standardkonfiguration.")
    except Exception as e:
        logger.error(f"Fehler beim Laden der Konfigurationsdatei: {e}. Verwende Standardkonfiguration.")
    
    if 'log_file' not in CONFIG:
        CONFIG['log_file'] = DEFAULT_CONFIG['log_file']
        logger.warning(f"'log_file' nicht in Konfiguration gefunden, verwende Standard: {CONFIG['log_file']}")
    if 'hosts_ip' not in CONFIG:
        CONFIG['hosts_ip'] = DEFAULT_CONFIG['hosts_ip']
        logger.warning(f"'hosts_ip' nicht in Konfiguration gefunden, verwende Standard: {CONFIG['hosts_ip']}")
    if 'use_smtp' not in CONFIG:
        CONFIG['use_smtp'] = DEFAULT_CONFIG['use_smtp']
        logger.warning(f"'use_smtp' nicht in Konfiguration gefunden, verwende Standard: {CONFIG['use_smtp']}")

    CONFIG['smtp_password'] = os.environ.get('SMTP_PASSWORD', CONFIG.get('smtp_password', ''))
    if CONFIG['send_email'] and CONFIG['use_smtp']:
        if not all([CONFIG.get(k) for k in ['smtp_server', 'smtp_port', 'smtp_user', 'smtp_password', 'email_recipient', 'email_sender']]):
            logger.warning("Ungültige SMTP-Konfiguration, deaktiviere E-Mail-Benachrichtigungen")
            CONFIG['send_email'] = False
    valid_dns_servers = []
    for server in CONFIG['dns_servers']:
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
        logger.warning("Keine gültigen DNS-Server angegeben, verwende Fallback: 8.8.8.8, 1.1.1.1")
        CONFIG['dns_servers'] = ["8.8.8.8", "1.1.1.1"]
    else:
        CONFIG['dns_servers'] = valid_dns_servers
    if not isinstance(CONFIG['cache_flush_interval'], (int, float)) or CONFIG['cache_flush_interval'] <= 0:
        logger.warning("Ungültiges cache_flush_interval, verwende Standard: 300")
        CONFIG['cache_flush_interval'] = 300
    if not isinstance(CONFIG['category_weights'], dict):
        logger.warning("Ungültige category_weights, verwende Standard")
        CONFIG['category_weights'] = DEFAULT_CONFIG['category_weights']
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump({k: v for k, v in CONFIG.items() if k != 'smtp_password'}, f, indent=4)
        logger.debug(f"Konfigurationsdatei aktualisiert: {config_path}")
    except Exception as e:
        logger.error(f"Fehler beim Speichern der Konfigurationsdatei: {e}")
    logger.info(f"Verwendete DNS-Server: {', '.join(CONFIG['dns_servers'])}")

def setup_logging():
    try:
        if 'log_file' not in CONFIG:
            CONFIG['log_file'] = DEFAULT_CONFIG['log_file']
            logger.warning(f"'log_file' nicht in Konfiguration gefunden, verwende Standard: {CONFIG['log_file']}")
        
        log_dir = os.path.dirname(CONFIG['log_file'])
        if log_dir and not os.access(log_dir, os.W_OK):
            logger.error(f"Keine Schreibrechte für Log-Verzeichnis {log_dir}, beende Skript")
            print(f"Keine Schreibrechte für Log-Verzeichnis {log_dir}, beende Skript")
            sys.exit(1)
        
        level = getattr(logging, CONFIG.get('logging_level', 'INFO').upper(), logging.INFO)
        if CONFIG.get('detailed_log', False):
            level = logging.DEBUG
        handler = RotatingFileHandler(CONFIG['log_file'], maxBytes=10*1024*1024, backupCount=5)
        if CONFIG.get('log_format') == 'json':
            handler.setFormatter(logging.Formatter(
                '{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "operation": "%(funcName)s"}'
            ))
        else:
            handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.handlers.clear()  # Entferne bestehende Handler
        logger.setLevel(level)
        logger.handlers = [handler, logging.StreamHandler()]
        logger.debug(f"Logging konfiguriert mit Level {logging.getLevelName(level)}")
        logger.info("Logging erfolgreich konfiguriert")
    except Exception as e:
        logger.error(f"Fehler beim Einrichten des Loggings: {e}")
        print(f"Fehler beim Einrichten des Loggings: {e}")
        sys.exit(1)

def calculate_md5(content: str) -> str:
    try:
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    except Exception as e:
        logger.error(f"Fehler beim Berechnen des MD5-Hash: {e}")
        return ""

def safe_save(filepath: str, content, is_json: bool = False):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            if is_json:
                json.dump(content, f, indent=4, ensure_ascii=False)
            else:
                f.write(content)
        logger.info(f"Datei gespeichert: {filepath}")
    except Exception as e:
        logger.error(f"Fehler beim Speichern von {filepath}: {e}")

def append_to_file(filepath: str, content: str):
    try:
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(content + '\n')
    except Exception as e:
        logger.error(f"Fehler beim Anhängen an {filepath}: {e}")

def send_email(subject: str, body: str):
    if not CONFIG['send_email']:
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = CONFIG['email_sender']
        msg['To'] = CONFIG['email_recipient']
        
        if CONFIG['use_smtp']:
            # SMTP-Versand
            with smtplib.SMTP(CONFIG['smtp_server'], CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(CONFIG['smtp_user'], CONFIG['smtp_password'])
                server.send_message(msg)
            logger.info("E-Mail-Benachrichtigung über SMTP gesendet")
        else:
            # Lokales Postfix via sendmail
            sendmail_cmd = ['/usr/sbin/sendmail', '-t', '-oi']
            process = subprocess.Popen(sendmail_cmd, stdin=subprocess.PIPE)
            process.communicate(msg.as_string().encode('utf-8'))
            if process.returncode == 0:
                logger.info("E-Mail-Benachrichtigung über lokales Postfix gesendet")
            else:
                raise Exception(f"sendmail failed with exit code {process.returncode}")
    except Exception as e:
        logger.error(f"Fehler beim Senden der E-Mail: {e}")

def is_ipv6_supported() -> bool:
    try:
        socket.create_connection(("ipv6.google.com", 80), timeout=2)
        logger.debug("IPv6 wird unterstützt")
        return True
    except (socket.gaierror, socket.timeout):
        logger.debug("IPv6 wird nicht unterstützt")
        return False

def export_statistics_csv():
    csv_path = os.path.join(TMP_DIR, 'statistics.csv')
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "URL", "Category", "Total", "Unique", "Reachable", "Unreachable",
                "Duplicates", "Subdomains", "Score"
            ])
            for url, stats in STATISTICS['list_stats'].items():
                writer.writerow([
                    url, stats['category'], stats['total'], stats['unique'],
                    stats['reachable'], stats['unreachable'], stats['duplicates'],
                    stats['subdomains'], stats['score']
                ])
        logger.info(f"Statistiken als CSV gespeichert: {csv_path}")
    except Exception as e:
        logger.error(f"Fehler beim Exportieren der CSV: {e}")

def export_prometheus_metrics(start_time: float):
    if not CONFIG['export_prometheus']:
        return
    metrics_path = os.path.join(TMP_DIR, 'metrics.prom')
    try:
        with open(metrics_path, 'w', encoding='utf-8') as f:
            f.write('# AdBlock Skript Metriken\n')
            f.write(f'adblock_total_domains {STATISTICS["total_domains"]}\n')
            f.write(f'adblock_unique_domains {STATISTICS["unique_domains"]}\n')
            f.write(f'adblock_reachable_domains {STATISTICS["reachable_domains"]}\n')
            f.write(f'adblock_unreachable_domains {STATISTICS["unreachable_domains"]}\n')
            f.write(f'adblock_duplicates {STATISTICS["duplicates"]}\n')
            f.write(f'adblock_cache_hits {STATISTICS["cache_hits"]}\n')
            f.write(f'adblock_cache_flushes {STATISTICS["cache_flushes"]}\n')
            f.write(f'adblock_trie_cache_hits {STATISTICS["trie_cache_hits"]}\n')
            f.write(f'adblock_cache_size {len(cache_manager.domain_cache.ram_storage)}\n')
            f.write(f'adblock_failed_lists {STATISTICS["failed_lists"]}\n')
            f.write(f'adblock_runtime_seconds {time.time() - start_time}\n')
            for url, stats in STATISTICS['list_stats'].items():
                safe_url = quote(url, safe='')
                f.write(f'adblock_list_total{{url="{safe_url}"}} {stats["total"]}\n')
                f.write(f'adblock_list_unique{{url="{safe_url}"}} {stats["unique"]}\n')
                f.write(f'adblock_list_reachable{{url="{safe_url}"}} {stats["reachable"]}\n')
                f.write(f'adblock_list_unreachable{{url="{safe_url}"}} {stats["unreachable"]}\n')
                f.write(f'adblock_list_duplicates{{url="{safe_url}"}} {stats["duplicates"]}\n')
                f.write(f'adblock_list_subdomains{{url="{safe_url}"}} {stats["subdomains"]}\n')
                f.write(f'adblock_list_score{{url="{safe_url}"}} {stats["score"]}\n')
        logger.info(f"Prometheus-Metriken gespeichert: {metrics_path}")
    except Exception as e:
        logger.error(f"Fehler beim Exportieren der Prometheus-Metriken: {e}")

# =============================================================================
# 6. VERZEICHNIS- UND DATEIMANAGEMENT
# =============================================================================

def initialize_directories_and_files():
    """Initialisiert Verzeichnisse und Standarddateien"""
    try:
        os.makedirs(TMP_DIR, exist_ok=True)
        files = [
            ('config.json', DEFAULT_CONFIG, True),
            ('hosts_sources.conf', '\n'.join([
                'https://adaway.org/hosts.txt',
                'https://v.firebog.net/hosts/Easyprivacy.txt'
            ]), False),
            ('whitelist.txt', '# Whitelist für Domains, eine pro Zeile\n', False),
            ('blacklist.txt', '# Blacklist für Domains, eine pro Zeile\n', False),
            (os.path.join(TMP_DIR, 'statistics.json'), {}, True)
        ]
        for path, content, is_json in files:
            filepath = os.path.join(SCRIPT_DIR, path)
            if not os.path.exists(filepath):
                safe_save(filepath, content, is_json)
                logger.info(f"Erstellt: {filepath}")
        logger.debug("Verzeichnisse und Dateien initialisiert")
    except Exception as e:
        logger.error(f"Fehler beim Initialisieren der Verzeichnisse und Dateien: {e}")
        raise

def cleanup_temp_files(cache_manager: CacheManager):
    """Bereinigt temporäre Dateien, die nicht mehr benötigt werden"""
    try:
        list_cache = cache_manager.load_list_cache()
        for file in os.listdir(TMP_DIR):
            if file.endswith('.tmp') or file.endswith('.filtered'):
                url = file.replace('.tmp', '').replace('.filtered', '').replace('__', '/').replace('_', '://')
                if url not in list_cache:
                    try:
                        os.remove(os.path.join(TMP_DIR, file))
                        logger.info(f"Obsolete Datei gelöscht: {file}")
                    except Exception as e:
                        logger.error(f"Fehler beim Löschen von {file}: {e}")
        logger.debug("Temporäre Dateien bereinigt")
    except Exception as e:
        logger.error(f"Fehler beim Bereinigen temporärer Dateien: {e}")

# =============================================================================
# 7. LISTEN- UND DOMAIN-MANAGEMENT
# =============================================================================

def load_whitelist_blacklist() -> tuple[set[str], set[str]]:
    """Lädt White- und Blacklist aus Dateien"""
    try:
        whitelist = set()
        blacklist = set()
        for file, target in [('whitelist.txt', whitelist), ('blacklist.txt', blacklist)]:
            filepath = os.path.join(SCRIPT_DIR, file)
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#') and ist_gueltige_domain(domain):
                            target.add(domain)
        logger.debug(f"Whitelist: {len(whitelist)} Einträge, Blacklist: {len(blacklist)} Einträge")
        return whitelist, blacklist
    except Exception as e:
        logger.error(f"Fehler beim Laden von Whitelist/Blacklist: {e}")
        return set(), set()

def load_hosts_sources() -> List[str]:
    """Lädt die Quell-URLs aus hosts_sources.conf"""
    sources_path = os.path.join(SCRIPT_DIR, 'hosts_sources.conf')
    try:
        if not os.path.exists(sources_path):
            logger.warning(f"Quell-URLs-Datei {sources_path} nicht gefunden, erstelle Standarddatei")
            with open(sources_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join([
                    'https://adaway.org/hosts.txt',
                    'https://v.firebog.net/hosts/Easyprivacy.txt'
                ]))
        with open(sources_path, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        priority = CONFIG['priority_lists']
        if CONFIG['prioritize_lists']:
            sources = sorted(sources, key=lambda x: 0 if x in priority else 1)
        logger.debug(f"Geladene Quell-URLs: {len(sources)}")
        return sources
    except Exception as e:
        logger.error(f"Fehler beim Laden der Quell-URLs: {e}")
        return []

def parse_domains(content: str, url: str) -> Iterator[str]:
    """Parst Domains aus dem Inhalt einer Liste"""
    try:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!')):
                continue
            match = DOMAIN_PATTERN.match(line)
            if match:
                domain = (match.group(1) or match.group(2)).lower()
                if ist_gueltige_domain(domain) and not domain.startswith('*'):
                    yield domain
    except Exception as e:
        logger.error(f"Fehler beim Parsen der Domains aus {url}: {e}")

def ist_gueltige_domain(domain: str) -> bool:
    """Validiert, ob eine Domain gültig ist"""
    try:
        return bool(DOMAIN_VALIDATOR.match(domain))
    except Exception as e:
        logger.error(f"Fehler beim Validieren der Domain {domain}: {e}")
        return False

def categorize_list(url: str) -> str:
    """Kategorisiert eine Liste basierend auf ihrer URL"""
    try:
        url_lower = url.lower()
        if 'malware' in url_lower or 'phishing' in url_lower or 'crypto' in url_lower:
            return 'malware'
        elif 'ads' in url_lower or 'ad' in url_lower or 'tracking' in url_lower:
            return 'ads'
        elif 'porn' in url_lower or 'adult' in url_lower:
            return 'adult'
        return 'unknown'
    except Exception as e:
        logger.error(f"Fehler beim Kategorisieren der URL {url}: {e}")
        return 'unknown'

# =============================================================================
# 8. RESSOURCENMANAGEMENT
# =============================================================================

async def select_best_dns_server(dns_servers: List[str], timeout: float = 5.0) -> List[str]:
    """Wählt die besten DNS-Server basierend auf Latenz"""
    async def test_server(server: str) -> tuple[str, float]:
        try:
            resolver = aiodns.DNSResolver(nameservers=[server], timeout=timeout)
            start = time.time()
            await resolver.query("example.com", 'A')
            latency = time.time() - start
            logger.debug(f"DNS-Server {server} Latenz: {latency:.2f}s")
            return server, latency
        except Exception as e:
            logger.debug(f"DNS-Server {server} nicht erreichbar: {e}")
            return server, float('inf')

    try:
        tasks = [test_server(server) for server in dns_servers]
        results = await asyncio.gather(*tasks)
        sorted_servers = [server for server, latency in sorted(results, key=lambda x: x[1]) if latency != float('inf')]
        if not sorted_servers:
            logger.warning("Kein DNS-Server erreichbar, verwende Standardserver")
            return dns_servers
        logger.debug(f"Ausgewählte DNS-Server: {sorted_servers}")
        return sorted_servers
    except Exception as e:
        logger.error(f"Fehler beim Auswählen der DNS-Server: {e}")
        return dns_servers

async def monitor_resources(cache_manager: CacheManager):
    """Asynchroner Task zur Überwachung von CPU, RAM und Netzwerklatenz alle 5 Sekunden"""
    while True:
        try:
            free_memory = psutil.virtual_memory().available
            cpu_usage = psutil.cpu_percent(interval=0.1)
            latency = await check_network_latency()
            max_jobs, batch_size, max_concurrent_dns = get_system_resources()
            cache_manager.adjust_cache_size()
            cache_manager.domain_cache.update_threshold()
            if free_memory < 150 * 1024 * 1024:  # Reduzierte Schwelle auf 150 MB
                logger.warning(f"RAM niedrig: {free_memory/(1024*1024):.2f} MB, Batch-Größe: {batch_size}, DNS-Anfragen: {max_concurrent_dns}")
                logger.setLevel(logging.INFO)
            else:
                logger.setLevel(logging.DEBUG if CONFIG.get('detailed_log', False) else logging.INFO)
            if latency > 1.0:
                max_concurrent_dns = max(5, max_concurrent_dns // 2)
                logger.info(f"Hohe Latenz ({latency:.2f}s), DNS-Anfragen reduziert: {max_concurrent_dns}")
            logger.debug(f"Ressourcen: RAM={free_memory/(1024*1024):.2f} MB, CPU={cpu_usage:.1f}%, Latenz={latency:.2f}s, Batch-Größe={batch_size}, DNS-Anfragen={max_concurrent_dns}")
            await asyncio.sleep(5)
        except Exception as e:
            logger.warning(f"Fehler bei Ressourcenüberwachung: {e}")
            await asyncio.sleep(5)

async def check_network_latency() -> float:
    """Prüft die Netzwerklatenz zu einem DNS-Server"""
    try:
        resolver = aiodns.DNSResolver(nameservers=[CONFIG['dns_servers'][0]], timeout=5.0)
        start = time.time()
        await resolver.query("example.com", 'A')
        latency = time.time() - start
        logger.debug(f"Netzwerklatenz zu {CONFIG['dns_servers'][0]}: {latency:.2f}s")
        return latency
    except aiodns.error.DNSError as e:
        logger.warning(f"DNS-Fehler bei Latenzprüfung: {e}")
        return float('inf')
    except Exception as e:
        logger.warning(f"Unbekannter Fehler bei Latenzprüfung: {e}")
        return float('inf')

def get_system_resources() -> tuple[int, int, int]:
    """Ermittelt verfügbare Systemressourcen und passt Jobs, Batch-Größe und DNS-Anfragen an"""
    try:
        cpu_load = psutil.cpu_percent(interval=0.1) / 100
        cpu_cores = psutil.cpu_count(logical=True) or 1
        free_memory = psutil.virtual_memory().available
        max_jobs = max(1, int(cpu_cores / (cpu_load + 0.1)))
        batch_size = max(10, min(200, int(free_memory / (400 * 1024))))
        max_concurrent_dns = max(5, min(50, int(free_memory / (1024 * 1024))))
        if free_memory < 50 * 1024 * 1024:
            max_jobs = 1
            batch_size = 10
            max_concurrent_dns = 5
            logger.warning("Sehr wenig RAM verfügbar, Low-Memory-Modus: Batch-Größe=10, Jobs=1, DNS-Anfragen=5")
        elif free_memory < 100 * 1024 * 1024:
            max_jobs = min(max_jobs, 2)
            batch_size = min(batch_size, 50)
            max_concurrent_dns = min(max_concurrent_dns, 5)
            logger.warning("Wenig RAM verfügbar: Batch-Größe reduziert auf 50, DNS-Anfragen auf 5")
        elif free_memory < 150 * 1024 * 1024:  # Reduzierte Schwelle auf 150 MB
            max_jobs = min(max_jobs, 2)
            batch_size = min(batch_size, 100)
            max_concurrent_dns = min(max_concurrent_dns, 10)
            logger.warning("Wenig RAM verfügbar: Batch-Größe reduziert auf 100, DNS-Anfragen auf 10")
        if cpu_load > 0.9:
            max_jobs = max(1, max_jobs // 2)
            logger.warning(f"Hohe CPU-Auslastung: {cpu_load*100}%, reduziere parallele Jobs: {max_jobs}")
        logger.debug(f"CPU-Last: {cpu_load:.2f}, Kerne: {cpu_cores}, Speicher: {free_memory/(1024*1024):.2f} MB")
        logger.debug(f"Empfohlene Jobs: {max_jobs}, Batch-Größe: {batch_size}, DNS-Anfragen: {max_concurrent_dns}")
        return max_jobs, batch_size, max_concurrent_dns
    except Exception as e:
        logger.error(f"Fehler bei Ressourcenermittlung: {e}, verwende Fallback")
        return 1, 10, 5

# =============================================================================
# 9. ASYNCHRONE DNS-VALIDIERUNG
# =============================================================================

async def test_dns_entry_async(domain: str, resolver, record_type: str = 'A', max_concurrent: int = 5) -> bool:
    """Testet eine Domain asynchron auf Erreichbarkeit mit optimierter Parallelität"""
    async def query_with_backoff(domain: str, record: str, resolver, attempt: int) -> bool:
        try:
            result = await resolver.query(domain, record)
            return bool(result)
        except aiodns.error.DNSError as e:
            if 'NXDOMAIN' in str(e):
                logger.debug(f"Domain {domain} nicht existent (NXDOMAIN, {record})")
                return False
            logger.debug(f"Fehler bei {domain} ({record}, Versuch {attempt + 1}): {e}")
            return False
        except Exception as e:
            logger.debug(f"Unbekannter Fehler bei {domain} ({record}, Versuch {attempt + 1}): {e}")
            return False

    try:
        with dns_cache_lock:
            if domain in DNS_CACHE:
                logger.debug(f"Domain {domain} aus Cache: {DNS_CACHE[domain]}")
                return DNS_CACHE[domain]
            if len(DNS_CACHE) >= MAX_DNS_CACHE_SIZE:
                oldest_domain = next(iter(DNS_CACHE))
                del DNS_CACHE[oldest_domain]
                logger.debug(f"Älteste Domain {oldest_domain} aus DNS-Cache entfernt")

        semaphore = asyncio.Semaphore(max_concurrent)
        async with semaphore:
            record_types = [record_type, 'AAAA'] if record_type == 'A' else [record_type]
            for record in record_types:
                for attempt in range(CONFIG['max_retries']):
                    reachable = await query_with_backoff(domain, record, resolver, attempt)
                    if reachable:
                        with dns_cache_lock:
                            DNS_CACHE[domain] = True
                        logger.debug(f"Domain {domain} erreichbar ({record})")
                        return True
                    delay = CONFIG['retry_delay'] * (2 ** attempt) if CONFIG['dns_retry_strategy'] == 'exponential' else CONFIG['retry_delay']
                    await asyncio.sleep(delay)
            with dns_cache_lock:
                DNS_CACHE[domain] = False
            logger.debug(f"Domain {domain} nicht erreichbar")
            return False
    except Exception as e:
        logger.error(f"Kritischer Fehler beim Testen der DNS-Domain {domain}: {e}")
        return False

async def test_single_domain_async(domain: str, url: str, resolver, cache_manager: CacheManager, whitelist: set[str], blacklist: set[str], max_concurrent: int = 5) -> bool:
    try:
        if domain in whitelist:
            logger.debug(f"Domain {domain} in Whitelist, überspringe Prüfung")
            return False
        if domain in blacklist:
            logger.debug(f"Domain {domain} in Blacklist, blockiere immer")
            return True
        if not CONFIG['always_check_all_domains']:
            cache = cache_manager.load_domain_cache()
            if domain in cache:
                entry = cache[domain]
                last_checked = datetime.fromisoformat(entry['checked_at'])
                if datetime.now() - last_checked < timedelta(days=CONFIG['domain_cache_validity_days']):
                    logger.debug(f"Domain {domain} aus Cache: {entry['reachable']}")
                    STATISTICS['cache_hits'] += 1
                    STATISTICS['list_stats'][url]['reachable' if entry['reachable'] else 'unreachable'] += 1
                    return entry['reachable']
        reachable = await test_dns_entry_async(domain, resolver, max_concurrent=max_concurrent)
        cache_manager.save_domain(domain, reachable, url)
        STATISTICS['list_stats'][url]['reachable' if reachable else 'unreachable'] += 1
        return reachable
    except Exception as e:
        logger.error(f"Fehler beim Testen der Domain {domain} für URL {url}: {e}")
        return False

async def test_domain_batch(domains: List[str], url: str, resolver, cache_manager: CacheManager, whitelist: set[str], blacklist: set[str], max_concurrent: int = 5) -> List[tuple[str, bool]]:
    """Testet einen Batch von Domains asynchron"""
    try:
        free_memory = psutil.virtual_memory().available
        cache_manager.domain_cache.update_threshold()
        _, batch_size, max_concurrent = get_system_resources()
        logger.debug(f"Batch-Größe für DNS-Validierung: {batch_size}, Max. DNS-Anfragen: {max_concurrent}, Freier RAM: {free_memory/(1024*1024):.2f} MB")
        results = []
        tasks = [test_single_domain_async(domain, url, resolver, cache_manager, whitelist, blacklist, max_concurrent) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        gc.collect()
        return [(domain, result) for domain, result in zip(domains, results) if not isinstance(result, Exception)]
    except Exception as e:
        logger.error(f"Fehler beim Testen des Domain-Batches für URL {url}: {e}")
        return []

# =============================================================================
# 10. LISTENBEWERTUNG
# =============================================================================

def evaluate_lists(url_counts: Dict[str, Dict], total_domains: int):
    """Bewertet die Qualität der Listen in Batches"""
    try:
        free_memory = psutil.virtual_memory().available
        _, batch_size, _ = get_system_resources()
        logger.debug(f"Batch-Größe für evaluate_lists: {batch_size}, Freier RAM: {free_memory/(1024*1024):.2f} MB")
        url_batches = [list(STATISTICS['list_stats'].items())[i:i + batch_size] for i in range(0, len(STATISTICS['list_stats']), batch_size)]
        for batch in url_batches:
            for url, stats in batch:
                counts = url_counts.get(url, {"total": 0, "unique": 0, "subdomains": 0})
                stats['total'] = counts['total']
                stats['unique'] = counts['unique']
                stats['subdomains'] = counts['subdomains']
                stats['category'] = categorize_list(url)
                if stats['total'] > 0:
                    unique_ratio = stats['unique'] / stats['total']
                    reachable_ratio = stats['reachable'] / (stats['reachable'] + stats['unreachable']) if stats['reachable'] + stats['unreachable'] > 0 else 0
                    category_weight = CONFIG['category_weights'].get(stats['category'], 1.0)
                    subdomain_ratio = stats['subdomains'] / stats['total'] if stats['total'] > 0 else 0
                    stats['score'] = (
                        unique_ratio * 0.4 +
                        reachable_ratio * 0.3 +
                        (1 if url in CONFIG['priority_lists'] else 0) * 0.1 -
                        subdomain_ratio * 0.1
                    ) * category_weight
                else:
                    stats['score'] = 0.0
                if stats['unique'] == 0 and stats['total'] > 0:
                    STATISTICS['list_recommendations'].append(f"Entfernen Sie {url}: Keine einzigartigen Domains.")
                elif stats['score'] < 0.2 and stats['total'] > 50:
                    STATISTICS['list_recommendations'].append(f"Überprüfen Sie {url}: Niedriger Score ({stats['score']:.2f}), wenig Nutzen.")
                elif stats['subdomains'] / stats['total'] > 0.5 and stats['total'] > 50:
                    STATISTICS['list_recommendations'].append(f"Überprüfen Sie {url}: Hoher Subdomain-Anteil ({stats['subdomains']/stats['total']:.2f}).")
                logger.info(f"Liste {url} ({stats['category']}): Score={stats['score']:.2f}, Einzigartig={stats['unique']}, Total={stats['total']}, Subdomains={stats['subdomains']}")
            gc.collect()
    except Exception as e:
        logger.error(f"Fehler beim Bewerten der Listen: {e}")

# =============================================================================
# 11. GIT-MANAGEMENT
# =============================================================================

def setup_git() -> bool:
    """Richtet Git und SSH für GitHub-Uploads ein"""
    try:
        subprocess.run(['git', '--version'], check=True)
        git_dir = os.path.join(SCRIPT_DIR, '.git')
        if os.path.exists(git_dir):
            # Prüfe, ob das Remote bereits existiert
            result = subprocess.run(['git', 'remote', '-v'], capture_output=True, text=True, cwd=SCRIPT_DIR)
            if CONFIG['github_repo'] in result.stdout:
                logger.debug("Git-Repository und Remote bereits konfiguriert")
            else:
                subprocess.run(['git', 'remote', 'add', 'origin', CONFIG['github_repo']], check=True, cwd=SCRIPT_DIR)
                logger.debug(f"Git-Remote hinzugefügt: {CONFIG['github_repo']}")
        else:
            subprocess.run(['git', 'init'], check=True, cwd=SCRIPT_DIR)
            subprocess.run(['git', 'checkout', '-b', CONFIG['github_branch']], check=True, cwd=SCRIPT_DIR)
            subprocess.run(['git', 'remote', 'add', 'origin', CONFIG['github_repo']], check=True, cwd=SCRIPT_DIR)
            logger.debug("Git-Repository initialisiert")

        ssh_key_path = os.path.expanduser('~/.ssh/adblock_rsa')
        if not os.path.exists(ssh_key_path):
            subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '4096', '-C', CONFIG['git_email'], '-N', '', '-f', ssh_key_path], check=True)
            pub_key_path = f"{ssh_key_path}.pub"
            if not os.path.exists(pub_key_path):
                raise FileNotFoundError(f"Öffentlicher Schlüssel {pub_key_path} nicht gefunden")
            with open(pub_key_path, 'r') as f:
                print(f"SSH-Schlüssel: {f.read()}\nFügen Sie diesen zu GitHub hinzu.")
            logger.info("SSH-Schlüssel erfolgreich generiert")
            exit(0)

        ssh_config_path = os.path.expanduser('~/.ssh/config')
        with open(ssh_config_path, 'a') as f:  # Append statt Überschreiben
            f.write(
                "\nHost github.com\n"
                "  HostName github.com\n"
                "  User git\n"
                f"  IdentityFile {ssh_key_path}\n"
                "  IdentitiesOnly yes\n"
            )
        logger.info(f"SSH-Konfigurationsdatei aktualisiert: {ssh_config_path}")

        # Stelle sicher, dass der SSH-Agent läuft und der Schlüssel geladen ist
        try:
            # Versuche, den Schlüssel hinzuzufügen
            subprocess.run(['ssh-add', ssh_key_path], check=True)
            logger.debug(f"SSH-Schlüssel {ssh_key_path} erfolgreich hinzugefügt")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Fehler beim Hinzufügen des SSH-Schlüssels: {e}")
            # Starte einen neuen SSH-Agent, falls nötig
            subprocess.run(['pkill', 'ssh-agent'], check=False)  # Beende bestehende Agenten
            process = subprocess.run('eval "$(ssh-agent -s)"', shell=True, check=True, capture_output=True, text=True)
            logger.debug(f"Neuer SSH-Agent gestartet: {process.stdout}")
            # Versuche erneut, den Schlüssel hinzuzufügen
            subprocess.run(['ssh-add', ssh_key_path], check=True)
            logger.debug(f"SSH-Schlüssel {ssh_key_path} nach Agent-Neustart hinzugefügt")

        # Teste die SSH-Verbindung zu GitHub
        result = subprocess.run(['ssh', '-T', 'git@github.com'], capture_output=True, text=True)
        if "successfully authenticated" in result.stderr or result.returncode == 0:
            logger.debug("SSH-Verbindung zu GitHub erfolgreich")
        else:
            logger.error(f"SSH-Verbindung zu GitHub fehlgeschlagen: {result.stderr}")
            return False

        logger.debug("Git und SSH erfolgreich eingerichtet")
        return True
    except Exception as e:
        logger.warning(f"Fehler bei Git-Konfiguration: {e}")
        send_email("Warnung im AdBlock-Skript", f"Git-Konfiguration fehlgeschlagen: {e}")
        return False

def upload_to_github():
    """Lädt die Hosts-Datei auf GitHub hoch, wenn aktiviert"""
    if not CONFIG['github_upload']:
        logger.info("GitHub-Upload deaktiviert")
        return
    hosts_file = os.path.join(SCRIPT_DIR, CONFIG['hosts_file'])
    try:
        if not os.path.exists(hosts_file):
            logger.warning("hosts.txt fehlt, überspringe Git-Upload")
            return
        new_hash = calculate_md5(open(hosts_file, 'r', encoding='utf-8').read())
        old_hash = ''
        if os.path.exists(HOSTS_HASH_PATH):
            with open(HOSTS_HASH_PATH, 'r', encoding='utf-8') as f:
                old_hash = f.read().strip()
        if new_hash == old_hash:
            logger.info("Keine Änderungen an hosts.txt, überspringe Git-Upload")
            return
        result = subprocess.run(['git', 'status', '--porcelain', CONFIG['hosts_file']], capture_output=True, text=True, cwd=SCRIPT_DIR)
        if not result.stdout.strip():
            logger.info("Keine Änderungen an hosts.txt erkannt, überspringe Git-Upload")
            return
        subprocess.run(['git', 'add', CONFIG['hosts_file']], check=True, capture_output=True, text=True, cwd=SCRIPT_DIR)
        commit_msg = f"Update hosts.txt: {STATISTICS['reachable_domains']} Domains, {STATISTICS['unique_domains']} einzigartig"
        result = subprocess.run(['git', 'commit', '-m', commit_msg], check=True, capture_output=True, text=True, cwd=SCRIPT_DIR)
        logger.debug(f"Git commit Ausgabe: {result.stdout}")
        result = subprocess.run(['git', 'push', 'origin', CONFIG['github_branch']], check=True, capture_output=True, text=True, cwd=SCRIPT_DIR)
        logger.debug(f"Git push Ausgabe: {result.stdout}")
        logger.info("Hosts-Datei erfolgreich auf GitHub hochgeladen")
        with open(HOSTS_HASH_PATH, 'w', encoding='utf-8') as f:
            f.write(new_hash)
    except subprocess.CalledProcessError as e:
        logger.warning(f"Fehler beim Hochladen auf GitHub: {e}, stderr: {e.stderr}")
        send_email("Warnung im AdBlock-Skript", f"Git-Upload fehlgeschlagen: {e}\nStderr: {e.stderr}")
    except Exception as e:
        logger.warning(f"Unbekannter Fehler beim Hochladen auf GitHub: {e}")
        send_email("Warnung im AdBlock-Skript", f"Git-Upload fehlgeschlagen: {e}")

# =============================================================================
# 12. HAUPTLOGIK
# =============================================================================

@backoff.on_exception(backoff.expo, (aiohttp.ClientError, asyncio.TimeoutError), max_tries=3)
async def process_list(url: str, cache_manager: CacheManager, session: aiohttp.ClientSession) -> tuple[int, int, int]:
    """Verarbeitet eine Blockliste und extrahiert Domains"""
    try:
        logger.debug(f"Verarbeite Liste: {url}")
        async with session.get(url, timeout=30) as response:
            if response.status == 404:
                logger.error(f"Liste {url} nicht gefunden (404)")
                STATISTICS['failed_lists'] += 1
                return 0, 0, 0
            if response.status >= 500:
                logger.warning(f"Serverfehler bei {url} (Status {response.status})")
                raise aiohttp.ClientError(f"Serverfehler: {response.status}")
            response.raise_for_status()
            content = await response.text()
        if not content.strip():
            logger.warning(f"Liste {url} ist leer")
            return 0, 0, 0
        current_md5 = calculate_md5(content)
        list_cache = cache_manager.load_list_cache()
        temp_file = os.path.join(TMP_DIR, f"{url.replace('://', '__').replace('/', '__')}.tmp")
        filtered_file = os.path.join(TMP_DIR, f"{url.replace('://', '__').replace('/', '__')}.filtered")
        if url in list_cache and list_cache[url]['md5'] == current_md5:
            logger.info(f"Liste {url} unverändert, verwende Cache")
            if os.path.exists(filtered_file):
                async with aiofiles.open(filtered_file, 'r', encoding='utf-8') as f:
                    unique_count = sum(1 for _ in await f.readlines() if _.strip())
                return unique_count, unique_count, 0
        trie = DomainTrie()
        domain_count = 0
        unique_count = 0
        subdomain_count = 0
        duplicate_count = 0
        seen_domains = set()
        batch = []
        async with aiofiles.open(temp_file, 'w', encoding='utf-8') as f_temp, aiofiles.open(filtered_file, 'w', encoding='utf-8') as f_filtered:
            for domain in parse_domains(content, url):
                free_memory = psutil.virtual_memory().available
                trie.storage.update_threshold()
                _, batch_size, _ = get_system_resources()
                batch_size = min(batch_size, 50)  # Begrenze Batch-Größe auf 50
                if free_memory < 50 * 1024 * 1024:
                    logger.warning(f"Kritischer Speicherstand: {free_memory/(1024*1024):.2f} MB frei, pausiere Verarbeitung")
                    await asyncio.sleep(5)
                if domain in seen_domains:
                    duplicate_count += 1
                    continue
                seen_domains.add(domain)
                trie.insert(domain)
                batch.append(domain)
                domain_count += 1
                if len(batch) >= batch_size:
                    for d in batch:
                        if CONFIG['remove_redundant_subdomains'] and trie.has_parent(d):
                            subdomain_count += 1
                        else:
                            await f_filtered.write(d + '\n')
                            unique_count += 1
                    await f_temp.write('\n'.join(batch) + '\n')
                    batch = []
                    trie.flush()
                    gc.collect()  # Häufigere Garbage Collection
                    logger.debug(f"Batch von {batch_size} Domains gespeichert, Speicher: {free_memory/(1024*1024):.2f} MB")
                if domain_count % 1000 == 0:
                    memory = psutil.Process().memory_info().rss / (1024 * 1024)
                    logger.debug(f"Verarbeite {url}: {domain_count} Domains, Speicher: {memory:.2f} MB")
                    trie.flush()  # Zusätzliches Flushen bei großen Listen
                    gc.collect()
            if batch:
                for d in batch:
                    if CONFIG['remove_redundant_subdomains'] and trie.has_parent(d):
                        subdomain_count += 1
                    else:
                        await f_filtered.write(d + '\n')
                        unique_count += 1
                await f_temp.write('\n'.join(batch) + '\n')
        list_cache[url] = {"md5": current_md5, "last_checked": datetime.now().isoformat()}
        cache_manager.save_list_cache(list_cache)
        trie.close()
        STATISTICS['duplicates'] += duplicate_count
        gc.collect()
        logger.info(f"Extrahierte {domain_count} Domains aus {url}, {unique_count} einzigartig, {duplicate_count} Duplikate")
        return domain_count, unique_count, subdomain_count
    except aiohttp.ClientError as e:
        logger.error(f"HTTP-Fehler beim Verarbeiten der Liste {url}: {e}")
        STATISTICS['failed_lists'] += 1
        return 0, 0, 0
    except asyncio.TimeoutError as e:
        logger.error(f"Timeout beim Verarbeiten der Liste {url}: {e}")
        STATISTICS['failed_lists'] += 1
        return 0, 0, 0
    except Exception as e:
        logger.error(f"Unbekannter Fehler beim Verarbeiten der Liste {url}: {e}")
        STATISTICS['failed_lists'] += 1
        return 0, 0, 0

async def main():
    """Hauptfunktion des Skripts"""
    cache_flush_task = None
    resource_monitor_task = None
    try:
        start_time = time.time()
        logger.info("Starte AdBlock-Skript")
        free_memory = psutil.virtual_memory().available / (1024 * 1024)
        logger.debug(f"Freier Speicher: {free_memory:.2f} MB")
        if free_memory < 50:
            logger.warning(f"Kritischer Speicherstand vor Start: {free_memory:.2f} MB frei, aktiviere Low-Memory-Modus")
        logger.debug("Lade Konfiguration...")
        try:
            load_config()
        except Exception as e:
            logger.error(f"Fehler beim Laden der Konfiguration: {e}")
            raise
        logger.debug("Konfiguration geladen")
        logger.debug("Richte Logging ein...")
        try:
            setup_logging()
        except Exception as e:
            logger.error(f"Fehler beim Einrichten des Loggings: {e}")
            raise
        logger.debug("Logging eingerichtet")
        logger.debug(f"Erstelle temporäres Verzeichnis: {TMP_DIR}")
        try:
            os.makedirs(TMP_DIR, exist_ok=True)
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des temporären Verzeichnisses {TMP_DIR}: {e}")
            raise
        logger.debug("Temporäres Verzeichnis erstellt")
        global cache_manager
        logger.debug("Initialisiere CacheManager...")
        try:
            cache_manager = CacheManager(DB_PATH, CONFIG['cache_flush_interval'])
        except Exception as e:
            logger.error(f"Fehler beim Initialisieren des CacheManagers: {e}")
            raise
        logger.debug("CacheManager initialisiert")
        logger.debug("Initialisiere Verzeichnisse und Dateien...")
        try:
            initialize_directories_and_files()
        except Exception as e:
            logger.error(f"Fehler beim Initialisieren der Verzeichnisse und Dateien: {e}")
            raise
        logger.debug("Verzeichnisse und Dateien initialisiert")
        logger.debug("Bereinige temporäre Dateien...")
        try:
            cleanup_temp_files(cache_manager)
        except Exception as e:
            logger.error(f"Fehler beim Bereinigen temporärer Dateien: {e}")
            raise
        logger.debug("Temporäre Dateien bereinigt")
        memory = psutil.Process().memory_info().rss / (1024 * 1024)
        logger.info(f"Initialer Speicherverbrauch: {memory:.2f} MB")
        logger.debug("Starte Cache-Flush- und Ressourcenüberwachungs-Tasks...")
        try:
            cache_flush_task = asyncio.create_task(cache_manager.flush_cache_periodically())
            resource_monitor_task = asyncio.create_task(monitor_resources(cache_manager))
        except Exception as e:
            logger.error(f"Fehler beim Starten der Cache-Flush- und Ressourcenüberwachungs-Tasks: {e}")
            raise
        logger.debug("Cache-Flush- und Ressourcenüberwachungs-Tasks gestartet")
        if CONFIG['github_upload']:
            logger.debug("Git-Upload aktiviert, verwende manuelle Git-Konfiguration")
        else:
            logger.debug("Git-Upload deaktiviert")
        logger.debug("Lade Quell-URLs...")
        try:
            sources = load_hosts_sources()
        except Exception as e:
            logger.error(f"Fehler beim Laden der Quell-URLs: {e}")
            raise
        if not sources:
            logger.error("Keine Quell-URLs in hosts_sources.conf gefunden")
            send_email("Fehler im AdBlock-Skript", "Keine Quell-URLs in hosts_sources.conf gefunden")
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
            return
        logger.debug(f"Geladene Quell-URLs: {len(sources)}")
        logger.debug("Lade Whitelist und Blacklist...")
        try:
            whitelist, blacklist = load_whitelist_blacklist()
        except Exception as e:
            logger.error(f"Fehler beim Laden von Whitelist/Blacklist: {e}")
            raise
        logger.debug(f"Whitelist: {len(whitelist)} Einträge, Blacklist: {len(blacklist)} Einträge")
        url_counts = {}
        processed_urls = []
        logger.debug("Starte Verarbeitung der Blocklisten...")
        async with aiohttp.ClientSession() as session:
            logger.debug("Wähle beste DNS-Server...")
            try:
                dns_servers = await select_best_dns_server(CONFIG['dns_servers'])
            except Exception as e:
                logger.error(f"Fehler beim Auswählen der DNS-Server: {e}")
                raise
            resolver = aiodns.DNSResolver(nameservers=dns_servers, timeout=CONFIG['domain_timeout'])
            logger.debug("DNS-Server ausgewählt")
            max_jobs, _, _ = get_system_resources()
            for i in range(0, len(sources), max_jobs):
                batch = sources[i:i + max_jobs]
                tasks = [process_list(url, cache_manager, session) for url in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for url, result in zip(batch, results):
                    if isinstance(result, Exception):
                        logger.error(f"Fehler bei {url}: {result}")
                        STATISTICS['failed_lists'] += 1
                        continue
                    total, unique, subdomains = result
                    if os.path.exists(os.path.join(TMP_DIR, f"{url.replace('://', '__').replace('/', '__')}.filtered")):
                        processed_urls.append(url)
                        url_counts[url] = {"total": total, "unique": unique, "subdomains": subdomains}
                    logger.info(f"Verarbeitet {url}: {unique} Domains")
                    memory = psutil.Process().memory_info().rss / (1024 * 1024)
                    logger.debug(f"Speicherverbrauch nach {url}: {memory:.2f} MB")
                    gc.collect()  # Häufigere Garbage Collection
        if not processed_urls:
            logger.error("Keine gültigen Domains gefunden")
            send_email("Fehler im AdBlock-Skript", "Keine gültigen Domains gefunden")
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
            return
        STATISTICS['total_domains'] = sum(counts['total'] for counts in url_counts.values())
        STATISTICS['unique_domains'] = sum(counts['unique'] for counts in url_counts.values())
        logger.debug("Statistiken berechnet")
        max_jobs, batch_size, max_concurrent_dns = get_system_resources()
        if os.path.exists(REACHABLE_FILE):
            os.remove(REACHABLE_FILE)
        if os.path.exists(UNREACHABLE_FILE):
            os.remove(UNREACHABLE_FILE)
        async with aiofiles.open(REACHABLE_FILE, 'a', encoding='utf-8') as f_reachable, aiofiles.open(UNREACHABLE_FILE, 'a', encoding='utf-8') as f_unreachable:
            for url in processed_urls:
                filtered_file = os.path.join(TMP_DIR, f"{url.replace('://', '__').replace('/', '__')}.filtered")
                if not os.path.exists(filtered_file):
                    continue
                domains = []
                async with aiofiles.open(filtered_file, 'r', encoding='utf-8') as f:
                    async for line in f:
                        domain = line.strip()
                        if domain:
                            free_memory = psutil.virtual_memory().available
                            cache_manager.domain_cache.update_threshold()
                            _, batch_size, max_concurrent_dns = get_system_resources()
                            domains.append(domain)
                            if len(domains) >= batch_size:
                                results = await test_domain_batch(domains, url, resolver, cache_manager, whitelist, blacklist, max_concurrent_dns)
                                for domain, reachable in results:
                                    if not isinstance(reachable, bool):
                                        logger.error(f"Ungültiges Ergebnis für Domain {domain}: {reachable}")
                                        continue
                                    if reachable:
                                        await f_reachable.write(domain + '\n')
                                        STATISTICS['reachable_domains'] += 1
                                    else:
                                        await f_unreachable.write(domain + '\n')
                                        STATISTICS['unreachable_domains'] += 1
                                domains = []
                                memory = psutil.Process().memory_info().rss / (1024 * 1024)
                                logger.debug(f"Speicherverbrauch nach Batch ({url}): {memory:.2f} MB")
                                gc.collect()  # Häufigere Garbage Collection
                                if free_memory < 50 * 1024 * 1024:
                                    logger.warning(f"Kritischer Speicherstand: {free_memory/(1024*1024):.2f} MB frei, reduziere Cache")
                                    cache_manager.current_cache_size = max(2, cache_manager.current_cache_size // 2)
                                    cache_manager.adjust_cache_size()
                                    cache_manager.domain_cache.use_ram = False
                    if domains:
                        results = await test_domain_batch(domains, url, resolver, cache_manager, whitelist, blacklist, max_concurrent_dns)
                        for domain, reachable in results:
                            if not isinstance(reachable, bool):
                                logger.error(f"Ungültiges Ergebnis für Domain {domain}: {reachable}")
                                continue
                            if reachable:
                                await f_reachable.write(domain + '\n')
                                STATISTICS['reachable_domains'] += 1
                            else:
                                await f_unreachable.write(domain + '\n')
                                STATISTICS['unreachable_domains'] += 1
        evaluate_lists(url_counts, STATISTICS['total_domains'])
        logger.debug("Listen bewertet")
        sorted_domains = []
        async with aiofiles.open(REACHABLE_FILE, 'r', encoding='utf-8') as f:
            sorted_domains = sorted([line.strip() async for line in f if line.strip()])
        logger.debug(f"Anzahl der erreichbaren Domains: {len(sorted_domains)}")
        logger.debug(f"Erste 5 erreichbare Domains (Beispiel): {sorted_domains[:5]}")
        dnsmasq_lines = []
        if CONFIG['use_ipv4_output']:
            dnsmasq_lines.extend(f"address=/{domain}/{CONFIG['web_server_ipv4']}" for domain in sorted_domains)
            logger.debug(f"IPv4-Ausgabe aktiviert, {len(dnsmasq_lines)} Einträge für dnsmasq.conf mit IPv4")
        if CONFIG['use_ipv6_output'] and is_ipv6_supported():
            dnsmasq_lines.extend(f"address=/{domain}/{CONFIG['web_server_ipv6']}" for domain in sorted_domains)
            logger.debug(f"IPv6-Ausgabe aktiviert, {len(dnsmasq_lines)} Einträge für dnsmasq.conf mit IPv6")
        dnsmasq_content = '\n'.join(dnsmasq_lines)
        hosts_content = '\n'.join(f"{CONFIG['hosts_ip']} {domain}" for domain in sorted_domains)
        logger.debug(f"Schreibe {len(sorted_domains)} Domains in hosts.txt mit IP {CONFIG['hosts_ip']}")
        async with aiofiles.open(os.path.join(SCRIPT_DIR, CONFIG['dns_config_file']), 'w', encoding='utf-8') as f:
            await f.write(dnsmasq_content)
        async with aiofiles.open(os.path.join(SCRIPT_DIR, CONFIG['hosts_file']), 'w', encoding='utf-8') as f:
            await f.write(hosts_content)
        if CONFIG['save_unreachable'] and os.path.exists(UNREACHABLE_FILE):
            async with aiofiles.open(UNREACHABLE_FILE, 'r', encoding='utf-8') as f:
                unreachable_domains = sorted([line.strip() async for line in f if line.strip()])
            async with aiofiles.open(os.path.join(TMP_DIR, 'unreachable.txt'), 'w', encoding='utf-8') as f:
                await f.write('\n'.join(unreachable_domains))
        if CONFIG['github_upload']:
            upload_to_github()
        safe_save(os.path.join(TMP_DIR, 'statistics.json'), STATISTICS, is_json=True)
        export_statistics_csv()
        export_prometheus_metrics(start_time)
        recommendations = '\n'.join(STATISTICS['list_recommendations']) if STATISTICS['list_recommendations'] else "Keine Empfehlungen"
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
        send_email("AdBlock-Skript Bericht", summary)
        try:
            subprocess.run(['systemctl', 'restart', 'dnsmasq'], check=True)
            logger.info("DNSMasq erfolgreich neu gestartet")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Fehler beim Neustarten von DNSMasq via systemctl: {e}, versuche Fallback...")
            try:
                subprocess.run(['service', 'dnsmasq', 'restart'], check=True)
                logger.info("DNSMasq erfolgreich via service neu gestartet")
            except subprocess.CalledProcessError as e:
                logger.error(f"Fehler beim Neustarten von DNSMasq: {e}")
                send_email("Fehler im AdBlock-Skript", f"DNSMasq-Neustart fehlgeschlagen: {e}")
        logger.info("Skript erfolgreich abgeschlossen")
    except Exception as e:
        logger.error(f"Kritischer Fehler in der Hauptfunktion: {e}")
        send_email("Kritischer Fehler im AdBlock-Skript", f"Skript fehlgeschlagen: {e}")
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
        async with cache_flush_lock:
            cache_manager.save_domain_cache()

if __name__ == "__main__":
    try:
        logger.debug("Skript wird gestartet")
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Skript durch Benutzer abgebrochen")
        sys.exit(0)
    except MemoryError:
        logger.error("Skript abgebrochen: Nicht genügend Speicher verfügbar")
        send_email("Kritischer Fehler im AdBlock-Skript", "Skript abgebrochen: Nicht genügend Speicher verfügbar")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Kritischer Fehler beim Start des Skripts: {e}")
        send_email("Kritischer Fehler im AdBlock-Skript", f"Skript fehlgeschlagen: {e}")
        sys.exit(1)