# -*- coding: utf-8 -*-
"""Klassen und Hilfsfunktionen f\xc3\xbcr das Caching."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import pickle
import shelve
import sqlite3
import threading
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from copy import deepcopy
from typing import Any, Dict, Mapping, MutableMapping, Optional, TypedDict

import psutil
from pybloom_live import ScalableBloomFilter
from urllib.parse import quote, unquote


from config import (
    CONFIG,
    DEFAULT_CONFIG,
    TMP_DIR,
    TRIE_CACHE_PATH,
    DB_PATH,
    MAX_DNS_CACHE_SIZE,
    dns_cache,
)

logger = logging.getLogger(__name__)


def _deep_merge(base: Dict[str, Any], updates: Mapping[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(base[key], value)
        else:
            base[key] = deepcopy(value)
    return base


def _merge_config(overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    merged = deepcopy(DEFAULT_CONFIG)
    if CONFIG:
        _deep_merge(merged, CONFIG)
    if overrides:
        _deep_merge(merged, overrides)
    return merged


def sanitize_tmp_identifier(url: str) -> str:
    """Kodiert eine URL so, dass sie als Dateiname verwendet werden kann."""

    return quote(url, safe="")


def desanitize_tmp_filename(identifier: str) -> str:
    """Rekonstruiert die ursprüngliche URL aus einem temporären Dateinamen."""

    return unquote(identifier)


class HybridStorage:
    """Hybrider Speicher, der RAM und Shelve auf der Festplatte verwendet."""

    def __init__(self, db_path: str):
        logger.debug("Initializing HybridStorage with db_path: %s", db_path)
        self.db_path = db_path
        self.db = None
        self.ram_storage: Dict[str, Any] = {}
        try:
            self.db = shelve.open(db_path, protocol=3, writeback=False)
        except Exception as exc:
            logger.warning(
                "Fehler beim Öffnen der HybridStorage-DB %s: %s. Versuche Reset.",
                db_path,
                exc,
            )
            self.reset_if_corrupt()
        self.ram_threshold = self.calculate_threshold()
        self._use_ram = False
        self.use_ram = self.should_use_ram()

    def calculate_threshold(self) -> int:
        try:
            free_memory = psutil.virtual_memory().available
            threshold = max(
                20 * 1024 * 1024,
                min(512 * 1024 * 1024, int(free_memory * 0.1)),
            )
            return threshold
        except Exception as exc:
            logger.warning("Threshold calc failed: %s", exc)
            return 20 * 1024 * 1024

    def update_threshold(self) -> None:
        self.ram_threshold = self.calculate_threshold()
        self.use_ram = self.should_use_ram()

    def should_use_ram(self) -> bool:
        try:
            free_memory = psutil.virtual_memory().available
            config_values = _merge_config()
            emergency_threshold = (
                config_values["resource_thresholds"]["emergency_memory_mb"]
                * 1024
                * 1024
            )
            return (
                free_memory > self.ram_threshold and free_memory > emergency_threshold
            )
        except Exception as exc:
            logger.warning("RAM check failed: %s", exc)
            return True

    def persist_ram_to_disk(self) -> None:
        """Persistiert den aktuellen RAM-Inhalt sicher auf die Festplatte."""

        if self.db is None:
            return

        if self.ram_storage:
            try:
                for key, value in list(self.ram_storage.items()):
                    self.db[key] = value
            except Exception as exc:
                logger.warning(
                    "Fehler beim Persistieren der RAM-Daten nach %s: %s",
                    self.db_path,
                    exc,
                )
                raise

        try:
            self.db.sync()
        except Exception as exc:
            logger.warning(
                "Fehler beim Synchronisieren der HybridStorage-DB %s: %s",
                self.db_path,
                exc,
            )

    @property
    def use_ram(self) -> bool:
        return getattr(self, "_use_ram", False)

    @use_ram.setter
    def use_ram(self, value: bool) -> None:
        previous = getattr(self, "_use_ram", None)
        bool_value = bool(value)
        if previous is None:
            self._use_ram = bool_value
            return
        if previous and not bool_value:
            self.persist_ram_to_disk()
            self.ram_storage.clear()
        self._use_ram = bool_value

    def flush_to_disk(self) -> None:
        self.persist_ram_to_disk()

    def reset_if_corrupt(self) -> None:
        try:
            if getattr(self, "db", None) is not None:
                try:
                    self.db.close()
                except Exception as exc:
                    logger.warning(
                        "Fehler beim Schließen der beschädigten DB %s: %s",
                        self.db_path,
                        exc,
                    )
                finally:
                    self.db = None
            for suffix in ("", ".db", ".dat", ".bak", ".dir"):
                candidate = f"{self.db_path}{suffix}"
                try:
                    os.remove(candidate)
                except FileNotFoundError:
                    continue
                except IsADirectoryError:
                    try:
                        shutil.rmtree(candidate)
                    except Exception as removal_exc:
                        logger.warning(
                            "Fehler beim Entfernen des Shelve-Verzeichnisses %s: %s",
                            candidate,
                            removal_exc,
                        )
                except Exception as removal_exc:
                    logger.warning(
                        "Fehler beim Entfernen der Shelve-Datei %s: %s",
                        candidate,
                        removal_exc,
                    )
            self.db = shelve.open(self.db_path, protocol=3, writeback=False)
            self.ram_storage.clear()
        except Exception as exc:
            logger.error("Fehler beim Zurücksetzen der DB: %s", exc)
            raise

    def __setitem__(self, key: str, value: Any) -> None:
        key = str(key)
        if self.use_ram:
            self.ram_storage[key] = value
        else:
            self.db[key] = value
            self.db.sync()

    def __getitem__(self, key: str) -> Any:
        key = str(key)
        return self.ram_storage[key] if self.use_ram else self.db[key]

    def __contains__(self, key: str) -> bool:
        key = str(key)
        return key in (self.ram_storage if self.use_ram else self.db)

    def __delitem__(self, key: str) -> None:
        key = str(key)
        if self.use_ram:
            del self.ram_storage[key]
        else:
            del self.db[key]
            self.db.sync()

    def items(self):
        return self.ram_storage.items() if self.use_ram else self.db.items()

    def __len__(self) -> int:
        return len(self.ram_storage) if self.use_ram else len(self.db)

    def clear(self) -> None:
        self.flush_to_disk()
        if self.use_ram:
            self.ram_storage.clear()
        else:
            self.db.clear()
            self.db.sync()

    def close(self) -> None:
        try:
            self.db.close()
        except Exception as exc:
            logger.warning("Fehler beim Schließen der DB: %s", exc)


@dataclass
class TrieNode:
    children: Dict[str, str]
    is_end: bool = False

    def __init__(self):
        self.children = {}
        self.is_end = False

    def __getstate__(self):
        return {"children": self.children, "is_end": self.is_end}

    def __setstate__(self, state):
        self.children = state["children"]
        self.is_end = state["is_end"]


class DomainTrie:
    """Trie für schnelle Domain-Abfragen."""

    def __init__(self, url: str, config: Optional[Mapping[str, Any]] = None):
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        db_path = os.path.join(TMP_DIR, f"trie_cache_{url_hash}.db")
        self.storage = HybridStorage(db_path)
        self.root_key = "root"
        self.config = _merge_config(config)
        if self.config.get("use_bloom_filter"):
            self.bloom_filter = ScalableBloomFilter(
                initial_capacity=self.config["bloom_filter_capacity"],
                error_rate=self.config["bloom_filter_error_rate"],
            )
        else:
            self.bloom_filter = None
        try:
            self.storage[self.root_key]
        except KeyError:
            self.storage[self.root_key] = TrieNode()

    def insert(self, domain: str) -> None:
        if self.bloom_filter and domain in self.bloom_filter:
            return
        node = self.storage[self.root_key]
        node_key = self.root_key
        parts = domain.split(".")[::-1]
        for i, part in enumerate(parts):
            if part not in node.children:
                new_key = f"{node_key}:{part}:{i}"
                node.children[part] = new_key
                self.storage[node_key] = node
                self.storage[new_key] = TrieNode()
            node_key = node.children[part]
            node = self.storage[node_key]
        node.is_end = True
        self.storage[node_key] = node
        if self.bloom_filter:
            self.bloom_filter.add(domain)

    def has_parent(self, domain: str) -> bool:
        parts = domain.split(".")[::-1]
        node = self.storage[self.root_key]
        node_key = self.root_key
        for i, part in enumerate(parts):
            if part not in node.children:
                return False
            node_key = node.children[part]
            node = self.storage[node_key]
            if node.is_end and i < len(parts) - 1:
                return True
        return False

    def flush(self) -> None:
        self.storage.persist_ram_to_disk()

    def close(self) -> None:
        self.storage.close()


def save_trie_cache(trie: DomainTrie, all_domains_hash: str) -> None:
    try:
        data = {"hash": all_domains_hash, "version": "1.0"}
        compressed = zlib.compress(pickle.dumps(data))
        with open(TRIE_CACHE_PATH, "wb") as f:
            f.write(compressed)
    except Exception as exc:
        logger.warning("Fehler beim Speichern des Trie-Caches: %s", exc)


def load_trie_cache(all_domains_hash: str, url: str) -> Optional[DomainTrie]:
    if not os.path.exists(TRIE_CACHE_PATH):
        return None
    try:
        with open(TRIE_CACHE_PATH, "rb") as f:
            compressed = f.read()
        data = pickle.loads(zlib.decompress(compressed))
        if data.get("hash") == all_domains_hash:
            return DomainTrie(url)
        return None
    except Exception as exc:
        logger.warning("Fehler beim Laden des Trie-Caches: %s", exc)
        return None


class DnsCacheEntry(TypedDict):
    reachable: bool
    timestamp: float


class CacheManager:
    """Verwaltet Domain- und Listen-Caches."""

    def __init__(
        self,
        db_path: str,
        flush_interval: int,
        config: Optional[Mapping[str, Any]] = None,
    ):
        self.db_path = db_path
        self.flush_interval = flush_interval
        self.config = _merge_config(config)
        os.makedirs(TMP_DIR, exist_ok=True)
        self.domain_cache = HybridStorage(os.path.join(TMP_DIR, "domain_cache.db"))
        self.list_cache: Dict[str, Dict] = {}
        self.dns_cache: MutableMapping[str, DnsCacheEntry | bool] = dns_cache
        self.last_flush = time.time()
        self.current_cache_size = self.calculate_dynamic_cache_size()
        self._db_lock = threading.Lock()
        self.init_database()

    def calculate_dynamic_cache_size(self) -> int:
        try:
            free_memory = psutil.virtual_memory().available
            return max(1000, int(free_memory / 50_000))
        except Exception:
            return 1000

    def adjust_cache_size(self) -> None:
        self.current_cache_size = self.calculate_dynamic_cache_size()
        self.save_domain_cache()

    def init_database(self) -> None:
        try:
            with self._db_lock:
                with sqlite3.connect(self.db_path, timeout=30) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        CREATE TABLE IF NOT EXISTS list_cache (
                            url TEXT PRIMARY KEY,
                            md5 TEXT,
                            last_checked TEXT,
                            total_domains INTEGER,
                            unique_domains INTEGER,
                            subdomains INTEGER,
                            duplicates INTEGER
                        )
                        """
                    )
                    existing_columns = {
                        row[1] for row in c.execute("PRAGMA table_info(list_cache)")
                    }
                    for column in (
                        "total_domains",
                        "unique_domains",
                        "subdomains",
                        "duplicates",
                    ):
                        if column not in existing_columns:
                            c.execute(
                                f"ALTER TABLE list_cache ADD COLUMN {column} INTEGER"
                            )
                    conn.commit()
        except Exception as exc:
            logger.warning("DB init failed: %s", exc)

    async def flush_cache_periodically(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.flush_interval)
                self.save_domain_cache()
            except asyncio.CancelledError:
                self.save_domain_cache()
                break
            except Exception as exc:
                logger.warning("Cache flush task error: %s", exc)

    def load_domain_cache(self):
        return self.domain_cache

    def get_dns_cache(self, domain: str) -> Optional[DnsCacheEntry]:
        if domain not in self.dns_cache:
            return None

        ttl = self.config.get("dns_cache_ttl", DEFAULT_CONFIG["dns_cache_ttl"])
        raw_entry = self.dns_cache[domain]
        if isinstance(raw_entry, bool):
            entry: DnsCacheEntry = {"reachable": raw_entry, "timestamp": time.time()}
            self.dns_cache[domain] = entry
        else:
            entry = raw_entry

        timestamp = entry.get("timestamp")
        if ttl > 0 and (timestamp is None or time.time() - timestamp > ttl):
            self.dns_cache.pop(domain, None)
            return None

        self.dns_cache.move_to_end(domain)
        return entry

    def save_dns_cache(self, domain: str, reachable: bool) -> None:
        entry: DnsCacheEntry = {"reachable": reachable, "timestamp": time.time()}
        self.dns_cache[domain] = entry
        self.dns_cache.move_to_end(domain)
        if len(self.dns_cache) > MAX_DNS_CACHE_SIZE:
            self.dns_cache.popitem(last=False)

    def save_domain_cache(self) -> None:
        try:
            if self.domain_cache.use_ram:
                self.domain_cache.flush_to_disk()
            if (
                len(self.domain_cache.ram_storage) > self.current_cache_size
                and self.domain_cache.use_ram
            ):
                sorted_items = sorted(
                    self.domain_cache.ram_storage.items(),
                    key=lambda x: x[1]["checked_at"],
                )
                self.domain_cache.ram_storage = dict(
                    sorted_items[-self.current_cache_size :]
                )
        except Exception as exc:
            logger.warning("Fehler beim Speichern des Domain-Caches: %s", exc)

    def save_domain(self, domain: str, reachable: bool, source_url: str) -> None:
        try:
            self.domain_cache[domain] = {
                "reachable": reachable,
                "checked_at": datetime.now().isoformat(),
                "source": source_url,
            }
            if (
                len(self.domain_cache.ram_storage) > self.current_cache_size
                and self.domain_cache.use_ram
            ):
                oldest_domain = min(
                    self.domain_cache.ram_storage,
                    key=lambda k: self.domain_cache.ram_storage[k]["checked_at"],
                )
                del self.domain_cache[oldest_domain]
        except Exception as exc:
            logger.warning("Fehler beim Speichern der Domain %s: %s", domain, exc)

    def load_list_cache(self) -> Dict[str, Dict]:
        try:
            with self._db_lock:
                with sqlite3.connect(self.db_path, timeout=30) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        SELECT
                            url,
                            md5,
                            last_checked,
                            total_domains,
                            unique_domains,
                            subdomains,
                            duplicates
                        FROM list_cache
                        """
                    )
                    self.list_cache = {
                        row[0]: {
                            "md5": row[1],
                            "last_checked": row[2],
                            "total_domains": row[3],
                            "unique_domains": row[4],
                            "subdomains": row[5],
                            "duplicates": row[6],
                        }
                        for row in c.fetchall()
                    }
                    conn.commit()
            return self.list_cache
        except Exception as exc:
            logger.warning("Fehler beim Zugriff auf List-Cache: %s", exc)
            return {}

    def get_list_cache_entry(self, url: str) -> Optional[Dict[str, str]]:
        try:
            with self._db_lock:
                with sqlite3.connect(self.db_path, timeout=30) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        SELECT
                            md5,
                            last_checked,
                            total_domains,
                            unique_domains,
                            subdomains,
                            duplicates
                        FROM list_cache
                        WHERE url = ?
                        """,
                        (url,),
                    )
                    row = c.fetchone()
                    conn.commit()
            if row:
                entry = {
                    "md5": row[0],
                    "last_checked": row[1],
                    "total_domains": row[2],
                    "unique_domains": row[3],
                    "subdomains": row[4],
                    "duplicates": row[5],
                }
                self.list_cache[url] = entry
                return entry
            return None
        except Exception as exc:
            logger.warning("Fehler beim Lesen des List-Caches für %s: %s", url, exc)
            return None

    def upsert_list_cache(
        self,
        url: str,
        md5: str,
        *,
        last_checked: Optional[str] = None,
        total_domains: Optional[int] = None,
        unique_domains: Optional[int] = None,
        subdomains: Optional[int] = None,
        duplicates: Optional[int] = None,
    ) -> None:
        timestamp = last_checked or datetime.now().isoformat()
        try:
            with self._db_lock:
                with sqlite3.connect(self.db_path, timeout=30) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        REPLACE INTO list_cache (
                            url,
                            md5,
                            last_checked,
                            total_domains,
                            unique_domains,
                            subdomains,
                            duplicates
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            url,
                            md5,
                            timestamp,
                            total_domains,
                            unique_domains,
                            subdomains,
                            duplicates,
                        ),
                    )
                    conn.commit()
            self.list_cache[url] = {
                "md5": md5,
                "last_checked": timestamp,
                "total_domains": total_domains,
                "unique_domains": unique_domains,
                "subdomains": subdomains,
                "duplicates": duplicates,
            }
        except Exception as exc:
            logger.warning(
                "Fehler beim Aktualisieren des List-Caches für %s: %s", url, exc
            )


def cleanup_temp_files(cache_manager: CacheManager) -> None:
    """Entfernt veraltete temporäre Dateien und Cache-Dateien."""

    try:
        list_cache = cache_manager.load_list_cache()
        valid_urls = set(list_cache.keys())
        active_config = getattr(cache_manager, "config", _merge_config())
        expiry = datetime.now() - timedelta(
            days=active_config["domain_cache_validity_days"]
        )

        valid_trie_basenames = {
            f"trie_cache_{hashlib.md5(url.encode('utf-8')).hexdigest()}"
            for url in valid_urls
        }

        for file in os.listdir(TMP_DIR):
            file_path = os.path.join(TMP_DIR, file)
            file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))

            if file.startswith("trie_cache_"):
                basename, _ = os.path.splitext(file)
                if basename not in valid_trie_basenames or file_mtime < expiry:
                    os.remove(file_path)
                continue

            if file.endswith(".db") and file != os.path.basename(DB_PATH):
                if file_mtime < expiry:
                    os.remove(file_path)
                continue

            if file.endswith(".tmp") or file.endswith(".filtered"):
                sanitized_name, _ = os.path.splitext(file)
                url = desanitize_tmp_filename(sanitized_name)
                if url not in valid_urls:
                    os.remove(file_path)
    except Exception as exc:
        logger.error("Fehler beim Bereinigen temporärer Dateien: %s", exc)
