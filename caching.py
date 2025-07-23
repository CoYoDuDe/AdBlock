# -*- coding: utf-8 -*-
"""Caching related classes and utilities."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import pickle
import shelve
import sqlite3
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import psutil
from pybloom_live import ScalableBloomFilter

from config import DEFAULT_CONFIG, TMP_DIR, TRIE_CACHE_PATH, DB_PATH

logger = logging.getLogger(__name__)


class HybridStorage:
    """Hybrid storage using RAM and shelve on disk."""

    def __init__(self, db_path: str):
        logger.debug("Initializing HybridStorage with db_path: %s", db_path)
        self.db_path = db_path
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception as exc:
                logger.warning("Fehler beim Löschen von %s: %s", db_path, exc)
        self.db = shelve.open(db_path, protocol=3, writeback=False)
        self.ram_storage: Dict[str, Any] = {}
        self.ram_threshold = self.calculate_threshold()
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
            emergency_threshold = (
                DEFAULT_CONFIG["resource_thresholds"]["emergency_memory_mb"]
                * 1024
                * 1024
            )
            return (
                free_memory > self.ram_threshold and free_memory > emergency_threshold
            )
        except Exception as exc:
            logger.warning("RAM check failed: %s", exc)
            return True

    def flush_to_disk(self) -> None:
        if self.use_ram:
            for key, value in self.ram_storage.items():
                self.db[key] = value
            self.db.sync()

    def reset_if_corrupt(self) -> None:
        try:
            self.db.close()
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
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
    """Trie for fast domain lookups."""

    def __init__(self, url: str):
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        db_path = os.path.join(TMP_DIR, f"trie_cache_{url_hash}.db")
        self.storage = HybridStorage(db_path)
        self.root_key = "root"
        if DEFAULT_CONFIG.get("use_bloom_filter"):
            self.bloom_filter = ScalableBloomFilter(
                initial_capacity=DEFAULT_CONFIG["bloom_filter_capacity"],
                error_rate=DEFAULT_CONFIG["bloom_filter_error_rate"],
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
        self.storage.clear()
        self.storage[self.root_key] = TrieNode()

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


class CacheManager:
    """Manage domain and list caches."""

    def __init__(self, db_path: str, flush_interval: int):
        self.db_path = db_path
        self.flush_interval = flush_interval
        os.makedirs(TMP_DIR, exist_ok=True)
        self.domain_cache = HybridStorage(os.path.join(TMP_DIR, "domain_cache.db"))
        self.list_cache: Dict[str, Dict] = {}
        self.last_flush = time.time()
        self.current_cache_size = self.calculate_dynamic_cache_size()
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
            conn = sqlite3.connect(self.db_path, timeout=30)
            c = conn.cursor()
            c.execute(
                "CREATE TABLE IF NOT EXISTS list_cache (url TEXT PRIMARY KEY, md5 TEXT, last_checked TEXT)"
            )
            conn.commit()
            conn.close()
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

    def save_domain_cache(self) -> None:
        try:
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
            conn = sqlite3.connect(self.db_path, timeout=30)
            c = conn.cursor()
            c.execute("SELECT url, md5, last_checked FROM list_cache")
            self.list_cache = {
                row[0]: {"md5": row[1], "last_checked": row[2]} for row in c.fetchall()
            }
            conn.close()
            return self.list_cache
        except Exception as exc:
            logger.warning("Fehler beim Zugriff auf List-Cache: %s", exc)
            return {}

    def save_list_cache(self, cache: Dict[str, Dict]) -> None:
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            c = conn.cursor()
            c.execute("DELETE FROM list_cache")
            for url, data in cache.items():
                c.execute(
                    "INSERT INTO list_cache (url, md5, last_checked) VALUES (?, ?, ?)",
                    (url, data["md5"], data["last_checked"]),
                )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("Fehler beim Speichern des List-Caches: %s", exc)


def cleanup_temp_files(cache_manager: CacheManager) -> None:
    """Remove outdated temporary and cache files."""

    try:
        list_cache = cache_manager.load_list_cache()
        valid_urls = set(list_cache.keys())
        expiry = datetime.now() - timedelta(
            days=DEFAULT_CONFIG["domain_cache_validity_days"]
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
                url = file.replace("__", "/").replace("_", "://")
                if url not in valid_urls:
                    os.remove(file_path)
    except Exception as exc:
        logger.error("Fehler beim Bereinigen temporärer Dateien: %s", exc)
