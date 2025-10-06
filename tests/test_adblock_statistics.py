import asyncio
import os
import sys
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import adblock  # noqa: E402
import caching  # noqa: E402
import config as config_module  # noqa: E402


def test_ensure_list_stats_entry_initializes_and_updates(monkeypatch):
    stats_store = defaultdict(adblock.create_default_list_stats_entry)
    monkeypatch.setitem(adblock.STATISTICS, "list_stats", stats_store)

    url = "https://example.com/list.txt"
    entry = adblock.ensure_list_stats_entry(url, total=10, unique=7, subdomains=2)

    assert entry["total"] == 10
    assert entry["unique"] == 7
    assert entry["duplicates"] == 3
    assert entry["subdomains"] == 2
    assert entry["reachable"] == 0
    assert entry["unreachable"] == 0

    entry["reachable"] = 5
    entry["unreachable"] = 1

    same_entry = adblock.ensure_list_stats_entry(url)

    assert same_entry is entry
    assert same_entry["reachable"] == 5
    assert same_entry["unreachable"] == 1

    updated_entry = adblock.ensure_list_stats_entry(url, duplicates=8)
    assert updated_entry["duplicates"] == 8


class FakeResponse:
    def __init__(self, content: str):
        self.status = 200
        self.reason = "OK"
        self._content = content

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return self._content

    def raise_for_status(self) -> None:
        return None


class FakeSession:
    def __init__(self, content: str):
        self._content = content

    def get(self, url: str, timeout: int):
        return FakeResponse(self._content)


def test_process_list_cache_reuses_statistics(monkeypatch, tmp_path):
    monkeypatch.setattr(adblock, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie_cache.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    os.makedirs(adblock.TMP_DIR, exist_ok=True)

    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values["use_bloom_filter"] = False
    config_values["remove_redundant_subdomains"] = True
    original_config = config_module.CONFIG.copy()
    original_adblock_config = adblock.CONFIG.copy()
    config_module.CONFIG.clear()
    config_module.CONFIG.update(config_values)
    adblock.CONFIG.clear()
    adblock.CONFIG.update(config_values)
    monkeypatch.setattr(adblock.config, "global_mode", adblock.SystemMode.NORMAL)

    monkeypatch.setattr(adblock, "get_system_resources", lambda: (10, 10, 10))
    monkeypatch.setattr(
        adblock.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=1_000_000_000),
    )
    monkeypatch.setattr(
        adblock.psutil,
        "Process",
        lambda: SimpleNamespace(
            memory_info=lambda: SimpleNamespace(rss=50 * 1024 * 1024)
        ),
    )

    domains = [
        "example.com",
        "duplicate.example.com",
        "duplicate.example.com",
        "sub.example.com",
        "unique.com",
    ]

    def fake_parse_domains(content: str, url: str):
        for domain in domains:
            yield domain

    monkeypatch.setattr(adblock, "parse_domains", fake_parse_domains)

    cache_manager = caching.CacheManager(
        str(tmp_path / "cache.db"), flush_interval=1, config=config_values
    )

    url = "https://example.com/list.txt"
    original_duplicates = adblock.STATISTICS.get("duplicates", 0)
    original_cache_hits = adblock.STATISTICS.get("cache_hits", 0)
    original_domain_sources = adblock.STATISTICS["domain_sources"].copy()
    adblock.STATISTICS["duplicates"] = 0
    adblock.STATISTICS["cache_hits"] = 0

    async def run_test():
        try:
            result_first = await adblock.process_list(
                url, cache_manager, FakeSession("data")
            )
            duplicates_after_first = adblock.STATISTICS["duplicates"]
            assert duplicates_after_first == 1
            assert result_first[2] > 0  # subdomain count

            result_second = await adblock.process_list(
                url, cache_manager, FakeSession("data")
            )

            assert result_second == result_first
            assert adblock.STATISTICS["duplicates"] == duplicates_after_first
            assert adblock.STATISTICS["cache_hits"] == 1
        finally:
            config_module.CONFIG.clear()
            config_module.CONFIG.update(original_config)
            adblock.CONFIG.clear()
            adblock.CONFIG.update(original_adblock_config)
            adblock.STATISTICS["duplicates"] = original_duplicates
            adblock.STATISTICS["cache_hits"] = original_cache_hits
            adblock.STATISTICS["domain_sources"] = original_domain_sources

    asyncio.run(run_test())
