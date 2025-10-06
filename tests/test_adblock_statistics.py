import asyncio
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import backoff
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import adblock  # noqa: E402
import caching  # noqa: E402
import config as config_module  # noqa: E402
import monitoring  # noqa: E402


def test_ensure_list_stats_entry_initializes_and_updates(monkeypatch):
    stats_store = defaultdict(adblock.create_default_list_stats_entry)
    monkeypatch.setitem(adblock.STATISTICS, "list_stats", stats_store)

    url = "https://example.com/list.txt"
    entry = adblock.ensure_list_stats_entry(url, total=10, unique=7, subdomains=2)

    assert entry["total"] == 10
    assert entry["unique"] == 7
    assert entry["duplicates"] == 1
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


class DummyCacheManager:
    def get_list_cache_entry(self, url):
        return None

    def upsert_list_cache(self, *args, **kwargs):
        return None


def test_get_system_resources_uses_non_blocking_cpu_percent(monkeypatch):
    intervals = []

    def fake_cpu_percent(interval=None):
        intervals.append(interval)
        return 25.0

    monkeypatch.setattr(monitoring, "_RESOURCE_CACHE", None)
    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fake_cpu_percent)
    monkeypatch.setattr(monitoring.psutil, "cpu_count", lambda logical=True: 8)
    monkeypatch.setattr(
        monitoring.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=2_000_000_000),
    )

    result = monitoring.get_system_resources()

    assert intervals, "psutil.cpu_percent wurde nicht aufgerufen"
    assert intervals[0] in (None, 0)
    assert isinstance(result, tuple)
    assert len(result) == 3


def test_get_system_resources_caches_recent_values(monkeypatch):
    times = [1000.0, 1000.01]

    def fake_monotonic():
        return times.pop(0)

    call_counter = {"count": 0}

    def fake_cpu_percent(interval=None):
        call_counter["count"] += 1
        return 30.0

    monkeypatch.setattr(monitoring, "_RESOURCE_CACHE", None)
    monkeypatch.setattr(monitoring.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fake_cpu_percent)
    monkeypatch.setattr(monitoring.psutil, "cpu_count", lambda logical=True: 4)
    monkeypatch.setattr(
        monitoring.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=1_000_000_000),
    )

    first = monitoring.get_system_resources()

    def fail_cpu_percent(interval=None):
        raise AssertionError("psutil.cpu_percent sollte nicht erneut aufgerufen werden")

    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fail_cpu_percent)

    second = monitoring.get_system_resources()

    assert first == second
    assert call_counter["count"] == 1


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
    adblock.STATISTICS["domain_sources"] = {}

    async def run_test():
        try:
            result_first = await adblock.process_list(
                url, cache_manager, FakeSession("data")
            )
            duplicates_after_first = adblock.STATISTICS["duplicates"]
            assert duplicates_after_first == 1
            assert result_first[0] == len(domains)
            assert result_first[2] > 0  # subdomain count
            assert result_first[3] == 1

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


def test_process_list_updates_total_and_duplicates(monkeypatch, tmp_path):
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
    original_list_stats = adblock.STATISTICS["list_stats"]
    original_domain_sources = adblock.STATISTICS["domain_sources"].copy()
    adblock.STATISTICS["duplicates"] = 0
    adblock.STATISTICS["list_stats"] = defaultdict(adblock.create_default_list_stats_entry)
    adblock.STATISTICS["domain_sources"] = {}

    async def run_test():
        try:
            total, unique, subdomains, duplicates = await adblock.process_list(
                url, cache_manager, FakeSession("data")
            )
            adblock.ensure_list_stats_entry(
                url,
                total=total,
                unique=unique,
                subdomains=subdomains,
                duplicates=duplicates,
            )
            stats_entry = adblock.STATISTICS["list_stats"][url]
            assert stats_entry["total"] == len(domains)
            assert stats_entry["unique"] == unique
            assert stats_entry["subdomains"] == subdomains
            assert stats_entry["duplicates"] == duplicates == 1
        finally:
            config_module.CONFIG.clear()
            config_module.CONFIG.update(original_config)
            adblock.CONFIG.clear()
            adblock.CONFIG.update(original_adblock_config)
            adblock.STATISTICS["duplicates"] = original_duplicates
            adblock.STATISTICS["list_stats"] = original_list_stats
            adblock.STATISTICS["domain_sources"] = original_domain_sources

    asyncio.run(run_test())


def test_process_list_retries_on_client_error(monkeypatch):
    original_failed_lists = adblock.STATISTICS.get("failed_lists", 0)
    original_error_message = adblock.STATISTICS.get("error_message", "")

    class FailingResponse:
        async def __aenter__(self):
            raise aiohttp.ClientError("Boom")

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FailingSession:
        def __init__(self):
            self.call_count = 0

        def get(self, url, timeout):
            self.call_count += 1
            return FailingResponse()

    async def immediate_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(backoff._async.asyncio, "sleep", immediate_sleep)
    monkeypatch.setitem(
        adblock.CONFIG,
        "http_timeout",
        adblock.CONFIG.get("http_timeout", 1),
    )

    session = FailingSession()
    cache_manager = DummyCacheManager()

    async def run_test():
        with pytest.raises(aiohttp.ClientError):
            await adblock.process_list("https://example.com/list.txt", cache_manager, session)

    asyncio.run(run_test())

    assert session.call_count == 3
    assert adblock.STATISTICS["failed_lists"] == original_failed_lists
    assert adblock.STATISTICS["error_message"] == original_error_message


def test_restart_dnsmasq_service_failure_triggers_email(monkeypatch):
    email_calls: list[tuple[str, str, dict]] = []

    def fake_send_email(subject: str, message: str, cfg: dict) -> None:
        email_calls.append((subject, message, cfg))

    monkeypatch.setattr(adblock, "send_email", fake_send_email)

    def fake_which(command: str) -> str | None:
        if command == "systemctl":
            return None
        if command == "service":
            return "/usr/sbin/service"
        return None

    monkeypatch.setattr(adblock.shutil, "which", fake_which)

    def fake_run(cmd, check):
        if cmd[0] == "service":
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd)
        pytest.fail(f"Unerwarteter Befehl aufgerufen: {cmd}")

    monkeypatch.setattr(adblock.subprocess, "run", fake_run)
    monkeypatch.setattr(adblock.config, "global_mode", adblock.SystemMode.NORMAL, raising=False)

    config_values = {"send_email": True}

    result = adblock.restart_dnsmasq(config_values)

    assert result is False
    assert email_calls, "Es wurde keine E-Mail-Benachrichtigung ausgelöst"
    subject, message, cfg = email_calls[-1]
    assert "DNSMasq-Neustart fehlgeschlagen" in message
    assert cfg is config_values
