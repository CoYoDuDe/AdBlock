import asyncio
import copy
import io
import logging
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import aiofiles
import aiohttp
import backoff
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import adblock  # noqa: E402
import caching  # noqa: E402
import config as config_module  # noqa: E402
import monitoring  # noqa: E402


def test_log_once_writes_single_record_and_console_entry(monkeypatch):
    records: list[str] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = adblock.logger
    original_handlers = list(logger.handlers)
    original_level = logger.level
    original_propagate = logger.propagate

    capture_handler = CaptureHandler(level=logging.DEBUG)

    fake_stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(logging.Formatter("%(message)s"))

    logger.handlers = [capture_handler, stream_handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False

    monkeypatch.setattr(adblock, "logged_messages", set())
    monkeypatch.setattr(adblock, "console_logged_messages", set())
    monkeypatch.setattr(config_module, "logged_messages", adblock.logged_messages)
    monkeypatch.setattr(
        config_module,
        "console_logged_messages",
        adblock.console_logged_messages,
    )

    try:
        adblock.log_once(logging.WARNING, "unique message", console=True)
        adblock.log_once(logging.WARNING, "unique message", console=True)

        assert records == ["unique message"]

        stream_handler.flush()
        console_lines = fake_stdout.getvalue().strip().splitlines()
        occurrences = sum(1 for line in console_lines if "unique message" in line)
        assert occurrences == 1
    finally:
        logger.handlers = original_handlers
        logger.setLevel(original_level)
        logger.propagate = original_propagate


def test_log_once_ignores_suppressed_level_until_logger_allows(monkeypatch):
    records: list[str] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = adblock.logger
    original_handlers = list(logger.handlers)
    original_level = logger.level
    original_propagate = logger.propagate

    capture_handler = CaptureHandler(level=logging.DEBUG)

    logger.handlers = [capture_handler]
    logger.setLevel(logging.WARNING)
    logger.propagate = False

    monkeypatch.setattr(adblock, "logged_messages", set())
    monkeypatch.setattr(adblock, "console_logged_messages", set())
    monkeypatch.setattr(config_module, "logged_messages", adblock.logged_messages)
    monkeypatch.setattr(
        config_module,
        "console_logged_messages",
        adblock.console_logged_messages,
    )

    try:
        adblock.log_once(logging.INFO, "leveled message", console=False)

        assert records == []
        assert not adblock.logged_messages
        assert not adblock.console_logged_messages

        logger.setLevel(logging.INFO)
        adblock.log_once(logging.INFO, "leveled message", console=False)

        assert records == ["leveled message"]
        assert adblock.logged_messages == {"leveled message"}
        assert not adblock.console_logged_messages
    finally:
        logger.handlers = original_handlers
        logger.setLevel(original_level)
        logger.propagate = original_propagate


def test_log_once_respects_filters_and_parent_handlers(monkeypatch):
    child_records: list[str] = []
    parent_records: list[str] = []

    class ChildHandler(logging.Handler):
        def emit(self, record):
            child_records.append(record.getMessage())

    class ParentHandler(logging.Handler):
        def emit(self, record):
            parent_records.append(record.getMessage())

    class BlockFilter(logging.Filter):
        def filter(self, record):
            return "blocked" not in record.getMessage()

    logger = adblock.logger
    parent_logger = logging.getLogger("adblock.test_parent")

    original_handlers = list(logger.handlers)
    original_filters = list(logger.filters)
    original_level = logger.level
    original_propagate = logger.propagate
    original_parent = logger.parent

    original_parent_handlers = list(parent_logger.handlers)
    original_parent_filters = list(parent_logger.filters)
    original_parent_level = parent_logger.level
    original_parent_propagate = parent_logger.propagate

    child_handler = ChildHandler(level=logging.INFO)
    parent_handler = ParentHandler(level=logging.INFO)

    parent_logger.handlers = [parent_handler]
    parent_logger.filters = []
    parent_logger.setLevel(logging.INFO)
    parent_logger.propagate = False

    logger.handlers = [child_handler]
    logger.filters = []
    logger.addFilter(BlockFilter())
    logger.setLevel(logging.INFO)
    logger.propagate = True
    logger.parent = parent_logger

    monkeypatch.setattr(adblock, "logged_messages", set())
    monkeypatch.setattr(adblock, "console_logged_messages", set())
    monkeypatch.setattr(config_module, "logged_messages", adblock.logged_messages)
    monkeypatch.setattr(
        config_module,
        "console_logged_messages",
        adblock.console_logged_messages,
    )

    try:
        adblock.log_once(logging.INFO, "blocked message")

        assert child_records == []
        assert parent_records == []
        assert not adblock.logged_messages
        assert not adblock.console_logged_messages

        adblock.log_once(logging.INFO, "allowed message")

        assert child_records == ["allowed message"]
        assert parent_records == ["allowed message"]
        assert adblock.logged_messages == {"allowed message"}
        assert not adblock.console_logged_messages
    finally:
        logger.handlers = original_handlers
        logger.filters = original_filters
        logger.setLevel(original_level)
        logger.propagate = original_propagate
        logger.parent = original_parent

        parent_logger.handlers = original_parent_handlers
        parent_logger.filters = original_parent_filters
        parent_logger.setLevel(original_parent_level)
        parent_logger.propagate = original_parent_propagate


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


class EmergencyTestCacheManager:
    def __init__(self, config):
        self.config = config

    def get_list_cache_entry(self, url):
        return None

    def upsert_list_cache(self, *args, **kwargs):
        return None


class MonitoringTestCacheManager:
    def __init__(self):
        self.adjust_calls = 0
        self.threshold_updates = 0
        self.domain_cache = SimpleNamespace(update_threshold=self._update_threshold)

    def adjust_cache_size(self):
        self.adjust_calls += 1

    def _update_threshold(self):
        self.threshold_updates += 1


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


def test_monitor_resources_triggers_emergency_on_cpu(monkeypatch, caplog):
    cache_manager = MonitoringTestCacheManager()
    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values["resource_thresholds"] = (
        config_values["resource_thresholds"].copy()
    )
    config_values["resource_thresholds"].update(
        moving_average_window=3,
        consecutive_violations=2,
        high_cpu_percent=85,
        high_latency_s=5.0,
        low_memory_mb=128,
        emergency_memory_mb=64,
    )
    config_values["send_email"] = True

    email_calls: list[tuple[str, str, dict]] = []

    def fake_send_email(subject: str, body: str, cfg: dict) -> None:
        email_calls.append((subject, body, cfg))

    monkeypatch.setattr(monitoring, "send_email", fake_send_email)
    monkeypatch.setattr(
        config_module, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )

    cpu_values = [90.0, 92.0, 93.0]
    memory_values = [512, 512, 512]
    latency_values = [0.2, 0.2, 0.2]
    counters = {"cpu": 0, "mem": 0, "lat": 0}

    def fake_cpu_percent(interval=None):
        index = min(counters["cpu"], len(cpu_values) - 1)
        counters["cpu"] += 1
        return cpu_values[index]

    def fake_virtual_memory():
        index = min(counters["mem"], len(memory_values) - 1)
        counters["mem"] += 1
        return SimpleNamespace(available=memory_values[index] * 1024 * 1024)

    async def fake_latency(_config):
        index = min(counters["lat"], len(latency_values) - 1)
        counters["lat"] += 1
        return latency_values[index]

    sleep_state = {"count": 0}

    async def fake_sleep(_seconds):
        sleep_state["count"] += 1
        if sleep_state["count"] >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fake_cpu_percent)
    monkeypatch.setattr(monitoring.psutil, "virtual_memory", fake_virtual_memory)
    monkeypatch.setattr(monitoring, "check_network_latency", fake_latency)
    monkeypatch.setattr(monitoring.asyncio, "sleep", fake_sleep)

    caplog.set_level(logging.WARNING, logger=monitoring.logger.name)
    asyncio.run(monitoring.monitor_resources(cache_manager, config_values))

    assert cache_manager.adjust_calls >= 1
    assert cache_manager.threshold_updates >= 1
    assert config_module.global_mode == adblock.SystemMode.EMERGENCY
    assert email_calls and email_calls[0][0] == "AdBlock Ressourcenwarnung: EMERGENCY"
    assert any("CPU-Auslastung" in message for message in caplog.messages)


def test_monitor_resources_detects_dns_failure_with_high_latency_threshold(
    monkeypatch, caplog
):
    """DNS-Ausfälle mit unendlicher Latenz erzwingen nun auch bei >5s Schwelle den Notmodus."""

    cache_manager = MonitoringTestCacheManager()
    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values["resource_thresholds"] = (
        config_values["resource_thresholds"].copy()
    )
    config_values["resource_thresholds"].update(
        moving_average_window=3,
        consecutive_violations=2,
        high_cpu_percent=95,
        high_latency_s=12.0,
        low_memory_mb=128,
        emergency_memory_mb=64,
    )
    config_values["send_email"] = False

    monkeypatch.setattr(
        config_module, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )

    cpu_values = [5.0, 6.0, 5.5]
    memory_values = [512, 512, 512]
    counters = {"cpu": 0, "mem": 0, "lat": 0}

    def fake_cpu_percent(interval=None):
        index = min(counters["cpu"], len(cpu_values) - 1)
        counters["cpu"] += 1
        return cpu_values[index]

    def fake_virtual_memory():
        index = min(counters["mem"], len(memory_values) - 1)
        counters["mem"] += 1
        return SimpleNamespace(available=memory_values[index] * 1024 * 1024)

    async def fake_latency(_config):
        counters["lat"] += 1
        return float("inf")

    sleep_state = {"count": 0}

    async def fake_sleep(_seconds):
        sleep_state["count"] += 1
        if sleep_state["count"] >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fake_cpu_percent)
    monkeypatch.setattr(monitoring.psutil, "virtual_memory", fake_virtual_memory)
    monkeypatch.setattr(monitoring, "check_network_latency", fake_latency)
    monkeypatch.setattr(monitoring.asyncio, "sleep", fake_sleep)

    caplog.set_level(logging.ERROR, logger=monitoring.logger.name)
    asyncio.run(monitoring.monitor_resources(cache_manager, config_values))

    assert counters["lat"] >= 2
    assert config_module.global_mode == adblock.SystemMode.EMERGENCY
    assert any("DNS-Latenz" in message for message in caplog.messages)


def test_monitor_resources_handles_primary_dns_failure(monkeypatch, caplog):
    cache_manager = MonitoringTestCacheManager()
    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values["resource_thresholds"] = (
        config_values["resource_thresholds"].copy()
    )
    config_values["resource_thresholds"].update(
        moving_average_window=3,
        consecutive_violations=2,
        high_cpu_percent=95,
        high_latency_s=5.0,
        low_memory_mb=128,
        emergency_memory_mb=64,
    )
    config_values["dns_servers"] = [
        "198.51.100.10",
        "198.51.100.11",
    ]
    config_values["send_email"] = True

    failing_server = config_values["dns_servers"][0]
    fallback_server = config_values["dns_servers"][1]

    attempts: dict[str, int] = {}
    select_calls: list[tuple[tuple[str, ...], float]] = []
    email_calls: list[tuple[str, str, dict]] = []

    async def fake_select_best_dns_server(servers, timeout=5.0):
        select_calls.append((tuple(servers), timeout))
        return list(servers)

    class FakeResolver:
        def __init__(self, nameservers, timeout):
            self.server = nameservers[0]
            self.timeout = timeout

        async def query(self, domain, record):
            attempts[self.server] = attempts.get(self.server, 0) + 1
            if self.server == failing_server:
                raise RuntimeError("resolver down")
            return [{"host": "93.184.216.34"}]

    def fake_virtual_memory():
        return SimpleNamespace(available=1_024 * 1_024 * 1_024)

    def fake_cpu_percent(interval=None):
        return 12.0

    async def fake_sleep(_seconds):
        fake_sleep.counter += 1
        if fake_sleep.counter >= 3:
            raise asyncio.CancelledError

    fake_sleep.counter = 0

    def fake_send_email(subject: str, body: str, cfg: dict) -> None:
        email_calls.append((subject, body, cfg))

    monkeypatch.setattr(
        monitoring, "select_best_dns_server", fake_select_best_dns_server
    )
    monkeypatch.setattr(monitoring.aiodns, "DNSResolver", FakeResolver)
    monkeypatch.setattr(monitoring.psutil, "virtual_memory", fake_virtual_memory)
    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fake_cpu_percent)
    monkeypatch.setattr(monitoring.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(monitoring, "send_email", fake_send_email)
    monkeypatch.setattr(
        config_module, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )

    caplog.set_level(logging.INFO, logger=monitoring.logger.name)
    asyncio.run(monitoring.monitor_resources(cache_manager, config_values))

    assert attempts.get(failing_server, 0) >= 1
    assert attempts.get(fallback_server, 0) >= 1
    assert select_calls
    assert not email_calls
    assert config_module.global_mode == adblock.SystemMode.NORMAL
    assert fake_sleep.counter >= 3
    assert not any("DNS-Latenz" in message for message in caplog.messages)


def test_monitor_resources_enters_low_memory_mode(monkeypatch, caplog):
    cache_manager = MonitoringTestCacheManager()
    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values["resource_thresholds"] = (
        config_values["resource_thresholds"].copy()
    )
    config_values["resource_thresholds"].update(
        moving_average_window=3,
        consecutive_violations=2,
        high_cpu_percent=95,
        high_latency_s=5.0,
        low_memory_mb=150,
        emergency_memory_mb=70,
    )
    config_values["send_email"] = True

    email_calls: list[tuple[str, str, dict]] = []

    def fake_send_email(subject: str, body: str, cfg: dict) -> None:
        email_calls.append((subject, body, cfg))

    monkeypatch.setattr(monitoring, "send_email", fake_send_email)
    monkeypatch.setattr(
        config_module, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )

    cpu_values = [10.0, 12.0, 11.0]
    memory_values = [145, 130, 125]
    latency_values = [0.1, 0.1, 0.1]
    counters = {"cpu": 0, "mem": 0, "lat": 0}

    def fake_cpu_percent(interval=None):
        index = min(counters["cpu"], len(cpu_values) - 1)
        counters["cpu"] += 1
        return cpu_values[index]

    def fake_virtual_memory():
        index = min(counters["mem"], len(memory_values) - 1)
        counters["mem"] += 1
        return SimpleNamespace(available=memory_values[index] * 1024 * 1024)

    async def fake_latency(_config):
        index = min(counters["lat"], len(latency_values) - 1)
        counters["lat"] += 1
        return latency_values[index]

    sleep_state = {"count": 0}

    async def fake_sleep(_seconds):
        sleep_state["count"] += 1
        if sleep_state["count"] >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fake_cpu_percent)
    monkeypatch.setattr(monitoring.psutil, "virtual_memory", fake_virtual_memory)
    monkeypatch.setattr(monitoring, "check_network_latency", fake_latency)
    monkeypatch.setattr(monitoring.asyncio, "sleep", fake_sleep)

    caplog.set_level(logging.WARNING, logger=monitoring.logger.name)
    asyncio.run(monitoring.monitor_resources(cache_manager, config_values))

    assert config_module.global_mode == adblock.SystemMode.LOW_MEMORY
    assert email_calls and email_calls[0][0] == "AdBlock Ressourcenwarnung: LOW_MEMORY"
    assert any("low_memory" in message for message in caplog.messages)


def test_monitor_resources_recovers_to_normal(monkeypatch, caplog):
    cache_manager = MonitoringTestCacheManager()
    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values["resource_thresholds"] = (
        config_values["resource_thresholds"].copy()
    )
    config_values["resource_thresholds"].update(
        moving_average_window=3,
        consecutive_violations=2,
        high_cpu_percent=85,
        high_latency_s=5.0,
        low_memory_mb=128,
        emergency_memory_mb=64,
    )
    config_values["send_email"] = True

    email_calls: list[tuple[str, str, dict]] = []

    def fake_send_email(subject: str, body: str, cfg: dict) -> None:
        email_calls.append((subject, body, cfg))

    monkeypatch.setattr(monitoring, "send_email", fake_send_email)
    monkeypatch.setattr(
        config_module, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )

    cpu_values = [95.0, 96.0, 25.0, 20.0, 15.0]
    memory_values = [512, 512, 512, 512, 512]
    latency_values = [0.2, 0.2, 0.2, 0.2, 0.2]
    counters = {"cpu": 0, "mem": 0, "lat": 0}

    def fake_cpu_percent(interval=None):
        index = min(counters["cpu"], len(cpu_values) - 1)
        counters["cpu"] += 1
        return cpu_values[index]

    def fake_virtual_memory():
        index = min(counters["mem"], len(memory_values) - 1)
        counters["mem"] += 1
        return SimpleNamespace(available=memory_values[index] * 1024 * 1024)

    async def fake_latency(_config):
        index = min(counters["lat"], len(latency_values) - 1)
        counters["lat"] += 1
        return latency_values[index]

    sleep_state = {"count": 0}

    async def fake_sleep(_seconds):
        sleep_state["count"] += 1
        if sleep_state["count"] >= 5:
            raise asyncio.CancelledError

    monkeypatch.setattr(monitoring.psutil, "cpu_percent", fake_cpu_percent)
    monkeypatch.setattr(monitoring.psutil, "virtual_memory", fake_virtual_memory)
    monkeypatch.setattr(monitoring, "check_network_latency", fake_latency)
    monkeypatch.setattr(monitoring.asyncio, "sleep", fake_sleep)

    caplog.set_level(logging.INFO, logger=monitoring.logger.name)
    asyncio.run(monitoring.monitor_resources(cache_manager, config_values))

    assert config_module.global_mode == adblock.SystemMode.NORMAL
    assert email_calls and len(email_calls) == 1
    assert email_calls[0][0] == "AdBlock Ressourcenwarnung: EMERGENCY"
    assert any("systemmodus gewechselt zu emergency" in message.lower() for message in caplog.messages)
    assert any("systemmodus gewechselt zu normal" in message.lower() for message in caplog.messages)


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


def test_process_list_enters_emergency_mode_and_flushes(monkeypatch, tmp_path):
    monkeypatch.setattr(adblock, "TMP_DIR", str(tmp_path), raising=False)
    os.makedirs(adblock.TMP_DIR, exist_ok=True)

    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values["use_bloom_filter"] = False
    config_values["remove_redundant_subdomains"] = False
    config_values["resource_thresholds"] = config_values["resource_thresholds"].copy()

    test_config = config_values.copy()
    monkeypatch.setattr(config_module, "CONFIG", test_config.copy(), raising=False)
    monkeypatch.setattr(adblock, "CONFIG", test_config.copy(), raising=False)
    monkeypatch.setattr(
        adblock.config, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )
    monkeypatch.setattr(
        config_module, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )

    memory_values_mb = [80, 40, 120, 120, 120]
    call_index = {"value": 0}

    def fake_virtual_memory():
        value_mb = memory_values_mb[min(call_index["value"], len(memory_values_mb) - 1)]
        call_index["value"] += 1
        return SimpleNamespace(available=value_mb * 1024 * 1024)

    monkeypatch.setattr(
        adblock.psutil, "virtual_memory", fake_virtual_memory, raising=False
    )
    monkeypatch.setattr(
        adblock.psutil,
        "Process",
        lambda: SimpleNamespace(
            memory_info=lambda: SimpleNamespace(rss=25 * 1024 * 1024)
        ),
        raising=False,
    )

    monkeypatch.setattr(
        adblock, "get_system_resources", lambda: (1, 50, 1), raising=False
    )

    sleep_calls: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    monkeypatch.setattr(adblock.asyncio, "sleep", fake_sleep, raising=False)

    gc_calls: list[None] = []

    def fake_collect() -> int:
        gc_calls.append(None)
        return 0

    monkeypatch.setattr(adblock.gc, "collect", fake_collect, raising=False)

    class RecordingTrie:
        def __init__(self, url: str, cfg: dict):
            self.url = url
            self.config = cfg
            self.storage = SimpleNamespace(update_threshold=lambda: None)
            self.flush_count = 0
            self.inserted: list[str] = []

        def has_parent(self, domain: str) -> bool:
            return False

        def insert(self, domain: str) -> bool:
            self.inserted.append(domain)
            return True

        def flush(self) -> None:
            self.flush_count += 1

        def close(self) -> None:
            return None

    created_tries: list[RecordingTrie] = []

    def fake_trie(url: str, cfg: dict) -> RecordingTrie:
        trie = RecordingTrie(url, cfg)
        created_tries.append(trie)
        return trie

    monkeypatch.setattr(adblock, "DomainTrie", fake_trie, raising=False)

    domains = ["emergency.example", "next.example"]

    def fake_parse_domains(content: str, url: str):
        yield from domains

    monkeypatch.setattr(adblock, "parse_domains", fake_parse_domains, raising=False)

    cache_manager = EmergencyTestCacheManager(test_config)

    session = FakeSession("dummy-content")
    url = "https://example.com/emergency.txt"
    results: dict[str, tuple[int, int, int, int]] = {}

    async def run_test() -> None:
        results["stats"] = await adblock.process_list(url, cache_manager, session)

    asyncio.run(run_test())

    result = results["stats"]
    assert result[0] == len(domains)
    assert created_tries, "DomainTrie sollte instanziiert werden"
    trie = created_tries[0]
    assert trie.flush_count >= 2
    assert trie.inserted == domains
    assert adblock.config.global_mode == adblock.SystemMode.EMERGENCY
    assert sleep_calls == []
    assert len(gc_calls) >= 2

    sanitized = adblock.sanitize_url_for_tmp(url)
    filtered_path = Path(adblock.TMP_DIR) / f"{sanitized}.filtered"
    assert filtered_path.exists()
    filtered_lines = [
        line.strip()
        for line in filtered_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert filtered_lines == domains


def test_process_list_recreates_filtered_file_when_missing(
    monkeypatch, tmp_path, caplog
):
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
    filtered_path = (
        Path(adblock.TMP_DIR) / f"{adblock.sanitize_url_for_tmp(url)}.filtered"
    )
    original_duplicates = adblock.STATISTICS.get("duplicates", 0)
    original_cache_hits = adblock.STATISTICS.get("cache_hits", 0)
    original_domain_sources = adblock.STATISTICS["domain_sources"].copy()
    adblock.STATISTICS["duplicates"] = 0
    adblock.STATISTICS["cache_hits"] = 0
    adblock.STATISTICS["domain_sources"] = {}

    async def run_test():
        try:
            await adblock.process_list(url, cache_manager, FakeSession("data"))

            assert filtered_path.exists()
            filtered_path.unlink()
            assert not filtered_path.exists()

            caplog.clear()
            with caplog.at_level(logging.DEBUG, logger=adblock.logger.name):
                result_second = await adblock.process_list(
                    url, cache_manager, FakeSession("data")
                )

            assert filtered_path.exists()
            assert result_second[0] == len(domains)
            assert (
                result_second[1] + result_second[2] + result_second[3]
                == result_second[0]
            )
            assert any(
                "gefilterte Datei" in message for message in caplog.messages
            ), "Fallback-Logeintrag fehlt"
            assert adblock.STATISTICS["cache_hits"] == 0
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
    adblock.STATISTICS["list_stats"] = defaultdict(
        adblock.create_default_list_stats_entry
    )
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


def test_process_list_emergency_flushes_batch(monkeypatch, tmp_path):
    monkeypatch.setattr(adblock, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie_cache.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    os.makedirs(adblock.TMP_DIR, exist_ok=True)

    config_values = copy.deepcopy(config_module.DEFAULT_CONFIG)
    config_values["use_bloom_filter"] = False
    config_values["remove_redundant_subdomains"] = False
    config_values["resource_thresholds"]["emergency_memory_mb"] = 500

    original_config = config_module.CONFIG.copy()
    original_adblock_config = adblock.CONFIG.copy()
    original_mode = getattr(adblock.config, "global_mode", adblock.SystemMode.NORMAL)
    config_module.CONFIG.clear()
    config_module.CONFIG.update(config_values)
    adblock.CONFIG.clear()
    adblock.CONFIG.update(config_values)
    monkeypatch.setattr(adblock.config, "global_mode", adblock.SystemMode.NORMAL)

    domains = ["example.com", "second.com"]

    def fake_parse_domains(content: str, url: str):
        for domain in domains:
            yield domain

    monkeypatch.setattr(adblock, "parse_domains", fake_parse_domains)

    class DummyCacheManager:
        def __init__(self, config):
            self.config = config

        def get_list_cache_entry(self, _url):
            return None

        def upsert_list_cache(self, *args, **kwargs):
            return None

    cache_manager = DummyCacheManager(config_values)

    flush_events: list[int] = []

    class DummyTrie:
        def __init__(self, url, trie_config):
            self.url = url
            self.config = trie_config
            self._domains: set[str] = set()
            self.storage = SimpleNamespace(update_threshold=lambda: None)

        def insert(self, domain: str) -> bool:
            if domain in self._domains:
                return False
            self._domains.add(domain)
            return True

        def has_parent(self, domain: str) -> bool:
            return False

        def flush(self) -> None:
            flush_events.append(len(self._domains))

        def close(self) -> None:
            return None

    monkeypatch.setattr(adblock, "DomainTrie", DummyTrie)

    memory_values = [
        600 * 1024 * 1024,  # initial free memory
        100 * 1024 * 1024,  # second iteration triggers emergency
        700 * 1024 * 1024,  # after emergency flush
        700 * 1024 * 1024,  # final flush
    ]

    def fake_virtual_memory():
        value = memory_values[0] if len(memory_values) == 1 else memory_values.pop(0)
        return SimpleNamespace(available=value)

    monkeypatch.setattr(adblock.psutil, "virtual_memory", fake_virtual_memory)

    monkeypatch.setattr(adblock, "get_system_resources", lambda: (10, 50, 10))

    sleep_calls: list[float] = []

    async def fake_sleep(duration: float):
        sleep_calls.append(duration)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    url = "https://example.com/list.txt"

    mode_after_run: list[adblock.SystemMode] = []

    async def run_test():
        try:
            await adblock.process_list(url, cache_manager, FakeSession("data"))
        finally:
            mode_after_run.append(adblock.config.global_mode)
            config_module.CONFIG.clear()
            config_module.CONFIG.update(original_config)
            adblock.CONFIG.clear()
            adblock.CONFIG.update(original_adblock_config)
            adblock.config.global_mode = original_mode

    asyncio.run(run_test())

    assert flush_events, "Der Trie wurde nie geflusht"
    assert flush_events[0] == 1, "Der erste Flush sollte den Notfall-Batch enthalten"
    assert len(flush_events) >= 2, "Der finale Flush sollte zusätzlich stattfinden"
    assert (
        sleep_calls == []
    ), "Es darf kein künstlicher Schlaf im Notfallpfad stattfinden"
    assert mode_after_run and mode_after_run[0] == adblock.SystemMode.EMERGENCY


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
            await adblock.process_list(
                "https://example.com/list.txt", cache_manager, session
            )

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
    monkeypatch.setattr(
        adblock.config, "global_mode", adblock.SystemMode.NORMAL, raising=False
    )

    config_values = {"send_email": True}

    result = adblock.restart_dnsmasq(config_values)

    assert result is False
    assert email_calls, "Es wurde keine E-Mail-Benachrichtigung ausgelöst"
    subject, message, cfg = email_calls[-1]
    assert "DNSMasq-Neustart fehlgeschlagen" in message
    assert cfg is config_values


def test_whitelist_domains_are_skipped_from_unreachable(monkeypatch, tmp_path):
    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir()

    original_statistics_ref = adblock.STATISTICS
    original_statistics = copy.deepcopy(adblock.STATISTICS)
    adblock.STATISTICS = copy.deepcopy(original_statistics)

    original_config = config_module.CONFIG.copy()
    original_adblock_config = adblock.CONFIG.copy()
    original_global_mode = config_module.global_mode
    original_cache_manager = config_module.cache_manager

    whitelist_domain = "whitelisted.test"
    blocked_domain = "blocked.test"

    monkeypatch.setattr(adblock, "SCRIPT_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(adblock, "TMP_DIR", str(tmp_dir), raising=False)
    monkeypatch.setattr(
        adblock, "REACHABLE_FILE", str(tmp_dir / "reachable.txt"), raising=False
    )
    monkeypatch.setattr(
        adblock, "UNREACHABLE_FILE", str(tmp_dir / "unreachable.txt"), raising=False
    )

    monkeypatch.setattr(config_module, "SCRIPT_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(config_module, "TMP_DIR", str(tmp_dir), raising=False)
    monkeypatch.setattr(
        config_module,
        "REACHABLE_FILE",
        adblock.REACHABLE_FILE,
        raising=False,
    )
    monkeypatch.setattr(
        config_module,
        "UNREACHABLE_FILE",
        adblock.UNREACHABLE_FILE,
        raising=False,
    )

    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values.update(
        {
            "github_upload": False,
            "send_email": False,
            "use_ipv4_output": False,
            "use_ipv6_output": False,
            "save_unreachable": True,
            "export_prometheus": False,
            "prioritize_lists": False,
            "priority_lists": [],
            "cache_flush_interval": 1,
        }
    )

    def fake_load_config(_config_path=None):
        config_module.CONFIG.clear()
        config_module.CONFIG.update(config_values)
        adblock.CONFIG.clear()
        adblock.CONFIG.update(config_values)

    monkeypatch.setattr(adblock, "load_config", fake_load_config)
    monkeypatch.setattr(adblock.config, "global_mode", adblock.SystemMode.NORMAL)
    monkeypatch.setattr(config_module, "global_mode", adblock.SystemMode.NORMAL)

    class DummyDomainCache:
        def __init__(self):
            self.use_ram = True

        def update_threshold(self):
            return None

        def total_items(self):
            return 0

    class DummyCacheManager:
        def __init__(self, *args, **kwargs):
            self.config = config_values
            self.domain_cache = DummyDomainCache()
            self.current_cache_size = 4
            self.flush_count = 0

        async def flush_cache_periodically(self):
            try:
                while True:
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                raise

        def adjust_cache_size(self):
            return None

        def save_domain_cache(self):
            return False

    async def fake_monitor_resources(*_args, **_kwargs):
        try:
            while True:
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            raise

    async def fake_process_list(url, cache_manager, session):
        filtered_path = tmp_dir / f"{adblock.sanitize_url_for_tmp(url)}.filtered"
        async with aiofiles.open(filtered_path, "w", encoding="utf-8") as handle:
            await handle.write(f"{whitelist_domain}\n{blocked_domain}\n")
        return 2, 2, 0, 0

    async def fake_test_domain_batch(domains, *_args, **_kwargs):
        results = [(domain, False) for domain in domains]
        results.append((whitelist_domain, False))
        return results

    class DummySession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class DummyResolver:
        pass

    monkeypatch.setattr(adblock, "CacheManager", DummyCacheManager)
    monkeypatch.setattr(adblock, "cleanup_temp_files", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(adblock, "monitor_resources", fake_monitor_resources)
    monkeypatch.setattr(adblock, "initialize_directories_and_files", lambda: None)
    monkeypatch.setattr(adblock, "process_list", fake_process_list)
    monkeypatch.setattr(adblock, "test_domain_batch", fake_test_domain_batch)
    monkeypatch.setattr(
        adblock, "load_hosts_sources", lambda *_: ["https://example.com/list.txt"]
    )
    monkeypatch.setattr(
        adblock,
        "load_whitelist_blacklist",
        lambda *_args: ({whitelist_domain}, set()),
    )

    async def fake_select_best_dns_server(*_args, **_kwargs):
        return ["8.8.8.8"]

    async def fake_is_ipv6_supported(*_args, **_kwargs):
        return False

    monkeypatch.setattr(adblock, "select_best_dns_server", fake_select_best_dns_server)
    monkeypatch.setattr(adblock, "is_ipv6_supported", fake_is_ipv6_supported)
    monkeypatch.setattr(adblock.aiohttp, "ClientSession", DummySession)
    monkeypatch.setattr(
        adblock.aiodns, "DNSResolver", lambda *args, **kwargs: DummyResolver()
    )
    monkeypatch.setattr(adblock, "send_email", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "upload_to_github", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "safe_save", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "export_statistics_csv", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        adblock, "export_prometheus_metrics", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(adblock, "evaluate_lists", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "restart_dnsmasq", lambda *args, **kwargs: True)
    monkeypatch.setattr(adblock, "get_system_resources", lambda: (1, 2, 1))
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

    original_dns_cache = adblock.DNS_CACHE.copy()

    async def run_main():
        await adblock.main(config_path=str(tmp_path / "config.json"), debug=False)

    try:
        asyncio.run(run_main())
        unreachable_path = Path(adblock.UNREACHABLE_FILE)
        assert unreachable_path.exists()
        unreachable_lines = {
            line.strip()
            for line in unreachable_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        assert whitelist_domain not in unreachable_lines
        assert blocked_domain in unreachable_lines
        assert adblock.STATISTICS["unreachable_domains"] == 1
    finally:
        adblock.DNS_CACHE.clear()
        adblock.DNS_CACHE.update(original_dns_cache)
        adblock.STATISTICS = original_statistics_ref
        adblock.STATISTICS.clear()
        adblock.STATISTICS.update(original_statistics)
        config_module.CONFIG.clear()
        config_module.CONFIG.update(original_config)
        adblock.CONFIG.clear()
        adblock.CONFIG.update(original_adblock_config)
        config_module.cache_manager = original_cache_manager
        config_module.global_mode = original_global_mode
        adblock.config.cache_manager = original_cache_manager
        adblock.config.global_mode = original_global_mode


def test_blacklist_domains_are_exported_without_processed_sources(
    monkeypatch, tmp_path
):
    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir()

    reachable_path = tmp_dir / "reachable.txt"
    unreachable_path = tmp_dir / "unreachable.txt"
    blacklist_domain = "manuell-block.test"

    original_statistics_ref = adblock.STATISTICS
    original_statistics = copy.deepcopy(adblock.STATISTICS)
    adblock.STATISTICS = copy.deepcopy(original_statistics)

    original_config = config_module.CONFIG.copy()
    original_adblock_config = adblock.CONFIG.copy()
    original_global_mode = config_module.global_mode
    original_cache_manager = config_module.cache_manager

    (tmp_path / "blacklist.txt").write_text(f"{blacklist_domain}\n", encoding="utf-8")

    monkeypatch.setattr(adblock, "SCRIPT_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(adblock, "TMP_DIR", str(tmp_dir), raising=False)
    monkeypatch.setattr(adblock, "REACHABLE_FILE", str(reachable_path), raising=False)
    monkeypatch.setattr(
        adblock, "UNREACHABLE_FILE", str(unreachable_path), raising=False
    )

    monkeypatch.setattr(config_module, "SCRIPT_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(config_module, "TMP_DIR", str(tmp_dir), raising=False)
    monkeypatch.setattr(
        config_module,
        "REACHABLE_FILE",
        adblock.REACHABLE_FILE,
        raising=False,
    )
    monkeypatch.setattr(
        config_module,
        "UNREACHABLE_FILE",
        adblock.UNREACHABLE_FILE,
        raising=False,
    )

    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values.update(
        {
            "github_upload": False,
            "send_email": False,
            "use_ipv4_output": True,
            "use_ipv6_output": False,
            "save_unreachable": False,
            "export_prometheus": False,
            "prioritize_lists": False,
            "priority_lists": [],
            "cache_flush_interval": 1,
        }
    )

    def fake_load_config(_config_path=None):
        config_module.CONFIG.clear()
        config_module.CONFIG.update(config_values)
        adblock.CONFIG.clear()
        adblock.CONFIG.update(config_values)

    monkeypatch.setattr(adblock, "load_config", fake_load_config)
    monkeypatch.setattr(adblock.config, "global_mode", adblock.SystemMode.NORMAL)
    monkeypatch.setattr(config_module, "global_mode", adblock.SystemMode.NORMAL)

    class DummyDomainCache:
        def __init__(self):
            self.use_ram = True

        def update_threshold(self):
            return None

        def total_items(self):
            return 0

    class DummyCacheManager:
        def __init__(self, *args, **kwargs):
            self.config = config_values
            self.domain_cache = DummyDomainCache()
            self.current_cache_size = 4
            self.flush_count = 0

        async def flush_cache_periodically(self):
            try:
                while True:
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                raise

        def adjust_cache_size(self):
            return None

        def save_domain_cache(self):
            return False

    async def fake_monitor_resources(*_args, **_kwargs):
        try:
            while True:
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            raise

    async def fake_process_list(url, cache_manager, session):
        return 0, 0, 0, 0

    async def fake_test_domain_batch(*_args, **_kwargs):
        return []

    class DummySession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class DummyResolver:
        pass

    async def fake_select_best_dns_server(*_args, **_kwargs):
        return ["8.8.8.8"]

    async def fake_is_ipv6_supported(*_args, **_kwargs):
        return False

    monkeypatch.setattr(adblock, "CacheManager", DummyCacheManager)
    monkeypatch.setattr(adblock, "cleanup_temp_files", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(adblock, "monitor_resources", fake_monitor_resources)
    monkeypatch.setattr(adblock, "initialize_directories_and_files", lambda: None)
    monkeypatch.setattr(adblock, "process_list", fake_process_list)
    monkeypatch.setattr(adblock, "test_domain_batch", fake_test_domain_batch)
    monkeypatch.setattr(
        adblock, "load_hosts_sources", lambda *_: ["https://example.com/list.txt"]
    )
    monkeypatch.setattr(adblock, "select_best_dns_server", fake_select_best_dns_server)
    monkeypatch.setattr(adblock, "is_ipv6_supported", fake_is_ipv6_supported)
    monkeypatch.setattr(adblock.aiohttp, "ClientSession", DummySession)
    monkeypatch.setattr(
        adblock.aiodns, "DNSResolver", lambda *args, **kwargs: DummyResolver()
    )
    monkeypatch.setattr(adblock, "send_email", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "upload_to_github", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "safe_save", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "export_statistics_csv", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        adblock, "export_prometheus_metrics", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(adblock, "evaluate_lists", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "restart_dnsmasq", lambda *args, **kwargs: True)
    monkeypatch.setattr(adblock, "get_system_resources", lambda: (1, 5, 1))
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

    original_dns_cache = adblock.DNS_CACHE.copy()

    async def run_main():
        await adblock.main(config_path=str(tmp_path / "config.json"), debug=False)

    try:
        asyncio.run(run_main())
        hosts_path = Path(adblock.SCRIPT_DIR) / config_values["hosts_file"]
        assert hosts_path.exists(), "hosts.txt wurde nicht erstellt"
        hosts_lines = hosts_path.read_text(encoding="utf-8").splitlines()
        assert any(
            line.strip() == f"{config_values['hosts_ip']} {blacklist_domain}"
            for line in hosts_lines
        ), "Blacklist-Domain fehlt in hosts.txt"
        assert adblock.STATISTICS["reachable_domains"] == 1
        assert adblock.STATISTICS["unique_domains"] == 1
        blacklist_stats = adblock.STATISTICS["list_stats"]["blacklist.txt"]
        assert blacklist_stats["reachable"] == 1
        assert blacklist_stats["unique"] == 1
    finally:
        adblock.DNS_CACHE.clear()
        adblock.DNS_CACHE.update(original_dns_cache)
        adblock.STATISTICS = original_statistics_ref
        adblock.STATISTICS.clear()
        adblock.STATISTICS.update(original_statistics)
        config_module.CONFIG.clear()
        config_module.CONFIG.update(original_config)
        adblock.CONFIG.clear()
        adblock.CONFIG.update(original_adblock_config)
        config_module.cache_manager = original_cache_manager
        config_module.global_mode = original_global_mode
        adblock.config.cache_manager = original_cache_manager
        adblock.config.global_mode = original_global_mode


def test_unique_domain_statistics_match_reachable_for_whitelist_only_lists(
    monkeypatch, tmp_path
):
    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir()

    reachable_path = tmp_dir / "reachable.txt"
    unreachable_path = tmp_dir / "unreachable.txt"

    original_statistics_ref = adblock.STATISTICS
    original_statistics = copy.deepcopy(adblock.STATISTICS)
    adblock.STATISTICS = copy.deepcopy(original_statistics)

    original_config = config_module.CONFIG.copy()
    original_adblock_config = adblock.CONFIG.copy()
    original_global_mode = config_module.global_mode
    original_cache_manager = config_module.cache_manager

    whitelist_domain = "allowed.only"
    sources = [
        "https://example.com/list-a.txt",
        "https://example.com/list-b.txt",
    ]

    monkeypatch.setattr(adblock, "SCRIPT_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(adblock, "TMP_DIR", str(tmp_dir), raising=False)
    monkeypatch.setattr(adblock, "REACHABLE_FILE", str(reachable_path), raising=False)
    monkeypatch.setattr(
        adblock, "UNREACHABLE_FILE", str(unreachable_path), raising=False
    )

    monkeypatch.setattr(config_module, "SCRIPT_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(config_module, "TMP_DIR", str(tmp_dir), raising=False)
    monkeypatch.setattr(
        config_module,
        "REACHABLE_FILE",
        adblock.REACHABLE_FILE,
        raising=False,
    )
    monkeypatch.setattr(
        config_module,
        "UNREACHABLE_FILE",
        adblock.UNREACHABLE_FILE,
        raising=False,
    )

    config_values = config_module.DEFAULT_CONFIG.copy()
    config_values.update(
        {
            "github_upload": False,
            "send_email": False,
            "use_ipv4_output": False,
            "use_ipv6_output": False,
            "save_unreachable": False,
            "export_prometheus": False,
            "prioritize_lists": False,
            "priority_lists": [],
            "cache_flush_interval": 1,
            "dns_servers": ["8.8.8.8"],
        }
    )

    def fake_load_config(_config_path=None):
        config_module.CONFIG.clear()
        config_module.CONFIG.update(config_values)
        adblock.CONFIG.clear()
        adblock.CONFIG.update(config_values)

    monkeypatch.setattr(adblock, "load_config", fake_load_config)
    monkeypatch.setattr(adblock.config, "global_mode", adblock.SystemMode.NORMAL)
    monkeypatch.setattr(config_module, "global_mode", adblock.SystemMode.NORMAL)

    class DummyDomainCache:
        def __init__(self):
            self.use_ram = True

        def update_threshold(self):
            return None

        def total_items(self):
            return 0

    class DummyCacheManager:
        def __init__(self, *args, **kwargs):
            self.config = config_values
            self.domain_cache = DummyDomainCache()
            self.current_cache_size = 4
            self.flush_count = 0

        async def flush_cache_periodically(self):
            try:
                while True:
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                raise

        def adjust_cache_size(self):
            return None

        def save_domain_cache(self):
            return False

    async def fake_monitor_resources(*_args, **_kwargs):
        try:
            while True:
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            raise

    async def fake_process_list(url, cache_manager, session):
        filtered_path = tmp_dir / f"{adblock.sanitize_url_for_tmp(url)}.filtered"
        async with aiofiles.open(filtered_path, "w", encoding="utf-8") as handle:
            await handle.write(f"{whitelist_domain}\n")
        return 1, 1, 0, 0

    async def fake_test_domain_batch(*_args, **_kwargs):
        return []

    class DummySession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class DummyResolver:
        pass

    monkeypatch.setattr(adblock, "CacheManager", DummyCacheManager)
    monkeypatch.setattr(adblock, "cleanup_temp_files", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(adblock, "monitor_resources", fake_monitor_resources)
    monkeypatch.setattr(adblock, "initialize_directories_and_files", lambda: None)
    monkeypatch.setattr(adblock, "process_list", fake_process_list)
    monkeypatch.setattr(adblock, "test_domain_batch", fake_test_domain_batch)
    monkeypatch.setattr(adblock, "load_hosts_sources", lambda *_: sources)
    monkeypatch.setattr(
        adblock,
        "load_whitelist_blacklist",
        lambda *_args: ({whitelist_domain}, set()),
    )

    async def fake_select_best_dns_server(*_args, **_kwargs):
        return ["8.8.8.8"]

    async def fake_is_ipv6_supported(*_args, **_kwargs):
        return False

    monkeypatch.setattr(adblock, "select_best_dns_server", fake_select_best_dns_server)
    monkeypatch.setattr(adblock, "is_ipv6_supported", fake_is_ipv6_supported)
    monkeypatch.setattr(adblock.aiohttp, "ClientSession", DummySession)
    monkeypatch.setattr(
        adblock.aiodns, "DNSResolver", lambda *args, **kwargs: DummyResolver()
    )
    monkeypatch.setattr(adblock, "send_email", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "upload_to_github", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "safe_save", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "export_statistics_csv", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        adblock, "export_prometheus_metrics", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(adblock, "evaluate_lists", lambda *args, **kwargs: None)
    monkeypatch.setattr(adblock, "restart_dnsmasq", lambda *args, **kwargs: True)
    monkeypatch.setattr(adblock, "get_system_resources", lambda: (2, 10, 1))
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

    original_dns_cache = adblock.DNS_CACHE.copy()

    async def run_main():
        await adblock.main(config_path=str(tmp_path / "config.json"), debug=False)

    try:
        asyncio.run(run_main())
        reachable_lines = []
        if reachable_path.exists():
            reachable_lines = [
                line
                for line in reachable_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        assert not reachable_lines
        assert adblock.STATISTICS["unique_domains"] == len(reachable_lines) == 0
    finally:
        adblock.DNS_CACHE.clear()
        adblock.DNS_CACHE.update(original_dns_cache)
        adblock.STATISTICS = original_statistics_ref
        adblock.STATISTICS.clear()
        adblock.STATISTICS.update(original_statistics)
        config_module.CONFIG.clear()
        config_module.CONFIG.update(original_config)
        adblock.CONFIG.clear()
        adblock.CONFIG.update(original_adblock_config)
        config_module.cache_manager = original_cache_manager
        config_module.global_mode = original_global_mode
        adblock.config.cache_manager = original_cache_manager
        adblock.config.global_mode = original_global_mode
