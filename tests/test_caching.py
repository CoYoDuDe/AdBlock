import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import caching  # noqa: E402
import config as config_module  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def reset_config():
    original = config_module.CONFIG.copy()
    config_module.CONFIG.clear()
    yield
    config_module.CONFIG.clear()
    config_module.CONFIG.update(original)


def test_domain_trie_flush_preserves_parent_detection(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    config_values = caching.DEFAULT_CONFIG.copy()
    config_values["use_bloom_filter"] = False
    config_values["remove_redundant_subdomains"] = True
    config_module.CONFIG.update(
        {
            "use_bloom_filter": False,
            "remove_redundant_subdomains": True,
        }
    )

    trie = caching.DomainTrie("http://example.com", config_module.CONFIG)
    first_batch = ["example.com"]
    for domain in first_batch:
        trie.insert(domain)

    assert trie.has_parent("sub.example.com")
    assert not trie.has_parent("example.com")

    trie.flush()
    assert trie.has_parent("sub.example.com")

    second_batch = ["sub.example.com", "unique-example.net"]
    processed_domains = []

    for domain in second_batch:
        if config_values["remove_redundant_subdomains"] and trie.has_parent(domain):
            continue
        trie.insert(domain)
        processed_domains.append(domain)

    assert processed_domains == ["unique-example.net"]

    trie.flush()
    assert trie.has_parent("sub.unique-example.net")
    trie.close()


def test_domain_trie_insert_returns_status_and_prevents_duplicates(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching.HybridStorage, "should_use_ram", lambda self: True)

    config_module.CONFIG.update(
        {
            "use_bloom_filter": True,
            "bloom_filter_capacity": 10,
            "bloom_filter_error_rate": 0.001,
        }
    )

    trie = caching.DomainTrie("http://example.com", config_module.CONFIG)
    try:
        assert trie.insert("example.com") is True
        root_after_first = trie.storage[trie.root_key]
        stored_keys_after_first = set(root_after_first.children.values())

        assert trie.insert("example.com") is False
        root_after_second = trie.storage[trie.root_key]
        assert set(root_after_second.children.values()) == stored_keys_after_first

        assert trie.insert("sub.example.com") is True
        assert trie.insert("sub.example.com") is False
    finally:
        trie.close()


def test_domain_trie_persists_parent_nodes_on_disk(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching.HybridStorage, "should_use_ram", lambda self: False)

    config_module.CONFIG.update({"use_bloom_filter": False})

    trie = caching.DomainTrie("http://example.com", config_module.CONFIG)
    assert trie.storage.use_ram is False

    trie.insert("example.com")
    trie.flush()
    trie.close()

    reloaded_trie = caching.DomainTrie("http://example.com", config_module.CONFIG)
    try:
        assert reloaded_trie.storage.use_ram is False
        assert reloaded_trie.has_parent("sub.example.com") is True
    finally:
        reloaded_trie.close()


def test_cache_manager_dns_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))
    monkeypatch.setattr(caching, "MAX_DNS_CACHE_SIZE", 2)

    cm = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
    cm.save_dns_cache("a.com", True)
    cm.save_dns_cache("b.com", False)
    cached_a = cm.get_dns_cache("a.com")
    cached_b = cm.get_dns_cache("b.com")
    assert cached_a is not None and cached_a["reachable"] is True
    assert cached_b is not None and cached_b["reachable"] is False
    assert cached_a["timestamp"] <= time.time()
    cm.save_dns_cache("c.com", True)
    assert "a.com" not in cm.dns_cache
    cm.save_domain("a.com", True, "url")
    cache = cm.load_domain_cache()
    assert "a.com" in cache


def test_cache_manager_dns_cache_expires_entries(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    cm = caching.CacheManager(
        str(tmp_path / "cache.db"), flush_interval=1, config={"dns_cache_ttl": 1}
    )
    cm.save_dns_cache("expired.com", True)
    cm.dns_cache["expired.com"]["timestamp"] -= 5

    assert cm.get_dns_cache("expired.com") is None
    assert "expired.com" not in cm.dns_cache


def test_cache_manager_persists_domain_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    monkeypatch.setattr(
        caching.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=0),
    )

    first_manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
    first_manager.save_domain("persistent.com", True, "https://source")
    first_manager.domain_cache.close()

    second_manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
    cached_entry = second_manager.domain_cache["persistent.com"]

    assert cached_entry["reachable"] is True
    assert cached_entry["source"] == "https://source"


def test_save_domain_cache_flushes_ram_storage_to_disk(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    available_memory = 512 * 1024 * 1024
    monkeypatch.setattr(
        caching.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=available_memory),
    )

    config_module.CONFIG.update(
        {"resource_thresholds": config_module.DEFAULT_CONFIG["resource_thresholds"]}
    )

    manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)

    assert manager.domain_cache.use_ram is True

    domains = {
        "ram-persist-1.com": (True, "https://source"),
        "ram-persist-2.net": (False, "https://source"),
    }

    for domain, (reachable, source_url) in domains.items():
        manager.save_domain(domain, reachable, source_url)

    manager.save_domain_cache()
    manager.domain_cache.close()

    second_manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)

    try:
        assert second_manager.domain_cache.use_ram is True
        for domain, (reachable, source_url) in domains.items():
            persisted_entry = second_manager.domain_cache.db[domain]
            assert persisted_entry["reachable"] is reachable
            assert persisted_entry["source"] == source_url
    finally:
        second_manager.domain_cache.close()


def test_cleanup_temp_files_keeps_valid_filtered_file(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    config_module.CONFIG.update({"domain_cache_validity_days": 30})

    cache_manager = caching.CacheManager(
        str(tmp_path / "cache.db"), flush_interval=1, config=config_module.CONFIG
    )
    url = "https://example.com/list.txt"
    cache_manager.upsert_list_cache(url, "dummy")
    sanitized = caching.sanitize_tmp_identifier(url)
    filtered_path = tmp_path / f"{sanitized}.filtered"
    filtered_path.write_text("example.com\n", encoding="utf-8")

    caching.cleanup_temp_files(cache_manager)

    assert filtered_path.exists()


def test_list_cache_upsert_thread_safe(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    cache_manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
    urls = [f"https://example.com/list{i}.txt" for i in range(5)]
    md5_values = [f"md5-{i}" for i in range(5)]

    def worker(target_url: str, md5_value: str) -> None:
        cache_manager.upsert_list_cache(target_url, md5_value)

    with ThreadPoolExecutor(max_workers=5) as executor:
        for target_url, md5_value in zip(urls, md5_values):
            executor.submit(worker, target_url, md5_value)

    cache_entries = cache_manager.load_list_cache()
    assert set(cache_entries.keys()) == set(urls)
    for target_url, md5_value in zip(urls, md5_values):
        assert cache_entries[target_url]["md5"] == md5_value
        assert "total_domains" in cache_entries[target_url]
        assert "unique_domains" in cache_entries[target_url]
        assert "subdomains" in cache_entries[target_url]
        assert "duplicates" in cache_entries[target_url]


def test_upsert_list_cache_persists_statistics(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    cache_manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
    url = "https://example.com/list.txt"
    cache_manager.upsert_list_cache(
        url,
        "hash",
        total_domains=42,
        unique_domains=30,
        subdomains=5,
        duplicates=7,
    )

    entry = cache_manager.get_list_cache_entry(url)
    assert entry is not None
    assert entry["total_domains"] == 42
    assert entry["unique_domains"] == 30
    assert entry["subdomains"] == 5
    assert entry["duplicates"] == 7


def test_hybrid_storage_reset_removes_all_shelve_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr(caching.psutil, "virtual_memory", lambda: SimpleNamespace(available=0))
    db_path = tmp_path / "hybrid_cache"
    storage = caching.HybridStorage(str(db_path))

    try:
        if storage.db is not None:
            storage.db.close()
    finally:
        storage.db = None

    sentinel = b"corrupt"
    suffixes = ("", ".db", ".dat", ".bak", ".dir")
    for suffix in suffixes:
        artifact = Path(f"{db_path}{suffix}")
        artifact.write_bytes(sentinel)

    storage.reset_if_corrupt()
    storage.use_ram = False
    storage["reinitialized"] = True

    assert storage.db is not None
    assert storage["reinitialized"] is True

    for suffix in suffixes:
        artifact = Path(f"{db_path}{suffix}")
        if artifact.exists():
            assert artifact.read_bytes() != sentinel
        else:
            assert not artifact.exists()

    if storage.db is not None:
        storage.db.close()


def test_hybrid_storage_total_items_counts_unique_entries(tmp_path):
    storage = caching.HybridStorage(str(tmp_path / "hybrid_cache_total"))

    try:
        storage.use_ram = False
        storage["disk-only.example"] = {"value": 1}
        storage["second.example"] = {"value": 2}

        storage.use_ram = True
        storage["disk-only.example"] = {"value": 3}
        storage["ram-only.example"] = {"value": 4}

        assert storage.total_items() == 3
    finally:
        storage.close()


def test_hybrid_storage_switch_to_disk_keeps_entries(monkeypatch, tmp_path):
    available_memory = 512 * 1024 * 1024
    monkeypatch.setattr(
        caching.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=available_memory),
    )

    storage = caching.HybridStorage(str(tmp_path / "hybrid_cache"))

    try:
        assert storage.use_ram is True

        entries = {
            "domain-a.com": {"reachable": True, "source": "https://example/a"},
            "domain-b.net": {"reachable": False, "source": "https://example/b"},
        }

        for key, value in entries.items():
            storage[key] = value

        storage.use_ram = False

        for key, value in entries.items():
            assert storage[key] == value

        assert storage.ram_storage == {}
    finally:
        storage.close()


def test_hybrid_storage_ram_mode_loads_persisted_entries(monkeypatch, tmp_path):
    monkeypatch.setattr(caching.HybridStorage, "should_use_ram", lambda self: True)

    db_path = tmp_path / "hybrid_cache_ram"

    first_storage = caching.HybridStorage(str(db_path))
    try:
        assert first_storage.use_ram is True
        first_storage["persisted-a.com"] = {"reachable": True}
        first_storage["persisted-b.net"] = {"reachable": False}
        first_storage.persist_ram_to_disk()
    finally:
        first_storage.close()

    second_storage = caching.HybridStorage(str(db_path))
    try:
        assert second_storage.use_ram is True
        assert second_storage.ram_storage == {}

        assert "persisted-a.com" in second_storage
        value = second_storage["persisted-b.net"]

        assert value["reachable"] is False
        assert set(second_storage.ram_storage) == {
            "persisted-a.com",
            "persisted-b.net",
        }
    finally:
        second_storage.close()
