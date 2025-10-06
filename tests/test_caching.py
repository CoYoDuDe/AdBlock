import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import caching  # noqa: E402


def test_domain_trie_flush_preserves_parent_detection(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    config = caching.DEFAULT_CONFIG.copy()
    config["use_bloom_filter"] = False
    config["remove_redundant_subdomains"] = True
    monkeypatch.setattr(caching, "DEFAULT_CONFIG", config)

    trie = caching.DomainTrie("http://example.com")
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
        if config["remove_redundant_subdomains"] and trie.has_parent(domain):
            continue
        trie.insert(domain)
        processed_domains.append(domain)

    assert processed_domains == ["unique-example.net"]

    trie.flush()
    assert trie.has_parent("sub.unique-example.net")
    trie.close()


def test_cache_manager_dns_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))
    monkeypatch.setattr(caching, "MAX_DNS_CACHE_SIZE", 2)

    cm = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
    cm.save_dns_cache("a.com", True)
    cm.save_dns_cache("b.com", False)
    assert cm.get_dns_cache("a.com") is True
    assert cm.get_dns_cache("b.com") is False
    cm.save_dns_cache("c.com", True)
    assert "a.com" not in cm.dns_cache
    cm.save_domain("a.com", True, "url")
    cache = cm.load_domain_cache()
    assert "a.com" in cache


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


def test_cleanup_temp_files_keeps_valid_filtered_file(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    cache_manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
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
