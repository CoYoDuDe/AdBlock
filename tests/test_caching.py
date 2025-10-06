import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import caching  # noqa: E402


def test_domain_trie_insert_and_parent(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    config = caching.DEFAULT_CONFIG.copy()
    config["use_bloom_filter"] = False
    monkeypatch.setattr(caching, "DEFAULT_CONFIG", config)

    trie = caching.DomainTrie("http://example.com")
    trie.insert("example.com")
    assert trie.has_parent("sub.example.com")
    assert not trie.has_parent("example.com")
    trie.flush()
    assert not trie.has_parent("sub.example.com")
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


def test_cleanup_temp_files_keeps_valid_filtered_file(monkeypatch, tmp_path):
    monkeypatch.setattr(caching, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(caching, "TRIE_CACHE_PATH", str(tmp_path / "trie.pkl"))
    monkeypatch.setattr(caching, "DB_PATH", str(tmp_path / "cache.db"))

    cache_manager = caching.CacheManager(str(tmp_path / "cache.db"), flush_interval=1)
    url = "https://example.com/list.txt"
    cache_manager.save_list_cache(
        {url: {"md5": "dummy", "last_checked": datetime.now().isoformat()}}
    )
    sanitized = caching.sanitize_tmp_identifier(url)
    filtered_path = tmp_path / f"{sanitized}.filtered"
    filtered_path.write_text("example.com\n", encoding="utf-8")

    caching.cleanup_temp_files(cache_manager)

    assert filtered_path.exists()
