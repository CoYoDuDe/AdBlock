from pathlib import Path
import sys

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
