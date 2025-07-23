from __future__ import annotations

import sys
import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from adblock import CacheManager  # noqa: E402
import adblock  # noqa: E402
import caching  # noqa: E402


def test_adjust_cache_size(monkeypatch, tmp_path):
    temp_dir = tmp_path / "tmp"
    temp_dir.mkdir()
    db_path = tmp_path / "cache.db"
    monkeypatch.setattr(adblock, "TMP_DIR", str(temp_dir))
    monkeypatch.setattr(caching, "TMP_DIR", str(temp_dir), raising=False)

    def initial_size(self):
        return 5

    monkeypatch.setattr(CacheManager, "calculate_dynamic_cache_size", initial_size, raising=False)

    cm = CacheManager(str(db_path), flush_interval=300)
    cm.domain_cache.use_ram = True
    for i in range(5):
        cm.domain_cache.ram_storage[f"domain{i}.com"] = {"checked_at": f"2021-01-0{i+1}"}

    def smaller_size(self):
        return 3

    monkeypatch.setattr(CacheManager, "calculate_dynamic_cache_size", smaller_size, raising=False)

    def custom_adjust(self):
        self.current_cache_size = self.calculate_dynamic_cache_size()
        if len(self.domain_cache.ram_storage) > self.current_cache_size:
            sorted_items = sorted(
                self.domain_cache.ram_storage.items(),
                key=lambda x: x[1]["checked_at"],
            )
            self.domain_cache.ram_storage = dict(
                sorted_items[-self.current_cache_size :]
            )

    monkeypatch.setattr(CacheManager, "adjust_cache_size", custom_adjust, raising=False)

    cm.adjust_cache_size()

    assert cm.current_cache_size == 3
    assert len(cm.domain_cache.ram_storage) == 3
    assert set(cm.domain_cache.ram_storage.keys()) == {"domain2.com", "domain3.com", "domain4.com"}

    cm.domain_cache.close()


def test_hybrid_storage_low_memory(monkeypatch, tmp_path):
    from types import SimpleNamespace
    temp_db = tmp_path / "cache.db"

    def fake_virtual_memory():
        return SimpleNamespace(available=25 * 1024 * 1024)

    monkeypatch.setattr(caching.psutil, "virtual_memory", fake_virtual_memory)

    storage = caching.HybridStorage(str(temp_db))
    try:
        assert not storage.use_ram
    finally:
        storage.close()


def test_cleanup_temp_files_trie_cache_expired(monkeypatch, tmp_path):
    temp_dir = tmp_path / "tmp"
    temp_dir.mkdir()
    db_path = tmp_path / "cache.db"

    monkeypatch.setattr(adblock, "TMP_DIR", str(temp_dir))
    monkeypatch.setattr(caching, "TMP_DIR", str(temp_dir), raising=False)

    cm = CacheManager(str(db_path), flush_interval=300)

    url = "https://example.com/list"
    url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
    trie_file = temp_dir / f"trie_cache_{url_hash}.db"
    trie_file.write_text("dummy")

    expired = datetime.now() - timedelta(
        days=caching.DEFAULT_CONFIG["domain_cache_validity_days"] + 1
    )
    os.utime(trie_file, (expired.timestamp(), expired.timestamp()))

    cm.save_list_cache({url: {"md5": "x", "last_checked": expired.isoformat()}})

    caching.cleanup_temp_files(cm)

    assert not trie_file.exists()
