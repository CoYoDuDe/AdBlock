from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from adblock import CacheManager  # noqa: E402
import adblock  # noqa: E402


def test_adjust_cache_size(monkeypatch, tmp_path):
    temp_dir = tmp_path / "tmp"
    temp_dir.mkdir()
    db_path = tmp_path / "cache.db"
    monkeypatch.setattr(adblock, "TMP_DIR", str(temp_dir))

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

    cm.adjust_cache_size()

    assert cm.current_cache_size == 3
    assert len(cm.domain_cache.ram_storage) == 3
    assert set(cm.domain_cache.ram_storage.keys()) == {"domain2.com", "domain3.com", "domain4.com"}

    cm.domain_cache.close()
