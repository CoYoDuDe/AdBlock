from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from adblock import DomainTrie  # noqa: E402
import adblock  # noqa: E402


def test_insert_and_has_parent(tmp_path, monkeypatch):
    temp_dir = tmp_path / "tmp"
    temp_dir.mkdir()
    monkeypatch.setattr(adblock, "TMP_DIR", str(temp_dir))
    adblock.CONFIG.clear()
    adblock.CONFIG.update(adblock.DEFAULT_CONFIG)
    trie = DomainTrie("test_url")
    try:
        trie.insert("example.com")
        assert trie.has_parent("sub.example.com")
        assert not trie.has_parent("example.com")
    finally:
        trie.close()
