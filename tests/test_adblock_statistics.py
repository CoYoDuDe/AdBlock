import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import adblock  # noqa: E402


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
