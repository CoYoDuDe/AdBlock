from __future__ import annotations

import logging
import time
from copy import deepcopy

from caching import HybridStorage
from config import DEFAULT_CONFIG
from filter_engine import evaluate_lists
from writer import export_prometheus_metrics, export_statistics_csv


def test_statistics_exports_and_metrics(tmp_path):
    statistics = {
        "total_domains": 10,
        "unique_domains": 8,
        "reachable_domains": 6,
        "unreachable_domains": 4,
        "duplicates": 2,
        "cache_hits": 0,
        "cache_flushes": 0,
        "trie_cache_hits": 0,
        "failed_lists": 0,
        "list_stats": {
            "https://ads.example.com/hosts.txt": {
                "total": 10,
                "unique": 8,
                "reachable": 6,
                "unreachable": 2,
                "duplicates": 2,
                "subdomains": 1,
                "score": 0.0,
                "category": "unknown",
            }
        },
    }

    config = deepcopy(DEFAULT_CONFIG)
    evaluate_lists(statistics, config)

    assert statistics["list_stats"], "Es sollten Listeneinträge vorhanden sein."

    csv_dir = tmp_path / "exports"
    csv_dir.mkdir()
    logger = logging.getLogger("adblock-test-logger")

    export_statistics_csv(str(csv_dir), statistics, logger)
    csv_content = (csv_dir / "statistics.csv").read_text(encoding="utf-8")
    assert "https://ads.example.com/hosts.txt" in csv_content
    assert ",6,2,2," in csv_content

    storage = HybridStorage(str(tmp_path / "domain_cache"))
    storage.use_ram = False
    try:
        storage["disk-only.example"] = {"checked_at": "now"}
        storage["another-disk.example"] = {"checked_at": "now"}
        cache_size = storage.total_items()
    finally:
        storage.close()

    assert cache_size == 2

    start_time = time.time() - 5
    export_prometheus_metrics(str(csv_dir), statistics, start_time, cache_size, logger)
    metrics_content = (csv_dir / "metrics.prom").read_text(encoding="utf-8")

    assert "adblock_list_total" in metrics_content
    assert "adblock_list_unique" in metrics_content
    assert "adblock_list_reachable" in metrics_content
