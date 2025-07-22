"""Helper routines for safely writing output files and statistics."""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from typing import Dict
from urllib.parse import quote


def safe_save(
    filepath: str, content, logger: logging.Logger, is_json: bool = False
) -> None:
    """Safely save content to a file."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            if is_json:
                json.dump(content, f, indent=4, ensure_ascii=False)
            else:
                f.write(content)
        logger.info("Datei gespeichert: %s", filepath)
    except Exception as exc:
        logger.error("Fehler beim Speichern von %s: %s", filepath, exc)


def append_to_file(filepath: str, content: str, logger: logging.Logger) -> None:
    """Append a line to a file."""
    try:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(content + "\n")
    except Exception as exc:
        logger.error("Fehler beim Anhängen an %s: %s", filepath, exc)


def export_statistics_csv(
    tmp_dir: str, statistics: Dict, logger: logging.Logger
) -> None:
    """Export statistics to a CSV file."""
    csv_path = os.path.join(tmp_dir, "statistics.csv")
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "URL",
                    "Category",
                    "Total",
                    "Unique",
                    "Reachable",
                    "Unreachable",
                    "Duplicates",
                    "Subdomains",
                    "Score",
                ]
            )
            for url, stats in statistics["list_stats"].items():
                writer.writerow(
                    [
                        url,
                        stats["category"],
                        stats["total"],
                        stats["unique"],
                        stats["reachable"],
                        stats["unreachable"],
                        stats["duplicates"],
                        stats["subdomains"],
                        stats["score"],
                    ]
                )
        logger.info("Statistiken als CSV gespeichert: %s", csv_path)
    except Exception as exc:
        logger.error("Fehler beim Exportieren der CSV: %s", exc)


def export_prometheus_metrics(
    tmp_dir: str,
    statistics: Dict,
    start_time: float,
    cache_size: int,
    logger: logging.Logger,
) -> None:
    """Write prometheus metrics file."""
    metrics_path = os.path.join(tmp_dir, "metrics.prom")
    try:
        with open(metrics_path, "w", encoding="utf-8") as f:
            f.write("# AdBlock Skript Metriken\n")
            f.write(f'adblock_total_domains {statistics["total_domains"]}\n')
            f.write(f'adblock_unique_domains {statistics["unique_domains"]}\n')
            f.write(f'adblock_reachable_domains {statistics["reachable_domains"]}\n')
            f.write(
                f'adblock_unreachable_domains {statistics["unreachable_domains"]}\n'
            )
            f.write(f'adblock_duplicates {statistics["duplicates"]}\n')
            f.write(f'adblock_cache_hits {statistics["cache_hits"]}\n')
            f.write(f'adblock_cache_flushes {statistics["cache_flushes"]}\n')
            f.write(f'adblock_trie_cache_hits {statistics["trie_cache_hits"]}\n')
            f.write(f"adblock_cache_size {cache_size}\n")
            f.write(f'adblock_failed_lists {statistics["failed_lists"]}\n')
            f.write(f"adblock_runtime_seconds {time.time() - start_time}\n")
            for url, stats in statistics["list_stats"].items():
                safe_url = quote(url, safe="")
                f.write(f'adblock_list_total{{url="{safe_url}"}} {stats["total"]}\n')
                f.write(f'adblock_list_unique{{url="{safe_url}"}} {stats["unique"]}\n')
                f.write(
                    f'adblock_list_reachable{{url="{safe_url}"}} {stats["reachable"]}\n'
                )
                f.write(
                    f'adblock_list_unreachable{{url="{safe_url}"}} {stats["unreachable"]}\n'
                )
                f.write(
                    f'adblock_list_duplicates{{url="{safe_url}"}} {stats["duplicates"]}\n'
                )
                f.write(
                    f'adblock_list_subdomains{{url="{safe_url}"}} {stats["subdomains"]}\n'
                )
                f.write(f'adblock_list_score{{url="{safe_url}"}} {stats["score"]}\n')
        logger.info("Prometheus-Metriken gespeichert: %s", metrics_path)
    except Exception as exc:
        logger.error("Fehler beim Exportieren der Prometheus-Metriken: %s", exc)
