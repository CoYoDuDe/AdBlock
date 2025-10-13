from __future__ import annotations

from adblock import calculate_unique_domains


def test_calculate_unique_domains_prefers_global_set_for_duplicates():
    url_counts = {
        "https://example.com/list1": {"unique": 2},
        "https://example.com/list2": {"unique": 2},
    }
    global_unique_domains = {"duplicate.example", "only-list1.example", "only-list2.example"}

    assert calculate_unique_domains(url_counts, global_unique_domains) == 3


def test_calculate_unique_domains_returns_zero_when_set_empty():
    url_counts = {
        "https://example.com/list1": {"unique": 5},
        "https://example.com/list2": {"unique": 3},
    }

    assert calculate_unique_domains(url_counts, set()) == 0
