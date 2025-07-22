"""Unit tests for categorize_list function."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is on the module search path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from filter_engine import categorize_list  # noqa: E402


def test_categorize_malware():
    assert categorize_list("https://example.com/malware-list.txt") == "malware"


def test_categorize_ads():
    assert categorize_list("https://ads.example.com/list") == "ads"


def test_categorize_porn():
    assert categorize_list("https://example.com/porn_sites.txt") == "adult"
