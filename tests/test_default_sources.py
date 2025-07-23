from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import adblock  # noqa: E402
from source_loader import load_hosts_sources  # noqa: E402
from config import DEFAULT_HOST_SOURCES  # noqa: E402


class DummyHandler(logging.Handler):
    def emit(self, record):
        pass


LOGGER = logging.getLogger("test_default_sources")
LOGGER.addHandler(DummyHandler())


def test_initialize_directories_creates_default_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(adblock, "SCRIPT_DIR", str(tmp_path))
    monkeypatch.setattr(adblock, "TMP_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(adblock, "logger", LOGGER)

    hosts_file = tmp_path / "hosts_sources.conf"
    if hosts_file.exists():
        hosts_file.unlink()

    adblock.initialize_directories_and_files()

    assert hosts_file.exists()
    assert hosts_file.read_text().strip().splitlines() == DEFAULT_HOST_SOURCES


def test_load_hosts_sources_uses_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(adblock, "logger", LOGGER)
    adblock.CONFIG.clear()
    adblock.CONFIG.update(adblock.DEFAULT_CONFIG)
    hosts_file = tmp_path / "hosts_sources.conf"
    if hosts_file.exists():
        hosts_file.unlink()

    sources = load_hosts_sources(adblock.CONFIG, str(tmp_path), LOGGER)

    assert hosts_file.exists()
    assert sources == DEFAULT_HOST_SOURCES
