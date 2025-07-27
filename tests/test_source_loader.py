from pathlib import Path
import sys
import logging

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import source_loader  # noqa: E402
from config import DEFAULT_HOST_SOURCES  # noqa: E402


def test_load_hosts_sources(tmp_path):
    cfg = {"prioritize_lists": True, "priority_lists": ["https://prio.com"]}
    file_path = tmp_path / "hosts_sources.conf"
    file_path.write_text("https://normal.com\n#comment\nhttps://prio.com\n")
    sources = source_loader.load_hosts_sources(
        cfg, str(tmp_path), logging.getLogger("test")
    )
    assert sources[0] == "https://prio.com"
    assert set(sources) == {"https://normal.com", "https://prio.com"}


def test_load_hosts_sources_creates_default(tmp_path):
    cfg = {"prioritize_lists": False, "priority_lists": []}
    sources = source_loader.load_hosts_sources(
        cfg, str(tmp_path), logging.getLogger("test")
    )
    assert (tmp_path / "hosts_sources.conf").exists()
    assert set(sources) == set(DEFAULT_HOST_SOURCES)


def test_load_whitelist_blacklist(tmp_path):
    (tmp_path / "whitelist.txt").write_text("example.com\n#ignore\ninvalid_domain\n")
    (tmp_path / "blacklist.txt").write_text("blocked.com\n")
    wl, bl = source_loader.load_whitelist_blacklist(
        str(tmp_path), logging.getLogger("test")
    )
    assert wl == {"example.com"}
    assert bl == {"blocked.com"}
