from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import adblock  # noqa: E402


def test_parse_args(tmp_path):
    cfg = tmp_path / "config.json"
    args = adblock.parse_args(["--config", str(cfg), "--debug"])
    assert args.config == str(cfg)
    assert args.debug


def test_cli_main_calls_main(monkeypatch, tmp_path):
    cfg = tmp_path / "config.json"

    called: dict[str, object] = {}

    async def fake_main(config_path=None, debug=False):  # type: ignore[override]
        called["config_path"] = config_path
        called["debug"] = debug

    monkeypatch.setattr(adblock, "main", fake_main)
    adblock.cli_main(["--config", str(cfg), "--debug"])
    assert called["config_path"] == str(cfg)
    assert called["debug"] is True
