from __future__ import annotations

import logging
import sys
from pathlib import Path
import subprocess

sys.path.append(str(Path(__file__).resolve().parent.parent))

from adblock import restart_dnsmasq  # noqa: E402
import adblock  # noqa: E402


def test_restart_fallback_to_service(monkeypatch):
    calls: list[list[str]] = []

    monkeypatch.setattr(adblock.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")

    def fake_run(cmd, check=True):
        calls.append(cmd)
        if cmd[0] == "systemctl":
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd)
        return None

    monkeypatch.setattr(adblock.subprocess, "run", fake_run)
    monkeypatch.setattr(adblock, "send_email", lambda *a, **k: None)

    assert restart_dnsmasq(adblock.CONFIG)
    assert calls == [
        ["systemctl", "restart", "dnsmasq"],
        ["service", "dnsmasq", "restart"],
    ]


def test_restart_no_command_logs_warning(monkeypatch, caplog):
    monkeypatch.setattr(adblock.shutil, "which", lambda cmd: None)
    monkeypatch.setattr(adblock, "send_email", lambda *a, **k: None)
    caplog.set_level(logging.WARNING)
    assert not restart_dnsmasq(adblock.CONFIG)
    assert any(
        "Weder systemctl noch service" in record.message for record in caplog.records
    )
