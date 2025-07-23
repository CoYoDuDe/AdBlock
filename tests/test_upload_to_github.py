from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import networking  # noqa: E402


def test_upload_to_github_runs_git_commands(monkeypatch):
    calls = []

    def fake_run(cmd, check=True):
        calls.append(list(cmd))

        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(networking.subprocess, "run", fake_run)

    cfg = {
        "github_repo": "git@github.com:test/repo.git",
        "github_branch": "main",
        "git_user": "Tester",
        "git_email": "tester@example.com",
        "hosts_file": "hosts.txt",
        "dns_config_file": "dnsmasq.conf",
    }

    networking.upload_to_github(cfg)

    assert ["git", "config", "user.name", "Tester"] in calls
    assert ["git", "config", "user.email", "tester@example.com"] in calls
    assert any(call[:2] == ["git", "add"] for call in calls)
    assert any(call[:2] == ["git", "commit"] for call in calls)
    assert ["git", "push", cfg["github_repo"], f"HEAD:{cfg['github_branch']}"] in calls
