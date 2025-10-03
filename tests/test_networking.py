from pathlib import Path
import sys
from unittest.mock import MagicMock
import subprocess
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import networking  # noqa: E402


def test_send_email_no_send(monkeypatch):
    mock_smtp = MagicMock()
    monkeypatch.setattr(networking, "smtplib", MagicMock(SMTP=mock_smtp))
    networking.send_email("sub", "body", {"send_email": False})
    assert not mock_smtp.called


def test_send_email_via_smtp(monkeypatch):
    mock_server = MagicMock()
    smtp_instance = MagicMock(
        __enter__=MagicMock(return_value=mock_server),
        __exit__=MagicMock(return_value=None),
    )
    smtp_cls = MagicMock(return_value=smtp_instance)
    monkeypatch.setattr(networking, "smtplib", MagicMock(SMTP=smtp_cls))
    config = {
        "send_email": True,
        "use_smtp": True,
        "email_sender": "a@b.com",
        "email_recipient": "c@d.com",
        "smtp_server": "srv",
        "smtp_port": 25,
        "smtp_user": "u",
        "smtp_password": "p",
    }
    networking.send_email("sub", "body", config)
    smtp_cls.assert_called_with("srv", 25)
    mock_server.starttls.assert_called()
    mock_server.login.assert_called_with("u", "p")
    mock_server.send_message.assert_called()


def _completed(args, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=args, returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_upload_to_github_runs_in_script_dir(monkeypatch):
    calls = []

    def fake_run(cmd, cwd=None, check=True, capture_output=False, text=False):
        calls.append((cmd, cwd))
        if cmd[1] == "check-ignore":
            path = cmd[-1]
            if path == "tmp":
                return _completed(cmd, returncode=0, stdout="tmp\n")
            return _completed(cmd, returncode=1)
        if cmd[1] == "config":
            return _completed(cmd)
        if cmd[1] == "add":
            return _completed(cmd)
        if cmd[1] == "status":
            return _completed(cmd, stdout=" M hosts.txt\n")
        if cmd[1] == "commit":
            return _completed(cmd)
        if cmd[1] == "push":
            return _completed(cmd)
        return _completed(cmd)

    fake_subprocess = SimpleNamespace(
        run=fake_run,
        CompletedProcess=subprocess.CompletedProcess,
        CalledProcessError=subprocess.CalledProcessError,
    )
    monkeypatch.setattr(networking, "subprocess", fake_subprocess)
    monkeypatch.setattr(networking.os.path, "isdir", lambda path: True)
    monkeypatch.setattr(
        networking.os.path,
        "exists",
        lambda path: path.endswith("hosts.txt") or path.endswith("dnsmasq.conf"),
    )

    config = {
        "github_repo": "git@github.com:example/repo.git",
        "github_branch": "main",
        "git_user": "user",
        "git_email": "mail@example.com",
        "hosts_file": "hosts.txt",
        "dns_config_file": "dnsmasq.conf",
    }

    networking.upload_to_github(config)

    assert all(cwd == networking.SCRIPT_DIR for _, cwd in calls if cwd is not None)
    push_calls = [cmd for cmd, _ in calls if cmd[1] == "push"]
    assert push_calls, "Push-Befehl wurde nicht ausgeführt"
    add_calls = [cmd for cmd, _ in calls if cmd[1] == "add"]
    assert add_calls, "Add-Befehl wurde nicht ausgeführt"
    for cmd in add_calls:
        assert "tmp" not in cmd, "Ignorierter tmp-Pfad wurde hinzugefügt"


def test_upload_to_github_skips_without_changes(monkeypatch):
    calls = []

    def fake_run(cmd, cwd=None, check=True, capture_output=False, text=False):
        calls.append(cmd)
        if cmd[1] == "check-ignore":
            return _completed(cmd, returncode=1)
        if cmd[1] == "status":
            return _completed(cmd, stdout="")
        return _completed(cmd)

    fake_subprocess = SimpleNamespace(
        run=fake_run,
        CompletedProcess=subprocess.CompletedProcess,
        CalledProcessError=subprocess.CalledProcessError,
    )
    monkeypatch.setattr(networking, "subprocess", fake_subprocess)
    monkeypatch.setattr(networking.os.path, "isdir", lambda path: True)
    monkeypatch.setattr(networking.os.path, "exists", lambda path: True)

    config = {
        "github_repo": "git@github.com:example/repo.git",
        "hosts_file": "hosts.txt",
        "dns_config_file": "dnsmasq.conf",
    }

    networking.upload_to_github(config)

    assert any(cmd[1] == "status" for cmd in calls)
    assert all(cmd[1] != "commit" for cmd in calls)
