import asyncio
from datetime import datetime
from pathlib import Path
import sys
from unittest.mock import MagicMock
import subprocess
from types import SimpleNamespace
import time
from threading import Lock

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


def test_domain_batch_limits_concurrency():
    class CountingResolver:
        def __init__(self):
            self.current_calls = 0
            self.max_parallel_calls = 0

        async def query(self, domain, record):
            self.current_calls += 1
            try:
                self.max_parallel_calls = max(
                    self.max_parallel_calls, self.current_calls
                )
                await asyncio.sleep(0)
                return [domain, record]
            finally:
                self.current_calls -= 1

    class DummyCacheManager:
        def get_dns_cache(self, domain):
            return None

        def load_domain_cache(self):
            return {}

        def save_dns_cache(self, domain, reachable):
            pass

        def save_domain(self, domain, reachable, url):
            pass

    resolver = CountingResolver()
    cache_manager = DummyCacheManager()
    domains = [f"example{i}.com" for i in range(6)]
    max_concurrent = 3

    results = asyncio.run(
        networking.test_domain_batch(
            domains,
            "https://example.com",
            resolver,
            cache_manager,
            set(),
            set(),
            dns_cache=None,
            cache_lock=None,
            max_concurrent=max_concurrent,
            config={"max_retries": 1, "retry_delay": 0},
        )
    )

    assert len(results) == len(domains)
    assert resolver.max_parallel_calls <= max_concurrent
    assert resolver.max_parallel_calls > 1


def test_test_dns_entry_async_respects_config(monkeypatch):
    class FailingResolver:
        def __init__(self):
            self.calls = 0

        async def query(self, domain, record):
            self.calls += 1
            raise networking.aiodns.error.DNSError("fail")

    sleep_calls = []

    async def fake_sleep(delay):
        sleep_calls.append(delay)

    monkeypatch.setattr(networking.asyncio, "sleep", fake_sleep)
    resolver = FailingResolver()
    config = {"max_retries": 2, "retry_delay": 0.01}

    async def run_test():
        semaphore = asyncio.Semaphore(1)
        return await networking.test_dns_entry_async(
            "example.com",
            resolver,
            record_type="TXT",
            semaphore=semaphore,
            config=config,
        )

    result = asyncio.run(run_test())

    assert result is False
    assert resolver.calls == config["max_retries"]
    assert sleep_calls == [config["retry_delay"]] * config["max_retries"]


def test_test_single_domain_async_respects_domain_cache_validity():
    class CacheManager:
        def get_dns_cache(self, domain):
            return None

        def load_domain_cache(self):
            return {
                "example.com": {
                    "checked_at": datetime.now().isoformat(),
                    "reachable": True,
                }
            }

        def save_dns_cache(self, domain, reachable):
            pass

        def save_domain(self, domain, reachable, url):
            pass

    class Resolver:
        def __init__(self):
            self.calls = 0

        async def query(self, domain, record):
            self.calls += 1
            return [domain, record]

    cache_manager = CacheManager()
    resolver = Resolver()
    config = {"domain_cache_validity_days": 0, "max_retries": 1, "retry_delay": 0}

    async def run_test():
        return await networking.test_single_domain_async(
            "example.com",
            "https://example.com",
            resolver,
            cache_manager,
            set(),
            set(),
            dns_cache=None,
            cache_lock=None,
            max_concurrent=1,
            semaphore=None,
            config=config,
        )

    result = asyncio.run(run_test())

    assert result is True
    assert resolver.calls == 1


def test_test_single_domain_async_respects_dns_cache_ttl():
    class CacheManager:
        def get_dns_cache(self, domain):
            return None

        def load_domain_cache(self):
            return {}

        def save_dns_cache(self, domain, reachable):
            pass

        def save_domain(self, domain, reachable, url):
            pass

    class Resolver:
        def __init__(self):
            self.calls = 0

        async def query(self, domain, record):
            self.calls += 1
            return [domain, record]

    dns_cache = {
        "example.com": {"reachable": True, "timestamp": time.time() - 2}
    }
    cache_lock = Lock()
    cache_manager = CacheManager()
    resolver = Resolver()
    config = {"dns_cache_ttl": 1, "max_retries": 1, "retry_delay": 0}

    async def run_test():
        return await networking.test_single_domain_async(
            "example.com",
            "https://example.com",
            resolver,
            cache_manager,
            set(),
            set(),
            dns_cache=dns_cache,
            cache_lock=cache_lock,
            max_concurrent=1,
            semaphore=None,
            config=config,
        )

    result = asyncio.run(run_test())

    assert result is True
    assert resolver.calls == 1
