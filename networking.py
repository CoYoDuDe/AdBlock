"""Netzwerkbezogene Hilfsfunktionen."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from datetime import datetime, timedelta
from typing import List, Tuple

import aiodns
from email.mime.text import MIMEText
import smtplib

from config import DEFAULT_CONFIG

logger = logging.getLogger(__name__)


def send_email(subject: str, body: str, config: dict) -> None:
    if not config.get("send_email", False):
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = config["email_sender"]
        msg["To"] = config["email_recipient"]
        if config.get("use_smtp", True):
            with smtplib.SMTP(config["smtp_server"], config["smtp_port"]) as server:
                server.starttls()
                server.login(config["smtp_user"], config["smtp_password"])
                server.send_message(msg)
            logger.info("E-Mail-Benachrichtigung gesendet")
        else:
            sendmail_cmd = ["/usr/sbin/sendmail", "-t", "-oi"]
            process = subprocess.Popen(sendmail_cmd, stdin=subprocess.PIPE)
            process.communicate(msg.as_string().encode("utf-8"))
            if process.returncode != 0:
                raise RuntimeError("sendmail failed")
    except Exception as exc:
        logger.error("Fehler beim Senden der E-Mail: %s", exc)


async def is_ipv6_supported(config: dict) -> bool:
    try:
        ipv6_servers = [s for s in config["dns_servers"] if ":" in s]
        if not ipv6_servers:
            return False
        resolver = aiodns.DNSResolver(nameservers=ipv6_servers, timeout=2)
        await resolver.query("example.com", "AAAA")
        return True
    except Exception:
        return False


async def select_best_dns_server(
    dns_servers: List[str], timeout: float = 5.0
) -> List[str]:
    async def test_server(server: str) -> Tuple[str, float]:
        try:
            resolver = aiodns.DNSResolver(nameservers=[server], timeout=timeout)
            start = asyncio.get_running_loop().time()
            await resolver.query("example.com", "A")
            latency = asyncio.get_running_loop().time() - start
            return server, latency
        except Exception:
            return server, float("inf")

    tasks = [test_server(server) for server in dns_servers]
    results = await asyncio.gather(*tasks)
    sorted_servers = [
        server
        for server, latency in sorted(results, key=lambda x: x[1])
        if latency != float("inf")
    ]
    return sorted_servers or dns_servers


async def test_dns_entry_async(
    domain: str, resolver, record_type: str = "A", max_concurrent: int = 5
) -> bool:
    async def query_with_backoff(
        domain: str, record: str, resolver, attempt: int
    ) -> bool:
        try:
            result = await resolver.query(domain, record)
            return bool(result)
        except aiodns.error.DNSError:
            return False
        except Exception:
            return False

    async with asyncio.Semaphore(max_concurrent):
        record_types = [record_type, "AAAA"] if record_type == "A" else [record_type]
        for record in record_types:
            for attempt in range(DEFAULT_CONFIG["max_retries"]):
                reachable = await query_with_backoff(domain, record, resolver, attempt)
                if reachable:
                    return True
                await asyncio.sleep(DEFAULT_CONFIG["retry_delay"])
        return False


async def test_single_domain_async(
    domain: str,
    url: str,
    resolver,
    cache_manager,
    whitelist: set[str],
    blacklist: set[str],
    max_concurrent: int = 5,
) -> bool:
    if domain in whitelist:
        return False
    if domain in blacklist:
        return True
    cache = cache_manager.load_domain_cache()
    if domain in cache:
        entry = cache[domain]
        last_checked = datetime.fromisoformat(entry["checked_at"])
        if datetime.now() - last_checked < timedelta(
            days=DEFAULT_CONFIG["domain_cache_validity_days"]
        ):
            return entry["reachable"]
    reachable = await test_dns_entry_async(
        domain, resolver, max_concurrent=max_concurrent
    )
    cache_manager.save_domain(domain, reachable, url)
    return reachable


async def test_domain_batch(
    domains: List[str],
    url: str,
    resolver,
    cache_manager,
    whitelist: set[str],
    blacklist: set[str],
    max_concurrent: int = 5,
):
    tasks = [
        test_single_domain_async(
            domain, url, resolver, cache_manager, whitelist, blacklist, max_concurrent
        )
        for domain in domains
    ]
    results = await asyncio.gather(*tasks)
    return list(zip(domains, results))


def setup_git() -> bool:
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as exc:
        logger.warning("git not available: %s", exc)
        return False


def upload_to_github(config: dict) -> None:
    """Commit hosts file and related artifacts to GitHub."""

    repo = config.get("github_repo")
    branch = config.get("github_branch", "main")
    git_user = config.get("git_user")
    git_email = config.get("git_email")

    try:
        subprocess.run(["git", "config", "user.name", git_user], check=True)
        subprocess.run(["git", "config", "user.email", git_email], check=True)

        files_to_add = [
            config.get("hosts_file", "hosts.txt"),
            config.get("dns_config_file", "dnsmasq.conf"),
            "tmp",
        ]
        subprocess.run(["git", "add", *files_to_add], check=True)

        commit_message = f"Update hosts {datetime.utcnow().isoformat()}"
        subprocess.run(["git", "commit", "-m", commit_message], check=True)

        subprocess.run(["git", "push", repo, f"HEAD:{branch}"], check=True)
        logger.info("Hosts-Datei erfolgreich auf GitHub hochgeladen")
    except subprocess.CalledProcessError as exc:
        logger.error("Git-Befehl fehlgeschlagen: %s", exc)
    except Exception as exc:  # pragma: no cover - unforeseen errors
        logger.error("Fehler beim Upload zu GitHub: %s", exc)
