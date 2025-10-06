"""Netzwerkbezogene Hilfsfunktionen."""

from __future__ import annotations

import asyncio
from threading import Lock
import logging
import os
import time
import subprocess
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import aiodns
from email.mime.text import MIMEText
import smtplib

from config import CONFIG, DEFAULT_CONFIG, MAX_DNS_CACHE_SIZE, SCRIPT_DIR

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
    domain: str,
    resolver,
    record_type: str = "A",
    semaphore: asyncio.Semaphore | None = None,
    config: dict | None = None,
) -> bool:
    if semaphore is None:
        raise ValueError("A semaphore instance is required")

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

    active_config = config or CONFIG or DEFAULT_CONFIG
    max_retries = active_config.get("max_retries", DEFAULT_CONFIG["max_retries"])
    retry_delay = active_config.get("retry_delay", DEFAULT_CONFIG["retry_delay"])

    async with semaphore:
        record_types = [record_type, "AAAA"] if record_type == "A" else [record_type]
        for record in record_types:
            for attempt in range(max_retries):
                reachable = await query_with_backoff(domain, record, resolver, attempt)
                if reachable:
                    return True
                await asyncio.sleep(retry_delay)
        return False


async def test_single_domain_async(
    domain: str,
    url: str,
    resolver,
    cache_manager,
    whitelist: set[str],
    blacklist: set[str],
    dns_cache: dict | None = None,
    cache_lock: Lock | None = None,
    max_concurrent: int = 5,
    semaphore: asyncio.Semaphore | None = None,
    config: dict | None = None,
) -> bool:
    if domain in whitelist:
        return False
    if domain in blacklist:
        return True
    active_config = config or CONFIG or DEFAULT_CONFIG
    domain_cache_validity = active_config.get(
        "domain_cache_validity_days",
        DEFAULT_CONFIG["domain_cache_validity_days"],
    )
    dns_cache_ttl = active_config.get("dns_cache_ttl", DEFAULT_CONFIG["dns_cache_ttl"])
    cached_dns = cache_manager.get_dns_cache(domain)
    if cached_dns is not None:
        return cached_dns
    cache = cache_manager.load_domain_cache()
    if domain in cache:
        entry = cache[domain]
        last_checked = datetime.fromisoformat(entry["checked_at"])
        if datetime.now() - last_checked < timedelta(days=domain_cache_validity):
            return entry["reachable"]

    if dns_cache is not None and cache_lock is not None:
        with cache_lock:
            info = dns_cache.get(domain)
            if info and time.time() - info["timestamp"] < dns_cache_ttl:
                return info["reachable"]
    semaphore = semaphore or asyncio.Semaphore(max_concurrent)
    reachable = await test_dns_entry_async(
        domain,
        resolver,
        semaphore=semaphore,
        config=active_config,
    )
    cache_manager.save_dns_cache(domain, reachable)
    cache_manager.save_domain(domain, reachable, url)
    if dns_cache is not None and cache_lock is not None:
        with cache_lock:
            if len(dns_cache) >= MAX_DNS_CACHE_SIZE:
                oldest_key = min(dns_cache, key=lambda k: dns_cache[k]["timestamp"])
                dns_cache.pop(oldest_key)
            dns_cache[domain] = {"reachable": reachable, "timestamp": time.time()}
    return reachable


async def test_domain_batch(
    domains: List[str],
    url: str,
    resolver,
    cache_manager,
    whitelist: set[str],
    blacklist: set[str],
    dns_cache: dict | None = None,
    cache_lock: Lock | None = None,
    max_concurrent: int = 5,
    config: dict | None = None,
):
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [
        test_single_domain_async(
            domain,
            url,
            resolver,
            cache_manager,
            whitelist,
            blacklist,
            dns_cache,
            cache_lock,
            max_concurrent,
            semaphore,
            config,
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
    """Commit hosts file und abhängige Artefakte in das Git-Repository."""

    repo = config.get("github_repo")
    if not repo:
        logger.warning("Kein Git-Repository konfiguriert, überspringe Upload")
        return

    branch = config.get("github_branch", "main")
    git_user = config.get("git_user")
    git_email = config.get("git_email")

    if not os.path.isdir(SCRIPT_DIR):
        logger.error("Arbeitsverzeichnis existiert nicht: %s", SCRIPT_DIR)
        return

    def run_git(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Hilfsfunktion, um Git-Befehle mit korrektem Arbeitsverzeichnis auszuführen."""

        return subprocess.run(
            ["git", *args],
            cwd=SCRIPT_DIR,
            check=check,
            capture_output=True,
            text=True,
        )

    try:
        if git_user:
            run_git(["config", "user.name", git_user])
        if git_email:
            run_git(["config", "user.email", git_email])

        candidate_files = [
            config.get("hosts_file", "hosts.txt"),
            config.get("dns_config_file", "dnsmasq.conf"),
            "tmp",
        ]
        files_to_add: list[str] = []
        ignored_files: list[str] = []
        for path in candidate_files:
            absolute_path = os.path.join(SCRIPT_DIR, path)
            if not os.path.exists(absolute_path):
                continue
            check_ignore = run_git(["check-ignore", path], check=False)
            if check_ignore.returncode == 0:
                ignored_files.append(path)
                continue
            files_to_add.append(path)

        for ignored in ignored_files:
            logger.debug("Überspringe von Git ignorierten Pfad: %s", ignored)

        if not files_to_add:
            logger.warning("Keine Dateien zum Hinzufügen gefunden, breche Upload ab")
            return

        run_git(["add", "--", *files_to_add])

        status_result = run_git(
            ["status", "--porcelain", "--", *files_to_add], check=False
        )
        if status_result.returncode != 0:
            logger.error(
                "Git-Status konnte nicht ermittelt werden: %s",
                status_result.stderr.strip(),
            )
            return

        if not status_result.stdout.strip():
            logger.info("Keine Änderungen zum Commit, überspringe Upload")
            return

        commit_message = f"Update hosts {datetime.now(timezone.utc).isoformat()}"
        run_git(["commit", "-m", commit_message])

        push_result = run_git(["push", repo, f"HEAD:{branch}"], check=False)
        if push_result.returncode != 0:
            logger.error("Git-Push fehlgeschlagen: %s", push_result.stderr.strip())
            return

        logger.info("Hosts-Datei erfolgreich auf GitHub hochgeladen")
    except subprocess.CalledProcessError as exc:
        logger.error(
            "Git-Befehl fehlgeschlagen: %s", exc.stderr.strip() if exc.stderr else exc
        )
    except Exception as exc:  # pragma: no cover - unforeseen errors
        logger.error("Fehler beim Upload zu GitHub: %s", exc)
