"""System monitoring helpers."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Optional, Tuple

import aiodns
import psutil

logger = logging.getLogger(__name__)

_RESOURCE_CACHE_TTL_SECONDS = 0.05
_RESOURCE_CACHE: Optional[Tuple[float, Tuple[int, int, int]]] = None


async def check_network_latency(config: dict) -> float:
    try:
        resolver = aiodns.DNSResolver(
            nameservers=[config["dns_servers"][0]], timeout=5.0
        )
        start = asyncio.get_running_loop().time()
        await resolver.query("example.com", "A")
        latency = asyncio.get_running_loop().time() - start
        return latency
    except Exception:
        return float("inf")


def get_system_resources() -> Tuple[int, int, int]:
    global _RESOURCE_CACHE

    now = time.monotonic()
    if _RESOURCE_CACHE is not None:
        cached_at, cached_values = _RESOURCE_CACHE
        if now - cached_at <= _RESOURCE_CACHE_TTL_SECONDS:
            return cached_values

    try:
        cpu_load = psutil.cpu_percent(interval=None) / 100
        cpu_cores = psutil.cpu_count(logical=True) or 1
        free_memory = psutil.virtual_memory().available
        max_jobs = max(1, int(cpu_cores / (cpu_load + 0.1)) // 2)
        batch_size = max(10, min(50, int(free_memory / (500 * 1024))))
        max_concurrent_dns = max(5, min(20, int(free_memory / (1024 * 1024))))
        values = (max_jobs, batch_size, max_concurrent_dns)
    except Exception as exc:
        logger.error("Fehler bei Ressourcenermittlung: %s", exc)
        values = (1, 5, 5)

    _RESOURCE_CACHE = (now, values)
    return values


async def monitor_resources(cache_manager, config: dict) -> None:
    logger.info("Starte Ressourcenüberwachung...")
    history = {
        "free_memory_mb": deque(
            maxlen=config["resource_thresholds"]["moving_average_window"]
        ),
        "cpu_usage_percent": deque(
            maxlen=config["resource_thresholds"]["moving_average_window"]
        ),
        "latency_s": deque(
            maxlen=config["resource_thresholds"]["moving_average_window"]
        ),
    }
    while True:
        try:
            free_memory = psutil.virtual_memory().available / (1024 * 1024)
            cpu_usage = psutil.cpu_percent(interval=0.1)
            latency = await check_network_latency(config)
            history["free_memory_mb"].append(free_memory)
            history["cpu_usage_percent"].append(cpu_usage)
            history["latency_s"].append(latency if latency != float("inf") else 5.0)
            cache_manager.adjust_cache_size()
            cache_manager.domain_cache.update_threshold()
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Fehler bei Ressourcenüberwachung: %s", exc)
            await asyncio.sleep(5)
