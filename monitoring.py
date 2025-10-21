"""System monitoring helpers."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Optional, Tuple

import aiodns
import psutil

import config as config_module
from networking import send_email

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
    thresholds = config.get("resource_thresholds", {})
    moving_window = max(1, int(thresholds.get("moving_average_window", 5)))
    consecutive_required = max(
        1, int(thresholds.get("consecutive_violations", 1))
    )
    low_memory_threshold = float(thresholds.get("low_memory_mb", 0))
    emergency_memory_threshold = float(
        thresholds.get("emergency_memory_mb", low_memory_threshold / 2 or 0)
    )
    cpu_threshold = float(thresholds.get("high_cpu_percent", 100))
    latency_threshold = float(thresholds.get("high_latency_s", float("inf")))

    def moving_average(values: deque[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    violation_streaks = {
        "cpu": 0,
        "latency": 0,
        "low_memory": 0,
        "emergency_memory": 0,
    }
    recovery_streak = 0

    try:
        from adblock import SystemMode
    except ImportError as exc:  # pragma: no cover - should not happen during runtime
        logger.error("SystemMode konnte nicht importiert werden: %s", exc)
        return

    current_mode = getattr(config_module, "global_mode", None)
    if not isinstance(current_mode, SystemMode):
        current_mode = SystemMode.NORMAL
        config_module.global_mode = current_mode

    history = {
        "free_memory_mb": deque(maxlen=moving_window),
        "cpu_usage_percent": deque(maxlen=moving_window),
        "latency_s": deque(maxlen=moving_window),
    }
    while True:
        try:
            free_memory = psutil.virtual_memory().available / (1024 * 1024)
            cpu_usage = psutil.cpu_percent(interval=0.1)
            latency = await check_network_latency(config)
            history["free_memory_mb"].append(free_memory)
            history["cpu_usage_percent"].append(cpu_usage)
            history["latency_s"].append(latency if latency != float("inf") else 5.0)

            sample_count = len(history["cpu_usage_percent"])
            avg_free_memory = moving_average(history["free_memory_mb"])
            avg_cpu = moving_average(history["cpu_usage_percent"])
            avg_latency = moving_average(history["latency_s"])

            memory_emergency = avg_free_memory <= emergency_memory_threshold
            memory_low = (
                avg_free_memory <= low_memory_threshold and not memory_emergency
            )
            cpu_high = avg_cpu >= cpu_threshold
            latency_high = avg_latency >= latency_threshold

            if memory_emergency:
                violation_streaks["emergency_memory"] += 1
            else:
                violation_streaks["emergency_memory"] = 0

            if memory_low:
                violation_streaks["low_memory"] += 1
            else:
                violation_streaks["low_memory"] = 0

            if cpu_high:
                violation_streaks["cpu"] += 1
            else:
                violation_streaks["cpu"] = 0

            if latency_high:
                violation_streaks["latency"] += 1
            else:
                violation_streaks["latency"] = 0

            any_violation = memory_emergency or memory_low or cpu_high or latency_high
            if any_violation:
                recovery_streak = 0
            elif sample_count >= consecutive_required:
                recovery_streak += 1

            desired_mode = current_mode
            alert_reason: Optional[str] = None
            alert_level = logging.INFO
            send_alert = False

            if (
                sample_count >= consecutive_required
                and violation_streaks["emergency_memory"] >= consecutive_required
            ):
                desired_mode = SystemMode.EMERGENCY
                alert_reason = (
                    "Durchschnittlich nur "
                    f"{avg_free_memory:.1f} MB frei (Grenzwert ≤ "
                    f"{emergency_memory_threshold:.1f} MB)"
                )
                alert_level = logging.ERROR
                send_alert = True
            elif (
                sample_count >= consecutive_required
                and violation_streaks["cpu"] >= consecutive_required
            ):
                desired_mode = SystemMode.EMERGENCY
                alert_reason = (
                    "CPU-Auslastung "
                    f"{avg_cpu:.1f}% überschreitet Grenzwert "
                    f"{cpu_threshold:.1f}%"
                )
                alert_level = logging.ERROR
                send_alert = True
            elif (
                sample_count >= consecutive_required
                and violation_streaks["latency"] >= consecutive_required
            ):
                desired_mode = SystemMode.EMERGENCY
                alert_reason = (
                    "DNS-Latenz "
                    f"{avg_latency:.2f}s überschreitet Grenzwert "
                    f"{latency_threshold:.2f}s"
                )
                alert_level = logging.ERROR
                send_alert = True
            elif (
                sample_count >= consecutive_required
                and violation_streaks["low_memory"] >= consecutive_required
            ):
                desired_mode = SystemMode.LOW_MEMORY
                alert_reason = (
                    "Durchschnittlich nur "
                    f"{avg_free_memory:.1f} MB frei (Grenzwert ≤ "
                    f"{low_memory_threshold:.1f} MB)"
                )
                alert_level = logging.WARNING
                send_alert = True
            elif (
                current_mode != SystemMode.NORMAL
                and sample_count >= consecutive_required
                and recovery_streak >= consecutive_required
            ):
                desired_mode = SystemMode.NORMAL
                alert_reason = (
                    "Ressourcen stabilisieren sich nach Grenzwertverletzungen"
                )
                alert_level = logging.INFO
                send_alert = False

            if desired_mode != current_mode:
                config_module.global_mode = desired_mode
                current_mode = desired_mode
                mode_message = (
                    f"Systemmodus gewechselt zu {desired_mode.value}: {alert_reason}"
                    if alert_reason
                    else f"Systemmodus gewechselt zu {desired_mode.value}"
                )
                logger.log(alert_level, mode_message)
                if send_alert and config.get("send_email", False):
                    subject = (
                        f"AdBlock Ressourcenwarnung: {desired_mode.value.upper()}"
                    )
                    body = (
                        "Der Ressourcenmonitor hat einen Grenzwert überschritten.\n\n"
                        f"Aktueller Systemmodus: {desired_mode.value}\n"
                        f"Grund: {alert_reason}\n"
                        f"Durchschnittliche CPU-Auslastung: {avg_cpu:.1f}%\n"
                        f"Durchschnittlicher freier Speicher: {avg_free_memory:.1f} MB\n"
                        f"Durchschnittliche DNS-Latenz: {avg_latency:.2f} s\n"
                    )
                    send_email(subject, body, config)

            cache_manager.adjust_cache_size()
            cache_manager.domain_cache.update_threshold()
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Fehler bei Ressourcenüberwachung: %s", exc)
            await asyncio.sleep(5)
