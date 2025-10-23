import json
from copy import deepcopy

import pytest

from adblock import CONFIG, load_config
from config import DEFAULT_CONFIG


@pytest.fixture(autouse=True)
def restore_config():
    original = deepcopy(CONFIG)
    try:
        yield
    finally:
        CONFIG.clear()
        CONFIG.update(original)


def test_load_config_preserves_nested_defaults(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"resource_thresholds": {"low_memory_mb": 128}}),
        encoding="utf-8",
    )

    load_config(str(config_path))

    assert CONFIG["resource_thresholds"]["low_memory_mb"] == 128
    assert (
        CONFIG["resource_thresholds"]["emergency_memory_mb"]
        == DEFAULT_CONFIG["resource_thresholds"]["emergency_memory_mb"]
    )


def test_load_config_retains_smtp_password(tmp_path, monkeypatch):
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    config_path = tmp_path / "config.json"
    password_value = "geheimes-passwort"
    config_path.write_text(
        json.dumps({"smtp_password": password_value}),
        encoding="utf-8",
    )

    load_config(str(config_path))

    assert CONFIG["smtp_password"] == password_value
    saved_config = json.loads(config_path.read_text(encoding="utf-8"))
    # Der SMTP-Zugang muss erhalten bleiben, damit networking.send_email weiterhin authentifizieren kann.
    assert saved_config["smtp_password"] == password_value


def test_load_config_preserves_user_email_preference_without_password(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "send_email": True,
                "use_smtp": True,
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "smtp_user": "user@example.com",
                "email_recipient": "admin@example.com",
                "email_sender": "bot@example.com",
            }
        ),
        encoding="utf-8",
    )

    load_config(str(config_path))

    assert CONFIG["send_email"] is False
    persisted_config = json.loads(config_path.read_text(encoding="utf-8"))
    # Benutzerpräferenzen auf der Platte bewahren, obwohl der Lauf ohne SMTP-Passwort E-Mails deaktiviert.
    assert persisted_config["send_email"] is True


def test_load_config_resets_invalid_domain_timeout(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"domain_timeout": 0}), encoding="utf-8")

    load_config(str(config_path))

    # Verhindert Laufzeitfehler in aiodns.DNSResolver(..., timeout=...) und im Ressourcenmonitor.
    assert CONFIG["domain_timeout"] == DEFAULT_CONFIG["domain_timeout"]
