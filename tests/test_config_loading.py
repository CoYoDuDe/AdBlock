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


def test_load_config_does_not_persist_env_smtp_password(tmp_path, monkeypatch):
    env_password = "env-secret"
    monkeypatch.setenv("SMTP_PASSWORD", env_password)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")

    load_config(str(config_path))

    assert CONFIG["smtp_password"] == env_password
    saved_config = json.loads(config_path.read_text(encoding="utf-8"))
    assert saved_config.get("smtp_password") != env_password
    assert "smtp_password" not in saved_config or saved_config["smtp_password"] == ""
