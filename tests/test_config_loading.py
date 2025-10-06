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
