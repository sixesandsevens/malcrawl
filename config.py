
"""Default configuration values for the crawler and signature scanners."""

import json
import os

DEFAULT_USER_AGENT = "MalCrawlBot/0.1"
DEFAULT_DEPTH = 2
TIMEOUT = 5

# default signature/scanner configuration
_DEFAULT_CFG = {
    "enable_yara": True,
    "enable_clamav": True,
    "yara_rules_path": "rules/yara",
    "verbosity": "info",
}

CONFIG_PATH = "config.json"

def _load_config(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    return {**_DEFAULT_CFG, **data}
        except Exception as exc:  # pragma: no cover - best effort
            print(f"[Config] Failed to load {path}: {exc}")
    return _DEFAULT_CFG


CONFIG = _load_config(CONFIG_PATH)

