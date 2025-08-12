
"""Default configuration values for the crawler and signature scanners."""

import json
import os

DEFAULT_USER_AGENT = "MalCrawlBot/0.1"
DEFAULT_DEPTH = 2
TIMEOUT = 5

# resource caps
MAX_PAGES = int(os.getenv("MAX_PAGES", "300"))
MAX_RUNTIME_SECS = int(os.getenv("MAX_RUNTIME_SECS", "600"))
MAX_SCRIPTS = int(os.getenv("MAX_SCRIPTS", "5000"))
MAX_BYTES_HTML = int(os.getenv("MAX_BYTES_HTML", "20_000_000"))

# default signature/scanner configuration
_DEFAULT_CFG = {
    "enable_yara": True,
    "enable_clamav": True,
    "yara_rules_path": "rules/yara",
    "verbosity": "info",
}

CONFIG_PATH = "config.json"

# Logging
LOG_DIR = "logs"
LOG_LEVEL = "INFO"          # DEBUG, INFO, WARNING, ERROR
LOG_TO_CONSOLE = True
LOG_JSON = True             # if False, switch to human/pretty logs
LOG_ROTATE_MB = 10          # per file
LOG_ROTATE_BACKUPS = 5

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

