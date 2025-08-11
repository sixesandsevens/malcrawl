# ============================================================
# MalCrawl — Codex Context Header
# Purpose: Keep changes aligned with MalCrawl’s architecture, priorities, and security model.
#
# PROJECT SUMMARY
# - MalCrawl is a forensic web crawler that fetches pages, (optionally) renders JS with Selenium, 
#   extracts inline/external JS, deobfuscates it, and flags suspicious behavior via signatures 
#   (YARA, ClamAV, custom JSON DB). Results are viewable in a web UI and via CLI.
# - Core values: lean core, modular heavy features (sandbox, diffing, plugin scanners), 
#   safe-by-default execution, human-readable output.
#
# CURRENT PRIORITIES (implement in this order)
# 1) CLI Enhancements:
#    - Full flags for scope, depth, detection backends, output format
#    - Progress output
#    - Resume previous scan
# 2) Sandboxing v1:
#    - Isolated JS execution (Node VM / py_mini_racer)
#    - Strict time/memory limits
#    - No network access
#    - Log eval, Function(), DOM writes, and timeouts
# 3) README Improvements:
#    - Add CLI usage examples
#    - Clarify installation process
#    - Include contribution guidelines
#
# CODING STYLE NOTES:
# - Keep modules small and single-purpose.
# - Use dependency injection for scanners to allow easy swapping.
# - Maintain HTML output readability (avoid dumping raw JSON without formatting).
# ============================================================


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

