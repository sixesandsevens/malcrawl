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


"""Functions for scanning HTML content for suspicious behavior."""

import re
import asyncio
from typing import List, Tuple, Dict

from urllib.parse import urljoin
import requests
from config import TIMEOUT, CONFIG
from deobfuscator import analyze_scripts
from signature_scanner import (
    load_yara_rules,
    scan_code_yara,
    scan_code_clamav,
)

load_yara_rules(CONFIG.get("yara_rules_path"))

def scan_page(
    soup,
    base_url,
    target_pattern: str | None = None,
    debug: bool = False,
) -> Tuple[List[str], List[dict], List[dict], List[Dict]]:
    """Analyze parsed HTML and return suspicious findings, script details and inline events."""
    print(f"[Scan] {base_url}")

    suspicious: List[str] = []
    inline_events: List[dict] = []

    script_codes: List[str] = []
    script_tags = soup.find_all('script')
    for s_tag in script_tags:
        if s_tag.has_attr('type') and 'javascript' not in s_tag['type']:
            if debug:
                print(f"[Debug] Skipping script type {s_tag['type']} src={s_tag.get('src')}")
            continue
        if s_tag.string and s_tag.string.strip():
            script_codes.append(s_tag.string)
        elif s_tag.get('src'):
            src_url = urljoin(base_url, s_tag['src'])
            try:
                resp = requests.get(src_url, timeout=TIMEOUT)
                if resp.ok:
                    script_codes.append(resp.text)
                else:
                    if debug:
                        print(f"[Debug] Failed to fetch {src_url}: {resp.status_code}")
            except Exception as e:
                if debug:
                    print(f"[Debug] Error fetching {src_url}: {e}")
        else:
            if debug:
                print(f"[Debug] Empty script tag encountered")
    scripts_data: List[dict] = []
    signature_matches: List[Dict] = []
    if script_codes:
        issues, scripts_data = asyncio.run(
            analyze_scripts(script_codes, target_pattern)
        )
        suspicious.extend(issues)
        for idx, item in enumerate(scripts_data, 1):
            snippet = item["deobfuscated"]
            if snippet.strip():
                preview = snippet.strip().replace("\n", " ")[:80]
                print(f"    JS Preview: {preview}")
            if item.get("target_hit"):
                suspicious.append(f"target hit in script: {target_pattern}")

            y_matches = scan_code_yara(snippet)
            if y_matches:
                for m in y_matches:
                    signature_matches.append(
                        {
                            "script_index": idx,
                            "tool": "yara",
                            "rule": m.get("rule"),
                            "description": m.get("description"),
                            "snippet": (m.get("strings") or [""])[0],
                        }
                    )
            c_result = scan_code_clamav(snippet)
            if c_result and c_result.get("infected"):
                signature_matches.append(
                    {
                        "script_index": idx,
                        "tool": "clamav",
                        "rule": c_result.get("signature"),
                        "description": None,
                        "snippet": "",
                    }
                )

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith('on'):
                code = tag.get(attr, '')
                suspicious.append(f"Inline JS event: <{tag.name}> - {attr}")
                inline_events.append({"event": attr, "tag": tag.name, "code": code})

    for iframe in soup.find_all('iframe'):
        if 'display:none' in str(iframe.get('style', '')):
            suspicious.append("Hidden iframe")

    if suspicious:
        print(f"  🚨 Suspicious content:")
        for s in suspicious:
            print(f"    ⚠️ {s}")
    else:
        print(f"  ✅ No major red flags found.")

    return suspicious, scripts_data, inline_events, signature_matches

