

"""Functions for scanning HTML content for suspicious behavior."""

import re
import asyncio
from typing import List, Tuple, Dict

from urllib.parse import urljoin
import requests
from config import TIMEOUT, CONFIG, DEFAULT_USER_AGENT
from deobfuscator import analyze_scripts
from signature_scanner import (
    load_yara_rules,
    scan_code_yara,
    scan_code_clamav,
)
from logging_utils import with_ctx, bind

log = with_ctx("malcrawl.scanner")

load_yara_rules(CONFIG.get("yara_rules_path"))

def scan_page(
    soup,
    base_url,
    scan_id=None,
    full_logging=False,
    target_pattern: str | None = None,
    debug: bool = False,
    user_agent: str = DEFAULT_USER_AGENT,
) -> Tuple[List[str], List[dict], List[dict], List[Dict]]:
    """Analyze parsed HTML and return suspicious findings, script details and inline events."""
    L = bind(log, scan_id=scan_id, url=base_url)
    if full_logging:
        L.debug("scan.start")

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
                headers = {"User-Agent": user_agent}
                resp = requests.get(src_url, timeout=TIMEOUT, headers=headers)
                if resp.ok:
                    script_codes.append(resp.text)
                else:
                    if full_logging:
                        L.debug(
                            "scripts.fetch_fail", extra={"status": resp.status_code, "url": src_url}
                        )
            except Exception as e:
                if full_logging:
                    L.error("scripts.fetch_error", exc_info=True, url=src_url)
        else:
            if full_logging:
                L.debug("scripts.empty_tag")
    scripts_data: List[dict] = []
    signature_matches: List[Dict] = []
    if script_codes:
        issues, scripts_data = asyncio.run(
            analyze_scripts(
                script_codes,
                target_pattern,
                scan_id=scan_id,
                full_logging=full_logging,
                source=base_url,
            )
        )
        suspicious.extend(issues)
        for idx, item in enumerate(scripts_data, 1):
            snippet = item["deobfuscated"]
            if item.get("target_hit"):
                suspicious.append(f"target hit in script: {target_pattern}")

            y_matches = scan_code_yara(snippet, scan_id=scan_id, meta={"url": base_url})
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
            c_result = scan_code_clamav(snippet, scan_id=scan_id)
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

    if inline_events:
        L.info(
            "detect.inline_events",
            extra={"events": [evt["event"] for evt in inline_events]},
        )
    if suspicious:
        L.info("detect.suspicious_strings", extra={"count": len(suspicious)})
    if full_logging:
        L.debug("scripts.external", extra={"count": len(script_codes)})

    return suspicious, scripts_data, inline_events, signature_matches

