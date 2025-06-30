"""Functions for scanning HTML content for suspicious behavior."""

import re
import asyncio
from typing import List, Tuple

from urllib.parse import urljoin
import requests
from config import TIMEOUT
from deobfuscator import analyze_scripts

def scan_page(
    soup,
    base_url,
    target_pattern: str | None = None,
    debug: bool = False,
) -> Tuple[List[str], List[dict], List[dict]]:
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
    if script_codes:
        issues, scripts_data = asyncio.run(analyze_scripts(script_codes, target_pattern))
        suspicious.extend(issues)
        for item in scripts_data:
            snippet = item["deobfuscated"]
            if snippet.strip():
                preview = snippet.strip().replace("\n", " ")[:80]
                print(f"    JS Preview: {preview}")
            if item.get("target_hit"):
                suspicious.append(f"target hit in script: {target_pattern}")

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

    return suspicious, scripts_data, inline_events

