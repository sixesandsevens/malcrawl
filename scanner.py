"""Functions for scanning HTML content for suspicious behavior."""

import re
import asyncio
from typing import List, Tuple

from deobfuscator import analyze_scripts

def scan_page(soup, base_url) -> Tuple[List[str], List[dict]]:
    """Analyze parsed HTML and return a list of suspicious findings and script details."""
    print(f"[Scan] {base_url}")

    suspicious: List[str] = []

    script_codes = [s.string or '' for s in soup.find_all('script')]
    scripts_data: List[dict] = []
    if script_codes:
        issues, scripts_data = asyncio.run(analyze_scripts(script_codes))
        suspicious.extend(issues)
        for item in scripts_data:
            snippet = item["deobfuscated"]
            if snippet.strip():
                preview = snippet.strip().replace("\n", " ")[:80]
                print(f"    JS Preview: {preview}")

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith('on'):
                suspicious.append(f"Inline JS event: <{tag.name}> - {attr}")

    for iframe in soup.find_all('iframe'):
        if 'display:none' in str(iframe.get('style', '')):
            suspicious.append("Hidden iframe")

    if suspicious:
        print(f"  🚨 Suspicious content:")
        for s in suspicious:
            print(f"    ⚠️ {s}")
    else:
        print(f"  ✅ No major red flags found.")

    return suspicious, scripts_data

