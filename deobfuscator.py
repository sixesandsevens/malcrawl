import asyncio
import base64
import re
from typing import List, Tuple

"""Asynchronous helpers for detecting and unpacking obfuscated JavaScript."""

OBFUSCATION_RE = re.compile(r"(eval\(|Function\(|setTimeout\(|atob\()")
LONG_VARS_RE = re.compile(r"var\s+[a-zA-Z0-9_$]{20,}")
HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
B64_RE = re.compile(r"atob\([\"']([A-Za-z0-9+/=]+)[\"']\)")

INTENT_PATTERNS = {
    "redirection": re.compile(r"location\\.href|window\\.location"),
    "credentials": re.compile(r"document\\.forms|password"),
    "beaconing": re.compile(r"fetch\(|XMLHttpRequest|navigator\\.sendBeacon"),
    "code_injection": re.compile(r"innerHTML|document\\.write"),
}


def detect_obfuscation(code: str) -> bool:
    """Return True if the code appears obfuscated."""
    if OBFUSCATION_RE.search(code):
        return True
    if LONG_VARS_RE.search(code):
        return True
    if HEX_RE.search(code):
        return True
    return False


def _decode_hex(match: re.Match) -> str:
    try:
        hex_str = match.group(0).replace("\\x", "")
        return bytes.fromhex(hex_str).decode("utf-8")
    except Exception:
        return match.group(0)


def _decode_b64(match: re.Match) -> str:
    try:
        return base64.b64decode(match.group(1)).decode("utf-8")
    except Exception:
        return match.group(0)


def deobfuscate(code: str) -> str:
    """Attempt to decode common obfuscation patterns."""
    code = HEX_RE.sub(_decode_hex, code)
    code = B64_RE.sub(_decode_b64, code)
    return code


def infer_intent(code: str) -> List[str]:
    """Return a list of potential malicious intents found in code."""
    intents = []
    for name, regex in INTENT_PATTERNS.items():
        if regex.search(code):
            intents.append(name)
    return intents


async def analyze_script(js_code: str) -> Tuple[List[str], str, List[str]]:
    """Full pipeline for a single script: detect, deobfuscate, infer intent."""
    findings: List[str] = []
    beautified = js_code
    intents: List[str] = []

    if detect_obfuscation(js_code):
        findings.append("obfuscated JavaScript")
        beautified = deobfuscate(js_code)

    intents = infer_intent(beautified)
    for intent in intents:
        findings.append(f"intent:{intent}")

    return findings, beautified, intents


async def analyze_scripts(scripts: List[str]) -> Tuple[List[str], List[dict]]:
    """Analyze multiple scripts concurrently."""
    tasks = [analyze_script(code) for code in scripts]
    results = await asyncio.gather(*tasks)
    findings: List[str] = []
    processed: List[dict] = []
    for (f, b, intents), orig in zip(results, scripts):
        findings.extend(f)
        processed.append(
            {
                "original": orig,
                "deobfuscated": b,
                "intent": ", ".join(intents) if intents else None,
            }
        )
    return findings, processed
