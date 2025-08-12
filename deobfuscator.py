
import asyncio
import base64
import re
from urllib.parse import unquote
from typing import List, Tuple

import jsbeautifier
from logging_utils import with_ctx, bind

log = with_ctx("malcrawl.deob")

"""Asynchronous helpers for detecting and unpacking obfuscated JavaScript."""

OBFUSCATION_RE = re.compile(r"(eval\(|Function\(|setTimeout\(|atob\()")
LONG_VARS_RE = re.compile(r"var\s+[a-zA-Z0-9_$]{20,}")
HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
B64_RE = re.compile(r"atob\([\"']([A-Za-z0-9+/=]+)[\"']\)")
EVAL_UNESCAPE_RE = re.compile(r"eval\(unescape\(['\"]([^'\"]+)['\"]\)\)")
FUNCTION_RETURN_RE = re.compile(r"Function\(['\"]return ([^'\"]+)['\"]\)\(\)")

# Basic behavioral fingerprints for intent classification
INTENT_PATTERNS = {
    "redirection": re.compile(r"location\\.href|window\\.location|top\\.location"),
    "credential_theft": re.compile(r"document\\.forms|password|login", re.I),
    "beaconing": re.compile(r"fetch\(|XMLHttpRequest|navigator\\.sendBeacon"),
    "code_injection": re.compile(r"innerHTML|document\\.write"),
    "coin_miner": re.compile(r"CoinHive|miner|WebMiner", re.I),
    "fingerprinting": re.compile(r"navigator\\.userAgent|canvas\\.toDataURL|audioContext|webGL", re.I),
    "alert_bomb": re.compile(r"alert\([^)]*\).*alert\(", re.S),
    "iframe_loader": re.compile(r"createElement\(\s*['\"]iframe['\"]\)"),
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


def deobfuscate(js_code: str, scan_id=None, source=None, full_logging=False):
    L = bind(log, scan_id=scan_id, url=source or "inline")
    try:
        if full_logging:
            L.debug("deob.start", extra={"size": len(js_code)})
        code = HEX_RE.sub(_decode_hex, js_code)
        code = B64_RE.sub(_decode_b64, code)
        m = EVAL_UNESCAPE_RE.search(code)
        if m:
            try:
                decoded = unquote(m.group(1))
                code = code.replace(m.group(0), decoded)
            except Exception:
                pass
        m = FUNCTION_RETURN_RE.search(code)
        if m:
            code = code.replace(m.group(0), m.group(1))
        cleaned = jsbeautifier.beautify(code)
        intents = infer_intent(cleaned)
        if intents:
            L.info("deob.intent", extra={"intent": intents})
        if full_logging:
            L.debug("deob.done", extra={"out_len": len(cleaned)})
        return cleaned, intents
    except Exception:
        L.error("deob.error", exc_info=True)
        return js_code, []


def infer_intent(code: str) -> List[str]:
    """Return a list of potential malicious intents found in code."""
    intents = []
    for name, regex in INTENT_PATTERNS.items():
        if regex.search(code):
            intents.append(name)
    return intents


DYNAMIC_PATTERNS = {
    "eval": re.compile(r"\beval\s*\("),
    "Function": re.compile(r"\bFunction\s*\("),
    "setTimeout": re.compile(r"setTimeout\s*\(\s*['\"]"),
    "setInterval": re.compile(r"setInterval\s*\(\s*['\"]"),
}


async def analyze_script(js_code: str, target: str | None = None, scan_id=None, source=None, full_logging=False) -> Tuple[List[str], str, List[str], bool, bool]:
    """Full pipeline for a single script: detect, deobfuscate, infer intent."""
    findings: List[str] = []
    beautified = js_code
    intents: List[str] = []
    changed = False
    target_hit = False

    if detect_obfuscation(js_code):
        findings.append("obfuscated JavaScript")
        deob, intents = deobfuscate(js_code, scan_id=scan_id, source=source, full_logging=full_logging)
        if deob != js_code:
            changed = True
        beautified = deob
    else:
        intents = infer_intent(beautified)

    for intent in intents:
        findings.append(f"intent:{intent}")

    for name, regex in DYNAMIC_PATTERNS.items():
        if regex.search(beautified):
            findings.append(f"dynamic:{name}")

    if target and re.search(target, beautified, re.I):
        target_hit = True
        findings.append(f"target:{target}")

    return findings, beautified, intents, changed, target_hit


async def analyze_scripts(scripts: List[str], target: str | None = None, scan_id=None, full_logging=False, source=None) -> Tuple[List[str], List[dict]]:
    """Analyze multiple scripts concurrently."""
    tasks = [analyze_script(code, target, scan_id=scan_id, source=source, full_logging=full_logging) for code in scripts]
    results = await asyncio.gather(*tasks)
    findings: List[str] = []
    processed: List[dict] = []
    for (f, b, intents, changed, hit), orig in zip(results, scripts):
        findings.extend(f)
        processed.append(
            {
                "original": orig,
                "deobfuscated": b,
                "intent": ", ".join(intents) if intents else None,
                "changed": changed,
                "target_hit": hit,
            }
        )
    return findings, processed
