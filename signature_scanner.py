
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Dict

try:
    import yara
except Exception as e:  # pragma: no cover - optional dependency
    yara = None

from config import CONFIG
from logging_utils import with_ctx, bind

log = with_ctx("malcrawl.signatures")

_YARA_RULES: List["yara.Rules"] = []


def load_yara_rules(path: str | None = None) -> None:
    """Load yara rules from the provided directory."""
    global _YARA_RULES
    if yara is None or not CONFIG.get("enable_yara"):
        return
    rules_dir = path or CONFIG.get("yara_rules_path", "rules/yara")
    if not os.path.isdir(rules_dir):
        return
    for fname in os.listdir(rules_dir):
        if not fname.endswith(('.yar', '.yara')):
            continue
        fpath = os.path.join(rules_dir, fname)
        try:
            _YARA_RULES.append(yara.compile(filepath=fpath))
        except Exception as exc:
            lineno = getattr(exc, 'lineno', '?')
            print(f"[YARA] Failed to compile {fname} line {lineno}: {exc}")


def scan_code_yara(code: str, scan_id=None, meta=None) -> List[Dict]:
    """Return list of matches for a piece of code."""
    L = bind(log, scan_id=scan_id, url=meta.get("url") if meta else None)
    matches: List[Dict] = []
    if yara is None or not CONFIG.get("enable_yara"):
        return matches
    try:
        for rule in _YARA_RULES:
            res = rule.match(data=code)
            for r in res:
                strings = []
                for off, ident, s in r.strings:
                    snippet = s.decode("utf-8", "ignore") if isinstance(s, bytes) else s
                    strings.append(snippet)
                matches.append(
                    {
                        "tool": "yara",
                        "rule": r.rule,
                        "description": r.meta.get("description"),
                        "strings": strings,
                    }
                )
        if matches:
            L.info("yara.match", extra={"matches": [m["rule"] for m in matches]})
        else:
            L.debug("yara.clean")
    except Exception:
        L.error("yara.error", exc_info=True)
    return matches


def scan_file_clamav(path: str, scan_id=None) -> Dict | None:
    L = bind(log, scan_id=scan_id, url=path)
    if not CONFIG.get("enable_clamav"):
        return None
    cmd = shutil.which("clamscan") or shutil.which("clamdscan")
    if not cmd:
        L.error("clam.missing")
        return {"error": "not installed"}
    try:
        proc = subprocess.run([cmd, path], capture_output=True, text=True)
    except Exception as exc:
        L.error("clam.error", exc_info=True)
        return {"error": str(exc)}
    out = proc.stdout + proc.stderr
    m = re.search(r"^(.*?): (.+?) FOUND$", out, re.MULTILINE)
    if m:
        L.info("clam.match", extra={"sig": m.group(2)})
        return {"infected": True, "signature": m.group(2)}
    L.debug("clam.clean")
    return {"infected": False}


def scan_code_clamav(code: str, scan_id=None) -> Dict | None:
    """Scan a code snippet by writing it to a temp file."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".js") as tmp:
        tmp.write(code)
    try:
        return scan_file_clamav(tmp.name, scan_id=scan_id)
    finally:
        os.unlink(tmp.name)
