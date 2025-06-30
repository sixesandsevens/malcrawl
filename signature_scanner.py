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


def scan_code_yara(code: str) -> List[Dict]:
    """Return list of matches for a piece of code."""
    matches = []
    if yara is None or not CONFIG.get("enable_yara"):
        return matches
    for rule in _YARA_RULES:
        try:
            res = rule.match(data=code)
            for r in res:
                strings = []
                for off, ident, s in r.strings:
                    snippet = s.decode('utf-8', 'ignore') if isinstance(s, bytes) else s
                    strings.append(snippet)
                matches.append({
                    "tool": "yara",
                    "rule": r.rule,
                    "description": r.meta.get('description'),
                    "strings": strings,
                })
        except Exception as exc:
            print(f"[YARA] Match error: {exc}")
    return matches


def scan_file_clamav(path: str) -> Dict | None:
    if not CONFIG.get("enable_clamav"):
        return None
    cmd = shutil.which('clamscan') or shutil.which('clamdscan')
    if not cmd:
        print("[ClamAV] clamscan not found")
        return {"error": "not installed"}
    try:
        proc = subprocess.run([cmd, path], capture_output=True, text=True)
    except Exception as exc:
        print(f"[ClamAV] failed to run: {exc}")
        return {"error": str(exc)}
    out = proc.stdout + proc.stderr
    m = re.search(r"^(.*?): (.+?) FOUND$", out, re.MULTILINE)
    if m:
        return {"infected": True, "signature": m.group(2)}
    return {"infected": False}


def scan_code_clamav(code: str) -> Dict | None:
    """Scan a code snippet by writing it to a temp file."""
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.js') as tmp:
        tmp.write(code)
    try:
        return scan_file_clamav(tmp.name)
    finally:
        os.unlink(tmp.name)
