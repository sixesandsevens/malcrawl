"""Lightweight JavaScript sandbox helper."""

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
from typing import Optional


def _run_node(js_path: str) -> dict:
    """Execute the given JS file in a constrained Node.js VM and capture actions."""
    if not shutil.which("node"):
        return {"log": ["node runtime not available"], "summary": "unavailable"}

    runner_code = textwrap.dedent(
        """
        const fs = require('fs');
        const vm = require('vm');
        const code = fs.readFileSync(process.argv[2], 'utf8');
        const log = [];
        const sandbox = {
          fetch: (u)=>{ log.push('fetch '+u); return Promise.resolve({}); },
          XMLHttpRequest: function(){ this.open = function(m,u){ this._u=u; }; this.send = function(){ log.push('xhr '+this._u); }; },
          localStorage: { getItem:(k)=>{ log.push('localStorage.get '+k); return null; }, setItem:(k,v)=>{ log.push('localStorage.set '+k); } },
          document: { createElement:(t)=>{ log.push('createElement '+t); return {}; }, cookie:'' },
          window:{},
          console:{log:()=>{}}
        };
        vm.createContext(sandbox);
        try { vm.runInContext(code, sandbox, {timeout:1000}); } catch(e) { log.push('error '+e.message); }
        console.log(JSON.stringify({log: log, summary: 'executed'}));
        """
    )
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".js") as runner:
        runner.write(runner_code)
    try:
        proc = subprocess.run(
            ["node", runner.name, js_path], capture_output=True, text=True, timeout=5
        )
        out = proc.stdout.strip()
        return json.loads(out) if out else {"log": [], "summary": "no output"}
    except Exception as exc:  # pragma: no cover - best effort
        return {"log": [f"error {exc}"], "summary": "failed"}
    finally:
        os.unlink(runner.name)


def sandbox_eval(js: Optional[str] = None, path: Optional[str] = None) -> dict:
    """Execute JavaScript from a blob or file in a safe context."""
    tmp_path = None
    if path is None:
        if js is None:
            return {"log": [], "summary": "no code"}
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".js")
        tmp.write(js)
        tmp.close()
        tmp_path = tmp.name
        path = tmp_path
    result = _run_node(path)
    if tmp_path:
        os.unlink(tmp_path)
    return result
