# 🕷️ MalCrawl — ROADMAP

_Last updated: 2025-08-11_

## 🎯 Vision
MalCrawl is a **forensic web crawler** focused on web-page behavior, suspicious JavaScript, and human-friendly reporting. Keep the **core lean**, but make it **modular** so heavy features (sandboxing, diffing, plugins) remain optional.

---

## ✅ Current State (Implemented)
- Crawl (requests) with depth control; optional **Selenium render** + **screenshots**.
- Targeted scans (page/limited scope), duplicate/loop avoidance.
- SQLite storage of scans, per-URL results, issues.
- Extraction of inline + external JS (where available) and suspicious attributes (e.g., `onclick`, `onload`).
- **Deobfuscation pipeline** with heuristics (base64/URI/hex) and **intent inference**.
- **Signatures**: YARA integrated; ClamAV optional; early **custom signatures DB**.
- Result UI: dark theme, per-URL cards, **code viewer** (original vs deobfuscated), copy-to-clipboard, screenshot thumbnails.
- CLI: scan, list, view, export (JSON); flags for Selenium/sandbox.
- JSON export route; basic status polling + progress bar.
- Dev hygiene: venv + requirements; `.gitignore` excludes DB/screenshots/exports; basic stdout logging.

---

## 🟡 In Progress / Partial
- Live progress stages & Cancel scan (present, needs polish & persistence per `scan_id`).
- Sandbox: isolated JS execution with timeouts & behavior logging (needs richer hooks + UI tab).
- Navigation: recent scans index, prev/next in result view (basic archive exists).
- REST API: some JSON endpoints exist; needs formal `/api/scans` etc.
- Concurrency: mostly synchronous; thread/async pool planned.
- Config: migrate to `.env` + CLI overrides (partial).

---

## 🎯 30‑Day Priorities (Quick Wins)
- [ ] **Status/Cancel**: return `scan_id` from `/start_scan`; add `/status/<scan_id>` polling and `/cancel/<scan_id>`; persist stage progress: `queued → fetching → rendering → scanning → signatures → done`.
- [ ] **Top‑level nav**: Global navbar (New Scan • Recent Scans • Signatures • Settings). “Back to results list” on details pages.
- [ ] **JS viewer polish**: line numbers, fixed-height + scroll, copy buttons on both panes, byte length + hash in headers.
- [ ] **Backends toggle**: `SCANNER_BACKENDS=["yara","clamav"]`, CLI `--backends=yara|clamav|all`; per-backend hit logging.
- [ ] **Export UX**: `/export/<scan_id>.json` + CLI `malcrawl export <scan_id> --output path.json`.

---

## 🧱 Core Upgrades (Next)
- [ ] **Screenshot diffing**  
  - Baseline in `screenshots/baseline/`, current in `screenshots/current/`  
  - Compute `imagehash` distance; threshold → “Visual change” badge; “View diff” modal.
- [ ] **Behavioral signatures** (`behavior_signatures.py`)  
  - Patterns: `eval/Function` on encoded text, timed redirects, event hijacks, iframe/cookie abuse, clipboard hijack.  
  - Return: `id`, `title`, `severity`, `evidence`. Store + render under “Behavioral Signatures”.
- [ ] **Targeted crawl controls**  
  - UI: scope selector (page • same‑host • same‑path) + depth slider.  
  - CLI: `--scope=page|host|path`, `--depth=N`.
- [ ] **Formal REST API**  
  - `/api/scans?limit=&offset=`; `/api/scans/<scan_id>`; `/api/scans/<scan_id>/items` (URLs/scripts/findings); `/api/signatures`.  
  - Simple API key via env `MALCRAWL_API_KEY` (`Authorization: Bearer …`).

- [ ] **Sandbox v1 (safer)**  
  - Separate process (Node VM), no network, time/mem caps.  
  - Hook & log: `eval`, `Function`, `document.write`, `setTimeout`, `atob`, `XMLHttpRequest/fetch` (stub).  
  - UI: “Sandbox Log” tab alongside code viewer.

- [ ] **Concurrency & resilience**  
  - Thread pool for fetch/render; per‑host rate limiting; retries with backoff; structured logging (JSON).

---

## 🌊 Stretch / Optional (Monster Mode)
- [ ] Rule management UI (enable/disable, edit descriptions, severities). “Reload rules” hot‑reload.  
- [ ] Plugin API: `scanners/<name>.py` with `scan(context)->findings` dynamically loaded.  
- [ ] Behavior timeline for repeated crawls (hash, issues, signatures, visual diff).  
- [ ] Packaging: `pipx` installable, profiles (`local-dev`, `hardened`, `rpi-lowmem`).  
- [ ] Advanced sandboxing (containers/VM, network capture), optional only.

---

## 🗂 File Touchpoints (for Codex)
- **Flask routes**: `app.py` → add `/start_scan` (returns `scan_id`), `/status/<scan_id>`, `/cancel/<scan_id>`, `/api/*`, `/export/<scan_id>.json`, `/screenshots/diff/<name>.png`.
- **Templates**: `templates/base.html`, `templates/index.html`, `templates/result.html` (nav, progress, code viewer polish, diff modal, sandbox tab).
- **Crawler**: `crawler.py` (scope/depth options, concurrency hooks, screenshot baseline/current storage).  
- **Scanning**: split modules `yara_scanner.py`, `clamav_scanner.py`, `behavior_signatures.py`; orchestrate in `scanner.py`.  
- **Sandbox**: `sandbox/executor.py` (separate process, caps, hooks) + serialize logs.  
- **Storage**: schema add: `scan_id`, `stage`, `backend_hits`, `behavior_hits`, `imagehash`, `diff_score`, `sandbox_log_ref`.  
- **Config**: `.env` (dotenv), CLI overrides via `argparse`, JSON fallback.  
- **CLI**: `cli.py` add flags `--backends`, `--scope`, `--depth`, `--sandbox`, `--output`; add `export` subcommand.

---

## 🔎 Decision Log
- **YARA vs ClamAV**: default to **YARA only** on low‑spec (Raspberry Pi) and CI; keep ClamAV optional for known binary coverage.  
- **Keep core lean**; heavy features behind flags; prefer modular scanners/sandbox.

---

## 🔐 Security Posture (dev)
- Run locally; avoid live execution by default.  
- If sandboxing: separate user/process, no outbound network, strict time/mem caps.  
- Keep DB/screenshots/exports out of VCS; sanitize logs; don’t store raw creds/cookies.

---

## 🤝 Contributing (short)
- Fork → feature branch → PR. Add docstrings/tests where possible.  
- Use issues for proposals; keep features modular.  
- Style: black/ruff (Python), prettier (web).

---

## 📌 Milestones
- **M1 (2 weeks)**: Quick wins complete; API skeleton; basic diffing.  
- **M2 (4–6 weeks)**: Behavioral signatures + sandbox v1 + concurrency.  
- **M3 (8+ weeks)**: Plugin API + timeline + packaging.

---

_“Stay lean. Add power only when it pays rent.”_  
