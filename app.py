

from flask import send_from_directory
from flask import Flask, render_template, request, url_for, jsonify
from markupsafe import Markup, escape
import re
import sqlite3
from urllib.parse import urlparse
import os, logging, json, uuid
from logging.handlers import RotatingFileHandler
from datetime import datetime
import sys
import io
import contextlib
from threading import Thread

from crawler import crawl, sanitize_filename, reset_state, CancelledError
from storage import list_scans, get_scan, get_results_for_scan
from config import (
    MAX_PAGES,
    LOG_DIR,
    LOG_LEVEL,
    LOG_TO_CONSOLE,
    LOG_JSON,
    LOG_ROTATE_MB,
    LOG_ROTATE_BACKUPS,
)
from logging_utils import with_ctx, bind

app = Flask(__name__)

os.makedirs(LOG_DIR, exist_ok=True)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        base = {
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        # include any additional attributes on the record (scan_id, url, etc.)
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in (
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
            ):
                continue
            base[key] = value
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False)


def setup_logging():
    root = logging.getLogger()
    root.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
    fh = RotatingFileHandler(
        os.path.join(LOG_DIR, "malcrawl.log"),
        maxBytes=LOG_ROTATE_MB * 1024 * 1024,
        backupCount=LOG_ROTATE_BACKUPS,
    )
    formatter = (
        JsonFormatter()
        if LOG_JSON
        else logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    fh.setFormatter(formatter)
    root.addHandler(fh)
    if LOG_TO_CONSOLE:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        root.addHandler(ch)


setup_logging()
log = logging.getLogger("malcrawl.app")
LOG_POSITIONS: dict[str, int] = {}
FULL_LOGGING = False

# Highlight suspicious JavaScript keywords
BAD_JS_RE = re.compile(r"(eval\(|document\.write|innerHTML)")


def highlight_bad(code: str) -> Markup:
    """Return HTML with risky JS functions emphasized."""
    escaped = escape(code)
    highlighted = BAD_JS_RE.sub(lambda m: f'<span class="text-danger fw-bold">{m.group(0)}</span>', escaped)
    return Markup(highlighted)

app.add_template_filter(highlight_bad, "highlight_bad")
API_TOKEN = os.getenv("MALCRAWL_API_TOKEN")

SCAN_STATUS = {}
CANCEL_FLAGS = set()


def require_token():
    token = request.headers.get("X-API-Token")
    if not API_TOKEN or token == API_TOKEN:
        return
    return jsonify({"error": "unauthorized"}), 401


def new_scan_status(domain: str) -> str:
    sid = uuid.uuid4().hex
    SCAN_STATUS[sid] = {
        "scan_id": sid,
        "domain": domain,
        "phase": "queue",
        "done": 0,
        "total": 0,
        "current_url": None,
        "elapsed": 0.0,
        "status": "running",
        "errors": [],
    }
    return sid


@app.before_request
def log_request():
    """Log basic request information."""
    bind(log, url=request.path, method=request.method, remote_addr=request.remote_addr).info(
        "http.request"
    )


@app.after_request
def log_response(response):
    """Log response details after handling a request."""
    bind(
        log,
        url=request.path,
        method=request.method,
        status=response.status_code,
    ).info("http.response")
    return response


@app.get("/scan-status/<scan_id>")
def scan_status(scan_id):
    return jsonify(SCAN_STATUS.get(scan_id) or {"error": "not_found"})


@app.post("/scan-cancel/<scan_id>")
def scan_cancel(scan_id):
    if scan_id in SCAN_STATUS:
        CANCEL_FLAGS.add(scan_id)
        SCAN_STATUS[scan_id]["status"] = "cancelling"
        log.info("scan_cancel", extra={"extra": {"scan_id": scan_id}})
        return jsonify({"ok": True})
    log.warning("scan_cancel_not_found", extra={"extra": {"scan_id": scan_id}})
    return jsonify({"error": "not_found"}), 404


@app.get("/scan-log/<scan_id>")
def scan_log(scan_id):
    """Return incremental log lines for the given scan."""
    log_path = os.path.join("logs", "malcrawl.log")
    pos = LOG_POSITIONS.get(scan_id, 0)
    lines: list[str] = []
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as fh:
            fh.seek(pos)
            for line in fh:
                if f'"scan_id": "{scan_id}"' in line:
                    lines.append(line.rstrip())
            LOG_POSITIONS[scan_id] = fh.tell()
    return jsonify({"lines": lines})


@app.get("/logs/<scan_id>")
def get_logs(scan_id):
    path = os.path.join(LOG_DIR, "malcrawl.log")
    if not os.path.exists(path):
        return jsonify([])
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("scan_id") == scan_id:
                rows.append(obj)
    return jsonify(rows[-500:])


@app.get("/api/scans")
def api_scans():
    auth = require_token()
    if auth:
        return auth
    page = int(request.args.get("page", 1))
    limit = min(int(request.args.get("limit", 50)), 200)
    scans, total = list_scans(page=page, limit=limit)
    return jsonify({"items": scans, "page": page, "limit": limit, "total": total})


@app.get("/api/scans/<scan_id>")
def api_scan(scan_id):
    auth = require_token()
    if auth:
        return auth
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not_found"}), 404
    return jsonify(scan)


@app.get("/api/scans/<scan_id>/results")
def api_scan_results(scan_id):
    auth = require_token()
    if auth:
        return auth
    page = int(request.args.get("page", 1))
    limit = min(int(request.args.get("limit", 100)), 500)
    rows, total = get_results_for_scan(scan_id, page=page, limit=limit)
    return jsonify({"items": rows, "page": page, "limit": limit, "total": total})


def run_crawl(scan_id, url, depth, ua, render_js, include_shots, target, debug, full_logging):
    """Background thread entry for crawl"""
    reset_state()
    start = datetime.datetime.utcnow()
    bind(
        log,
        scan_id=scan_id,
        url=url,
    ).info(
        "scan.thread_start",
        extra={
            "depth": depth,
            "render_js": render_js,
            "screenshots": include_shots,
            "target": target,
            "debug": debug,
        },
    )
    try:
        crawl(
            url,
            scan_id=scan_id,
            depth=depth,
            use_sqlite=True,
            user_agent=ua,
            render_js=render_js,
            include_screenshots=include_shots,
            target_pattern=target,
            debug=debug,
            full_logging=full_logging,
        )
        if SCAN_STATUS.get(scan_id, {}).get("status") == "running":
            SCAN_STATUS[scan_id]["phase"] = "done"
            SCAN_STATUS[scan_id]["status"] = "completed"
    except CancelledError:
        SCAN_STATUS[scan_id]["phase"] = "done"
        SCAN_STATUS[scan_id]["status"] = "cancelled"
    except Exception as exc:
        SCAN_STATUS[scan_id]["phase"] = "done"
        SCAN_STATUS[scan_id]["status"] = "error"
        SCAN_STATUS[scan_id].setdefault("errors", []).append(str(exc))
    finally:
        SCAN_STATUS[scan_id]["elapsed"] = (datetime.datetime.utcnow() - start).total_seconds()
        log.info(
            "scan_thread_end",
            extra={
                "extra": {
                    "scan_id": scan_id,
                    "status": SCAN_STATUS[scan_id].get("status"),
                    "elapsed": SCAN_STATUS[scan_id].get("elapsed"),
                }
            },
        )


@app.route("/start_scan", methods=["POST"])
def start_scan():
    """API endpoint to kick off a crawl asynchronously."""
    url = request.form.get("url")
    depth = int(request.form.get("depth", 2))
    ua = request.form.get("user_agent")
    render_js = request.form.get("render_js") == "on"
    include_shots = request.form.get("include_shots") == "on"
    target = request.form.get("target_pattern")
    debug = request.form.get("debug_mode") == "on"
    full_logging = request.form.get("full_logging") == "1"

    global FULL_LOGGING
    FULL_LOGGING = full_logging

    if not url:
        return jsonify({"error": "URL required"}), 400

    domain = urlparse(url).netloc
    scan_id = new_scan_status(domain)
    SCAN_STATUS[scan_id]["total"] = MAX_PAGES
    SCAN_STATUS[scan_id]["full_logging"] = full_logging

    scan_log = bind(with_ctx("malcrawl.scan"), scan_id=scan_id)
    if full_logging:
        logging.getLogger().setLevel(logging.DEBUG)
        scan_log.info("full_logging enabled for this scan")
    else:
        logging.getLogger().setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    LOG_POSITIONS[scan_id] = (
        os.path.getsize(os.path.join(LOG_DIR, "malcrawl.log"))
        if os.path.exists(os.path.join(LOG_DIR, "malcrawl.log"))
        else 0
    )

    bind(log, scan_id=scan_id, url=url).info(
        "scan.start",
        extra={
            "depth": depth,
            "user_agent": ua,
            "render_js": render_js,
            "screenshots": include_shots,
            "target": target,
            "debug": debug,
        },
    )

    thread = Thread(
        target=run_crawl,
        args=(
            scan_id,
            url,
            depth,
            ua,
            render_js,
            include_shots,
            target,
            debug,
            full_logging,
        ),
    )
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id})

@app.route('/screenshots/<filename>')
def serve_screenshot(filename):
    return send_from_directory('screenshots', filename)


@app.route("/recent")
def recent_scans():
    """List domains from the most recent crawl results."""
    conn = sqlite3.connect("malcrawl.db")
    cur = conn.cursor()
    cur.execute("SELECT url FROM crawl_results ORDER BY timestamp DESC LIMIT 50")
    seen = []
    domains = []
    for (url,) in cur.fetchall():
        domain = urlparse(url).netloc
        if domain not in seen:
            seen.append(domain)
            domains.append(domain)
    conn.close()
    return render_template("recent.html", domains=domains, year=datetime.datetime.now().year)


@app.route("/signatures")
def signatures_page():
    """Placeholder page for signature management."""
    return render_template("signatures.html", year=datetime.datetime.now().year)


@app.get("/logs")
def view_logs():
    return render_template("logs.html", year=datetime.datetime.now().year)


@app.route("/", methods=["GET"])
def index():
    """Render the main form."""
    user_agents = [
        "MalCrawlBot/0.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/113.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
        "curl/7.68.0"
    ]
    output_formats = ["html", "json", "zip"]

    return render_template(
        "index.html",
        user_agents=user_agents,
        output_formats=output_formats,
        full_logging=FULL_LOGGING,
        year=datetime.datetime.now().year,
    )

@app.route("/site/<path:domain>")
def site_results(domain):
    """Display stored crawl results for a given domain."""
    conn = sqlite3.connect("malcrawl.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM crawl_results WHERE url LIKE ? ORDER BY timestamp DESC", (f"%{domain}%",))
    crawl_data = cur.fetchall()

    results = []
    for row in crawl_data:
        crawl_id, url, timestamp, links, images, videos, status = row
        cur.execute(
            "SELECT issue FROM suspicious_findings WHERE crawl_result_id = ?",
            (crawl_id,))
        issues = [r[0] for r in cur.fetchall()]

        # Check if a screenshot was captured for this URL
        screenshot_name = sanitize_filename(url)
        screenshot_path = os.path.join("screenshots", screenshot_name)
        screenshot = screenshot_name if os.path.exists(screenshot_path) else None

        results.append({
            "id": crawl_id,
            "url": url,
            "timestamp": timestamp,
            "links": links,
            "images": images,
            "videos": videos,
            "issues": issues,
            "screenshot": screenshot,
            "status": status,
        })

    conn.close()
    return render_template("results.html", results=results, domain=domain, year=datetime.datetime.now().year)


def load_result(result_id):
    conn = sqlite3.connect("malcrawl.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM crawl_results WHERE id = ?",
        (result_id,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    cur.execute(
        "SELECT issue FROM suspicious_findings WHERE crawl_result_id = ?",
        (result_id,),
    )
    raw_issues = [r[0] for r in cur.fetchall()]
    issues = []
    inline_events = []
    for i in raw_issues:
        if i.startswith("Inline JS event:"):
            m = re.search(r"Inline JS event: <([^>]+)> - (\w+)", i)
            if m:
                inline_events.append({"event": m.group(2), "tag": m.group(1)})
        else:
            issues.append(i)

    try:
        cur.execute(
            "SELECT original, deobfuscated, intent, target_hit FROM deobfuscated_scripts WHERE crawl_result_id = ?",
            (result_id,),
        )
        scripts = []
        for o, d, i, th in cur.fetchall():
            if not (o or '').strip() and not (d or '').strip():
                continue
            scripts.append({
                "original": o,
                "deobfuscated": d,
                "intent": i,
                "changed": (d or "").strip() != (o or "").strip(),
                "target_hit": bool(th),
            })
    except sqlite3.OperationalError:
        scripts = []

    try:
        cur.execute(
            "SELECT script_index, tool, rule, snippet FROM signature_matches WHERE crawl_result_id = ?",
            (result_id,),
        )
        signatures = [
            {
                "script_index": r[0],
                "tool": r[1],
                "rule": r[2],
                "snippet": r[3],
            }
            for r in cur.fetchall()
        ]
    except sqlite3.OperationalError:
        signatures = []
    screenshot_name = sanitize_filename(row["url"])
    screenshot_path = os.path.join("screenshots", screenshot_name)
    screenshot = screenshot_name if os.path.exists(screenshot_path) else None

    conn.close()

    return {
        "id": row["id"],
        "url": row["url"],
        "timestamp": row["timestamp"],
        "links": row["num_links"],
        "images": row["num_images"],
        "videos": row["num_videos"],
        "issues": issues,
        "inline_events": inline_events,
        "deobfuscated_scripts": scripts,
        "signatures": signatures,
        "screenshot": screenshot,
        "status": row["status"],
    }


@app.route("/result/<result_id>")
def view_result(result_id):
    """Display full details for a single crawl entry."""
    result = load_result(result_id)
    if result:
        domain = urlparse(result["url"]).netloc
        shots = []
        if result.get("screenshot"):
            shots.append({"url": url_for('serve_screenshot', filename=result["screenshot"])})
        return render_template(
            "result.html",
            result=result,
            domain=domain,
            screenshots=shots,
            scan_id=request.args.get("scan_id"),
            year=datetime.datetime.now().year,
        )
    else:
        return "Scan not found", 404


@app.route("/export/<path:domain>.json")
def export_json(domain):
    """Export crawl results for a domain as JSON."""
    conn = sqlite3.connect("malcrawl.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM crawl_results WHERE url LIKE ? ORDER BY timestamp DESC", (f"%{domain}%",))
    crawl_data = cur.fetchall()

    results = []
    for row in crawl_data:
        crawl_id, url, timestamp, links, images, videos, status = row
        cur.execute("SELECT issue FROM suspicious_findings WHERE crawl_result_id = ?", (crawl_id,))
        raw_issues = [r[0] for r in cur.fetchall()]
        issues = []
        inline_events = []
        for i in raw_issues:
            if i.startswith("Inline JS event:"):
                m = re.search(r"Inline JS event: <([^>]+)> - (\w+)", i)
                if m:
                    inline_events.append({"event": m.group(2), "tag": m.group(1)})
            else:
                issues.append(i)
        cur.execute(
            "SELECT original, deobfuscated, intent, target_hit FROM deobfuscated_scripts WHERE crawl_result_id=?",
            (crawl_id,),
        )
        scripts = []
        for o, d, i, th in cur.fetchall():
            scripts.append({
                "original": o,
                "deobfuscated": d,
                "intent": i,
                "changed": (d or "").strip() != (o or "").strip(),
                "target_hit": bool(th),
            })
        cur.execute(
            "SELECT script_index, tool, rule, snippet FROM signature_matches WHERE crawl_result_id=?",
            (crawl_id,),
        )
        signatures = [
            {
                "script_index": r[0],
                "tool": r[1],
                "rule": r[2],
                "snippet": r[3],
            }
            for r in cur.fetchall()
        ]
        screenshot_name = sanitize_filename(url)
        screenshot_path = os.path.join("screenshots", screenshot_name)
        screenshot = screenshot_name if os.path.exists(screenshot_path) else None
        results.append({
            "id": crawl_id,
            "url": url,
            "timestamp": timestamp,
            "links": links,
            "images": images,
            "videos": videos,
            "issues": issues,
            "inline_events": inline_events,
            "deobfuscated_scripts": scripts,
            "signatures": signatures,
            "screenshot": screenshot,
            "status": status,
        })

    conn.close()
    return jsonify({"domain": domain, "results": results})

if __name__ == "__main__":
    app.run(debug=True)
