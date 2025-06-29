from flask import send_from_directory
from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
from urllib.parse import urlparse
import os
import datetime
from threading import Thread
from crawler import crawl, sanitize_filename, reset_state
from crawler import stop_scan

app = Flask(__name__)

# Simple dictionary to expose crawl progress
SCAN_STATUS = {
    "current_url": "",
    "current_index": 0,
    "total": 0,
    "logs": [],
    "done": True,
    "domain": "",
    "stage": "idle",
}


def run_crawl(url, depth, ua, render_js, include_shots):
    """Background thread entry for crawl"""
    reset_state()
    crawl(
        url,
        depth=depth,
        use_sqlite=True,
        user_agent=ua,
        render_js=render_js,
        include_screenshots=include_shots,
        status=SCAN_STATUS,
    )
    SCAN_STATUS["total"] = SCAN_STATUS.get("current_index", 0)
    SCAN_STATUS["done"] = True
    SCAN_STATUS["stage"] = "complete"


@app.route("/start_scan", methods=["POST"])
def start_scan():
    """API endpoint to kick off a crawl asynchronously."""
    url = request.form.get("url")
    depth = int(request.form.get("depth", 2))
    ua = request.form.get("user_agent")
    render_js = request.form.get("render_js") == "on"
    include_shots = request.form.get("include_shots") == "on"

    if not url:
        return jsonify({"error": "URL required"}), 400

    domain = urlparse(url).netloc

    # reset status
    SCAN_STATUS.update(
        {
            "current_url": "",
            "current_index": 0,
            "total": 0,
            "logs": [],
            "done": False,
            "domain": domain,
            "stage": "queueing",
        }
    )

    thread = Thread(target=run_crawl, args=(url, depth, ua, render_js, include_shots))
    thread.daemon = True
    thread.start()

    return jsonify({"status": "started"})


@app.route("/scan-status")
def scan_status():
    """Return current crawl status."""
    return jsonify(SCAN_STATUS)


@app.route("/stop_scan", methods=["POST"])
def stop_scan_route():
    """Endpoint to stop an in-progress scan."""
    stop_scan()
    return jsonify({"status": "stopping"})

@app.route('/screenshots/<filename>')
def serve_screenshot(filename):
    return send_from_directory('screenshots', filename)


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

    return render_template("index.html", user_agents=user_agents, output_formats=output_formats, year=datetime.datetime.now().year)

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
        issues = [r[0] for r in cur.fetchall()]
        screenshot_name = sanitize_filename(url)
        screenshot_path = os.path.join("screenshots", screenshot_name)
        screenshot = screenshot_name if os.path.exists(screenshot_path) else None
        results.append({
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
    return jsonify({"domain": domain, "results": results})

if __name__ == "__main__":
    app.run(debug=True)
