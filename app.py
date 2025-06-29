from flask import send_from_directory
from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from urllib.parse import urlparse
from crawler import crawl

app = Flask(__name__)

@app.route('/screenshots/<filename>')
def serve_screenshot(filename):
    return send_from_directory('screenshots', filename)


@app.route("/", methods=["GET", "POST"])
def index():
    user_agents = [
        "MalCrawlBot/0.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/113.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
        "curl/7.68.0"
    ]
    output_formats = ["html", "json", "zip"]

    if request.method == "POST":
        url = request.form.get("url")
        depth = int(request.form.get("depth", 2))
        ua = request.form.get("user_agent")
        render_js = request.form.get("render_js") == "on"
        out_format = request.form.get("output_format")

        if url:
            crawl(url, depth=depth, use_sqlite=True, user_agent=ua, render_js=render_js)
            domain = urlparse(url).netloc
            return redirect(url_for("site_results", domain=domain))

    return render_template("index.html", user_agents=user_agents, output_formats=output_formats)

@app.route("/site/<path:domain>")
def site_results(domain):
    conn = sqlite3.connect("malcrawl.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM crawl_results WHERE url LIKE ? ORDER BY timestamp DESC", (f"%{domain}%",))
    crawl_data = cur.fetchall()

    results = []
    for row in crawl_data:
        crawl_id, url, timestamp, links, images, videos = row
        cur.execute("SELECT issue FROM suspicious_findings WHERE crawl_result_id = ?", (crawl_id,))
        issues = [r[0] for r in cur.fetchall()]
        results.append({
            "url": url,
            "timestamp": timestamp,
            "links": links,
            "images": images,
            "videos": videos,
            "issues": issues
        })

    conn.close()
    return render_template("results.html", results=results, domain=domain)

if __name__ == "__main__":
    app.run(debug=True)
