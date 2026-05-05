
import sqlite3
import os
import re
from urllib.parse import urlparse

DB_PATH = "malcrawl.db"

"""Utility functions for persisting crawl results to SQLite."""

# helper to name screenshot files

def sanitize_filename(url: str) -> str:
    parsed = urlparse(url)
    filename = f"{parsed.netloc}{parsed.path}".replace("/", "_").strip("_")
    return filename + ".png" if filename else "index.png"

# ensure core tables exist

def _ensure_base_tables(cur):
    cur.execute(
        """CREATE TABLE IF NOT EXISTS crawl_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            num_links INTEGER,
            num_images INTEGER,
            num_videos INTEGER,
            status TEXT DEFAULT 'success'
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS suspicious_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            crawl_result_id INTEGER,
            issue TEXT,
            FOREIGN KEY(crawl_result_id) REFERENCES crawl_results(id)
        )"""
    )


def _ensure_status_column(cur):
    cur.execute("PRAGMA table_info(crawl_results)")
    columns = [r[1] for r in cur.fetchall()]
    if 'status' not in columns:
        cur.execute("ALTER TABLE crawl_results ADD COLUMN status TEXT DEFAULT 'success'")


def _ensure_deob_table(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deobfuscated_scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            crawl_result_id INTEGER,
            original TEXT,
            deobfuscated TEXT,
            intent TEXT,
            target_hit INTEGER DEFAULT 0,
            FOREIGN KEY(crawl_result_id) REFERENCES crawl_results(id)
        )
        """
    )


def _ensure_target_hit_column(cur):
    """Ensure the `target_hit` column exists on deobfuscated_scripts."""
    cur.execute("PRAGMA table_info(deobfuscated_scripts)")
    columns = [r[1] for r in cur.fetchall()]
    if 'target_hit' not in columns:
        cur.execute(
            "ALTER TABLE deobfuscated_scripts ADD COLUMN target_hit INTEGER DEFAULT 0"
        )


def _ensure_signature_table(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS signature_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            crawl_result_id INTEGER,
            script_index INTEGER,
            tool TEXT,
            rule TEXT,
            snippet TEXT,
            FOREIGN KEY(crawl_result_id) REFERENCES crawl_results(id)
        )
        """
    )


def log_crawl_result(
    url,
    num_links,
    num_images,
    num_videos,
    suspicious,
    scripts=None,
    matches=None,
    status="success",
):
    """Persist a single crawl result and its findings."""

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_base_tables(cur)
    _ensure_status_column(cur)
    _ensure_deob_table(cur)
    _ensure_target_hit_column(cur)
    _ensure_signature_table(cur)

    cur.execute(
        "INSERT INTO crawl_results (url, num_links, num_images, num_videos, status) VALUES (?, ?, ?, ?, ?)",
        (url, num_links, num_images, num_videos, status),
    )
    crawl_id = cur.lastrowid

    for issue in suspicious:
        cur.execute(
            "INSERT INTO suspicious_findings (crawl_result_id, issue) VALUES (?, ?)",
            (crawl_id, issue),
        )

    if scripts:
        for item in scripts:
            cur.execute(
                "INSERT INTO deobfuscated_scripts (crawl_result_id, original, deobfuscated, intent, target_hit) VALUES (?, ?, ?, ?, ?)",
                (
                    crawl_id,
                    item.get("original"),
                    item.get("deobfuscated"),
                    item.get("intent"),
                    1 if item.get("target_hit") else 0,
                ),
            )

    if matches:
        for m in matches:
            cur.execute(
                "INSERT INTO signature_matches (crawl_result_id, script_index, tool, rule, snippet) VALUES (?, ?, ?, ?, ?)",
                (
                    crawl_id,
                    m.get("script_index"),
                    m.get("tool"),
                    m.get("rule"),
                    m.get("snippet"),
                ),
            )

    conn.commit()
    conn.close()
    return crawl_id


def fetch_results(domain: str, *, as_dataclass: bool = False) -> list:
    from result_schema import CrawlResult, InlineEvent, ScriptArtifact, SignatureMatch

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_base_tables(cur)
    _ensure_deob_table(cur)
    _ensure_signature_table(cur)
    _ensure_status_column(cur)
    _ensure_target_hit_column(cur)
    cur.execute(
        "SELECT * FROM crawl_results WHERE url LIKE ? ORDER BY timestamp DESC",
        (f"%{domain}%",),
    )
    crawl_data = cur.fetchall()
    results = []
    for row in crawl_data:
        crawl_id, url, timestamp, links, images, videos, status = row
        cur.execute(
            "SELECT issue FROM suspicious_findings WHERE crawl_result_id=?",
            (crawl_id,),
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
    if not as_dataclass:
        return results
    return [
        CrawlResult(
            id=r["id"],
            url=r["url"],
            timestamp=r["timestamp"],
            links=r["links"],
            images=r["images"],
            videos=r["videos"],
            issues=list(r["issues"]),
            inline_events=[InlineEvent(**e) for e in r["inline_events"]],
            deobfuscated_scripts=[ScriptArtifact(**s) for s in r["deobfuscated_scripts"]],
            signatures=[SignatureMatch(**m) for m in r["signatures"]],
            screenshot=r["screenshot"],
            status=r["status"],
        )
        for r in results
    ]

# Utility helpers


def list_scans(page: int = 1, limit: int = 50):
    """Return a paginated list of scans."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_base_tables(cur)
    _ensure_status_column(cur)
    off = (page - 1) * limit
    cur.execute("SELECT COUNT(*) FROM crawl_results")
    total = cur.fetchone()[0]
    cur.execute(
        """SELECT id, url as domain, timestamp as started_at, timestamp as finished_at, status
           FROM crawl_results ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
        (limit, off),
    )
    items = [dict(zip([c[0] for c in cur.description], row)) for row in cur.fetchall()]
    conn.close()
    return items, total


def get_scan(scan_id: int):
    """Return a single scan's metadata."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_base_tables(cur)
    _ensure_status_column(cur)
    cur.execute(
        """SELECT id, url as domain, timestamp as started_at, timestamp as finished_at, status
           FROM crawl_results WHERE id=?""",
        (scan_id,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    data = dict(zip([c[0] for c in cur.description], row))
    conn.close()
    return data


def get_results_for_scan(scan_id: int, page: int = 1, limit: int = 100):
    """Return suspicious findings for a scan."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_base_tables(cur)
    off = (page - 1) * limit
    cur.execute(
        "SELECT COUNT(*) FROM suspicious_findings WHERE crawl_result_id=?",
        (scan_id,),
    )
    total = cur.fetchone()[0]
    cur.execute(
        """SELECT id, issue FROM suspicious_findings
           WHERE crawl_result_id=? LIMIT ? OFFSET ?""",
        (scan_id, limit, off),
    )
    rows = [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]
    conn.close()
    return rows, total


def fetch_result(result_id: int, *, as_dataclass: bool = False):
    """Load a single scan result by ID."""
    from result_schema import CrawlResult, InlineEvent, ScriptArtifact, SignatureMatch

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_base_tables(cur)
    _ensure_deob_table(cur)
    _ensure_signature_table(cur)
    _ensure_status_column(cur)
    _ensure_target_hit_column(cur)
    cur.execute("SELECT * FROM crawl_results WHERE id=?", (result_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    crawl_id, url, timestamp, links, images, videos, status = row
    cur.execute(
        "SELECT issue FROM suspicious_findings WHERE crawl_result_id=?",
        (crawl_id,),
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
    cur.execute(
        "SELECT original, deobfuscated, intent, target_hit FROM deobfuscated_scripts WHERE crawl_result_id=?",
        (crawl_id,),
    )
    scripts = []
    for o, d, i, th in cur.fetchall():
        scripts.append(
            {
                "original": o,
                "deobfuscated": d,
                "intent": i,
                "changed": (d or "").strip() != (o or "").strip(),
                "target_hit": bool(th),
            }
        )
    cur.execute(
        "SELECT script_index, tool, rule, snippet FROM signature_matches WHERE crawl_result_id=?",
        (crawl_id,),
    )
    signatures = [
        {"script_index": r[0], "tool": r[1], "rule": r[2], "snippet": r[3]}
        for r in cur.fetchall()
    ]
    screenshot_name = sanitize_filename(url)
    screenshot_path = os.path.join("screenshots", screenshot_name)
    screenshot = screenshot_name if os.path.exists(screenshot_path) else None
    conn.close()
    data = {
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
    }
    if not as_dataclass:
        return data
    return CrawlResult(
        id=data["id"],
        url=data["url"],
        timestamp=data["timestamp"],
        links=data["links"],
        images=data["images"],
        videos=data["videos"],
        issues=list(data["issues"]),
        inline_events=[InlineEvent(**e) for e in data["inline_events"]],
        deobfuscated_scripts=[ScriptArtifact(**s) for s in data["deobfuscated_scripts"]],
        signatures=[SignatureMatch(**m) for m in data["signatures"]],
        screenshot=data["screenshot"],
        status=data["status"],
    )
