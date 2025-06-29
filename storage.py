import sqlite3

DB_PATH = "malcrawl.db"

"""Utility functions for persisting crawl results to SQLite."""

def _ensure_status_column(cur):
    cur.execute("PRAGMA table_info(crawl_results)")
    columns = [r[1] for r in cur.fetchall()]
    if 'status' not in columns:
        cur.execute("ALTER TABLE crawl_results ADD COLUMN status TEXT DEFAULT 'success'")


def log_crawl_result(url, num_links, num_images, num_videos, suspicious, status="success"):
    """Persist a single crawl result and its findings."""

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_status_column(cur)

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

    conn.commit()
    conn.close()
