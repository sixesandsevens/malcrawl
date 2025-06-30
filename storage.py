import sqlite3

DB_PATH = "malcrawl.db"

"""Utility functions for persisting crawl results to SQLite."""

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


def log_crawl_result(
    url,
    num_links,
    num_images,
    num_videos,
    suspicious,
    scripts=None,
    status="success",
):
    """Persist a single crawl result and its findings."""

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _ensure_status_column(cur)
    _ensure_deob_table(cur)

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

    conn.commit()
    conn.close()
    return crawl_id
