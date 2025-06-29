import sqlite3

DB_PATH = "malcrawl.db"

def log_crawl_result(url, num_links, num_images, num_videos, suspicious):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("INSERT INTO crawl_results (url, num_links, num_images, num_videos) VALUES (?, ?, ?, ?)",
                (url, num_links, num_images, num_videos))
    crawl_id = cur.lastrowid

    for issue in suspicious:
        cur.execute("INSERT INTO suspicious_findings (crawl_result_id, issue) VALUES (?, ?)", (crawl_id, issue))

    conn.commit()
    conn.close()
