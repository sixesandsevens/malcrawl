
import os
import shutil
import requests
import time
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import (
    DEFAULT_USER_AGENT,
    TIMEOUT,
    MAX_PAGES,
    MAX_RUNTIME_SECS,
    MAX_SCRIPTS,
    MAX_BYTES_HTML,
)
from scanner import scan_page
from storage import log_crawl_result
from logging_utils import with_ctx, bind

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions

visited = set()
pages_seen = 0
scripts_seen = 0
bytes_html = 0
start_time = 0.0

log = with_ctx("malcrawl.crawler")


def reset_state():
    """Reset counters for a new crawl run."""
    global visited, pages_seen, scripts_seen, bytes_html, start_time
    visited = set()
    pages_seen = 0
    scripts_seen = 0
    bytes_html = 0
    start_time = time.time()


class CancelledError(Exception):
    """Raised when a scan is cancelled."""


def should_cancel(scan_id):
    from app import CANCEL_FLAGS
    return scan_id in CANCEL_FLAGS


def update_status(scan_id, **kw):
    from app import SCAN_STATUS
    st = SCAN_STATUS.get(scan_id)
    if st:
        st.update(kw)

def detect_browser():
    if shutil.which("chromedriver"):
        return "chrome"
    elif shutil.which("chromium-browser"):
        return "chromium"
    elif shutil.which("geckodriver"):
        return "firefox"
    else:
        raise RuntimeError("No supported WebDriver found (install geckodriver, chromedriver, or chromium-browser)")

def get_driver(browser="firefox"):
    if browser == "chrome" and shutil.which("chromedriver"):
        options = ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        return webdriver.Chrome(service=ChromeService(shutil.which("chromedriver")), options=options)

    elif browser == "chromium" and shutil.which("chromium-browser"):
        options = ChromeOptions()
        options.binary_location = shutil.which("chromium-browser")
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        return webdriver.Chrome(service=ChromeService(shutil.which("chromedriver")), options=options)

    elif browser == "firefox" and shutil.which("geckodriver"):
        options = FirefoxOptions()
        options.add_argument("--headless")
        return webdriver.Firefox(service=FirefoxService(shutil.which("geckodriver")), options=options)

    raise RuntimeError("No compatible WebDriver found for the selected browser")

def fetch_with_selenium(url, screenshot_path=None, browser="firefox"):
    """Fetch a page using Selenium with a bounded load time.

    Selenium's driver.get() can hang indefinitely if a page never finishes
    loading. To avoid blocking the crawl, a page-load timeout is set and the
    driver is always quit in a finally block. Optionally capture a screenshot
    when ``screenshot_path`` is provided.
    """

    driver = None
    try:
        print(f"[Selenium] Launching {browser} driver for {url}")
        driver = get_driver(browser)
        driver.set_page_load_timeout(TIMEOUT)
        driver.get(url)

        if screenshot_path:
            print(f"[Selenium] Saving screenshot to {screenshot_path}")
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            driver.save_screenshot(screenshot_path)

        return driver.page_source
    except WebDriverException as e:
        print(f"[Selenium Error] {e}")
        return None
    finally:
        if driver:
            driver.quit()
            print("[Selenium] Driver closed")

def sanitize_filename(url):
    parsed = urlparse(url)
    filename = f"{parsed.netloc}{parsed.path}".replace("/", "_").strip("_")
    return filename + ".png" if filename else "index.png"

def crawl(
    url,
    scan_id=None,
    depth=2,
    use_sqlite=False,
    user_agent=DEFAULT_USER_AGENT,
    render_js=False,
    browser=None,
    include_screenshots=False,
    target_pattern=None,
    debug=False,
    full_logging=False,
):
    global pages_seen, scripts_seen, bytes_html
    L = bind(log, scan_id=scan_id, url=url)
    if full_logging:
        L.debug("crawl.start", extra={"depth": depth, "render_js": render_js})
    if should_cancel(scan_id):
        raise CancelledError()
    if pages_seen >= MAX_PAGES:
        update_status(scan_id, status="partial", phase="done", last_event="limit.pages")
        return
    if time.time() - start_time > MAX_RUNTIME_SECS:
        update_status(scan_id, status="partial", phase="done", last_event="limit.time")
        return
    if scripts_seen >= MAX_SCRIPTS:
        update_status(scan_id, status="partial", phase="done", last_event="limit.scripts")
        return
    if bytes_html >= MAX_BYTES_HTML:
        update_status(scan_id, status="partial", phase="done", last_event="limit.bytes")
        return
    if url in visited or depth == 0:
        return
    visited.add(url)

    update_status(scan_id, phase="fetch", current_url=url, last_event="fetch.start")

    if render_js and browser is None:
        browser = detect_browser()

    L.info("fetch.start")

    headers = {"User-Agent": user_agent}
    html = None

    try:
        if render_js:
            screenshot_path = None
            if include_screenshots:
                screenshot_name = sanitize_filename(url)
                screenshot_path = os.path.join("screenshots", screenshot_name)
            html = fetch_with_selenium(url, screenshot_path, browser=browser)
            if html is None:
                if use_sqlite:
                    log_crawl_result(url, 0, 0, 0, [], status="error: selenium failure")
                update_status(scan_id, status="error", phase="done", last_event="fetch.error", last_error="selenium failure")
                return
        else:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            html = response.text

        bytes_html += len(html or "")
        soup = BeautifulSoup(html, "html.parser")
        L.info(
            "fetch.done",
            extra={"status": getattr(response, "status_code", 200), "bytes": len(html or "")},
        )
    except Exception as e:
        if use_sqlite:
            log_crawl_result(url, 0, 0, 0, [], status=f"error: {e}")
        update_status(scan_id, status="error", phase="done", last_event="fetch.error", last_error=str(e))
        L.error("fetch.error", exc_info=True)
        return

    if full_logging:
        L.debug("parse.start")

    links = [a["href"] for a in soup.find_all("a", href=True)]
    images = [img["src"] for img in soup.find_all("img", src=True)]
    videos = [v["src"] for v in soup.find_all("video", src=True)]
    sources = [s["src"] for s in soup.find_all("source", src=True)]
    total_videos = len(videos) + len(sources)

    suspicious, scripts, inline_events, matches = scan_page(
        soup,
        url,
        scan_id=scan_id,
        full_logging=full_logging,
        target_pattern=target_pattern,
        debug=debug,
        user_agent=user_agent,
    )

    scripts_seen += len(scripts)
    pages_seen += 1
    update_status(
        scan_id,
        done=pages_seen,
        phase="scanning",
        current_url=url,
        items_crawled=pages_seen,
        last_event="scan.page",
    )

    if use_sqlite:
        log_crawl_result(
            url,
            len(links),
            len(images),
            total_videos,
            suspicious,
            scripts=scripts,
            matches=matches,
            status="success",
        )

    L.info(
        "links.discovered",
        extra={"links": len(links), "images": len(images), "videos": total_videos},
    )

    for a in links:
        next_url = urljoin(url, a)
        parsed = urlparse(next_url)
        if parsed.scheme in ("http", "https"):
            if full_logging:
                bind(log, scan_id=scan_id, url=next_url).debug(
                    "enqueue", extra={"remaining_depth": depth - 1}
                )
            crawl(
                next_url,
                scan_id=scan_id,
                depth=depth - 1,
                use_sqlite=use_sqlite,
                user_agent=user_agent,
                render_js=render_js,
                browser=browser,
                include_screenshots=include_screenshots,
                target_pattern=target_pattern,
                debug=debug,
                full_logging=full_logging,
            )
            if should_cancel(scan_id):
                raise CancelledError()
