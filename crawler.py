
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
):
    global pages_seen, scripts_seen, bytes_html
    if should_cancel(scan_id):
        raise CancelledError()
    if pages_seen >= MAX_PAGES:
        update_status(scan_id, status="partial", phase="done", errors=["Stopped: page_cap"])
        return
    if time.time() - start_time > MAX_RUNTIME_SECS:
        update_status(scan_id, status="partial", phase="done", errors=["Stopped: time_cap"])
        return
    if scripts_seen >= MAX_SCRIPTS:
        update_status(scan_id, status="partial", phase="done", errors=["Stopped: script_cap"])
        return
    if bytes_html >= MAX_BYTES_HTML:
        update_status(scan_id, status="partial", phase="done", errors=["Stopped: byte_cap"])
        return
    if url in visited or depth == 0:
        return
    visited.add(url)

    update_status(scan_id, phase="fetch", current_url=url)

    if render_js and browser is None:
        browser = detect_browser()

    log = logging.getLogger("crawler")
    log.info("fetch_start", extra={"extra": {"scan_id": scan_id, "url": url}})

    headers = {'User-Agent': user_agent}
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
                update_status(scan_id, status="error", phase="done", errors=["selenium failure"])
                return
        else:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            html = response.text

        bytes_html += len(html or "")
        soup = BeautifulSoup(html, 'html.parser')
    except Exception as e:
        if use_sqlite:
            log_crawl_result(url, 0, 0, 0, [], status=f"error: {e}")
        update_status(scan_id, status="error", phase="done", errors=[str(e)])
        return

    links = [a['href'] for a in soup.find_all('a', href=True)]
    images = [img['src'] for img in soup.find_all('img', src=True)]
    videos = [v['src'] for v in soup.find_all('video', src=True)]
    sources = [s['src'] for s in soup.find_all('source', src=True)]
    total_videos = len(videos) + len(sources)

    suspicious, scripts, inline_events, matches = scan_page(
        soup, url, target_pattern=target_pattern, debug=debug, user_agent=user_agent
    )

    scripts_seen += len(scripts)
    pages_seen += 1
    update_status(scan_id, done=pages_seen, phase="scanning", current_url=url)

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

    for a in links:
        next_url = urljoin(url, a)
        parsed = urlparse(next_url)
        if parsed.scheme in ('http', 'https'):
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
            )
            if should_cancel(scan_id):
                raise CancelledError()
