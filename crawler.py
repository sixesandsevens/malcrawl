
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
from crawl_session import CrawlSession, CancelCheck, StatusUpdate

log = with_ctx("malcrawl.crawler")


def reset_state():
    """Back-compat no-op: CrawlSession owns state now."""
    return


class CancelledError(Exception):
    """Raised when a scan is cancelled."""


def _default_cancel_check(_scan_id):
    return False


def _default_status_update(_scan_id, **_kw):
    return

def detect_browser():
    if shutil.which("chromedriver"):
        if shutil.which("google-chrome") or shutil.which("google-chrome-stable"):
            return "chrome"
        if shutil.which("chromium") or shutil.which("chromium-browser"):
            return "chromium"
        return "chrome"
    elif shutil.which("chromium") or shutil.which("chromium-browser"):
        return "chromium"
    elif shutil.which("geckodriver"):
        return "firefox"
    else:
        raise RuntimeError("No supported browser found (install Chromium/Chrome with a compatible driver, or geckodriver)")


def get_driver(browser="firefox"):
    if browser == "chrome" and shutil.which("chromedriver"):
        options = ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        if user_agent:
            options.add_argument(f"--user-agent={user_agent}")
        return webdriver.Chrome(service=ChromeService(shutil.which("chromedriver")), options=options)

    elif browser == "chromium" and (shutil.which("chromium") or shutil.which("chromium-browser")):
        binary = shutil.which("chromium") or shutil.which("chromium-browser")
        options = ChromeOptions()
        options.binary_location = binary
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        if user_agent:
            options.add_argument(f"--user-agent={user_agent}")
        driver_path = shutil.which("chromedriver")
        if driver_path:
            return webdriver.Chrome(service=ChromeService(driver_path), options=options)
        return webdriver.Chrome(options=options)

    elif browser == "firefox" and shutil.which("geckodriver"):
        options = FirefoxOptions()
        options.add_argument("--headless")
        if user_agent:
            options.set_preference("general.useragent.override", user_agent)
        return webdriver.Firefox(service=FirefoxService(shutil.which("geckodriver")), options=options)

    raise RuntimeError("No compatible WebDriver found for the selected browser")

def fetch_with_selenium(url, screenshot_path=None, browser="firefox", user_agent=None):
    """Fetch a page using Selenium with a bounded load time.

    Selenium's driver.get() can hang indefinitely if a page never finishes
    loading. To avoid blocking the crawl, a page-load timeout is set and the
    driver is always quit in a finally block. Optionally capture a screenshot
    when ``screenshot_path`` is provided.
    """

    from selenium.common.exceptions import WebDriverException

    driver = None
    try:
        print(f"[Selenium] Launching {browser} driver for {url}")
        driver = get_driver(browser, user_agent=user_agent)
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
    session: CrawlSession | None = None,
    cancel_check: CancelCheck | None = None,
    status_update: StatusUpdate | None = None,
):
    if session is None:
        session = CrawlSession(
            scan_id=scan_id,
            cancel_check=cancel_check or _default_cancel_check,
            status_update=status_update or _default_status_update,
        )
    else:
        # ensure scan_id and callbacks remain consistent across recursion
        session.scan_id = scan_id or session.scan_id
        if cancel_check is not None:
            session.cancel_check = cancel_check
        if status_update is not None:
            session.status_update = status_update

    st = session.state

    L = bind(log, scan_id=session.scan_id, url=url)
    if full_logging:
        L.debug("crawl.start", extra={"depth": depth, "render_js": render_js})
    if session.cancelled():
        raise CancelledError()
    if st.pages_seen >= MAX_PAGES:
        session.update(status="partial", phase="done", last_event="limit.pages")
        return
    if time.time() - st.start_time > MAX_RUNTIME_SECS:
        session.update(status="partial", phase="done", last_event="limit.time")
        return
    if st.scripts_seen >= MAX_SCRIPTS:
        session.update(status="partial", phase="done", last_event="limit.scripts")
        return
    if st.bytes_html >= MAX_BYTES_HTML:
        session.update(status="partial", phase="done", last_event="limit.bytes")
        return
    if url in st.visited or depth == 0:
        return
    st.visited.add(url)

    session.update(phase="fetch", current_url=url, last_event="fetch.start")

    L.info("fetch.start")

    headers = {"User-Agent": user_agent}
    html = None
    status_code = 200

    try:
        if render_js:
            if browser is None:
                browser = detect_browser()
            screenshot_path = None
            if include_screenshots:
                screenshot_name = sanitize_filename(url)
                screenshot_path = os.path.join("screenshots", screenshot_name)
            html = fetch_with_selenium(
                url,
                screenshot_path,
                browser=browser,
                user_agent=user_agent,
            )
            if html is None:
                if use_sqlite:
                    log_crawl_result(url, 0, 0, 0, [], status="error: selenium failure")
                session.update(
                    status="error",
                    phase="done",
                    last_event="fetch.error",
                    last_error="selenium failure",
                )
                return
        else:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            status_code = response.status_code
            html = response.text

        st.bytes_html += len(html or "")
        soup = BeautifulSoup(html, "html.parser")
        L.info(
            "fetch.done",
            extra={"status": status_code, "bytes": len(html or "")},
        )
    except Exception as e:
        if use_sqlite:
            log_crawl_result(url, 0, 0, 0, [], status=f"error: {e}")
        session.update(
            status="error",
            phase="done",
            last_event="fetch.error",
            last_error=str(e),
        )
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
        scan_id=session.scan_id,
        full_logging=full_logging,
        target_pattern=target_pattern,
        debug=debug,
        user_agent=user_agent,
    )

    st.scripts_seen += len(scripts)
    st.pages_seen += 1
    session.update(
        done=st.pages_seen,
        phase="scanning",
        current_url=url,
        items_crawled=st.pages_seen,
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
                bind(log, scan_id=session.scan_id, url=next_url).debug(
                    "enqueue", extra={"remaining_depth": depth - 1}
                )
            crawl(
                next_url,
                scan_id=session.scan_id,
                depth=depth - 1,
                use_sqlite=use_sqlite,
                user_agent=user_agent,
                render_js=render_js,
                browser=browser,
                include_screenshots=include_screenshots,
                target_pattern=target_pattern,
                debug=debug,
                full_logging=full_logging,
                session=session,
            )
            if session.cancelled():
                raise CancelledError()
