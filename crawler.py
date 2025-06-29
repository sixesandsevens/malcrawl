
import os
import shutil
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import DEFAULT_USER_AGENT, TIMEOUT
from scanner import scan_page
from storage import log_crawl_result

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions

visited = set()
_stop = False


def reset_state():
    """Reset visited cache for a new crawl run."""
    global visited, _stop
    visited = set()
    _stop = False

def stop_scan():
    """Signal the crawler to stop as soon as possible."""
    global _stop
    _stop = True

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
    try:
        driver = get_driver(browser)
        driver.get(url)
        if screenshot_path:
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            driver.save_screenshot(screenshot_path)
        html = driver.page_source
        driver.quit()
        return html
    except WebDriverException as e:
        print(f"[Selenium Error] {e}")
        return None

def sanitize_filename(url):
    parsed = urlparse(url)
    filename = f"{parsed.netloc}{parsed.path}".replace("/", "_").strip("_")
    return filename + ".png" if filename else "index.png"

def crawl(
    url,
    depth=2,
    use_sqlite=False,
    user_agent=DEFAULT_USER_AGENT,
    render_js=False,
    browser=None,
    include_screenshots=False,
    status=None,
):
    if _stop:
        if status is not None:
            status.setdefault("logs", []).append("Scan stopped")
            status["done"] = True
        return
    if url in visited or depth == 0:
        return
    visited.add(url)

    if status is not None:
        status["current_url"] = url
        status["current_index"] += 1
        status.setdefault("logs", []).append(f"Scanning {url}")
        status["stage"] = "fetching"

    if render_js and browser is None:
        browser = detect_browser()

    print(f"[Crawl] {url} using {'Selenium' if render_js else 'requests'}")

    headers = {'User-Agent': user_agent}
    html = None

    try:
        if render_js:
            if status is not None:
                status["stage"] = "rendering"
            screenshot_path = None
            if include_screenshots:
                screenshot_name = sanitize_filename(url)
                screenshot_path = os.path.join("screenshots", screenshot_name)
            html = fetch_with_selenium(url, screenshot_path, browser=browser)
            if html is None:
                if use_sqlite:
                    log_crawl_result(url, 0, 0, 0, [], status="error: selenium failure")
                return
        else:
            if status is not None:
                status["stage"] = "fetching"
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            html = response.text

        soup = BeautifulSoup(html, 'html.parser')
        if status is not None:
            status["stage"] = "scanning"
    except Exception as e:
        print(f"[Error] Failed to fetch {url}: {e}")
        if status is not None:
            status.setdefault("logs", []).append(f"Error fetching {url}: {e}")
        if use_sqlite:
            log_crawl_result(url, 0, 0, 0, [], status=f"error: {e}")
        return

    links = [a['href'] for a in soup.find_all('a', href=True)]
    images = [img['src'] for img in soup.find_all('img', src=True)]
    videos = [v['src'] for v in soup.find_all('video', src=True)]
    sources = [s['src'] for s in soup.find_all('source', src=True)]
    total_videos = len(videos) + len(sources)

    suspicious, scripts = scan_page(soup, url)

    if status is not None:
        if suspicious:
            status.setdefault("logs", []).append(f"{url} - {len(suspicious)} findings")
        else:
            status.setdefault("logs", []).append(f"{url} - clean")

    if use_sqlite:
        log_crawl_result(
            url,
            len(links),
            len(images),
            total_videos,
            suspicious,
            scripts=scripts,
            status="success",
        )

    for a in links:
        next_url = urljoin(url, a)
        parsed = urlparse(next_url)
        if parsed.scheme in ('http', 'https'):
            crawl(
                next_url,
                depth - 1,
                use_sqlite,
                user_agent,
                render_js,
                browser,
                include_screenshots,
                status,
            )
            if _stop:
                break
