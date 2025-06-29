"""Core crawling logic for MalCrawl."""

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
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.chrome import ChromeDriverManager

# Keep track of URLs that have been crawled to avoid loops
visited = set()

def detect_browser():
    """Return the browser to use for Selenium based on environment and binaries."""

    # Prefer value from the MALCRAWL_BROWSER environment variable if provided
    env_choice = os.getenv("MALCRAWL_BROWSER")
    if env_choice in {"chrome", "firefox"}:
        return env_choice

    # Check if drivers are available in PATH
    if shutil.which("geckodriver"):
        return "firefox"
    if shutil.which("chromedriver"):
        return "chrome"

    # Fallback to firefox, webdriver-manager will download the driver if needed
    return "firefox"

def get_driver(browser="firefox"):
    """Create a Selenium WebDriver instance using webdriver-manager."""

    if browser == "chrome":
        options = ChromeOptions()
        options.headless = True
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        service = ChromeService(ChromeDriverManager().install())
        return webdriver.Chrome(service=service, options=options)

    # Default to Firefox
    options = FirefoxOptions()
    options.headless = True
    service = FirefoxService(GeckoDriverManager().install())
    return webdriver.Firefox(service=service, options=options)

def fetch_with_selenium(url, screenshot_path=None, browser="firefox"):
    """Render a page with Selenium and optionally capture a screenshot."""

    driver = None
    try:
        driver = get_driver(browser)
        driver.get(url)
        if screenshot_path:
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            driver.save_screenshot(screenshot_path)
        html = driver.page_source
        return html
    except WebDriverException as e:
        print(f"[Selenium Error] {e}")
        return None
    finally:
        if driver:
            driver.quit()

def sanitize_filename(url):
    """Create a filesystem-friendly filename for the screenshot."""

    parsed = urlparse(url)
    filename = f"{parsed.netloc}{parsed.path}".replace("/", "_").strip("_")
    return (filename + ".png") if filename else "index.png"

def crawl(url, depth=2, use_sqlite=False, user_agent=DEFAULT_USER_AGENT, render_js=False, browser=None):
    """Recursively crawl a URL collecting basic metrics."""

    # Avoid processing the same URL multiple times
    if url in visited or depth == 0:
        return
    visited.add(url)

    if render_js and browser is None:
        browser = detect_browser()

    print(f"[Crawl] {url} using {'Selenium' if render_js else 'requests'}")

    headers = {'User-Agent': user_agent}
    html = None

    try:
        if render_js:
            screenshot_name = sanitize_filename(url)
            screenshot_path = os.path.join("screenshots", screenshot_name)
            html = fetch_with_selenium(url, screenshot_path, browser=browser)
            if html is None:
                return
        else:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            html = response.text

        soup = BeautifulSoup(html, 'html.parser')
    except Exception as e:
        print(f"[Error] Failed to fetch {url}: {e}")
        return

    links = [a['href'] for a in soup.find_all('a', href=True)]
    images = [img['src'] for img in soup.find_all('img', src=True)]
    videos = [v['src'] for v in soup.find_all('video', src=True)]
    sources = [s['src'] for s in soup.find_all('source', src=True)]
    total_videos = len(videos) + len(sources)

    suspicious = scan_page(soup, url)

    if use_sqlite:
        log_crawl_result(url, len(links), len(images), total_videos, suspicious)

    for a in links:
        next_url = urljoin(url, a)
        parsed = urlparse(next_url)
        if parsed.scheme in ('http', 'https'):
            crawl(next_url, depth - 1, use_sqlite, user_agent, render_js, browser)
