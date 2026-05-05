import importlib.util
import unittest
from unittest.mock import patch

for module_name in ("bs4", "jsbeautifier", "requests", "selenium"):
    if importlib.util.find_spec(module_name) is None:
        raise unittest.SkipTest(f"Dependency not installed ({module_name})")

from crawler import crawl


class TestCrawlerRenderJs(unittest.TestCase):
    def test_render_js_fetch_done_does_not_require_response(self):
        html = "<html><body><h1>ok</h1></body></html>"

        with patch("crawler.fetch_with_selenium", return_value=html):
            crawl(
                "https://example.test/",
                scan_id="render-js-test",
                depth=1,
                render_js=True,
                browser="firefox",
                use_sqlite=False,
            )

    def test_render_js_browser_detection_error_updates_status(self):
        status = {}

        def status_update(_scan_id, **kw):
            status.update(kw)

        with patch("crawler.detect_browser", side_effect=RuntimeError("No supported WebDriver found")):
            crawl(
                "https://example.test/",
                scan_id="render-js-test",
                depth=1,
                render_js=True,
                use_sqlite=False,
                status_update=status_update,
            )

        self.assertEqual(status["status"], "error")
        self.assertIn("No supported WebDriver found", status["last_error"])
