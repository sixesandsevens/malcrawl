import unittest

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None

try:
    from scanner import scan_page
except Exception:  # pragma: no cover
    scan_page = None


class TestStaticScan(unittest.TestCase):
    def test_scan_page_smoke(self):
        if BeautifulSoup is None or scan_page is None:
            self.skipTest("Dependencies not installed (beautifulsoup4)")
        with open("tests/mocks/test.html", "r", encoding="utf-8") as fh:
            html = fh.read()
        soup = BeautifulSoup(html, "html.parser")
        suspicious, scripts, inline_events, matches = scan_page(
            soup, "file://tests/mocks/test.html", scan_id="test", full_logging=False
        )
        self.assertIsInstance(suspicious, list)
        self.assertIsInstance(scripts, list)
        self.assertIsInstance(inline_events, list)
        self.assertIsInstance(matches, list)
