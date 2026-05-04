import importlib.util
import unittest

for module_name in ("bs4", "jsbeautifier", "requests"):
    if importlib.util.find_spec(module_name) is None:
        raise unittest.SkipTest(f"Dependency not installed ({module_name})")

from bs4 import BeautifulSoup
from scanner import scan_page


class TestStaticScan(unittest.TestCase):
    def test_scan_page_smoke(self):
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
