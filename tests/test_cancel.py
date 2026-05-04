import importlib.util
import unittest

for module_name in ("bs4", "jsbeautifier", "requests", "selenium"):
    if importlib.util.find_spec(module_name) is None:
        raise unittest.SkipTest(f"Dependency not installed ({module_name})")

from crawler import CancelledError, crawl


class TestCancel(unittest.TestCase):
    def test_crawl_respects_cancel(self):
        def cancel_check(_sid):
            return True

        with self.assertRaises(CancelledError):
            crawl("https://example.invalid/", scan_id="x", cancel_check=cancel_check)
