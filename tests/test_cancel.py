import unittest

try:
    from crawler import CancelledError, crawl
except Exception:  # pragma: no cover
    CancelledError = None
    crawl = None


class TestCancel(unittest.TestCase):
    def test_crawl_respects_cancel(self):
        if CancelledError is None or crawl is None:
            self.skipTest("Dependencies not installed (beautifulsoup4)")
        def cancel_check(_sid):
            return True

        with self.assertRaises(CancelledError):
            crawl("https://example.invalid/", scan_id="x", cancel_check=cancel_check)
