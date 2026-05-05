import os
import tempfile
import unittest

import storage


class TestStorageFreshDb(unittest.TestCase):
    def test_get_results_for_scan_fresh_db_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "fresh.db")
            old_path = storage.DB_PATH
            try:
                storage.DB_PATH = db_path
                rows, total = storage.get_results_for_scan(123, page=1, limit=10)
                self.assertEqual(rows, [])
                self.assertEqual(total, 0)
            finally:
                storage.DB_PATH = old_path

