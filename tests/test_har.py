from __future__ import annotations

import os
import tempfile
import unittest

from har_analyzer.har import filter_records, har_to_records, save_sanitized_har


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sanitized_sample.har")


class HarTests(unittest.TestCase):
    def test_parse_and_filter_records(self):
        records = har_to_records(FIXTURE)
        self.assertEqual(len(records), 2)
        scoped = filter_records(records, ["api.example.com"], [])
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0].path, "/api/v1/users/100/profile")

    def test_sanitize_har_masks_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "clean.har")
            save_sanitized_har(FIXTURE, output)
            with open(output, "r", encoding="utf-8") as handle:
                data = handle.read()
            self.assertIn("[REDACTED]", data)
            self.assertNotIn("masked@example.com", data)


if __name__ == "__main__":
    unittest.main()

