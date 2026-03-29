from __future__ import annotations

import os
import tempfile
import unittest

from har_analyzer.cli import main


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sanitized_sample.har")


class CliTests(unittest.TestCase):
    def test_sanitize_har_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "sanitized.har")
            code = main(["sanitize-har", "--input", FIXTURE, "--output", output])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(output))

    def test_export_filtered_records_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "filtered-records.json")
            code = main(
                [
                    "export-filtered-records",
                    "--har",
                    FIXTURE,
                    "--scope-domain",
                    "api.example.com",
                    "--output",
                    output,
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(output))
            with open(output, "r", encoding="utf-8") as handle:
                contents = handle.read()
            self.assertIn('"request_id": "entry-0000"', contents)
            self.assertNotIn('/static/app.js', contents)


if __name__ == "__main__":
    unittest.main()
