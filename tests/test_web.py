from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from har_analyzer.web import _discover_har_files, _suggest_scope_hosts, create_app


class WebTests(unittest.TestCase):
    def test_create_app_or_skip_when_fastapi_missing(self):
        try:
            app = create_app("artifacts")
        except RuntimeError:
            self.skipTest("FastAPI is not installed in the local environment")
            return
        self.assertIsNotNone(app)

    def test_suggest_scope_hosts_filters_tracking_and_static(self):
        with tempfile.TemporaryDirectory() as tmp:
            har_path = os.path.join(tmp, "sample.har")
            payload = {
                "log": {
                    "entries": [
                        {
                            "startedDateTime": "2025-01-01T00:00:00Z",
                            "time": 10,
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/v1/users",
                                "headers": [{"name": "host", "value": "api.example.com"}],
                                "queryString": [],
                            },
                            "response": {"status": 200, "headers": [], "content": {"text": "{}"}},
                        },
                        {
                            "startedDateTime": "2025-01-01T00:00:01Z",
                            "time": 10,
                            "request": {
                                "method": "GET",
                                "url": "https://www.google-analytics.com/script.js",
                                "headers": [{"name": "host", "value": "www.google-analytics.com"}],
                                "queryString": [],
                            },
                            "response": {"status": 200, "headers": [], "content": {"text": "x"}},
                        },
                    ]
                }
            }
            with open(har_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            self.assertEqual(_suggest_scope_hosts(har_path), ["api.example.com"])

    def test_discover_har_files_reads_har_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            har_dir = os.path.join(tmp, "HAR files")
            os.makedirs(har_dir, exist_ok=True)
            sample = os.path.join(har_dir, "demo.har")
            with open(sample, "w", encoding="utf-8") as handle:
                handle.write("{}")
            with mock.patch("har_analyzer.web.DEFAULT_HAR_DIR", Path(har_dir)):
                files = _discover_har_files()
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["label"], "demo.har")


if __name__ == "__main__":
    unittest.main()
