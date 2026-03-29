from __future__ import annotations

import unittest

from har_analyzer.context import build_endpoint_context
from har_analyzer.models import RequestRecord


class ContextTests(unittest.TestCase):
    def test_build_endpoint_context_uses_neighbor_window(self):
        records = []
        for index in range(5):
            records.append(
                RequestRecord(
                    request_id="entry-%04d" % index,
                    entry_index=index,
                    started_at="",
                    method="POST",
                    url="https://api.example.com/path/%d" % index,
                    scheme="https",
                    host="api.example.com",
                    path="/path/%d" % index,
                    response_status=200,
                )
            )
        context = build_endpoint_context(records, neighbor_window=2)
        neighbors = context.neighboring_requests["entry-0002"]
        self.assertEqual([item["relative_position"] for item in neighbors], [-2, -1, 1, 2])
        self.assertEqual(neighbors[0]["path"], "/path/0")
        self.assertEqual(neighbors[-1]["path"], "/path/4")


if __name__ == "__main__":
    unittest.main()
