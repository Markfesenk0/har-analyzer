from __future__ import annotations

import unittest

from har_analyzer.redaction import redact_string, redact_value


class RedactionTests(unittest.TestCase):
    def test_redact_string_masks_common_sensitive_patterns(self):
        value = "Email admin@example.com Phone +15551234567 Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
        clean = redact_string(value)
        self.assertIn("[REDACTED_EMAIL]", clean)
        self.assertIn("[REDACTED_PHONE]", clean)
        self.assertIn("[REDACTED_TOKEN]", clean)

    def test_redact_value_masks_json_fields(self):
        clean = redact_value('{"email":"user@example.com","password":"secret","profile":{"phone":"+15551234567"}}')
        self.assertIn("[REDACTED]", clean)
        self.assertNotIn("user@example.com", clean)


if __name__ == "__main__":
    unittest.main()

