from __future__ import annotations

import unittest

from har_analyzer.evaluation import evaluate_result
from har_analyzer.models import AttackHypothesis, ExecutionResult, RequestRecord


class EvaluationTests(unittest.TestCase):
    def test_detects_idor_like_response(self):
        record = RequestRecord(
            request_id="entry-1",
            entry_index=0,
            started_at="",
            method="GET",
            url="https://api.example.com/api/v1/users/100/profile",
            scheme="https",
            host="api.example.com",
            path="/api/v1/users/100/profile",
            response_status=200,
            response_headers={},
            response_body='{"user_id":100,"email":"masked@example.com","name":"Alice"}',
        )
        hypothesis = AttackHypothesis(
            hypothesis_id="hyp-1",
            original_request_id=record.request_id,
            endpoint_key=record.endpoint_key(),
            attack_type="IDOR",
            severity="high",
            expected_signal="Different user data returned",
            rationale="numeric id",
            method="GET",
            url="https://api.example.com/api/v1/users/101/profile",
            headers={"authorization": "Bearer token"},
            body=None,
            mutation_summary="id 100 -> 101",
        )
        result = ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=record.request_id,
            method="GET",
            url=hypothesis.url,
            status_code=200,
            response_headers={},
            response_body='{"user_id":101,"email":"other@example.com","name":"Bob"}',
            outcome="ok",
        )
        findings = evaluate_result(record, hypothesis, result)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].attack_type, "IDOR")


if __name__ == "__main__":
    unittest.main()

