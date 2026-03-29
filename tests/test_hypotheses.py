from __future__ import annotations

import unittest
from unittest import mock

from har_analyzer.hypotheses import OpenAICompatibleClient, ProviderResponseError, _build_analysis_prompt, _extract_provider_message, _resolve_mutation
from har_analyzer.models import EndpointContext, RequestRecord, RunConfig


class HypothesisParsingTests(unittest.TestCase):
    def test_resolve_mutation_applies_delta_changes(self):
        record = RequestRecord(
            request_id="req-1",
            entry_index=0,
            started_at="",
            method="POST",
            url="https://api.example.com/v1/users/100",
            scheme="https",
            host="api.example.com",
            path="/v1/users/100",
            request_headers={"Authorization": "Bearer token", "X-App": "mobile"},
            request_body='{"user_id":100}',
        )
        mutation = _resolve_mutation(
            record,
            {
                "changes": {
                    "url": "https://api.example.com/v1/users/101",
                    "headers": {
                        "Authorization": None,
                        "X-Debug": "1",
                    },
                }
            },
        )
        self.assertEqual(mutation["method"], "POST")
        self.assertEqual(mutation["url"], "https://api.example.com/v1/users/101")
        self.assertEqual(mutation["body"], '{"user_id":100}')
        self.assertNotIn("Authorization", mutation["headers"])
        self.assertEqual(mutation["headers"]["X-App"], "mobile")
        self.assertEqual(mutation["headers"]["X-Debug"], "1")

    def test_build_analysis_prompt_compacts_request_shape(self):
        record = RequestRecord(
            request_id="entry-0047",
            entry_index=47,
            started_at="2025-03-12T19:21:04.379+02:00",
            method="POST",
            url="https://api.example.com/login",
            scheme="https",
            host="api.example.com",
            path="/login",
            query_params={"client": "mobile"},
            request_headers={"content-type": "application/json"},
            request_body='{"Token":"abc","ID":"301066","Phone":"0546807054"}',
            response_status=200,
            response_headers={"content-type": "application/json"},
            response_body="x" * 5000,
            duration_ms=123.45,
            flags=["authorization_header_present"],
        )
        config = RunConfig(
            har_path="fixture.har",
            target_domains=["api.example.com"],
            max_body_chars=4000,
            truncated_body_chars=1000,
        )
        prompt = _build_analysis_prompt(record, record_context(), config)
        request_payload = prompt["request"]
        self.assertNotIn("request_id", request_payload)
        self.assertNotIn("entry_index", request_payload)
        self.assertNotIn("started_at", request_payload)
        self.assertNotIn("scheme", request_payload)
        self.assertNotIn("duration_ms", request_payload)
        self.assertNotIn("flags", request_payload)
        self.assertEqual(request_payload["request_body"]["ID"], "301066")
        self.assertTrue(request_payload["response_body"]["truncated"])
        self.assertEqual(len(request_payload["response_body"]["preview"]), 1000)
        context_payload = prompt["context"]
        self.assertNotIn("api_summary", context_payload)
        self.assertNotIn("endpoint_groups", context_payload)
        self.assertEqual(len(context_payload["neighboring_requests"]), 2)
        self.assertEqual(context_payload["neighboring_requests"][0]["relative_position"], -1)

    def test_extract_provider_message_falls_back_to_reasoning_content(self):
        content, reasoning = _extract_provider_message(
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning_content": '{"hypotheses":[]}',
                        }
                    }
                ]
            }
        )
        self.assertEqual(content, '{"hypotheses":[]}')
        self.assertEqual(reasoning, '{"hypotheses":[]}')

    def test_openai_compatible_client_retries_without_response_format(self):
        client = OpenAICompatibleClient("https://example.invalid/v1/openai", "test", "Qwen/Qwen3.5-9B")
        record = RequestRecord(
            request_id="entry-0000",
            entry_index=0,
            started_at="",
            method="POST",
            url="https://api.example.com/login",
            scheme="https",
            host="api.example.com",
            path="/login",
        )
        config = RunConfig(
            har_path="fixture.har",
            target_domains=["api.example.com"],
            provider="deepinfra",
            model="Qwen/Qwen3.5-9B",
            llm_timeout_seconds=60,
        )
        calls = []

        def fake_post_json(url, payload, headers, timeout_seconds):
            calls.append(payload)
            if "response_format" in payload:
                raise ProviderResponseError(
                    'Provider returned HTTP 405: {"detail":"json_object response format is not supported for model: Qwen/Qwen3.5-9B"}',
                    raw_content='{"detail":"json_object response format is not supported for model: Qwen/Qwen3.5-9B"}',
                )
            return (
                {"choices": [{"message": {"content": '{"hypotheses":[]}'}}]},
                '{"choices":[{"message":{"content":"{\\"hypotheses\\":[]}"}}]}',
            )

        with mock.patch("har_analyzer.hypotheses._post_json", side_effect=fake_post_json):
            results = client.generate_hypotheses(record, record_context(), config)

        self.assertEqual(results, [])
        self.assertEqual(len(calls), 2)
        self.assertIn("response_format", calls[0])
        self.assertNotIn("response_format", calls[1])
        self.assertFalse(client.supports_json_object_response_format)

    def test_openai_compatible_client_retries_on_model_busy(self):
        client = OpenAICompatibleClient("https://example.invalid/v1/openai", "test", "zai-org/GLM-5")
        record = RequestRecord(
            request_id="entry-0001",
            entry_index=1,
            started_at="",
            method="POST",
            url="https://api.example.com/login",
            scheme="https",
            host="api.example.com",
            path="/login",
        )
        config = RunConfig(
            har_path="fixture.har",
            target_domains=["api.example.com"],
            provider="deepinfra",
            model="zai-org/GLM-5",
            llm_timeout_seconds=60,
            llm_busy_retry_count=2,
            llm_busy_retry_base_delay_seconds=0.01,
        )
        calls = []

        def fake_post_json(url, payload, headers, timeout_seconds):
            calls.append(payload)
            if len(calls) == 1:
                raise ProviderResponseError(
                    'Provider returned HTTP 429: {"error":{"message":"Model busy, retry later"}}',
                    raw_content='{"error":{"message":"Model busy, retry later"}}',
                    status_code=429,
                )
            return (
                {"choices": [{"message": {"content": '{"hypotheses":[]}'}}]},
                '{"choices":[{"message":{"content":"{\\"hypotheses\\":[]}"}}]}',
            )

        with mock.patch("har_analyzer.hypotheses._post_json", side_effect=fake_post_json):
            with mock.patch("har_analyzer.hypotheses.time.sleep") as sleep_mock:
                results = client.generate_hypotheses(record, record_context(), config)

        self.assertEqual(results, [])
        self.assertEqual(len(calls), 2)
        sleep_mock.assert_called_once()


def record_context():
    return EndpointContext(
        auth_header_names=["authorization"],
        neighboring_requests={
            "entry-0047": [
                {"relative_position": -1, "method": "POST", "path": "/login", "normalized_path": "/login", "response_status": 200},
                {"relative_position": 1, "method": "POST", "path": "/verify", "normalized_path": "/verify", "response_status": 200},
            ]
        },
        endpoint_groups={"/login": ["POST /login"]},
        api_summary="Observed 1 scoped request.",
    )


if __name__ == "__main__":
    unittest.main()
