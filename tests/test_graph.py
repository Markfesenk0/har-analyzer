from __future__ import annotations

import os
import tempfile
import unittest
import json
from unittest import mock

from har_analyzer.graph import run_scan
from har_analyzer.hypotheses import LLMClient
from har_analyzer.models import AttackHypothesis, ExecutionResult, RunConfig
from har_analyzer.persistence import RunStore


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sanitized_sample.har")


def fake_transport(hypothesis: AttackHypothesis, config: RunConfig) -> ExecutionResult:
    return ExecutionResult(
        hypothesis_id=hypothesis.hypothesis_id,
        request_id=hypothesis.original_request_id,
        method=hypothesis.method,
        url=hypothesis.url,
        status_code=200,
        response_headers={"content-type": "application/json"},
        response_body='{"user_id":101,"email":"other@example.com","name":"Bob"}',
        outcome="ok",
    )


class GraphTests(unittest.TestCase):
    class EmptyHypothesisClient(LLMClient):
        def build_preview(self, record, context, config):
            return {"provider": "test", "payload": {"messages": [{"role": "user", "content": "x"}]}}

        def generate_hypotheses(self, record, context, config):
            return []

    def test_run_scan_creates_redacted_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = "test-key"
            os.environ["LANGCHAIN_PROJECT"] = "har-analyzer-test"
            config = RunConfig(
                har_path=FIXTURE,
                target_domains=["api.example.com"],
                artifact_dir=tmp,
                database_path=os.path.join(tmp, "runs.sqlite3"),
                inter_request_delay_ms=0,
            )
            run = run_scan(config, transport=fake_transport)
            self.assertEqual(run.status, "completed")
            self.assertTrue(os.path.exists(run.report_json_path))
            with open(run.report_json_path, "r", encoding="utf-8") as handle:
                report = handle.read()
            self.assertNotIn("other@example.com", report)
            self.assertIn("[REDACTED_EMAIL]", report)
            items = RunStore(config.database_path).get_request_items(run.run_id)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].status, "completed")
            with open(os.path.join(run.artifact_dir, "sanitized-input.har"), "r", encoding="utf-8") as handle:
                self.assertIn('"log"', handle.read())

    def test_cancel_requested_run_finishes_as_canceled(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = "test-key"
            os.environ["LANGCHAIN_PROJECT"] = "har-analyzer-test"
            config = RunConfig(
                har_path=FIXTURE,
                target_domains=["api.example.com"],
                artifact_dir=tmp,
                database_path=os.path.join(tmp, "runs.sqlite3"),
                inter_request_delay_ms=0,
            )
            store = RunStore(config.database_path)
            run = store.create_run(config)
            store.request_cancel(run.run_id)
            canceled_run = run_scan(config, transport=fake_transport, store=store, run=run)
            self.assertEqual(canceled_run.status, "canceled")

    def test_provider_parse_failure_is_saved_as_debug_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = "test-key"
            os.environ["LANGCHAIN_PROJECT"] = "har-analyzer-test"
            config = RunConfig(
                har_path=FIXTURE,
                target_domains=["api.example.com"],
                artifact_dir=tmp,
                database_path=os.path.join(tmp, "runs.sqlite3"),
                inter_request_delay_ms=0,
                provider="deepinfra",
                llm_base_url="https://example.invalid/v1/openai",
                llm_api_key="test",
                model="fake-model",
            )
            fake_provider_payload = {"choices": [{"message": {"content": "not-json"}}]}
            with mock.patch("har_analyzer.hypotheses._post_json", return_value=(fake_provider_payload, '{"choices":[{"message":{"content":"not-json"}}]}')):
                run = run_scan(config, transport=fake_transport)
            items = RunStore(config.database_path).get_request_items(run.run_id)
            self.assertEqual(items[0].status, "error")
            self.assertTrue(items[0].debug_artifact_path)
            self.assertTrue(os.path.exists(items[0].debug_artifact_path))
            self.assertEqual(run.status, "completed")

    def test_step_mode_waits_for_approval_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = "test-key"
            os.environ["LANGCHAIN_PROJECT"] = "har-analyzer-test"
            config = RunConfig(
                har_path=FIXTURE,
                target_domains=["api.example.com"],
                artifact_dir=tmp,
                database_path=os.path.join(tmp, "runs.sqlite3"),
                inter_request_delay_ms=0,
                step_mode=True,
            )
            store = RunStore(config.database_path)
            run = store.create_run(config)

            def worker():
                run_scan(config, transport=fake_transport, store=store, run=run)

            import threading, time
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            time.sleep(0.5)
            item = store.get_request_items(run.run_id)[0]
            self.assertEqual(item.approval_state, "pending")
            store.update_request_item(run.run_id, item.request_id, approval_state="approved")
            thread.join(timeout=5)
            final_item = store.get_request_items(run.run_id)[0]
            self.assertEqual(final_item.approval_state, "approved")

    def test_step_mode_creates_single_attempt_after_approval_for_empty_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = "test-key"
            os.environ["LANGCHAIN_PROJECT"] = "har-analyzer-test"
            config = RunConfig(
                har_path=FIXTURE,
                target_domains=["api.example.com"],
                artifact_dir=tmp,
                database_path=os.path.join(tmp, "runs.sqlite3"),
                inter_request_delay_ms=0,
                step_mode=True,
            )
            store = RunStore(config.database_path)
            run = store.create_run(config)

            def worker():
                run_scan(config, llm_client=self.EmptyHypothesisClient(), transport=fake_transport, store=store, run=run)

            import threading, time
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            time.sleep(0.5)
            self.assertEqual(store.get_llm_attempt_items(run.run_id), [])
            item = store.get_request_items(run.run_id)[0]
            self.assertEqual(item.approval_state, "pending")
            store.update_request_item(run.run_id, item.request_id, approval_state="approved")
            thread.join(timeout=5)
            final_item = store.get_request_items(run.run_id)[0]
            attempts = store.get_llm_attempt_items(run.run_id, request_id=item.request_id)
            self.assertEqual(final_item.stage, "no_hypotheses")
            self.assertEqual(len(attempts), 1)

    def test_step_mode_advances_to_next_request_after_no_hypotheses(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = "test-key"
            os.environ["LANGCHAIN_PROJECT"] = "har-analyzer-test"
            har_path = os.path.join(tmp, "two.har")
            payload = {
                "log": {
                    "entries": [
                        {
                            "startedDateTime": "2025-01-01T00:00:00Z",
                            "time": 10,
                            "request": {
                                "method": "POST",
                                "url": "https://api.example.com/one",
                                "headers": [{"name": "host", "value": "api.example.com"}],
                                "queryString": [],
                                "postData": {"text": '{"a":1}'},
                            },
                            "response": {"status": 200, "headers": [], "content": {"text": "{}"}},
                        },
                        {
                            "startedDateTime": "2025-01-01T00:00:01Z",
                            "time": 10,
                            "request": {
                                "method": "POST",
                                "url": "https://api.example.com/two",
                                "headers": [{"name": "host", "value": "api.example.com"}],
                                "queryString": [],
                                "postData": {"text": '{"b":2}'},
                            },
                            "response": {"status": 200, "headers": [], "content": {"text": "{}"}},
                        },
                    ]
                }
            }
            with open(har_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            config = RunConfig(
                har_path=har_path,
                target_domains=["api.example.com"],
                artifact_dir=tmp,
                database_path=os.path.join(tmp, "runs.sqlite3"),
                inter_request_delay_ms=0,
                step_mode=True,
            )
            store = RunStore(config.database_path)
            run = store.create_run(config)

            def worker():
                run_scan(config, llm_client=self.EmptyHypothesisClient(), transport=fake_transport, store=store, run=run)

            import threading, time
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            time.sleep(0.5)
            items = store.get_request_items(run.run_id)
            first = items[0]
            second = items[1]
            store.update_request_item(run.run_id, first.request_id, approval_state="approved")

            deadline = time.time() + 5
            second_item = None
            while time.time() < deadline:
                refreshed = {item.request_id: item for item in store.get_request_items(run.run_id)}
                first_item = refreshed[first.request_id]
                second_item = refreshed[second.request_id]
                if first_item.stage == "no_hypotheses" and second_item.stage == "awaiting_llm_approval":
                    break
                time.sleep(0.1)
            self.assertIsNotNone(second_item)
            self.assertEqual(second_item.stage, "awaiting_llm_approval")
            store.update_request_item(run.run_id, second.request_id, approval_state="skipped")
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
