from __future__ import annotations

import os
import tempfile
import unittest

from har_analyzer.models import AttackHypothesis, RequestRecord, RunConfig
from har_analyzer.persistence import RunStore


class PersistenceTests(unittest.TestCase):
    def test_pause_resume_cancel_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunStore(os.path.join(tmp, "runs.sqlite3"))
            config = RunConfig(har_path="fixture.har", target_domains=["api.example.com"], artifact_dir=tmp, database_path=os.path.join(tmp, "runs.sqlite3"))
            run = store.create_run(config)
            store.request_pause(run.run_id)
            self.assertTrue(store.get_run(run.run_id).pause_requested)
            store.request_resume(run.run_id)
            self.assertFalse(store.get_run(run.run_id).pause_requested)
            store.request_cancel(run.run_id)
            self.assertTrue(store.get_run(run.run_id).cancel_requested)

    def test_seed_request_items_stores_redacted_previews(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunStore(os.path.join(tmp, "runs.sqlite3"))
            config = RunConfig(har_path="fixture.har", target_domains=["api.example.com"], artifact_dir=tmp, database_path=os.path.join(tmp, "runs.sqlite3"))
            run = store.create_run(config)
            record = RequestRecord(
                request_id="req-1",
                entry_index=0,
                started_at="",
                method="POST",
                url="https://api.example.com/login",
                scheme="https",
                host="api.example.com",
                path="/login",
                request_headers={"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz"},
                request_body='{"email":"user@example.com","password":"secret"}',
                response_status=200,
                response_headers={"Set-Cookie": "session=abc; HttpOnly"},
                response_body='{"token":"abcdefghijklmnopqrstuvwxyz","email":"user@example.com"}',
            )
            store.seed_request_items(run.run_id, [record])
            item = store.get_request_items(run.run_id)[0]
            self.assertIn("[REDACTED]", item.request_headers_json)
            self.assertIn("[REDACTED]", item.request_body)
            self.assertIn("[REDACTED]", item.original_response_headers_json)
            self.assertIn("[REDACTED]", item.original_response_body)

    def test_seed_request_items_can_store_raw_previews(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunStore(os.path.join(tmp, "runs.sqlite3"))
            config = RunConfig(har_path="fixture.har", target_domains=["api.example.com"], artifact_dir=tmp, database_path=os.path.join(tmp, "runs.sqlite3"))
            run = store.create_run(config)
            record = RequestRecord(
                request_id="req-1",
                entry_index=0,
                started_at="",
                method="POST",
                url="https://api.example.com/login",
                scheme="https",
                host="api.example.com",
                path="/login",
                request_headers={"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz"},
                request_body='{"email":"user@example.com","password":"secret"}',
                response_status=200,
                response_headers={"Set-Cookie": "session=abc; HttpOnly"},
                response_body='{"token":"abcdefghijklmnopqrstuvwxyz","email":"user@example.com"}',
            )
            store.seed_request_items(run.run_id, [record], redact=False)
            item = store.get_request_items(run.run_id)[0]
            self.assertIn("Bearer abcdefghijklmnopqrstuvwxyz", item.request_headers_json)
            self.assertIn("user@example.com", item.request_body)
            self.assertIn("session=abc; HttpOnly", item.original_response_headers_json)
            self.assertIn("user@example.com", item.original_response_body)

    def test_replace_hypothesis_items_stores_replay_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunStore(os.path.join(tmp, "runs.sqlite3"))
            config = RunConfig(har_path="fixture.har", target_domains=["api.example.com"], artifact_dir=tmp, database_path=os.path.join(tmp, "runs.sqlite3"))
            run = store.create_run(config)
            hypothesis = AttackHypothesis(
                hypothesis_id="hyp-1",
                original_request_id="req-1",
                endpoint_key="POST /login",
                attack_type="auth_bypass",
                severity="medium",
                expected_signal="Still returns data",
                rationale="Remove auth",
                method="POST",
                url="https://api.example.com/login",
                headers={"X-Test": "1"},
                body="{}",
                mutation_summary="Removed Authorization header",
            )
            attempt_index = store.create_llm_attempt(run.run_id, "req-1", '{"messages":[]}')
            store.replace_hypothesis_items(run.run_id, "req-1", attempt_index, [hypothesis], redact=False)
            store.update_hypothesis_item(
                run.run_id,
                "hyp-1",
                status="completed",
                stage="completed",
                execution_outcome="ok",
                response_status_code=200,
                response_body='{"ok":true}',
                findings_count=1,
            )
            items = store.get_hypothesis_items(run.run_id, request_id="req-1")
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].attempt_index, attempt_index)
            self.assertEqual(items[0].attack_type, "auth_bypass")
            self.assertEqual(items[0].execution_outcome, "ok")
            self.assertEqual(items[0].findings_count, 1)

    def test_create_llm_attempt_stores_immutable_attempt_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunStore(os.path.join(tmp, "runs.sqlite3"))
            config = RunConfig(har_path="fixture.har", target_domains=["api.example.com"], artifact_dir=tmp, database_path=os.path.join(tmp, "runs.sqlite3"))
            run = store.create_run(config)
            first = store.create_llm_attempt(run.run_id, "req-1", '{"prompt":"one"}')
            second = store.create_llm_attempt(run.run_id, "req-1", '{"prompt":"two"}')
            store.update_llm_attempt(run.run_id, "req-1", first, status="completed", llm_response_message_content='{"hypotheses":[]}')
            attempts = store.get_llm_attempt_items(run.run_id, request_id="req-1")
            self.assertEqual([item.attempt_index for item in attempts], [1, 2])
            self.assertEqual(attempts[0].llm_request_json, '{"prompt":"one"}')
            self.assertEqual(attempts[0].llm_response_message_content, '{"hypotheses":[]}')


if __name__ == "__main__":
    unittest.main()
