from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import AttackHypothesis, ExecutionResult, Finding, HypothesisRunItem, LLMAttemptRunItem, RequestRecord, RequestRunItem, RunConfig, RunRecord
from .redaction import maybe_redact_mapping, maybe_redact_value


class RunStore(object):
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        Path(os.path.dirname(database_path) or ".").mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path)

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    har_path TEXT NOT NULL,
                    target_domains TEXT NOT NULL,
                    artifact_dir TEXT NOT NULL,
                    report_markdown_path TEXT,
                    report_json_path TEXT,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    total_requests INTEGER NOT NULL DEFAULT 0,
                    processed_requests INTEGER NOT NULL DEFAULT 0,
                    current_endpoint TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    config_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    finding_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS request_items (
                    run_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    entry_index INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    hypothesis_count INTEGER NOT NULL DEFAULT 0,
                    executed_count INTEGER NOT NULL DEFAULT 0,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    summary TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    debug_artifact_path TEXT NOT NULL DEFAULT '',
                    request_headers_json TEXT NOT NULL DEFAULT '{}',
                    request_body TEXT NOT NULL DEFAULT '',
                    original_response_status INTEGER NOT NULL DEFAULT 0,
                    original_response_headers_json TEXT NOT NULL DEFAULT '{}',
                    original_response_body TEXT NOT NULL DEFAULT '',
                    latest_status_code INTEGER NOT NULL DEFAULT 0,
                    latest_response_headers_json TEXT NOT NULL DEFAULT '{}',
                    latest_response_body TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, request_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS hypothesis_items (
                    run_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    hypothesis_id TEXT NOT NULL,
                    attempt_index INTEGER NOT NULL DEFAULT 1,
                    sequence_index INTEGER NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mutation_summary TEXT NOT NULL DEFAULT '',
                    rationale TEXT NOT NULL DEFAULT '',
                    expected_signal TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '',
                    url TEXT NOT NULL DEFAULT '',
                    headers_json TEXT NOT NULL DEFAULT '{}',
                    body TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'generated',
                    stage TEXT NOT NULL DEFAULT 'generated',
                    execution_outcome TEXT NOT NULL DEFAULT '',
                    execution_error TEXT NOT NULL DEFAULT '',
                    response_status_code INTEGER NOT NULL DEFAULT 0,
                    response_headers_json TEXT NOT NULL DEFAULT '{}',
                    response_body TEXT NOT NULL DEFAULT '',
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, hypothesis_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_attempt_items (
                    run_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    attempt_index INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    stage TEXT NOT NULL DEFAULT 'prepared',
                    llm_request_json TEXT NOT NULL DEFAULT '{}',
                    llm_response_text TEXT NOT NULL DEFAULT '',
                    llm_response_message_content TEXT NOT NULL DEFAULT '',
                    debug_artifact_path TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, request_id, attempt_index)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS notes (
                    note_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL DEFAULT '',
                    request_id TEXT NOT NULL DEFAULT '',
                    hypothesis_id TEXT NOT NULL DEFAULT '',
                    content TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._ensure_run_columns(connection)
            self._ensure_request_item_columns(connection)
            self._ensure_hypothesis_item_columns(connection)
            self._ensure_llm_attempt_columns(connection)

    def _ensure_run_columns(self, connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()}
        desired = {
            "total_requests": "INTEGER NOT NULL DEFAULT 0",
            "processed_requests": "INTEGER NOT NULL DEFAULT 0",
            "current_endpoint": "TEXT NOT NULL DEFAULT ''",
            "last_error": "TEXT NOT NULL DEFAULT ''",
            "pause_requested": "INTEGER NOT NULL DEFAULT 0",
            "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
            "total_prompt_tokens": "INTEGER NOT NULL DEFAULT 0",
            "total_completion_tokens": "INTEGER NOT NULL DEFAULT 0",
            "total_estimated_cost_usd": "REAL NOT NULL DEFAULT 0.0",
            "llm_call_count": "INTEGER NOT NULL DEFAULT 0",
            "cost_unavailable_count": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, definition in desired.items():
            if name not in columns:
                connection.execute("ALTER TABLE runs ADD COLUMN %s %s" % (name, definition))

    def _ensure_request_item_columns(self, connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(request_items)").fetchall()}
        desired = {
            "request_headers_json": "TEXT NOT NULL DEFAULT '{}'",
            "request_body": "TEXT NOT NULL DEFAULT ''",
            "original_response_status": "INTEGER NOT NULL DEFAULT 0",
            "original_response_headers_json": "TEXT NOT NULL DEFAULT '{}'",
            "original_response_body": "TEXT NOT NULL DEFAULT ''",
            "latest_status_code": "INTEGER NOT NULL DEFAULT 0",
            "latest_response_headers_json": "TEXT NOT NULL DEFAULT '{}'",
            "latest_response_body": "TEXT NOT NULL DEFAULT ''",
            "llm_request_json": "TEXT NOT NULL DEFAULT '{}'",
            "llm_response_text": "TEXT NOT NULL DEFAULT ''",
            "llm_response_message_content": "TEXT NOT NULL DEFAULT ''",
            "approval_state": "TEXT NOT NULL DEFAULT 'not_required'",
        }
        for name, definition in desired.items():
            if name not in columns:
                connection.execute("ALTER TABLE request_items ADD COLUMN %s %s" % (name, definition))

    def _ensure_hypothesis_item_columns(self, connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(hypothesis_items)").fetchall()}
        desired = {
            "attempt_index": "INTEGER NOT NULL DEFAULT 1",
            "llm_validation_json": "TEXT NOT NULL DEFAULT ''",
            "validation_prompt_tokens": "INTEGER NOT NULL DEFAULT 0",
            "validation_completion_tokens": "INTEGER NOT NULL DEFAULT 0",
            "validation_total_tokens": "INTEGER NOT NULL DEFAULT 0",
            "validation_estimated_cost_usd": "REAL NOT NULL DEFAULT 0.0",
            "validation_model_used": "TEXT NOT NULL DEFAULT ''",
            "validation_cost_available": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, definition in desired.items():
            if name not in columns:
                connection.execute("ALTER TABLE hypothesis_items ADD COLUMN %s %s" % (name, definition))

    def _ensure_llm_attempt_columns(self, connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(llm_attempt_items)").fetchall()}
        desired = {
            "prompt_tokens": "INTEGER NOT NULL DEFAULT 0",
            "completion_tokens": "INTEGER NOT NULL DEFAULT 0",
            "total_tokens": "INTEGER NOT NULL DEFAULT 0",
            "estimated_cost_usd": "REAL NOT NULL DEFAULT 0.0",
            "model_used": "TEXT NOT NULL DEFAULT ''",
            "cost_available": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, definition in desired.items():
            if name not in columns:
                connection.execute("ALTER TABLE llm_attempt_items ADD COLUMN %s %s" % (name, definition))

    def create_run(self, config: RunConfig) -> RunRecord:
        run_id = datetime.utcnow().strftime("run-%Y%m%d-%H%M%S")
        record = RunRecord(
            run_id=run_id,
            created_at=datetime.utcnow().isoformat() + "Z",
            status="running",
            har_path=config.har_path,
            target_domains=list(config.target_domains),
            artifact_dir=os.path.join(config.artifact_dir, run_id),
            config=config.to_dict(),
        )
        Path(record.artifact_dir).mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, created_at, status, har_path, target_domains, artifact_dir, findings_count, config_json
                    , total_requests, processed_requests, current_endpoint, last_error, pause_requested, cancel_requested
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.run_id,
                    record.created_at,
                    record.status,
                    record.har_path,
                    json.dumps(record.target_domains),
                    record.artifact_dir,
                    record.findings_count,
                    json.dumps(record.config),
                    record.total_requests,
                    record.processed_requests,
                    record.current_endpoint,
                    record.last_error,
                    1 if record.pause_requested else 0,
                    1 if record.cancel_requested else 0,
                ),
            )
        return record

    def finalize_run(self, run: RunRecord, findings: List[Finding], report_markdown_path: str, report_json_path: str, status: str = "completed") -> None:
        run.status = status
        run.findings_count = len(findings)
        run.report_markdown_path = report_markdown_path
        run.report_json_path = report_json_path
        run.processed_requests = run.total_requests
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET status = ?, report_markdown_path = ?, report_json_path = ?, findings_count = ?, processed_requests = ?, current_endpoint = ?, last_error = ?, pause_requested = 0
                WHERE run_id = ?
                """,
                (run.status, run.report_markdown_path, run.report_json_path, run.findings_count, run.processed_requests, "", run.last_error, run.run_id),
            )
            connection.execute("DELETE FROM findings WHERE run_id = ?", (run.run_id,))
            for finding in findings:
                connection.execute(
                    """
                    INSERT INTO findings (finding_id, run_id, severity, endpoint, finding_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        finding.finding_id,
                        run.run_id,
                        finding.severity,
                        finding.endpoint,
                        json.dumps(finding.to_dict(), ensure_ascii=False),
                    ),
                )

    def mark_run_failed(self, run_id: str, error: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET status = ?, last_error = ?, current_endpoint = ?
                WHERE run_id = ?
                """,
                ("failed", error, "", run_id),
            )

    def update_run_progress(
        self,
        run_id: str,
        *,
        status: Optional[str] = None,
        total_requests: Optional[int] = None,
        processed_requests: Optional[int] = None,
        current_endpoint: Optional[str] = None,
        last_error: Optional[str] = None,
    ) -> None:
        assignments = []
        params = []
        for key, value in [
            ("status", status),
            ("total_requests", total_requests),
            ("processed_requests", processed_requests),
            ("current_endpoint", current_endpoint),
            ("last_error", last_error),
        ]:
            if value is not None:
                assignments.append("%s = ?" % key)
                params.append(value)
        if not assignments:
            return
        params.append(run_id)
        with self._connect() as connection:
            connection.execute("UPDATE runs SET %s WHERE run_id = ?" % ", ".join(assignments), params)

    def add_run_cost(
        self,
        run_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        estimated_cost_usd: float,
        cost_available: bool,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET total_prompt_tokens = COALESCE(total_prompt_tokens, 0) + ?,
                    total_completion_tokens = COALESCE(total_completion_tokens, 0) + ?,
                    total_estimated_cost_usd = COALESCE(total_estimated_cost_usd, 0.0) + ?,
                    llm_call_count = COALESCE(llm_call_count, 0) + 1,
                    cost_unavailable_count = COALESCE(cost_unavailable_count, 0) + ?
                WHERE run_id = ?
                """,
                (
                    int(prompt_tokens or 0),
                    int(completion_tokens or 0),
                    float(estimated_cost_usd or 0.0),
                    0 if cost_available else 1,
                    run_id,
                ),
            )

    def request_pause(self, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE runs SET pause_requested = 1, status = ? WHERE run_id = ?", ("paused", run_id))

    def request_resume(self, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE runs SET pause_requested = 0, status = ? WHERE run_id = ?", ("running", run_id))

    def request_cancel(self, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE runs SET cancel_requested = 1, status = ? WHERE run_id = ?", ("cancel_requested", run_id))

    def seed_request_items(self, run_id: str, records: List[RequestRecord], redact: bool = True) -> None:
        now = datetime.utcnow().isoformat() + "Z"
        with self._connect() as connection:
            connection.execute("DELETE FROM request_items WHERE run_id = ?", (run_id,))
            for record in records:
                connection.execute(
                    """
                    INSERT INTO request_items (
                        run_id, request_id, entry_index, method, host, path, url, status, stage, hypothesis_count, executed_count, findings_count, summary, error, debug_artifact_path, updated_at
                        , request_headers_json, request_body, original_response_status, original_response_headers_json, original_response_body, latest_status_code, latest_response_headers_json, latest_response_body
                        , llm_request_json, llm_response_text, llm_response_message_content, approval_state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        record.request_id,
                        record.entry_index,
                        record.method,
                        record.host,
                        record.path,
                        record.url,
                        "queued",
                        "queued",
                        0,
                        0,
                        0,
                        "",
                        "",
                        "",
                        now,
                        json.dumps(maybe_redact_mapping(record.request_headers, redact), ensure_ascii=False),
                        str(maybe_redact_value(record.request_body or "", redact)),
                        record.response_status or 0,
                        json.dumps(maybe_redact_mapping(record.response_headers, redact), ensure_ascii=False),
                        str(maybe_redact_value(record.response_body or "", redact)),
                        0,
                        "{}",
                        "",
                        "{}",
                        "",
                        "",
                        "not_required",
                    ),
                )

    def update_request_item(self, run_id: str, request_id: str, **fields) -> None:
        if not fields:
            return
        fields["updated_at"] = datetime.utcnow().isoformat() + "Z"
        assignments = []
        params = []
        for key, value in fields.items():
            assignments.append("%s = ?" % key)
            params.append(value)
        params.extend([run_id, request_id])
        with self._connect() as connection:
            connection.execute(
                "UPDATE request_items SET %s WHERE run_id = ? AND request_id = ?" % ", ".join(assignments),
                params,
            )

    def create_llm_attempt(self, run_id: str, request_id: str, llm_request_json: str) -> int:
        now = datetime.utcnow().isoformat() + "Z"
        with self._connect() as connection:
            next_attempt = connection.execute(
                "SELECT COALESCE(MAX(attempt_index), 0) + 1 FROM llm_attempt_items WHERE run_id = ? AND request_id = ?",
                (run_id, request_id),
            ).fetchone()[0]
            connection.execute(
                """
                INSERT INTO llm_attempt_items (
                    run_id, request_id, attempt_index, status, stage, llm_request_json, llm_response_text,
                    llm_response_message_content, debug_artifact_path, error, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, request_id, next_attempt, "pending", "prepared", llm_request_json, "", "", "", "", now),
            )
        return int(next_attempt)

    def update_llm_attempt(self, run_id: str, request_id: str, attempt_index: int, **fields) -> None:
        if not fields:
            return
        fields["updated_at"] = datetime.utcnow().isoformat() + "Z"
        assignments = []
        params = []
        for key, value in fields.items():
            assignments.append("%s = ?" % key)
            params.append(value)
        params.extend([run_id, request_id, attempt_index])
        with self._connect() as connection:
            connection.execute(
                "UPDATE llm_attempt_items SET %s WHERE run_id = ? AND request_id = ? AND attempt_index = ?" % ", ".join(assignments),
                params,
            )

    def get_llm_attempt_items(self, run_id: str, request_id: Optional[str] = None) -> List[LLMAttemptRunItem]:
        query = """
            SELECT run_id, request_id, attempt_index, status, stage, llm_request_json, llm_response_text,
                   llm_response_message_content, debug_artifact_path, error, updated_at,
                   COALESCE(prompt_tokens, 0), COALESCE(completion_tokens, 0), COALESCE(total_tokens, 0),
                   COALESCE(estimated_cost_usd, 0.0), COALESCE(model_used, ''), COALESCE(cost_available, 0)
            FROM llm_attempt_items
            WHERE run_id = ?
        """
        params: List[object] = [run_id]
        if request_id is not None:
            query += " AND request_id = ?"
            params.append(request_id)
        query += " ORDER BY request_id ASC, attempt_index ASC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            LLMAttemptRunItem(
                run_id=row[0],
                request_id=row[1],
                attempt_index=row[2],
                status=row[3],
                stage=row[4],
                llm_request_json=row[5],
                llm_response_text=row[6],
                llm_response_message_content=row[7],
                debug_artifact_path=row[8],
                error=row[9],
                updated_at=row[10],
                prompt_tokens=row[11],
                completion_tokens=row[12],
                total_tokens=row[13],
                estimated_cost_usd=row[14],
                model_used=row[15],
                cost_available=bool(row[16]),
            )
            for row in rows
        ]

    def replace_hypothesis_items(self, run_id: str, request_id: str, attempt_index: int, hypotheses: List[AttackHypothesis], redact: bool = True) -> None:
        now = datetime.utcnow().isoformat() + "Z"
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM hypothesis_items WHERE run_id = ? AND request_id = ? AND attempt_index = ?",
                (run_id, request_id, attempt_index),
            )
            for index, hypothesis in enumerate(hypotheses, start=1):
                connection.execute(
                    """
                    INSERT INTO hypothesis_items (
                        run_id, request_id, hypothesis_id, attempt_index, sequence_index, attack_type, severity, mutation_summary, rationale, expected_signal,
                        method, url, headers_json, body, status, stage, execution_outcome, execution_error, response_status_code,
                        response_headers_json, response_body, findings_count, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        request_id,
                        hypothesis.hypothesis_id,
                        attempt_index,
                        index,
                        hypothesis.attack_type,
                        hypothesis.severity,
                        hypothesis.mutation_summary,
                        hypothesis.rationale,
                        hypothesis.expected_signal,
                        hypothesis.method,
                        hypothesis.url,
                        json.dumps(maybe_redact_mapping(hypothesis.headers, redact), ensure_ascii=False),
                        str(maybe_redact_value(hypothesis.body or "", redact)),
                        "generated",
                        "generated",
                        "",
                        "",
                        0,
                        "{}",
                        "",
                        0,
                        now,
                    ),
                )

    def update_hypothesis_item(self, run_id: str, hypothesis_id: str, **fields) -> None:
        if not fields:
            return
        fields["updated_at"] = datetime.utcnow().isoformat() + "Z"
        assignments = []
        params = []
        for key, value in fields.items():
            assignments.append("%s = ?" % key)
            params.append(value)
        params.extend([run_id, hypothesis_id])
        with self._connect() as connection:
            connection.execute(
                "UPDATE hypothesis_items SET %s WHERE run_id = ? AND hypothesis_id = ?" % ", ".join(assignments),
                params,
            )

    def get_hypothesis_items(self, run_id: str, request_id: Optional[str] = None) -> List[HypothesisRunItem]:
        query = """
            SELECT run_id, request_id, hypothesis_id, attempt_index, sequence_index, attack_type, severity, mutation_summary, rationale, expected_signal,
                   method, url, headers_json, body, status, stage, execution_outcome, execution_error, response_status_code,
                   response_headers_json, response_body, findings_count, COALESCE(llm_validation_json, '') as llm_validation_json, updated_at,
                   COALESCE(validation_prompt_tokens, 0), COALESCE(validation_completion_tokens, 0), COALESCE(validation_total_tokens, 0),
                   COALESCE(validation_estimated_cost_usd, 0.0), COALESCE(validation_model_used, ''), COALESCE(validation_cost_available, 0)
            FROM hypothesis_items
            WHERE run_id = ?
        """
        params: List[object] = [run_id]
        if request_id is not None:
            query += " AND request_id = ?"
            params.append(request_id)
        query += " ORDER BY request_id ASC, attempt_index ASC, sequence_index ASC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            HypothesisRunItem(
                run_id=row[0],
                request_id=row[1],
                hypothesis_id=row[2],
                attempt_index=row[3],
                sequence_index=row[4],
                attack_type=row[5],
                severity=row[6],
                mutation_summary=row[7],
                rationale=row[8],
                expected_signal=row[9],
                method=row[10],
                url=row[11],
                headers_json=row[12],
                body=row[13],
                status=row[14],
                stage=row[15],
                execution_outcome=row[16],
                execution_error=row[17],
                response_status_code=row[18],
                response_headers_json=row[19],
                response_body=row[20],
                findings_count=row[21],
                llm_validation_json=row[22],
                updated_at=row[23],
                validation_prompt_tokens=row[24],
                validation_completion_tokens=row[25],
                validation_total_tokens=row[26],
                validation_estimated_cost_usd=row[27],
                validation_model_used=row[28],
                validation_cost_available=bool(row[29]),
            )
            for row in rows
        ]

    def refresh_run_counters(self, run_id: str) -> None:
        with self._connect() as connection:
            total_requests = connection.execute(
                "SELECT COUNT(*) FROM request_items WHERE run_id = ?",
                (run_id,),
            ).fetchone()[0]
            processed_requests = connection.execute(
                "SELECT COUNT(*) FROM request_items WHERE run_id = ? AND status IN ('completed', 'error')",
                (run_id,),
            ).fetchone()[0]
            findings_count = connection.execute(
                "SELECT COALESCE(SUM(findings_count), 0) FROM request_items WHERE run_id = ?",
                (run_id,),
            ).fetchone()[0]
            connection.execute(
                "UPDATE runs SET total_requests = ?, processed_requests = ?, findings_count = ? WHERE run_id = ?",
                (total_requests, processed_requests, findings_count, run_id),
            )

    def list_runs(self) -> List[RunRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id, created_at, status, har_path, target_domains, artifact_dir, report_markdown_path, report_json_path, findings_count, config_json
                    , total_requests, processed_requests, current_endpoint, last_error, pause_requested, cancel_requested
                    , COALESCE(total_prompt_tokens, 0), COALESCE(total_completion_tokens, 0), COALESCE(total_estimated_cost_usd, 0.0), COALESCE(llm_call_count, 0), COALESCE(cost_unavailable_count, 0)
                FROM runs
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [self._row_to_run(row) for row in rows]

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT run_id, created_at, status, har_path, target_domains, artifact_dir, report_markdown_path, report_json_path, findings_count, config_json
                    , total_requests, processed_requests, current_endpoint, last_error, pause_requested, cancel_requested
                    , COALESCE(total_prompt_tokens, 0), COALESCE(total_completion_tokens, 0), COALESCE(total_estimated_cost_usd, 0.0), COALESCE(llm_call_count, 0), COALESCE(cost_unavailable_count, 0)
                FROM runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        return self._row_to_run(row) if row else None

    def get_findings(self, run_id: str) -> List[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT finding_json FROM findings WHERE run_id = ? ORDER BY severity DESC, endpoint ASC",
                (run_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def list_all_findings(self, run_id: Optional[str] = None, severity: Optional[str] = None, limit: int = 500) -> List[dict]:
        """List findings across all runs or filtered by run_id/severity."""
        with self._connect() as connection:
            query = "SELECT finding_json FROM findings WHERE 1=1"
            params = []
            if run_id:
                query += " AND run_id = ?"
                params.append(run_id)
            if severity:
                query += " AND severity = ?"
                params.append(severity.lower())
            query += " ORDER BY severity DESC, endpoint ASC LIMIT ?"
            params.append(limit)
            rows = connection.execute(query, params).fetchall()
        return [json.loads(row[0]) for row in rows]

    def delete_run(self, run_id: str) -> None:
        """Delete a run and all associated data (findings, request items, notes, etc.)."""
        with self._connect() as connection:
            connection.execute("DELETE FROM notes WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM llm_attempt_items WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM hypothesis_items WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM request_items WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
            connection.commit()

    # --- Notes ---

    def save_note(self, note_id: str, run_id: str, request_id: str, hypothesis_id: str, content: str) -> None:
        now = datetime.utcnow().isoformat() + "Z"
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO notes (note_id, run_id, request_id, hypothesis_id, content, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(note_id) DO UPDATE SET content = ?, updated_at = ?""",
                (note_id, run_id, request_id, hypothesis_id, content, now, now, content, now),
            )

    def get_notes(self, run_id: Optional[str] = None, request_id: Optional[str] = None, hypothesis_id: Optional[str] = None) -> List[Dict[str, str]]:
        query = "SELECT note_id, run_id, request_id, hypothesis_id, content, created_at, updated_at FROM notes WHERE 1=1"
        params: List[object] = []
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        if request_id:
            query += " AND request_id = ?"
            params.append(request_id)
        if hypothesis_id:
            query += " AND hypothesis_id = ?"
            params.append(hypothesis_id)
        query += " ORDER BY updated_at DESC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {"note_id": r[0], "run_id": r[1], "request_id": r[2], "hypothesis_id": r[3], "content": r[4], "created_at": r[5], "updated_at": r[6]}
            for r in rows
        ]

    def get_all_notes(self) -> List[Dict[str, str]]:
        return self.get_notes()

    def delete_note(self, note_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM notes WHERE note_id = ?", (note_id,))

    def get_note_counts(self, run_id: str) -> Dict[str, int]:
        """Get note counts grouped by request_id for a run."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT request_id, COUNT(*) FROM notes WHERE run_id = ? AND request_id != '' GROUP BY request_id",
                (run_id,),
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    def get_request_items(self, run_id: str) -> List[RequestRunItem]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id, request_id, entry_index, method, host, path, url, status, stage, hypothesis_count, executed_count, findings_count, summary, error, debug_artifact_path, updated_at,
                       request_headers_json, request_body, original_response_status, original_response_headers_json, original_response_body, latest_status_code, latest_response_headers_json, latest_response_body,
                       llm_request_json, llm_response_text, llm_response_message_content, approval_state
                FROM request_items
                WHERE run_id = ?
                ORDER BY entry_index ASC
                """,
                (run_id,),
            ).fetchall()
        return [
            RequestRunItem(
                run_id=row[0],
                request_id=row[1],
                entry_index=row[2],
                method=row[3],
                host=row[4],
                path=row[5],
                url=row[6],
                status=row[7],
                stage=row[8],
                hypothesis_count=row[9],
                executed_count=row[10],
                findings_count=row[11],
                summary=row[12],
                error=row[13],
                debug_artifact_path=row[14],
                updated_at=row[15],
                request_headers_json=row[16] if len(row) > 16 else "{}",
                request_body=row[17] if len(row) > 17 else "",
                original_response_status=row[18] if len(row) > 18 else 0,
                original_response_headers_json=row[19] if len(row) > 19 else "{}",
                original_response_body=row[20] if len(row) > 20 else "",
                latest_status_code=row[21] if len(row) > 21 else 0,
                latest_response_headers_json=row[22] if len(row) > 22 else "{}",
                latest_response_body=row[23] if len(row) > 23 else "",
                llm_request_json=row[24] if len(row) > 24 else "{}",
                llm_response_text=row[25] if len(row) > 25 else "",
                llm_response_message_content=row[26] if len(row) > 26 else "",
                approval_state=row[27] if len(row) > 27 else "not_required",
            )
            for row in rows
        ]

    def _row_to_run(self, row) -> RunRecord:
        return RunRecord(
            run_id=row[0],
            created_at=row[1],
            status=row[2],
            har_path=row[3],
            target_domains=json.loads(row[4]),
            artifact_dir=row[5],
            report_markdown_path=row[6],
            report_json_path=row[7],
            findings_count=row[8],
            config=json.loads(row[9]),
            total_requests=row[10] if len(row) > 10 else 0,
            processed_requests=row[11] if len(row) > 11 else 0,
            current_endpoint=row[12] if len(row) > 12 else "",
            last_error=row[13] if len(row) > 13 else "",
            pause_requested=bool(row[14]) if len(row) > 14 else False,
            cancel_requested=bool(row[15]) if len(row) > 15 else False,
            total_prompt_tokens=row[16] if len(row) > 16 else 0,
            total_completion_tokens=row[17] if len(row) > 17 else 0,
            total_estimated_cost_usd=row[18] if len(row) > 18 else 0.0,
            llm_call_count=row[19] if len(row) > 19 else 0,
            cost_unavailable_count=row[20] if len(row) > 20 else 0,
        )
