from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


def _serialize(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _serialize(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value


@dataclass
class RunConfig:
    har_path: str
    target_domains: List[str]
    provider: str = "builtin"
    model: str = "builtin-heuristics"
    langsmith_project: str = "har-analyzer"
    concurrency: int = 4
    per_endpoint_hypothesis_cap: int = 10
    global_request_cap: int = 100
    inter_request_delay_ms: int = 500
    excluded_path_patterns: List[str] = field(default_factory=list)
    allow_unsafe_artifacts: bool = False
    artifact_dir: str = "artifacts"
    database_path: str = "artifacts/runs.sqlite3"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_timeout_seconds: float = 60.0
    llm_busy_retry_count: int = 2
    llm_busy_retry_base_delay_seconds: float = 2.0
    request_timeout_seconds: float = 20.0
    ui_host: str = "127.0.0.1"
    ui_port: int = 8765
    max_body_chars: int = 4000
    truncated_body_chars: int = 1000
    neighbor_context_window: int = 2
    run_artifact_dir: str = ""
    step_mode: bool = False
    redact_by_default: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class RequestRecord:
    request_id: str
    entry_index: int
    started_at: str
    method: str
    url: str
    scheme: str
    host: str
    path: str
    query_params: Dict[str, str] = field(default_factory=dict)
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    duration_ms: float = 0.0
    flags: List[str] = field(default_factory=list)

    def endpoint_key(self) -> str:
        return "%s %s" % (self.method.upper(), self.path)

    def normalized_path(self) -> str:
        parts = []
        for part in self.path.strip("/").split("/"):
            if part.isdigit():
                parts.append("{id}")
            else:
                parts.append(part)
        return "/" + "/".join(part for part in parts if part)

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class EndpointContext:
    auth_header_names: List[str] = field(default_factory=list)
    cookies_seen: List[str] = field(default_factory=list)
    recurring_parameters: Dict[str, int] = field(default_factory=dict)
    resource_ids_seen: List[str] = field(default_factory=list)
    user_roles_seen: List[str] = field(default_factory=list)
    neighboring_requests: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    endpoint_groups: Dict[str, List[str]] = field(default_factory=dict)
    api_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class EndpointBudget:
    endpoint_key: str
    hypotheses_fired: int = 0
    max_hypotheses: int = 10
    seen_payload_hashes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class AttackHypothesis:
    hypothesis_id: str
    original_request_id: str
    endpoint_key: str
    attack_type: str
    severity: str
    expected_signal: str
    rationale: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    mutation_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class ExecutionResult:
    hypothesis_id: str
    request_id: str
    method: str
    url: str
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    duration_ms: float = 0.0
    body_size_delta: int = 0
    outcome: str = "not_run"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class Finding:
    finding_id: str
    request_id: str
    hypothesis_id: str
    title: str
    attack_type: str
    severity: str
    confidence: str
    endpoint: str
    summary: str
    expected_signal: str
    owasp: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    remediation: str = ""
    reproduction_curl: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class RunRecord:
    run_id: str
    created_at: str
    status: str
    har_path: str
    target_domains: List[str]
    artifact_dir: str
    report_markdown_path: Optional[str] = None
    report_json_path: Optional[str] = None
    findings_count: int = 0
    total_requests: int = 0
    processed_requests: int = 0
    current_endpoint: str = ""
    last_error: str = ""
    pause_requested: bool = False
    cancel_requested: bool = False
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class RequestRunItem:
    run_id: str
    request_id: str
    entry_index: int
    method: str
    host: str
    path: str
    url: str
    status: str = "queued"
    stage: str = "queued"
    hypothesis_count: int = 0
    executed_count: int = 0
    findings_count: int = 0
    summary: str = ""
    error: str = ""
    debug_artifact_path: str = ""
    request_headers_json: str = "{}"
    request_body: str = ""
    original_response_status: int = 0
    original_response_headers_json: str = "{}"
    original_response_body: str = ""
    latest_status_code: int = 0
    latest_response_headers_json: str = "{}"
    latest_response_body: str = ""
    llm_request_json: str = "{}"
    llm_response_text: str = ""
    llm_response_message_content: str = ""
    approval_state: str = "not_required"
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class HypothesisRunItem:
    run_id: str
    request_id: str
    hypothesis_id: str
    attempt_index: int
    sequence_index: int
    attack_type: str
    severity: str
    mutation_summary: str = ""
    rationale: str = ""
    expected_signal: str = ""
    method: str = ""
    url: str = ""
    headers_json: str = "{}"
    body: str = ""
    status: str = "generated"
    stage: str = "generated"
    execution_outcome: str = ""
    execution_error: str = ""
    response_status_code: int = 0
    response_headers_json: str = "{}"
    response_body: str = ""
    findings_count: int = 0
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)


@dataclass
class LLMAttemptRunItem:
    run_id: str
    request_id: str
    attempt_index: int
    status: str = "pending"
    stage: str = "prepared"
    llm_request_json: str = "{}"
    llm_response_text: str = ""
    llm_response_message_content: str = ""
    debug_artifact_path: str = ""
    error: str = ""
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)
