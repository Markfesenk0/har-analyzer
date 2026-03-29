from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .config import validate_langsmith_env
from .context import build_endpoint_context
from .evaluation import evaluate_result
from .executor import Transport, execute_hypothesis, should_fire
from .har import build_scoped_har_payload, filter_records, har_to_records, load_har
from .hypotheses import LLMClient, ProviderResponseError, get_llm_client
from .models import AttackHypothesis, EndpointBudget, ExecutionResult, Finding, RequestRecord, RunConfig, RunRecord
from .persistence import RunStore
from .redaction import maybe_redact_value, sanitize_har_payload
from .reporting import write_reports

GraphState = Dict[str, object]
ProgressCallback = Callable[[str, str, Dict[str, object]], None]


class ScanCancelledError(RuntimeError):
    pass


def build_graph():
    try:
        from langgraph.graph import END, START, StateGraph
    except Exception:
        return None

    graph = StateGraph(dict)
    graph.add_node("ingest_har", ingest_har)
    graph.add_node("filter_scope", filter_scope)
    graph.add_node("redact_input_copy", redact_input_copy)
    graph.add_node("enrich_context", enrich_context)
    graph.add_node("analyze_request", analyze_request)
    graph.add_node("execute_attack", execute_attack_node)
    graph.add_node("evaluate_response", evaluate_response_node)
    graph.add_node("persist_and_report", persist_and_report)

    graph.add_edge(START, "ingest_har")
    graph.add_edge("ingest_har", "filter_scope")
    graph.add_edge("filter_scope", "redact_input_copy")
    graph.add_edge("redact_input_copy", "enrich_context")
    graph.add_edge("enrich_context", "analyze_request")
    graph.add_conditional_edges(
        "analyze_request",
        _route_after_analyze,
        {"execute_attack": "execute_attack", "persist_and_report": "persist_and_report", "analyze_request": "analyze_request"},
    )
    graph.add_edge("execute_attack", "evaluate_response")
    graph.add_conditional_edges(
        "evaluate_response",
        _route_after_evaluate,
        {"execute_attack": "execute_attack", "analyze_request": "analyze_request", "persist_and_report": "persist_and_report"},
    )
    graph.add_edge("persist_and_report", END)
    return graph.compile()


def run_scan(
    config: RunConfig,
    llm_client: Optional[LLMClient] = None,
    transport: Optional[Transport] = None,
    progress_callback: Optional[ProgressCallback] = None,
    store: Optional[RunStore] = None,
    run: Optional[RunRecord] = None,
) -> RunRecord:
    validate_langsmith_env()
    store = store or RunStore(config.database_path)
    run = run or store.create_run(config)
    config.run_artifact_dir = run.artifact_dir
    state: GraphState = {
        "config": config,
        "store": store,
        "run": run,
        "llm_client": llm_client or get_llm_client(config),
        "transport": transport,
        "progress_callback": progress_callback,
        "records": [],
        "scoped_records": [],
        "context": None,
        "budgets": {},
        "findings": [],
        "execution_results": [],
        "findings_by_request": {},
    }
    try:
        compiled = build_graph()
        if compiled is not None:
            compiled.invoke(state)
        else:
            _run_sequential(state)
    except ScanCancelledError as error:
        run.last_error = str(error)
        markdown_path, json_path = write_reports(run, state["findings"], unsafe=state["config"].allow_unsafe_artifacts)
        store.finalize_run(run, state["findings"], markdown_path, json_path, status="canceled")
        store.update_run_progress(run.run_id, current_endpoint="", last_error=str(error))
        refreshed_run = store.get_run(run.run_id)
        if refreshed_run is not None:
            state["run"] = refreshed_run
        _emit_progress(state, "canceled", str(error), run_id=run.run_id)
    except Exception as error:
        _write_failure_artifact(run.artifact_dir, error)
        store.mark_run_failed(run.run_id, str(error))
        _emit_progress(state, "error", "Run failed: %s" % error, run_id=run.run_id)
        raise
    return state["run"]


def ingest_har(state: GraphState) -> GraphState:
    config = state["config"]
    state["records"] = har_to_records(config.har_path)
    _emit_progress(state, "ingest_har", "Loaded %d HAR entries" % len(state["records"]))
    return state


def filter_scope(state: GraphState) -> GraphState:
    config = state["config"]
    store = state["store"]
    run = state["run"]
    state["scoped_records"] = filter_records(state["records"], config.target_domains, config.excluded_path_patterns)
    store.seed_request_items(run.run_id, state["scoped_records"], redact=config.redact_by_default)
    store.update_run_progress(run.run_id, total_requests=len(state["scoped_records"]), processed_requests=0, current_endpoint="")
    run.total_requests = len(state["scoped_records"])
    _emit_progress(state, "filter_scope", "Scoped %d API calls for analysis" % len(state["scoped_records"]), total_requests=len(state["scoped_records"]))
    return state


def redact_input_copy(state: GraphState) -> GraphState:
    config = state["config"]
    run = state["run"]
    payload = load_har(config.har_path)
    payload = build_scoped_har_payload(payload, state["scoped_records"], sanitize=not config.allow_unsafe_artifacts)
    path = os.path.join(run.artifact_dir, "sanitized-input.har")
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    state["sanitized_har_path"] = path
    _emit_progress(state, "redact_input_copy", "Wrote scoped sanitized HAR copy to %s" % path)
    return state


def enrich_context(state: GraphState) -> GraphState:
    state["context"] = build_endpoint_context(state["scoped_records"], state["config"].neighbor_context_window)
    state.setdefault("current_index", 0)
    _emit_progress(state, "enrich_context", "Built context across %d scoped endpoints" % len(state["scoped_records"]))
    return state


def analyze_request(state: GraphState) -> GraphState:
    records = state["scoped_records"]
    current_index = int(state.get("current_index", 0))
    if current_index >= len(records):
        state["current_hypotheses"] = []
        return state
    record = records[current_index]
    _honor_run_controls(state, record)
    state["current_record"] = record
    config = state["config"]
    llm_client = state["llm_client"]
    store = state["store"]
    run = state["run"]
    existing_items = {item.request_id: item for item in store.get_request_items(run.run_id)}
    existing_item = existing_items.get(record.request_id)
    if existing_item is not None and existing_item.status == "completed" and existing_item.stage in {"no_hypotheses", "completed", "skipped_llm"}:
        state["current_hypotheses"] = []
        state["current_hypothesis_index"] = 0
        state["current_index"] = current_index + 1
        return state
    existing_approval_state = existing_item.approval_state if existing_item is not None else "not_required"
    approval_state = "pending" if config.step_mode else "auto"
    needs_manual_approval = config.step_mode
    if config.step_mode and existing_approval_state in {"approved", "skipped"}:
        approval_state = existing_approval_state
        needs_manual_approval = False
    preview = llm_client.build_preview(record, state["context"], config)
    llm_request_json = json.dumps(maybe_redact_value(preview, config.redact_by_default), indent=2, ensure_ascii=False)
    attempt_index = None
    state["current_attempt_index"] = None
    store.update_run_progress(run.run_id, current_endpoint=record.endpoint_key(), status="running")
    store.update_request_item(
        run.run_id,
        record.request_id,
        status="running",
        stage="analyze_request",
        summary="Generating hypotheses",
        error="",
        debug_artifact_path=existing_item.debug_artifact_path if existing_item is not None else "",
        llm_request_json=llm_request_json,
        llm_response_text=existing_item.llm_response_text if existing_item is not None else "",
        llm_response_message_content=existing_item.llm_response_message_content if existing_item is not None else "",
        approval_state=approval_state,
    )
    if needs_manual_approval:
        store.update_run_progress(run.run_id, status="awaiting_approval")
        store.update_request_item(
            run.run_id,
            record.request_id,
            status="awaiting_approval",
            stage="awaiting_llm_approval",
            summary="Waiting for approval before sending to the LLM",
        )
        _emit_progress(state, "awaiting_llm_approval", "Waiting for approval for %s" % record.endpoint_key(), request_id=record.request_id)
        approval_outcome = _wait_for_llm_approval(state, record)
        if approval_outcome == "skipped":
            state["current_hypotheses"] = []
            state["current_hypothesis_index"] = 0
            state["current_index"] = current_index + 1
            return state
        store.update_run_progress(run.run_id, status="running")
    attempt_index = store.create_llm_attempt(run.run_id, record.request_id, llm_request_json)
    state["current_attempt_index"] = attempt_index
    _emit_progress(state, "analyze_request", "Analyzing %s" % record.endpoint_key(), request_id=record.request_id)
    try:
        hypotheses = llm_client.generate_hypotheses(record, state["context"], config)
        _persist_llm_response_debug(
            store,
            run.run_id,
            record.request_id,
            getattr(llm_client, "last_provider_response_text", ""),
            getattr(llm_client, "last_message_content", ""),
            getattr(llm_client, "last_debug_path", ""),
            config.redact_by_default,
            attempt_index=attempt_index or 1,
        )
        _emit_progress(
            state,
            "llm_response",
            "LLM response received for %s" % record.endpoint_key(),
            request_id=record.request_id,
            content_chars=len(getattr(llm_client, "last_message_content", "") or ""),
            debug_artifact_path=getattr(llm_client, "last_debug_path", ""),
            content_preview=(getattr(llm_client, "last_message_content", "") or "")[:300],
        )
    except ProviderResponseError as error:
        _persist_llm_response_debug(store, run.run_id, record.request_id, error.raw_content, "", error.debug_artifact_path, config.redact_by_default, attempt_index=attempt_index or 1)
        store.update_request_item(
            run.run_id,
            record.request_id,
            status="error",
            stage="analyze_request",
            error=str(error),
            summary="Provider response could not be parsed",
            debug_artifact_path=error.debug_artifact_path,
            approval_state="approved" if config.step_mode else "auto",
        )
        store.update_llm_attempt(
            run.run_id,
            record.request_id,
            attempt_index or 1,
            status="error",
            stage="analyze_request",
            error=str(error),
            debug_artifact_path=error.debug_artifact_path,
        )
        store.update_run_progress(run.run_id, last_error=str(error))
        store.refresh_run_counters(run.run_id)
        state["current_hypotheses"] = []
        state["current_hypothesis_index"] = 0
        state["current_index"] = current_index + 1
        _emit_progress(
            state,
            "analyze_request",
            "Provider parsing failed for %s" % record.endpoint_key(),
            request_id=record.request_id,
            error=str(error),
            debug_artifact_path=error.debug_artifact_path,
            content_preview=(error.raw_content or "")[:300],
        )
        return state
    except Exception as error:
        store.update_request_item(
            run.run_id,
            record.request_id,
            status="error",
            stage="analyze_request",
            error=str(error),
            summary="Unexpected analysis error",
            approval_state="approved" if config.step_mode else "auto",
        )
        store.update_llm_attempt(
            run.run_id,
            record.request_id,
            attempt_index or 1,
            status="error",
            stage="analyze_request",
            error=str(error),
        )
        store.update_run_progress(run.run_id, last_error=str(error))
        store.refresh_run_counters(run.run_id)
        state["current_hypotheses"] = []
        state["current_hypothesis_index"] = 0
        state["current_index"] = current_index + 1
        _emit_progress(state, "analyze_request", "Analysis failed for %s" % record.endpoint_key(), request_id=record.request_id, error=str(error))
        return state
    endpoint_key = record.endpoint_key()
    budgets = state["budgets"]
    if endpoint_key not in budgets:
        budgets[endpoint_key] = EndpointBudget(
            endpoint_key=endpoint_key,
            max_hypotheses=config.per_endpoint_hypothesis_cap,
        )
    state["current_hypotheses"] = hypotheses
    state["current_hypothesis_index"] = 0
    store.replace_hypothesis_items(run.run_id, record.request_id, attempt_index or 1, hypotheses, redact=config.redact_by_default)
    store.update_llm_attempt(
        run.run_id,
        record.request_id,
        attempt_index or 1,
        status="completed",
        stage="hypotheses_generated",
    )
    if hypotheses:
        store.update_request_item(
            run.run_id,
            record.request_id,
            stage="pending_attacks",
            summary="Generated %d hypotheses" % len(hypotheses),
            hypothesis_count=len(hypotheses),
            approval_state="approved" if config.step_mode else "auto",
        )
    else:
        store.update_request_item(
            run.run_id,
            record.request_id,
            status="completed",
            stage="no_hypotheses",
            summary="No attack hypotheses generated",
            hypothesis_count=0,
            approval_state="approved" if config.step_mode else "auto",
        )
        store.refresh_run_counters(run.run_id)
        state["current_index"] = current_index + 1
    return state


def execute_attack_node(state: GraphState) -> GraphState:
    record = state["current_record"]
    _honor_run_controls(state, record)
    store = state["store"]
    run = state["run"]
    hypotheses: List[AttackHypothesis] = state.get("current_hypotheses", [])
    index = int(state.get("current_hypothesis_index", 0))
    hypothesis = hypotheses[index]
    store.update_request_item(
        run.run_id,
        record.request_id,
        stage="execute_attack",
        summary="Executing hypothesis %d of %d" % (index + 1, len(hypotheses)),
    )
    store.update_hypothesis_item(
        run.run_id,
        hypothesis.hypothesis_id,
        status="running",
        stage="execute_attack",
    )
    _emit_progress(state, "execute_attack", "Executing %s for %s" % (hypothesis.attack_type, record.endpoint_key()), request_id=record.request_id, hypothesis_id=hypothesis.hypothesis_id)
    budget = state["budgets"][record.endpoint_key()]
    config = state["config"]
    executed_so_far = len(state["execution_results"])
    if not should_fire(hypothesis, budget, executed_so_far, config):
        result = ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            outcome="skipped",
            error="Skipped due to budget or dedupe controls.",
        )
    else:
        result = execute_hypothesis(hypothesis, record, config, state.get("transport"))
    state["current_hypothesis"] = hypothesis
    state["current_result"] = result
    state["execution_results"].append(result)
    store.update_request_item(
        run.run_id,
        record.request_id,
        executed_count=index + 1,
        summary="Latest result: %s" % result.outcome,
        error=result.error or "",
        latest_status_code=result.status_code or 0,
        latest_response_headers_json=json.dumps(maybe_redact_value(result.response_headers, config.redact_by_default), ensure_ascii=False),
        latest_response_body=str(maybe_redact_value(result.response_body or "", config.redact_by_default)),
    )
    store.update_hypothesis_item(
        run.run_id,
        hypothesis.hypothesis_id,
        status="executed",
        stage="execute_attack",
        execution_outcome=result.outcome,
        execution_error=result.error or "",
        response_status_code=result.status_code or 0,
        response_headers_json=json.dumps(maybe_redact_value(result.response_headers, config.redact_by_default), ensure_ascii=False),
        response_body=str(maybe_redact_value(result.response_body or "", config.redact_by_default)),
    )
    return state


def evaluate_response_node(state: GraphState) -> GraphState:
    record = state["current_record"]
    hypothesis = state["current_hypothesis"]
    result = state["current_result"]
    store = state["store"]
    run = state["run"]
    findings = evaluate_result(record, hypothesis, result)
    state["findings"].extend(findings)
    request_findings = int(state["findings_by_request"].get(record.request_id, 0)) + len(findings)
    state["findings_by_request"][record.request_id] = request_findings
    state["current_hypothesis_index"] = int(state.get("current_hypothesis_index", 0)) + 1
    is_done = state["current_hypothesis_index"] >= len(state.get("current_hypotheses", []))
    store.update_request_item(
        run.run_id,
        record.request_id,
        status="completed" if is_done else "running",
        stage="completed" if is_done else "evaluate_response",
        findings_count=request_findings,
        summary="Finished with %d finding(s)" % request_findings if is_done else "Evaluating response",
    )
    store.update_hypothesis_item(
        run.run_id,
        hypothesis.hypothesis_id,
        status="completed",
        stage="completed" if findings else "evaluated",
        findings_count=len(findings),
    )
    if is_done:
        store.refresh_run_counters(run.run_id)
        state["current_index"] = int(state.get("current_index", 0)) + 1
    _emit_progress(state, "evaluate_response", "Evaluated %s for %s" % (hypothesis.attack_type, record.endpoint_key()), request_id=record.request_id, findings=len(findings))
    return state


def persist_and_report(state: GraphState) -> GraphState:
    run = state["run"]
    store = state["store"]
    findings = state["findings"]
    markdown_path, json_path = write_reports(run, findings, unsafe=state["config"].allow_unsafe_artifacts)
    store.finalize_run(run, findings, markdown_path, json_path)
    store.refresh_run_counters(run.run_id)
    refreshed_run = store.get_run(run.run_id)
    if refreshed_run is not None:
        state["run"] = refreshed_run
    _emit_progress(state, "persist_and_report", "Wrote reports for %s" % run.run_id, report_markdown_path=markdown_path, report_json_path=json_path)
    return state


def _route_after_analyze(state: GraphState) -> str:
    hypotheses = state.get("current_hypotheses", [])
    scoped_records = state.get("scoped_records", [])
    if hypotheses:
        return "execute_attack"
    if int(state.get("current_index", 0)) < len(scoped_records):
        return "analyze_request"
    return "persist_and_report"


def _route_after_evaluate(state: GraphState) -> str:
    hypothesis_index = int(state.get("current_hypothesis_index", 0))
    current_hypotheses = state.get("current_hypotheses", [])
    scoped_records = state.get("scoped_records", [])
    if hypothesis_index < len(current_hypotheses):
        return "execute_attack"
    if int(state.get("current_index", 0)) < len(scoped_records):
        return "analyze_request"
    return "persist_and_report"


def _run_sequential(state: GraphState) -> None:
    ingest_har(state)
    filter_scope(state)
    redact_input_copy(state)
    enrich_context(state)
    state["current_index"] = 0
    records = state["scoped_records"]
    while int(state.get("current_index", 0)) < len(records):
        analyze_request(state)
        while int(state.get("current_hypothesis_index", 0)) < len(state.get("current_hypotheses", [])):
            execute_attack_node(state)
            evaluate_response_node(state)
    persist_and_report(state)


def _emit_progress(state: GraphState, stage: str, message: str, **payload) -> None:
    callback = state.get("progress_callback")
    if callback:
        callback(stage, message, payload)


def _write_failure_artifact(artifact_dir: str, error: Exception) -> None:
    Path(artifact_dir).mkdir(parents=True, exist_ok=True)
    path = Path(artifact_dir) / "run_failure.txt"
    path.write_text("".join(traceback.format_exception(type(error), error, error.__traceback__)), encoding="utf-8")


def _honor_run_controls(state: GraphState, record: Optional[RequestRecord] = None) -> None:
    store = state["store"]
    run = store.get_run(state["run"].run_id)
    if run is None:
        return
    state["run"] = run
    request_id = record.request_id if record is not None else ""
    if run.cancel_requested:
        if request_id:
            store.update_request_item(
                run.run_id,
                request_id,
                status="error",
                stage="canceled",
                error="Run canceled by user",
                summary="Canceled before completion",
            )
            store.refresh_run_counters(run.run_id)
        raise ScanCancelledError("Run canceled by user.")
    paused_notified = False
    while run.pause_requested:
        if request_id:
            store.update_request_item(
                run.run_id,
                request_id,
                status="paused",
                stage="paused",
                summary="Paused by user",
            )
        if not paused_notified:
            _emit_progress(state, "paused", "Run paused", run_id=run.run_id, request_id=request_id)
            paused_notified = True
        time.sleep(1.0)
        run = store.get_run(state["run"].run_id)
        if run is None:
            return
        state["run"] = run
        if run.cancel_requested:
            raise ScanCancelledError("Run canceled by user.")
    if paused_notified and request_id:
        store.update_request_item(
            run.run_id,
            request_id,
            status="running",
            stage="resumed",
            summary="Resumed",
        )
        _emit_progress(state, "resumed", "Run resumed", run_id=run.run_id, request_id=request_id)


def _wait_for_llm_approval(state: GraphState, record: RequestRecord) -> str:
    store = state["store"]
    run_id = state["run"].run_id
    while True:
        _honor_run_controls(state, record)
        items = {item.request_id: item for item in store.get_request_items(run_id)}
        item = items.get(record.request_id)
        if item is None:
            return "approved"
        if item.approval_state == "approved":
            return "approved"
        if item.approval_state == "skipped":
            store.update_request_item(
                run_id,
                record.request_id,
                status="completed",
                stage="skipped_llm",
                summary="Skipped by analyst before LLM send",
            )
            store.refresh_run_counters(run_id)
            _emit_progress(state, "skipped_llm", "Skipped %s before LLM send" % record.endpoint_key(), request_id=record.request_id)
            return "skipped"
        time.sleep(1.0)


def _persist_llm_response_debug(
    store: RunStore,
    run_id: str,
    request_id: str,
    raw_response_text: str,
    message_content: str,
    debug_artifact_path: str = "",
    redact: bool = True,
    attempt_index: int = 1,
) -> None:
    safe_response_text = maybe_redact_value(raw_response_text or "", redact)
    safe_message_content = maybe_redact_value(message_content or "", redact)
    store.update_request_item(
        run_id,
        request_id,
        llm_response_text=safe_response_text,
        llm_response_message_content=safe_message_content,
        debug_artifact_path=debug_artifact_path,
    )
    store.update_llm_attempt(
        run_id,
        request_id,
        attempt_index,
        status="completed" if (raw_response_text or message_content) else "pending",
        stage="llm_response_received",
        llm_response_text=safe_response_text,
        llm_response_message_content=safe_message_content,
        debug_artifact_path=debug_artifact_path,
    )
