from __future__ import annotations

import os
import threading
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
from collections import Counter

from .har import filter_records, har_to_records
from .config import get_default_unsafe_unredacted, get_supported_provider_options, load_run_config, save_api_key, has_saved_key
from .graph import run_scan
from .persistence import RunStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HAR_DIR = PROJECT_ROOT / "HAR files"


def create_app(artifact_dir: str = "artifacts"):
    try:
        from fastapi import FastAPI, Form, Request, Query
        from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, FileResponse, JSONResponse
        from fastapi.templating import Jinja2Templates
    except Exception as error:
        raise RuntimeError("FastAPI is required for the local web UI: %s" % error)
    globals()["Request"] = Request

    app = FastAPI(title="HAR Analyzer")
    template_dir = Path(__file__).with_name("templates")
    templates = Jinja2Templates(directory=str(template_dir))
    store = RunStore(os.getenv("HAR_ANALYZER_DB_PATH", os.path.join(artifact_dir, "runs.sqlite3")))
    unsafe_default = "true" if get_default_unsafe_unredacted() else "false"
    provider_options = get_supported_provider_options()

    # Jinja2 filters
    def filter_basename(path: str) -> str:
        return Path(path).name
    templates.env.filters["basename"] = filter_basename

    def filter_prettyjson(value: str) -> str:
        """Pretty-print a JSON string."""
        if not value or value in ("{}", "null", ""):
            return value or ""
        try:
            parsed = json.loads(value)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            return value
    templates.env.filters["prettyjson"] = filter_prettyjson

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        runs = store.list_runs()
        # Compute finding severity counts across ALL runs
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_findings = 0
        for run in runs:
            findings = store.get_findings(run.run_id)
            total_findings += len(findings)
            for finding in findings:
                severity = finding.get("severity", "low").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        # Stats for dashboard cards
        stats = {
            "total_scans": len(runs),
            "running": sum(1 for r in runs if r.status in ("running", "processing")),
            "completed": sum(1 for r in runs if r.status == "completed"),
            "total_findings": total_findings,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
        }

        # Build trend data for Plotly line chart (simplified: just use severity distribution)
        severity_trend_data = [
            {
                "x": ["Critical", "High", "Medium", "Low"],
                "y": [
                    severity_counts["critical"],
                    severity_counts["high"],
                    severity_counts["medium"],
                    severity_counts["low"],
                ],
                "type": "bar",
                "marker": {"color": ["#a64b3a", "#d97706", "#d97706", "#2d8a3a"]},
                "name": "Findings"
            }
        ]

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "current_page": "dashboard",
                "recent_runs": runs[:5],
                "runs": runs,
                "stats": stats,
                "severity_trend_data": severity_trend_data,
                "severity_chart_data": {
                    "labels": ["Critical", "High", "Medium", "Low"],
                    "values": [
                        severity_counts["critical"],
                        severity_counts["high"],
                        severity_counts["medium"],
                        severity_counts["low"],
                    ],
                },
            },
        )

    @app.get("/new-scan", response_class=HTMLResponse)
    def new_scan(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="new_scan.html",
            context={
                "current_page": "new_scan",
                "recent_runs": store.list_runs()[:5],
                "har_files": _discover_har_files(),
                "provider_options": provider_options,
                "defaults": {
                    "provider": os.getenv("HAR_ANALYZER_LLM_PROVIDER", "builtin"),
                    "model": os.getenv("HAR_ANALYZER_MODEL", "builtin-heuristics"),
                    "validation_model": os.getenv("HAR_ANALYZER_VALIDATION_MODEL", ""),
                    "unsafe_unredacted": unsafe_default,
                    "step_mode": os.getenv("HAR_ANALYZER_STEP_MODE", "false").lower(),
                    "redact_by_default": os.getenv("HAR_ANALYZER_REDACT_BY_DEFAULT", "false").lower(),
                    "concurrency": os.getenv("HAR_ANALYZER_CONCURRENCY", "4"),
                    "inter_request_delay_ms": os.getenv("HAR_ANALYZER_INTER_REQUEST_DELAY_MS", "500"),
                    "per_endpoint_hypothesis_cap": os.getenv("HAR_ANALYZER_ENDPOINT_CAP", "10"),
                    "global_request_cap": os.getenv("HAR_ANALYZER_GLOBAL_CAP", "250"),
                },
            },
        )

    @app.post("/scan")
    def start_scan(
        har_path: str = Form(...),
        scope_domains: List[str] = Form(...),
        unsafe_unredacted: str = Form("false"),
        provider: str = Form(""),
        model: str = Form(""),
        api_key: str = Form(""),
        api_key_env: str = Form(""),
        save_key: str = Form("false"),
        scan_mode: str = Form("full"),
        step_mode: str = Form("true"),
        concurrency: Optional[int] = Form(None),
        inter_request_delay_ms: Optional[int] = Form(None),
        per_endpoint_hypothesis_cap: Optional[int] = Form(None),
        global_request_cap: Optional[int] = Form(None),
    ):
        # Resolve API key: direct input > env variable > saved > .env default
        resolved_api_key = api_key.strip()
        if not resolved_api_key and api_key_env.strip():
            resolved_api_key = os.getenv(api_key_env.strip(), "")
        # Save API key if requested
        if resolved_api_key and save_key.lower() == "true":
            save_api_key(provider.strip(), resolved_api_key)
        config = load_run_config(
            har_path=har_path,
            target_domains=[item.strip() for item in scope_domains if item and item.strip()],
            artifact_dir=artifact_dir,
            allow_unsafe_artifacts=unsafe_unredacted.lower() == "true",
            provider=provider.strip(),
            model=model.strip(),
            api_key=resolved_api_key,
            step_mode=step_mode.lower() == "true",
            hypotheses_only=scan_mode.strip() == "hypotheses_only",
        )
        # Apply advanced settings if provided
        if concurrency is not None and concurrency > 0:
            config.concurrency = concurrency
        if inter_request_delay_ms is not None and inter_request_delay_ms >= 0:
            config.inter_request_delay_ms = inter_request_delay_ms
        if per_endpoint_hypothesis_cap is not None and per_endpoint_hypothesis_cap > 0:
            config.per_endpoint_hypothesis_cap = per_endpoint_hypothesis_cap
        if global_request_cap is not None and global_request_cap > 0:
            config.global_request_cap = global_request_cap

        run = store.create_run(config)
        config.run_artifact_dir = run.artifact_dir
        thread = threading.Thread(
            target=_background_scan,
            args=(config, store, run),
            daemon=True,
        )
        thread.start()
        return RedirectResponse(url="/runs/%s" % run.run_id, status_code=303)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: str):
        run = store.get_run(run_id)
        findings = store.get_findings(run_id)
        request_items = store.get_request_items(run_id)
        hypothesis_items = store.get_hypothesis_items(run_id)
        llm_attempt_items = store.get_llm_attempt_items(run_id)

        # Compute elapsed time
        elapsed_seconds = 0
        if run and run.created_at:
            try:
                created = datetime.fromisoformat(run.created_at.replace('Z', '+00:00'))
                elapsed = datetime.now(created.tzinfo) - created if created.tzinfo else datetime.now() - created
                elapsed_seconds = int(elapsed.total_seconds())
            except Exception:
                pass

        # Compute success rate (2xx responses)
        success_rate = 0
        if request_items:
            successful = sum(1 for item in request_items if str(item.original_response_status).startswith('2'))
            success_rate = round((successful / len(request_items)) * 100, 1)

        # Estimate remaining time
        estimated_remaining_time = "--"
        if run and run.total_requests > 0 and elapsed_seconds > 0:
            processed = run.processed_requests or 0
            if processed > 0:
                avg_time_per_request = elapsed_seconds / processed
                remaining_requests = run.total_requests - processed
                remaining_seconds = int(avg_time_per_request * remaining_requests)
                if remaining_seconds > 0:
                    minutes = remaining_seconds // 60
                    seconds = remaining_seconds % 60
                    if minutes > 0:
                        estimated_remaining_time = f"{minutes}m {seconds}s"
                    else:
                        estimated_remaining_time = f"{seconds}s"

        return templates.TemplateResponse(
            request=request,
            name="run_detail.html",
            context={
                "current_page": "runs",
                "recent_runs": store.list_runs()[:5],
                "run": run,
                "findings": findings,
                "request_items": [item.to_dict() for item in request_items],
                "hypothesis_items": [item.to_dict() for item in hypothesis_items],
                "llm_attempt_items": [item.to_dict() for item in llm_attempt_items],
                # Slim versions for page-data JSON (no heavy response bodies)
                "request_items_slim": [
                    {"request_id": i.request_id, "method": i.method, "path": i.path, "url": i.url,
                     "host": i.host, "status": i.status, "stage": i.stage, "entry_index": i.entry_index,
                     "hypothesis_count": i.hypothesis_count, "findings_count": i.findings_count,
                     "original_response_status": i.original_response_status, "summary": i.summary,
                     "approval_state": i.approval_state}
                    for i in request_items
                ],
                "hypothesis_items_slim": [
                    {"hypothesis_id": h.hypothesis_id, "request_id": h.request_id, "attack_type": h.attack_type,
                     "severity": h.severity, "mutation_summary": h.mutation_summary, "status": h.status,
                     "stage": h.stage, "execution_outcome": h.execution_outcome, "execution_error": h.execution_error,
                     "response_status_code": h.response_status_code, "findings_count": h.findings_count,
                     "method": h.method, "url": h.url, "updated_at": h.updated_at}
                    for h in hypothesis_items
                ],
                "elapsed_seconds": elapsed_seconds,
                "success_rate": success_rate,
                "estimated_remaining_time": estimated_remaining_time,
                "note_counts": store.get_note_counts(run_id),
            },
        )

    @app.get("/runs/{run_id}/approve", response_class=HTMLResponse)
    def approval_queue(request: Request, run_id: str):
        run = store.get_run(run_id)
        request_items = store.get_request_items(run_id)
        # Filter pending items
        pending_items = [item for item in request_items if item.approval_state == "pending"]
        hypothesis_items = store.get_hypothesis_items(run_id)
        return templates.TemplateResponse(
            request=request,
            name="approval_queue.html",
            context={
                "current_page": "runs",
                "recent_runs": store.list_runs()[:5],
                "run": run,
                "pending_items": pending_items,
                "hypothesis_items": hypothesis_items,
            },
        )

    @app.get("/reports", response_class=HTMLResponse)
    def reports(request: Request, severity: Optional[str] = Query(None), q: Optional[str] = Query(None)):
        runs = store.list_runs()
        all_findings = []
        # Build per-scan groups: list of {run, findings} for scans that have findings
        scan_groups = []
        for run in runs:
            findings = store.get_findings(run.run_id)
            for f in findings:
                f["_run_id"] = run.run_id
            all_findings.extend(findings)
            if findings:
                scan_groups.append({"run": run, "findings": findings})

        # Compute stats BEFORE filtering (so summary cards always show totals)
        severity_counts = Counter(f.get("severity", "low").lower() for f in all_findings)

        # Apply filters to each scan group
        active_severity = ""
        q_lower = ""
        if severity and severity.lower() in {"critical", "high", "medium", "low", "info"}:
            active_severity = severity.lower()
        if q and q.strip():
            q_lower = q.strip().lower()

        filtered_groups = []
        total_visible = 0
        for group in scan_groups:
            filtered = group["findings"]
            if active_severity:
                filtered = [f for f in filtered if f.get("severity", "").lower() == active_severity]
            if q_lower:
                filtered = [f for f in filtered if q_lower in (f.get("title", "") + " " + f.get("endpoint", "") + " " + f.get("attack_type", "")).lower()]
            if filtered:
                filtered_groups.append({"run": group["run"], "findings": filtered})
                total_visible += len(filtered)

        return templates.TemplateResponse(
            request=request,
            name="reports.html",
            context={
                "current_page": "reports",
                "recent_runs": store.list_runs()[:5],
                "scan_groups": filtered_groups,
                "total_findings": total_visible,
                "total_scans": len(scan_groups),
                "severity_counts": {
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                },
                "active_severity": severity or "",
                "search_query": q or "",
            },
        )

    @app.get("/runs/{run_id}/report", response_class=HTMLResponse)
    def report_detail(request: Request, run_id: str):
        run = store.get_run(run_id)
        findings = store.get_findings(run_id)
        request_items = store.get_request_items(run_id)

        # Compute OWASP categories
        owasp_counts = Counter()
        for finding in findings:
            for tag in finding.get("owasp", []):
                owasp_counts[tag] += 1

        # Compute severity counts
        severity_counts = Counter(f.get("severity", "low") for f in findings)

        return templates.TemplateResponse(
            request=request,
            name="report_detail.html",
            context={
                "current_page": "reports",
                "recent_runs": store.list_runs()[:5],
                "run": run,
                "findings": findings,
                "request_items": request_items,
                "owasp_counts": dict(owasp_counts),
                "severity_counts": dict(severity_counts),
            },
        )

    @app.get("/settings", response_class=HTMLResponse)
    def settings(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "current_page": "settings",
                "recent_runs": store.list_runs()[:5],
                "provider_options": provider_options,
                "current_config": {
                    "llm_provider": os.getenv("HAR_ANALYZER_LLM_PROVIDER", "builtin"),
                    "model": os.getenv("HAR_ANALYZER_MODEL", "builtin-heuristics"),
                    "concurrency": os.getenv("HAR_ANALYZER_CONCURRENCY", "4"),
                    "endpoint_cap": os.getenv("HAR_ANALYZER_ENDPOINT_CAP", "10"),
                    "global_cap": os.getenv("HAR_ANALYZER_GLOBAL_CAP", "100"),
                    "inter_request_delay_ms": os.getenv("HAR_ANALYZER_INTER_REQUEST_DELAY_MS", "500"),
                    "redact_by_default": os.getenv("HAR_ANALYZER_REDACT_BY_DEFAULT", "false"),
                    "step_mode": os.getenv("HAR_ANALYZER_STEP_MODE", "true"),
                },
            },
        )

    @app.get("/runs/{run_id}/logs")
    def run_logs(run_id: str):
        """Return log/failure files from the run's artifact directory."""
        run = store.get_run(run_id)
        if not run:
            return JSONResponse({"error": "Run not found"}, status_code=404)
        artifact_dir = Path(run.artifact_dir)
        logs = {}
        # Read failure traceback
        failure_path = artifact_dir / "run_failure.txt"
        if failure_path.exists():
            try:
                logs["failure"] = failure_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                logs["failure"] = "(could not read file)"
        # Read scan debug log (live progress log)
        scan_log_path = artifact_dir / "scan_debug.log"
        if scan_log_path.exists():
            try:
                logs["scan_log"] = scan_log_path.read_text(encoding="utf-8", errors="replace")[-10000:]  # last 10KB
            except Exception:
                pass
        # Read any debug files
        for debug_file in sorted(artifact_dir.glob("debug-*.txt"))[:20]:
            try:
                logs[debug_file.name] = debug_file.read_text(encoding="utf-8", errors="replace")[:5000]
            except Exception:
                pass
        logs["run_status"] = run.status
        logs["last_error"] = run.last_error or ""
        logs["artifact_dir"] = str(artifact_dir)
        return logs

    @app.get("/runs/{run_id}/debug-dump")
    def debug_dump(run_id: str):
        """Return the full scan debug dump JSON."""
        run = store.get_run(run_id)
        if not run:
            return JSONResponse({"error": "Run not found"}, status_code=404)
        dump_path = Path(run.artifact_dir) / "scan_dump.json"
        if not dump_path.exists():
            # Generate it on the fly if not yet written
            _write_scan_debug_dump(store, run)
        if dump_path.exists():
            try:
                return json.loads(dump_path.read_text(encoding="utf-8"))
            except Exception:
                return JSONResponse({"error": "Could not read dump"}, status_code=500)
        return JSONResponse({"error": "No debug dump available"}, status_code=404)

    @app.get("/runs/{run_id}/snapshot")
    def run_snapshot(run_id: str):
        run = store.get_run(run_id)
        request_items = [item.to_dict() for item in store.get_request_items(run_id)]
        llm_attempt_items = [item.to_dict() for item in store.get_llm_attempt_items(run_id)]
        hypothesis_items = [item.to_dict() for item in store.get_hypothesis_items(run_id)]
        findings = store.get_findings(run_id)
        return {
            "run": run.to_dict() if run else None,
            "request_items": request_items,
            "llm_attempt_items": llm_attempt_items,
            "hypothesis_items": hypothesis_items,
            "findings": findings,
        }

    @app.get("/api/has-key/{provider_name}")
    def check_saved_key(provider_name: str):
        return {"has_key": has_saved_key(provider_name)}

    # --- Notes ---

    @app.get("/notes", response_class=HTMLResponse)
    def notes_page(request: Request, q: Optional[str] = Query(None)):
        all_notes = store.get_all_notes()
        # Enrich notes with run/request info for display
        runs_cache = {r.run_id: r for r in store.list_runs()}
        for note in all_notes:
            run = runs_cache.get(note["run_id"])
            note["_har_name"] = Path(run.har_path).name if run else "Unknown"
            if note["request_id"]:
                items = store.get_request_items(note["run_id"])
                item = next((i for i in items if i.request_id == note["request_id"]), None)
                note["_endpoint"] = "%s %s" % (item.method, item.path) if item else note["request_id"]
            else:
                note["_endpoint"] = ""
        if q and q.strip():
            q_lower = q.strip().lower()
            all_notes = [n for n in all_notes if q_lower in (n.get("content", "") + " " + n.get("_endpoint", "")).lower()]
        return templates.TemplateResponse(
            request=request,
            name="notes.html",
            context={
                "current_page": "notes",
                "recent_runs": store.list_runs()[:5],
                "notes": all_notes,
                "search_query": q or "",
            },
        )

    @app.get("/api/notes")
    def api_get_notes(run_id: Optional[str] = Query(None), request_id: Optional[str] = Query(None), hypothesis_id: Optional[str] = Query(None)):
        return store.get_notes(run_id=run_id, request_id=request_id, hypothesis_id=hypothesis_id)

    @app.post("/api/notes")
    def api_save_note(request: Request, body: dict):
        import uuid
        note_id = body.get("note_id") or ("note-%s" % uuid.uuid4().hex[:12])
        store.save_note(
            note_id=note_id,
            run_id=body.get("run_id", ""),
            request_id=body.get("request_id", ""),
            hypothesis_id=body.get("hypothesis_id", ""),
            content=body.get("content", ""),
        )
        return {"success": True, "note_id": note_id}

    @app.delete("/api/notes/{note_id}")
    def api_delete_note(note_id: str):
        store.delete_note(note_id)
        return {"success": True}


    @app.post("/api/proxy")
    def proxy_request(body: dict):
        """Forward a request server-side and return the response (avoids CORS)."""
        import httpx
        import ipaddress
        import socket
        import time

        method = (body.get("method") or "GET").upper()
        url = body.get("url", "").strip()
        headers = body.get("headers") or {}
        req_body = body.get("body") or ""

        # Drop headers that httpx must control itself
        for h in ("content-length", "transfer-encoding", "host"):
            headers = {k: v for k, v in headers.items() if k.lower() != h}

        if not url:
            return JSONResponse({"error": "URL is required"}, status_code=400)

        # Validate URL: block private IPs, loopback, and cloud metadata
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return JSONResponse({"error": "Only http/https URLs are allowed"}, status_code=400)
            hostname = parsed.hostname or ""
            # Block cloud metadata endpoints
            if hostname in ("169.254.169.254", "metadata.google.internal"):
                return JSONResponse({"error": "Cloud metadata endpoints are blocked"}, status_code=403)
            # Resolve hostname and check for private/loopback IPs
            try:
                resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for family, socktype, proto, canonname, sockaddr in resolved:
                    ip = ipaddress.ip_address(sockaddr[0])
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return JSONResponse({"error": "Requests to private/internal addresses are blocked (%s resolves to %s)" % (hostname, ip)}, status_code=403)
            except socket.gaierror:
                return JSONResponse({"error": "Could not resolve hostname: %s" % hostname}, status_code=400)
        except Exception as exc:
            return JSONResponse({"error": "Invalid URL: %s" % str(exc)}, status_code=400)

        # Parse body as JSON if possible for POST/PUT/PATCH
        content = None
        json_body = None
        if req_body and method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                json_body = json.loads(req_body)
            except (json.JSONDecodeError, TypeError):
                content = req_body.encode("utf-8") if isinstance(req_body, str) else req_body

        try:
            start = time.time()
            with httpx.Client(timeout=30, follow_redirects=True, verify=False) as client:
                resp = client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json_body if json_body is not None else None,
                    content=content,
                )
            duration_ms = int((time.time() - start) * 1000)

            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
                "duration_ms": duration_ms,
            }
        except httpx.RequestError as exc:
            return JSONResponse({"error": "Request failed: %s" % str(exc)}, status_code=502)
        except Exception as exc:
            return JSONResponse({"error": "Unexpected error: %s" % str(exc)}, status_code=500)

    @app.get("/api/har-files")
    def har_files():
        return {"files": _discover_har_files()}

    @app.get("/api/har-hosts")
    def har_hosts(har_path: str):
        return {"hosts": _suggest_scope_hosts(har_path)}

    @app.get("/runs/{run_id}/requests/{request_id}", response_class=HTMLResponse)
    def request_detail(request: Request, run_id: str, request_id: str):
        run = store.get_run(run_id)
        items = {item.request_id: item for item in store.get_request_items(run_id)}
        item = items.get(request_id)
        llm_attempt_items = store.get_llm_attempt_items(run_id, request_id=request_id)
        hypothesis_items = store.get_hypothesis_items(run_id, request_id=request_id)
        findings = [finding for finding in store.get_findings(run_id) if finding.get("request_id") == request_id]

        # Parse LLM responses for better display
        parsed_attempts = []
        for attempt in llm_attempt_items:
            info = {"attempt": attempt, "is_echo": False, "parsed_hypotheses": [], "model_verdict": ""}
            if attempt.llm_response_text:
                try:
                    raw = json.loads(attempt.llm_response_text)
                    msg = (raw.get("choices") or [{}])[0].get("message") or {}
                    content = msg.get("content") or ""
                    reasoning = msg.get("reasoning_content") or ""
                    info["raw_content"] = content
                    info["raw_reasoning"] = reasoning
                    # Determine which field has the actual answer
                    answer_text = content.strip() if content.strip() else reasoning.strip()
                    if answer_text:
                        try:
                            parsed = json.loads(answer_text)
                            if "hypotheses" in parsed:
                                info["parsed_hypotheses"] = parsed["hypotheses"]
                                if not parsed["hypotheses"]:
                                    info["model_verdict"] = "Model returned 0 hypotheses (endpoint deemed low-risk)"
                                else:
                                    info["model_verdict"] = "%d hypothes%s generated" % (len(parsed["hypotheses"]), "is" if len(parsed["hypotheses"]) == 1 else "es")
                            elif "request" in parsed and "task" in parsed:
                                info["is_echo"] = True
                                info["model_verdict"] = "Model echoed the prompt back without generating hypotheses (endpoint deemed low-risk or model error)"
                            else:
                                info["model_verdict"] = "Unexpected response structure"
                        except (json.JSONDecodeError, ValueError):
                            info["model_verdict"] = "Non-JSON response from model"
                            info["raw_content"] = answer_text
                except (json.JSONDecodeError, KeyError, IndexError):
                    info["model_verdict"] = "Could not parse provider response"
            parsed_attempts.append(info)

        return templates.TemplateResponse(
            request=request,
            name="request_detail.html",
            context={
                "current_page": "runs",
                "recent_runs": store.list_runs()[:5],
                "run": run,
                "item": item,
                "llm_attempt_items": llm_attempt_items,
                "hypothesis_items": hypothesis_items,
                "findings": findings,
                "findings_by_hyp": _group_findings_by_hypothesis(findings),
                "parsed_attempts": parsed_attempts,
            },
        )

    @app.get("/runs/{run_id}/requests/{request_id}/detail")
    def request_detail_json(run_id: str, request_id: str):
        """JSON API for approval queue detail panel."""
        items = {item.request_id: item for item in store.get_request_items(run_id)}
        item = items.get(request_id)
        if item is None:
            return JSONResponse({"error": "Item not found"}, status_code=404)
        hypothesis_items = store.get_hypothesis_items(run_id, request_id=request_id)
        first_hyp = hypothesis_items[0] if hypothesis_items else None
        return {
            "request_id": item.request_id,
            "method": item.method,
            "endpoint": item.path,
            "url": item.url,
            "host": item.host,
            "status": item.status,
            "stage": item.stage,
            "approval_state": item.approval_state,
            "attack_type": first_hyp.attack_type if first_hyp else "Pending LLM analysis",
            "severity": first_hyp.severity if first_hyp else "-",
            "confidence_level": "high" if first_hyp and first_hyp.severity in ("critical", "high") else "medium" if first_hyp else "low",
            "reasoning": first_hyp.rationale if first_hyp else "Hypotheses will be generated after approval.",
            "expected_impact": first_hyp.expected_signal if first_hyp else "-",
            "actual_impact": first_hyp.execution_outcome if first_hyp else "-",
            "request": {
                "method": item.method,
                "url": item.url,
                "headers": json.loads(item.request_headers_json) if item.request_headers_json else {},
                "body": item.request_body or "",
            },
            "hypotheses": [h.to_dict() for h in hypothesis_items],
            "hypothesis_count": len(hypothesis_items),
        }

    @app.post("/runs/{run_id}/requests/{request_id}/approve")
    def approve_request(request: Request, run_id: str, request_id: str):
        store.update_request_item(run_id, request_id, approval_state="approved", status="running", stage="approved_for_llm", summary="Approved by analyst")
        store.update_run_progress(run_id, status="running")
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return JSONResponse({"success": True, "request_id": request_id})
        return RedirectResponse(url="/runs/%s/requests/%s" % (run_id, request_id), status_code=303)

    @app.post("/runs/{run_id}/requests/{request_id}/skip")
    def skip_request(request: Request, run_id: str, request_id: str):
        store.update_request_item(run_id, request_id, approval_state="skipped", status="completed", stage="skipped_llm", summary="Skipped by analyst")
        store.refresh_run_counters(run_id)
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return JSONResponse({"success": True, "request_id": request_id})
        return RedirectResponse(url="/runs/%s/requests/%s" % (run_id, request_id), status_code=303)

    @app.post("/runs/{run_id}/approve-all")
    def approve_all_pending(run_id: str):
        """Approve current pending request AND switch to auto mode for remaining."""
        items = store.get_request_items(run_id)
        approved_count = 0
        for item in items:
            if item.approval_state == "pending":
                store.update_request_item(run_id, item.request_id, approval_state="approved", status="running", stage="approved_for_llm", summary="Approved by analyst")
                approved_count += 1
        # Disable step_mode so future requests auto-approve
        run = store.get_run(run_id)
        if run:
            config = dict(run.config)
            config["step_mode"] = False
            with store._connect() as conn:
                conn.execute("UPDATE runs SET config_json = ? WHERE run_id = ?", (json.dumps(config), run_id))
        store.update_run_progress(run_id, status="running")
        total_remaining = sum(1 for item in items if item.status in ("queued", "awaiting_approval"))
        return JSONResponse({"success": True, "approved_count": approved_count, "switched_to_auto": True, "remaining": total_remaining})

    @app.get("/runs/{run_id}/debug/{request_id}", response_class=PlainTextResponse)
    def debug_artifact(run_id: str, request_id: str):
        items = {item.request_id: item for item in store.get_request_items(run_id)}
        item = items.get(request_id)
        if item is None or not item.debug_artifact_path:
            return PlainTextResponse("No debug artifact for this request.", status_code=404)
        path = Path(item.debug_artifact_path)
        if not path.exists():
            return PlainTextResponse("Debug artifact path does not exist.", status_code=404)
        return PlainTextResponse(path.read_text(encoding="utf-8"))

    @app.get("/runs/{run_id}/requests/{request_id}/attempts/{attempt_index}/debug", response_class=PlainTextResponse)
    def debug_attempt_artifact(run_id: str, request_id: str, attempt_index: int):
        attempts = {
            (item.request_id, item.attempt_index): item
            for item in store.get_llm_attempt_items(run_id)
        }
        attempt = attempts.get((request_id, attempt_index))
        if attempt is None or not attempt.debug_artifact_path:
            return PlainTextResponse("No debug artifact for this LLM attempt.", status_code=404)
        path = Path(attempt.debug_artifact_path)
        if not path.exists():
            return PlainTextResponse("Debug artifact path does not exist.", status_code=404)
        return PlainTextResponse(path.read_text(encoding="utf-8"))

    @app.post("/runs/{run_id}/pause")
    def pause_run(run_id: str):
        store.request_pause(run_id)
        return RedirectResponse(url="/runs/%s" % run_id, status_code=303)

    @app.post("/runs/{run_id}/resume")
    def resume_run(run_id: str):
        store.request_resume(run_id)
        return RedirectResponse(url="/runs/%s" % run_id, status_code=303)

    @app.post("/runs/{run_id}/cancel")
    def cancel_run(run_id: str):
        store.request_cancel(run_id)
        return RedirectResponse(url="/runs/%s" % run_id, status_code=303)

    @app.post("/runs/{run_id}/delete")
    def delete_run(run_id: str, request: Request):
        store.delete_run(run_id)
        if "application/json" in (request.headers.get("accept") or ""):
            return {"success": True}
        return RedirectResponse(url="/", status_code=303)

    @app.get("/runs/{run_id}/report.json")
    def report_json(run_id: str):
        run = store.get_run(run_id)
        if not run or not run.report_json_path:
            return JSONResponse({"error": "Report not found"}, status_code=404)
        path = Path(run.report_json_path)
        if not path.exists():
            return JSONResponse({"error": "Report file does not exist"}, status_code=404)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return JSONResponse({"error": "Could not read report"}, status_code=500)

    @app.get("/runs/{run_id}/report.md")
    def report_md(run_id: str):
        run = store.get_run(run_id)
        if not run or not run.report_markdown_path:
            return PlainTextResponse("Report not found", status_code=404)
        path = Path(run.report_markdown_path)
        if not path.exists():
            return PlainTextResponse("Report file does not exist", status_code=404)
        return PlainTextResponse(path.read_text(encoding="utf-8"))

    return app


# Create app instance for uvicorn
app = create_app()
def serve(host: str, port: int, artifact_dir: str) -> int:
    try:
        import uvicorn
    except Exception as error:
        raise RuntimeError("uvicorn is required to launch the UI: %s" % error)
    app = create_app(artifact_dir)
    uvicorn.run(app, host=host, port=port)
    return 0


def _background_scan(config, store, run) -> None:
    log_path = os.path.join(run.artifact_dir, "scan_debug.log")
    try:
        def progress(stage, message, payload):
            suffix_parts = []
            if payload.get("request_id"):
                suffix_parts.append("request_id=%s" % payload["request_id"])
            if payload.get("hypothesis_id"):
                suffix_parts.append("hypothesis_id=%s" % payload["hypothesis_id"])
            if payload.get("error"):
                suffix_parts.append("error=%s" % payload["error"])
            suffix = (" | " + " | ".join(suffix_parts)) if suffix_parts else ""
            line = "[%s] %s%s" % (stage, message, suffix)
            print("[web:%s] %s%s" % (stage, message, suffix))
            preview = payload.get("content_preview")
            if preview:
                line += "\n  preview: %s" % preview[:500]
                print("[web:%s:preview] %s" % (stage, preview))
            debug_artifact_path = payload.get("debug_artifact_path")
            if debug_artifact_path:
                line += "\n  debug: %s" % debug_artifact_path
                print("[web:%s:debug] %s" % (stage, debug_artifact_path))
            # Append to debug log file
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(datetime.now().isoformat() + " " + line + "\n")
            except Exception:
                pass

        run_scan(config, store=store, run=run, progress_callback=progress)
        # Write a post-scan debug dump
        _write_scan_debug_dump(store, run)
    except Exception as exc:
        import traceback
        error_text = traceback.format_exc()
        print("[web:CRASH] Background scan crashed: %s" % exc)
        print(error_text)
        # Write crash to log and failure file
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(datetime.now().isoformat() + " [CRASH] " + error_text + "\n")
            failure_path = os.path.join(run.artifact_dir, "run_failure.txt")
            with open(failure_path, "w", encoding="utf-8") as f:
                f.write(error_text)
            store.mark_run_failed(run.run_id, str(exc))
        except Exception:
            pass


def _write_scan_debug_dump(store, run) -> None:
    """Write a comprehensive debug dump after scan completes."""
    dump_path = os.path.join(run.artifact_dir, "scan_dump.json")
    try:
        items = store.get_request_items(run.run_id)
        all_hyps = store.get_hypothesis_items(run.run_id)
        all_attempts = store.get_llm_attempt_items(run.run_id)
        findings = store.get_findings(run.run_id)

        dump = {
            "run_id": run.run_id,
            "status": store.get_run(run.run_id).status if store.get_run(run.run_id) else run.status,
            "total_requests": run.total_requests,
            "processed_requests": run.processed_requests,
            "findings_count": len(findings),
            "requests": [],
        }

        for item in items:
            req_hyps = [h for h in all_hyps if h.request_id == item.request_id]
            req_attempts = [a for a in all_attempts if a.request_id == item.request_id]
            req_findings = [f for f in findings if f.get("request_id") == item.request_id]

            req_dump = {
                "request_id": item.request_id,
                "method": item.method,
                "path": item.path,
                "url": item.url,
                "status": item.status,
                "stage": item.stage,
                "summary": item.summary,
                "error": item.error,
                "original_response_status": item.original_response_status,
                "hypothesis_count": len(req_hyps),
                "findings_count": len(req_findings),
                "llm_attempts": [],
                "hypotheses": [],
                "findings": req_findings,
            }

            for attempt in req_attempts:
                req_dump["llm_attempts"].append({
                    "attempt_index": attempt.attempt_index,
                    "status": attempt.status,
                    "stage": attempt.stage,
                    "error": attempt.error,
                    "response_preview": (attempt.llm_response_message_content or "")[:500],
                })

            for hyp in req_hyps:
                req_dump["hypotheses"].append({
                    "hypothesis_id": hyp.hypothesis_id,
                    "attack_type": hyp.attack_type,
                    "severity": hyp.severity,
                    "mutation_summary": hyp.mutation_summary,
                    "rationale": hyp.rationale,
                    "expected_signal": hyp.expected_signal,
                    "method": hyp.method,
                    "url": hyp.url,
                    "body_preview": (hyp.body or "")[:300],
                    "response_status_code": hyp.response_status_code,
                    "response_body_preview": (hyp.response_body or "")[:300],
                    "execution_outcome": hyp.execution_outcome,
                    "execution_error": hyp.execution_error,
                    "findings_count": hyp.findings_count,
                })

            dump["requests"].append(req_dump)

        with open(dump_path, "w", encoding="utf-8") as f:
            json.dump(dump, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _group_findings_by_hypothesis(findings: list) -> dict:
    grouped = {}
    for f in findings:
        hid = f.get("hypothesis_id", "")
        grouped.setdefault(hid, []).append(f)
    return grouped


def _discover_har_files() -> List[dict]:
    if not DEFAULT_HAR_DIR.exists():
        return []
    out = []
    for path in sorted(DEFAULT_HAR_DIR.glob("*.har")):
        out.append(
            {
                "label": path.name,
                "path": str(path.resolve()),
            }
        )
    return out


def _suggest_scope_hosts(har_path: str) -> List[str]:
    path = Path(har_path).expanduser()
    if not path.is_absolute():
        candidate = PROJECT_ROOT / har_path
        if candidate.exists():
            path = candidate
    if not path.exists():
        return []
    try:
        records = filter_records(har_to_records(str(path)), [], [])
    except Exception:
        return []
    counts = {}
    for record in records:
        host = record.host.strip().lower()
        if not host:
            continue
        counts[host] = counts.get(host, 0) + 1
    return [host for host, _count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
