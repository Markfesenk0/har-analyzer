from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import List

from .har import filter_records, har_to_records
from .config import get_default_unsafe_unredacted, get_supported_provider_options, load_run_config
from .graph import run_scan
from .persistence import RunStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HAR_DIR = PROJECT_ROOT / "HAR files"


def create_app(artifact_dir: str = "artifacts"):
    try:
        from fastapi import FastAPI, Form, Request
        from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
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

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "runs": store.list_runs(),
                "har_files": _discover_har_files(),
                "provider_options": provider_options,
                "defaults": {
                    "provider": os.getenv("HAR_ANALYZER_LLM_PROVIDER", "builtin"),
                    "model": os.getenv("HAR_ANALYZER_MODEL", "builtin-heuristics"),
                    "unsafe_unredacted": unsafe_default,
                    "step_mode": os.getenv("HAR_ANALYZER_STEP_MODE", "true").lower(),
                    "redact_by_default": os.getenv("HAR_ANALYZER_REDACT_BY_DEFAULT", "false").lower(),
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
        step_mode: str = Form("true"),
    ):
        config = load_run_config(
            har_path=har_path,
            target_domains=[item.strip() for item in scope_domains if item and item.strip()],
            artifact_dir=artifact_dir,
            allow_unsafe_artifacts=unsafe_unredacted.lower() == "true",
            provider=provider.strip(),
            model=model.strip(),
            step_mode=step_mode.lower() == "true",
        )
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
        return templates.TemplateResponse(
            request=request,
            name="run_detail.html",
            context={"run": run, "findings": findings, "request_items": request_items},
        )

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
        return templates.TemplateResponse(
            request=request,
            name="request_detail.html",
            context={"run": run, "item": item, "llm_attempt_items": llm_attempt_items, "hypothesis_items": hypothesis_items, "findings": findings},
        )

    @app.post("/runs/{run_id}/requests/{request_id}/approve")
    def approve_request(run_id: str, request_id: str):
        store.update_request_item(run_id, request_id, approval_state="approved", status="running", stage="approved_for_llm", summary="Approved by analyst")
        store.update_run_progress(run_id, status="running")
        return RedirectResponse(url="/runs/%s/requests/%s" % (run_id, request_id), status_code=303)

    @app.post("/runs/{run_id}/requests/{request_id}/skip")
    def skip_request(run_id: str, request_id: str):
        store.update_request_item(run_id, request_id, approval_state="skipped", status="completed", stage="skipped_llm", summary="Skipped by analyst")
        store.refresh_run_counters(run_id)
        return RedirectResponse(url="/runs/%s/requests/%s" % (run_id, request_id), status_code=303)

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

    return app


def serve(host: str, port: int, artifact_dir: str) -> int:
    try:
        import uvicorn
    except Exception as error:
        raise RuntimeError("uvicorn is required to launch the UI: %s" % error)
    app = create_app(artifact_dir)
    uvicorn.run(app, host=host, port=port)
    return 0


def _background_scan(config, store, run) -> None:
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
            print("[web:%s] %s%s" % (stage, message, suffix))
            preview = payload.get("content_preview")
            if preview:
                print("[web:%s:preview] %s" % (stage, preview))
            debug_artifact_path = payload.get("debug_artifact_path")
            if debug_artifact_path:
                print("[web:%s:debug] %s" % (stage, debug_artifact_path))

        run_scan(config, store=store, run=run, progress_callback=progress)
    except Exception:
        return


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
