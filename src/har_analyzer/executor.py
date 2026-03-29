from __future__ import annotations

import hashlib
import json
import time
from typing import Callable, Dict, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

import jwt

from .models import AttackHypothesis, EndpointBudget, ExecutionResult, RequestRecord, RunConfig

Transport = Callable[[AttackHypothesis, RunConfig], ExecutionResult]


def hash_request(hypothesis: AttackHypothesis) -> str:
    payload = {
        "method": hypothesis.method,
        "url": hypothesis.url,
        "headers": dict(sorted(hypothesis.headers.items())),
        "body": hypothesis.body or "",
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def should_fire(hypothesis: AttackHypothesis, budget: EndpointBudget, global_executed: int, config: RunConfig) -> bool:
    if budget.hypotheses_fired >= budget.max_hypotheses:
        return False
    if global_executed >= config.global_request_cap:
        return False
    payload_hash = hash_request(hypothesis)
    if payload_hash in budget.seen_payload_hashes:
        return False
    budget.seen_payload_hashes.append(payload_hash)
    budget.hypotheses_fired += 1
    return True


def detect_expired_bearer(headers: Dict[str, str]) -> bool:
    for key, value in headers.items():
        if key.lower() == "authorization" and value.lower().startswith("bearer "):
            token = value.split(" ", 1)[1]
            try:
                payload = jwt.decode(
                    token,
                    algorithms=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "none"],
                    options={"verify_signature": False},
                )
            except Exception:
                return False
            exp = payload.get("exp")
            if not exp:
                return False
            return int(exp) <= int(time.time())
    return False


def execute_hypothesis(
    hypothesis: AttackHypothesis,
    original_record: RequestRecord,
    config: RunConfig,
    transport: Optional[Transport] = None,
) -> ExecutionResult:
    if detect_expired_bearer(hypothesis.headers):
        return ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            outcome="token_expired",
            error="Authorization token appears expired based on its exp claim.",
        )
    if config.inter_request_delay_ms:
        time.sleep(config.inter_request_delay_ms / 1000.0)
    active_transport = transport or default_transport
    result = active_transport(hypothesis, config)
    result.body_size_delta = len(result.response_body or "") - len(original_record.response_body or "")
    return result


def default_transport(hypothesis: AttackHypothesis, config: RunConfig) -> ExecutionResult:
    data = None
    if hypothesis.body is not None:
        data = hypothesis.body.encode("utf-8")
    request = urllib_request.Request(
        hypothesis.url,
        data=data,
        headers=hypothesis.headers,
        method=hypothesis.method.upper(),
    )
    started = time.time()
    try:
        with urllib_request.urlopen(request, timeout=config.request_timeout_seconds) as response:
            body = response.read().decode("utf-8", "ignore")
            duration = (time.time() - started) * 1000.0
            return ExecutionResult(
                hypothesis_id=hypothesis.hypothesis_id,
                request_id=hypothesis.original_request_id,
                method=hypothesis.method,
                url=hypothesis.url,
                status_code=getattr(response, "status", None),
                response_headers=dict(response.headers.items()),
                response_body=body,
                duration_ms=duration,
                outcome="ok",
            )
    except urllib_error.HTTPError as error:
        body = error.read().decode("utf-8", "ignore")
        duration = (time.time() - started) * 1000.0
        return ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            status_code=error.code,
            response_headers=dict(error.headers.items()),
            response_body=body,
            duration_ms=duration,
            outcome="http_error",
            error=str(error),
        )
    except Exception as error:
        duration = (time.time() - started) * 1000.0
        return ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            duration_ms=duration,
            outcome="transport_error",
            error=str(error),
        )
