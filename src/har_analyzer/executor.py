from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from typing import Callable, Dict, Optional, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlparse

import jwt

from .models import AttackHypothesis, EndpointBudget, ExecutionResult, RequestRecord, RunConfig
from .token_injection import apply_token_injections
from .evaluation import discover_tokens_in_response

Transport = Callable[[AttackHypothesis, RunConfig], ExecutionResult]


def validate_hypothesis_url(url: str, allowed_domains: list, config: RunConfig) -> Tuple[bool, str]:
    """
    Validate URL is safe to execute (SSRF protection).
    Returns: (is_valid, error_reason)
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL format: {e}"

    # 1. Only http/https allowed
    if parsed.scheme not in ('http', 'https'):
        return False, f"Unsupported scheme: {parsed.scheme} (only http/https allowed)"

    # 2. Domain must match config.target_domains
    netloc = parsed.netloc.lower()
    domain_match = False
    for domain in allowed_domains:
        domain_lower = domain.lower()
        if netloc == domain_lower or netloc.endswith('.' + domain_lower):
            domain_match = True
            break

    if not domain_match:
        return False, f"Domain {netloc} not in allowed list"

    # 3. Block private/loopback IPs (127.0.0.1, 192.168.*, 10.*, etc.)
    try:
        hostname = parsed.hostname
        if hostname:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False, f"Private/loopback IP not allowed: {hostname}"
    except ValueError:
        pass  # Not an IP, that's fine

    return True, ""


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


def execute_rate_limit_test(
    hypothesis: AttackHypothesis,
    original_record: RequestRecord,
    config: RunConfig,
    transport: Optional[Transport] = None,
) -> ExecutionResult:
    """Send a burst of identical requests to test if rate limiting is enforced."""
    burst_count = 15
    results = {"total": burst_count, "success_2xx": 0, "rate_limited_429": 0, "errors": 0, "latencies_ms": [], "status_codes": []}

    active_transport = transport or default_transport
    # Use a minimal config clone with no inter-request delay for the burst
    burst_config = RunConfig(har_path=config.har_path, target_domains=config.target_domains)
    burst_config.request_timeout_seconds = config.request_timeout_seconds
    burst_config.inter_request_delay_ms = 0  # No delay — that's the point

    for i in range(burst_count):
        started = time.time()
        try:
            result = active_transport(hypothesis, burst_config)
            latency = (time.time() - started) * 1000.0
            results["latencies_ms"].append(round(latency, 1))
            results["status_codes"].append(result.status_code)
            if result.status_code == 429:
                results["rate_limited_429"] += 1
            elif result.status_code and result.status_code < 500:
                results["success_2xx"] += 1  # 2xx, 3xx, 4xx all count as "endpoint responded"
            else:
                results["errors"] += 1
        except Exception:
            results["errors"] += 1
            results["latencies_ms"].append(round((time.time() - started) * 1000.0, 1))

    avg_latency = round(sum(results["latencies_ms"]) / max(len(results["latencies_ms"]), 1), 1)
    max_latency = round(max(results["latencies_ms"]) if results["latencies_ms"] else 0, 1)

    is_rate_limited = results["rate_limited_429"] > 0
    outcome = "rate_limited" if is_rate_limited else "ok"

    summary = json.dumps({
        "burst_size": burst_count,
        "success_2xx": results["success_2xx"],
        "rate_limited_429": results["rate_limited_429"],
        "other_errors": results["errors"],
        "avg_latency_ms": avg_latency,
        "max_latency_ms": max_latency,
        "status_codes": results["status_codes"],
        "verdict": "Rate limiting IS enforced" if is_rate_limited else "NO rate limiting detected — all %d requests succeeded" % results["success_2xx"],
    }, indent=2)

    return ExecutionResult(
        hypothesis_id=hypothesis.hypothesis_id,
        request_id=hypothesis.original_request_id,
        method=hypothesis.method,
        url=hypothesis.url,
        status_code=429 if is_rate_limited else 200,
        response_body=summary,
        duration_ms=sum(results["latencies_ms"]),
        outcome=outcome,
        error="" if is_rate_limited else "No rate limiting: %d/%d requests returned 2xx" % (results["success_2xx"], burst_count),
    )


def execute_hypothesis(
    hypothesis: AttackHypothesis,
    original_record: RequestRecord,
    config: RunConfig,
    transport: Optional[Transport] = None,
) -> ExecutionResult:
    # Rate limit test: only on auth-sensitive endpoints, skip on regular CRUD
    if hypothesis.attack_type.lower().replace(" ", "_") in ("rate_limit_test", "rate_limit_bypass", "rate_limiting", "brute_force"):
        path_lower = (original_record.path or "").lower()
        is_auth_endpoint = any(kw in path_lower for kw in ("login", "auth", "verify", "otp", "password", "reset", "coupon", "voucher", "token", "signup", "register"))
        if is_auth_endpoint:
            return execute_rate_limit_test(hypothesis, original_record, config, transport)
        else:
            return ExecutionResult(
                hypothesis_id=hypothesis.hypothesis_id,
                request_id=hypothesis.original_request_id,
                method=hypothesis.method,
                url=hypothesis.url,
                outcome="skipped",
                error="Rate limit testing skipped — not an authentication/sensitive endpoint",
            )

    # SSRF Protection: Validate URL before executing
    is_valid, error_msg = validate_hypothesis_url(hypothesis.url, config.target_domains, config)
    if not is_valid:
        return ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            outcome="validation_failed",
            error=f"URL validation failed: {error_msg}",
        )

    # Apply token injections (replaces outdated tokens with fresh ones from config)
    if config.token_injection_rules:
        injected_headers = apply_token_injections(original_record, config)
        # Create a copy of hypothesis with injected headers
        hypothesis_with_tokens = AttackHypothesis(
            hypothesis_id=hypothesis.hypothesis_id,
            original_request_id=hypothesis.original_request_id,
            endpoint_key=hypothesis.endpoint_key,
            method=hypothesis.method,
            url=hypothesis.url,
            headers={**hypothesis.headers, **injected_headers},
            body=hypothesis.body,
            attack_type=hypothesis.attack_type,
            severity=hypothesis.severity,
            expected_signal=hypothesis.expected_signal,
            rationale=hypothesis.rationale,
            mutation_summary=hypothesis.mutation_summary,
        )
        hypothesis = hypothesis_with_tokens

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
        body = hypothesis.body
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf-8")
    # Clean up headers that cause transport issues
    clean_headers = {}
    has_auth_header = any(k.lower() == "authorization" for k in hypothesis.headers)
    for key, value in hypothesis.headers.items():
        lower = key.lower()
        # Remove Content-Length — urllib recalculates it from the actual data
        if lower == "content-length":
            continue
        # Replace Accept-Encoding — urllib can't handle br (Brotli) or zstd
        if lower == "accept-encoding":
            clean_headers[key] = "gzip, deflate"
            continue
        # Remove hop-by-hop headers that shouldn't be forwarded
        if lower in ("connection", "keep-alive", "transfer-encoding", "te", "upgrade"):
            continue
        # For auth bypass tests: if Authorization was removed, also strip Cookie
        # to prevent cookies from maintaining the session and masking the bypass
        if lower == "cookie" and not has_auth_header and hypothesis.attack_type in ("auth_bypass", "Auth Bypass", "authentication_bypass"):
            continue
        clean_headers[key] = value
    # URL-encode any unsafe characters in the query string (LLM often
    # produces raw payloads like  ' OR '1'='1  without encoding them).
    from urllib.parse import urlparse, urlunparse, quote
    _parsed = urlparse(hypothesis.url)
    _safe_url = urlunparse((
        _parsed.scheme, _parsed.netloc, quote(_parsed.path, safe="/:@!$&'()*+,;=-._~"),
        _parsed.params, quote(_parsed.query, safe="/:@!$&'()*+,;=-._~%?"), _parsed.fragment,
    ))
    request = urllib_request.Request(
        _safe_url,
        data=data,
        headers=clean_headers,
        method=hypothesis.method.upper(),
    )
    started = time.time()
    try:
        with urllib_request.urlopen(request, timeout=config.request_timeout_seconds) as response:
            body = response.read().decode("utf-8", "ignore")
            duration = (time.time() - started) * 1000.0
            response_headers = dict(response.headers.items())
            discovered_tokens = discover_tokens_in_response(body, response_headers)
            return ExecutionResult(
                hypothesis_id=hypothesis.hypothesis_id,
                request_id=hypothesis.original_request_id,
                method=hypothesis.method,
                url=hypothesis.url,
                status_code=getattr(response, "status", None),
                response_headers=response_headers,
                response_body=body,
                duration_ms=duration,
                outcome="ok",
                discovered_tokens=discovered_tokens,
            )
    except urllib_error.HTTPError as error:
        body = error.read().decode("utf-8", "ignore")
        duration = (time.time() - started) * 1000.0
        response_headers = dict(error.headers.items())
        discovered_tokens = discover_tokens_in_response(body, response_headers)
        return ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            status_code=error.code,
            response_headers=response_headers,
            response_body=body,
            duration_ms=duration,
            outcome="http_error",
            error=str(error),
            discovered_tokens=discovered_tokens,
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
