from __future__ import annotations

import difflib
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .models import AttackHypothesis, ExecutionResult, Finding, RequestRecord, RunConfig
from .redaction import redact_string, redact_value

_MASKED_HOST = "localhost:8080"


def _mask_url(url: str) -> str:
    """Replace real domain with localhost in URLs sent to LLM."""
    if not url:
        return url
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return urlunparse(("http", _MASKED_HOST, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return url

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
TOKEN_HINT_RE = re.compile(r"\b(?:eyJ[a-zA-Z0-9._\-]+|[A-F0-9]{24,}|[A-Za-z0-9_\-]{32,})\b")

# Additional secret/PII patterns
PHONE_RE = re.compile(r"(?:\+?1?\s?)?\(?([0-9]{3})\)?[\s.-]?([0-9]{3})[\s.-]?([0-9]{4})\b")
SSN_RE = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b")
API_KEY_RE = re.compile(r"(?:api[_-]?key|apikey|api_token|access_token|secret_key|private_key|password)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", re.IGNORECASE)
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY")


def scan_response_for_secrets(response_body: str) -> List[Dict[str, str]]:
    """
    Scan response body for exposed secrets and PII.
    Returns list of discovered secrets.
    """
    if not response_body:
        return []

    findings = []

    # Email addresses
    if EMAIL_RE.search(response_body):
        findings.append({
            "type": "email",
            "severity": "medium",
            "message": "Email address detected in response",
        })

    # Phone numbers
    if PHONE_RE.search(response_body):
        findings.append({
            "type": "phone",
            "severity": "medium",
            "message": "Phone number detected in response",
        })

    # Social Security Numbers
    if SSN_RE.search(response_body):
        findings.append({
            "type": "ssn",
            "severity": "critical",
            "message": "Social Security Number pattern detected",
        })

    # Credit card numbers
    if CREDIT_CARD_RE.search(response_body):
        findings.append({
            "type": "credit_card",
            "severity": "critical",
            "message": "Credit card number pattern detected",
        })

    # JWT or Bearer tokens
    if TOKEN_HINT_RE.search(response_body):
        findings.append({
            "type": "jwt_token",
            "severity": "high",
            "message": "JWT or Bearer token detected in response",
        })

    # API Keys
    if API_KEY_RE.search(response_body):
        findings.append({
            "type": "api_key",
            "severity": "high",
            "message": "API key or access token detected in response",
        })

    # AWS keys
    if AWS_KEY_RE.search(response_body):
        findings.append({
            "type": "aws_key",
            "severity": "critical",
            "message": "AWS access key or secret detected",
        })

    # Private keys
    if PRIVATE_KEY_RE.search(response_body):
        findings.append({
            "type": "private_key",
            "severity": "critical",
            "message": "Private key material detected in response",
        })

    return findings


def discover_tokens_in_response(
    response_body: str,
    response_headers: Dict[str, str],
) -> Dict[str, str]:
    """
    Discover tokens in response that could be injected into future requests.
    Returns dict of {header_name: token_value} pairs.

    Checks:
    - Authorization header in response
    - Set-Cookie headers
    - JSON body fields: token, access_token, jwt, session_token, bearer_token
    """
    discovered = {}

    if not response_body and not response_headers:
        return discovered

    # Check for Authorization header in response
    for header_name, header_value in response_headers.items():
        if header_name.lower() == "authorization":
            discovered["Authorization"] = header_value
            break

    # Check for Set-Cookie headers (extract session tokens)
    for header_name, header_value in response_headers.items():
        if header_name.lower() == "set-cookie":
            # Extract cookie name and value
            cookie_parts = header_value.split(";", 1)
            if "=" in cookie_parts[0]:
                cookie_name, cookie_value = cookie_parts[0].split("=", 1)
                discovered[f"Cookie"] = f"{cookie_name.strip()}={cookie_value.strip()}"
                break

    # Check for tokens in JSON response body
    if response_body:
        try:
            payload = json.loads(response_body)
            token_value = _extract_token_from_json(payload)
            if token_value:
                discovered["Authorization"] = f"Bearer {token_value}"
        except Exception:
            pass

    return discovered


def _extract_token_from_json(obj, max_depth: int = 3) -> Optional[str]:
    """
    Recursively search JSON object for token-like fields.
    Looks for keys: token, access_token, jwt, session_token, bearer_token, id_token
    """
    if max_depth <= 0 or not isinstance(obj, dict):
        return None

    # Check common token field names
    token_keys = {"token", "access_token", "jwt", "session_token", "bearer_token", "id_token"}
    for key in token_keys:
        if key in obj:
            value = obj[key]
            if isinstance(value, str) and value.strip():
                return value

    # Recurse into nested objects
    for value in obj.values():
        if isinstance(value, dict):
            token = _extract_token_from_json(value, max_depth - 1)
            if token:
                return token

    return None


def evaluate_result(
    record: RequestRecord,
    hypothesis: AttackHypothesis,
    result: ExecutionResult,
) -> List[Finding]:
    findings: List[Finding] = []
    if result.outcome == "token_expired":
        return findings

    # SSRF detection: check for recognizable probe URL responses
    if hypothesis.attack_type.upper() in ("SSRF", "SERVER-SIDE REQUEST FORGERY"):
        ssrf_finding = _detect_ssrf(record, hypothesis, result)
        if ssrf_finding:
            findings.append(ssrf_finding)

    # Check for access control issues
    if _indicates_access_control_issue(record, hypothesis, result):
        findings.append(
            Finding(
                finding_id="finding-%s" % uuid.uuid4().hex[:12],
                request_id=record.request_id,
                hypothesis_id=hypothesis.hypothesis_id,
                title="%s likely succeeded against %s" % (hypothesis.attack_type, record.path),
                attack_type=hypothesis.attack_type,
                severity=hypothesis.severity,
                confidence="medium",
                endpoint=record.endpoint_key(),
                summary="The modified request matched the expected signal and returned comparable data instead of being denied.",
                expected_signal=hypothesis.expected_signal,
                owasp=_owasp_mapping(hypothesis.attack_type),
                evidence=_build_evidence(record, hypothesis, result),
                remediation="Enforce server-side authorization checks on object and function access before returning data.",
                reproduction_curl=build_curl_command(hypothesis),
            )
        )

    # Scan for secrets/PII in response
    secret_detections = scan_response_for_secrets(result.response_body or "")
    if secret_detections:
        severity_levels = [d["severity"] for d in secret_detections]
        # Use highest severity from detected secrets
        max_severity = "critical" if "critical" in severity_levels else ("high" if "high" in severity_levels else "medium")

        findings.append(
            Finding(
                finding_id="finding-%s" % uuid.uuid4().hex[:12],
                request_id=record.request_id,
                hypothesis_id=hypothesis.hypothesis_id,
                title="Sensitive data exposed: %s" % record.endpoint_key(),
                attack_type="excessive_data_exposure",
                severity=max_severity,
                confidence="high",
                endpoint=record.endpoint_key(),
                summary="Response contains %d type(s) of sensitive data: %s" % (
                    len(secret_detections),
                    ", ".join(d["type"] for d in secret_detections),
                ),
                expected_signal=hypothesis.expected_signal,
                owasp=["API3:2023 Broken Object Property Level Authorization", "API8:2023 Security Misconfiguration"],
                evidence=[{"type": d["type"], "message": d["message"]} for d in secret_detections] + _build_evidence(record, hypothesis, result),
                remediation="Remove sensitive fields from API responses. Only return data needed for the client. Never expose: SSN, credit cards, tokens, API keys, private keys.",
                reproduction_curl=build_curl_command(hypothesis),
            )
        )

    # Legacy sensitive leakage detection (kept for compatibility)
    secret_findings = detect_sensitive_leakage(record, hypothesis, result)
    findings.extend(secret_findings)

    return findings


def build_curl_command(hypothesis: AttackHypothesis) -> str:
    parts = ["curl", "-X", hypothesis.method.upper()]
    for key, value in sorted(hypothesis.headers.items()):
        parts.extend(["-H", "'%s: %s'" % (key, redact_string(str(value)))])
    if hypothesis.body:
        body = hypothesis.body
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        parts.extend(["--data", "'%s'" % redact_string(body)])
    parts.append("'%s'" % hypothesis.url)
    return " ".join(parts)


def diff_summary(original: str, replayed: str, limit: int = 10) -> List[str]:
    lines = difflib.unified_diff(
        (original or "").splitlines(),
        (replayed or "").splitlines(),
        lineterm="",
        n=1,
    )
    out = []
    for line in lines:
        if line.startswith(("---", "+++", "@@")):
            continue
        out.append(line)
        if len(out) >= limit:
            break
    return out


def detect_sensitive_leakage(
    record: RequestRecord,
    hypothesis: AttackHypothesis,
    result: ExecutionResult,
) -> List[Finding]:
    body = result.response_body or ""
    evidence = []
    if EMAIL_RE.search(body):
        evidence.append({"type": "pii", "match": "[REDACTED_EMAIL]"})
    if TOKEN_HINT_RE.search(body):
        evidence.append({"type": "secret", "match": "[REDACTED_SECRET]"})
    if not evidence:
        return []
    return [
        Finding(
            finding_id="finding-%s" % uuid.uuid4().hex[:12],
            request_id=record.request_id,
            hypothesis_id=hypothesis.hypothesis_id,
            title="Sensitive data exposed by %s" % record.path,
            attack_type="excessive_data_exposure",
            severity="medium",
            confidence="medium",
            endpoint=record.endpoint_key(),
            summary="The replayed response included PII or token-like material that should be reviewed for exposure risk.",
            expected_signal=hypothesis.expected_signal,
            owasp=["API3:2023 Broken Object Property Level Authorization", "API8:2023 Security Misconfiguration"],
            evidence=evidence + _build_evidence(record, hypothesis, result),
            remediation="Minimize sensitive fields in API responses and ensure they are returned only to authorized callers.",
            reproduction_curl=build_curl_command(hypothesis),
        )
    ]


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SSRF_PROBE_DOMAINS = ("icanhazip.com", "ifconfig.me", "httpbin.org")


def _detect_ssrf(
    record: RequestRecord,
    hypothesis: AttackHypothesis,
    result: ExecutionResult,
) -> Optional[Finding]:
    """Detect SSRF by checking if the response contains recognizable content from
    well-known probe URLs (icanhazip.com, ifconfig.me, httpbin.org) that would not
    normally appear in the original endpoint's response."""
    response_body = result.response_body or ""
    original_body = record.response_body or ""
    if not response_body:
        return None

    signals = []

    # Check if any probe domain is mentioned in the hypothesis mutation
    mutation = (hypothesis.mutation_summary or "").lower() + (hypothesis.body or "").lower()
    uses_probe = any(domain in mutation for domain in _SSRF_PROBE_DOMAINS)
    if not uses_probe:
        return None

    # Signal 1: Response contains an IP address that wasn't in the original response
    # (icanhazip.com and ifconfig.me return just an IP)
    response_ips = set(_IPV4_RE.findall(response_body))
    original_ips = set(_IPV4_RE.findall(original_body))
    new_ips = response_ips - original_ips
    if new_ips:
        signals.append("New IP address(es) appeared in response: %s" % ", ".join(sorted(new_ips)))

    # Signal 2: httpbin.org JSON signature (returns {"origin": "...", "url": "..."})
    if "httpbin.org" in mutation:
        if '"origin"' in response_body and '"url"' in response_body:
            signals.append("Response contains httpbin.org JSON signature (origin + url fields)")

    # Signal 3: Response changed substantially and now contains data consistent with
    # a fetched URL (status 2xx, different body shape)
    if result.status_code and 200 <= result.status_code < 300:
        if record.response_status and 200 <= record.response_status < 300:
            # Both succeeded — check if the response body changed meaningfully
            if response_body != original_body and len(response_body.strip()) > 0:
                # Look for a plain IP-like response that is very different from original
                stripped = response_body.strip()
                if _IPV4_RE.fullmatch(stripped):
                    signals.append("Response body is a bare IP address: %s" % stripped)

    if not signals:
        return None

    evidence_parts = _build_evidence(record, hypothesis, result)
    evidence_parts.append({"ssrf_signals": signals})

    return Finding(
        finding_id="finding-%s" % uuid.uuid4().hex[:12],
        request_id=record.request_id,
        hypothesis_id=hypothesis.hypothesis_id,
        title="SSRF confirmed on %s" % record.path,
        attack_type="SSRF",
        severity="high",
        confidence="high" if len(signals) >= 2 else "medium",
        endpoint=record.endpoint_key(),
        summary="The server appears to have fetched an external URL, confirming server-side request forgery. %s" % "; ".join(signals),
        expected_signal=hypothesis.expected_signal,
        owasp=["API7:2023 Server Side Request Forgery"],
        evidence=evidence_parts,
        remediation="Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains. Block requests to internal/private IP ranges.",
        reproduction_curl=build_curl_command(hypothesis),
    )


def _indicates_access_control_issue(
    record: RequestRecord,
    hypothesis: AttackHypothesis,
    result: ExecutionResult,
) -> bool:
    """
    Improved detection: Check if modified request succeeded when original failed,
    or returned different data than original.
    """
    if result.status_code is None:
        return False

    # Signal 1: Status code changed from 401/403 to 2xx
    # Strong indicator of access control bypass
    if record.response_status in (401, 403) and result.status_code and 200 <= result.status_code < 300:
        return True

    # Signal 2: Both succeeded (2xx) but returned different user/resource IDs
    if record.response_status and 200 <= record.response_status < 300:
        if result.status_code and 200 <= result.status_code < 300:
            if hypothesis.attack_type in {"IDOR", "BOLA"}:
                # Check if responses are structurally similar (same shape)
                if _structurally_similar(record.response_body or "", result.response_body or ""):
                    # Check if resource IDs are different
                    if _contains_different_resource_id(record.response_body or "", result.response_body or ""):
                        return True

    # Signal 3: Response size increased significantly
    # Indicates more data was returned than original (leaked data)
    size_increase = len(result.response_body or "") - len(record.response_body or "")
    if size_increase > 200:  # Threshold: 200 bytes increase = likely leaked data
        return True

    # Signal 4: Auth bypass - got response when should have been denied
    if hypothesis.attack_type == "auth_bypass":
        if record.response_status in (401, 403):
            if result.response_body and result.status_code and 200 <= result.status_code < 300:
                return True

    return False


def _contains_different_resource_id(original: str, modified: str) -> bool:
    """
    Check if responses contain different user/resource IDs.
    Looks for patterns like "user_id": 123 or "id": "abc"
    """
    try:
        # Pattern: "user_id": 123 OR "user_id": "abc" OR 'user_id': 123
        id_pattern = r'["\']?(?:user_?id|account_?id|owner_?id|id)["\']?\s*:\s*([0-9]+|["\'][^"\']+["\'])'

        orig_ids = set(re.findall(id_pattern, original, re.IGNORECASE))
        mod_ids = set(re.findall(id_pattern, modified, re.IGNORECASE))

        # If sets are different and both have values, IDs changed
        return len(orig_ids) > 0 and len(mod_ids) > 0 and orig_ids != mod_ids
    except Exception:
        return False


def _structurally_similar(original: str, replayed: str) -> bool:
    original_shape, replayed_shape = _json_shape(original), _json_shape(replayed)
    return bool(original_shape and replayed_shape and original_shape == replayed_shape)


def _json_shape(value: str) -> Tuple[str, ...]:
    try:
        payload = json.loads(value)
    except Exception:
        return tuple()
    return tuple(_walk_shape(payload))


def _walk_shape(payload) -> List[str]:
    if isinstance(payload, dict):
        out = []
        for key in sorted(payload):
            out.append("dict:%s" % key)
            out.extend(_walk_shape(payload[key]))
        return out
    if isinstance(payload, list):
        if not payload:
            return ["list:empty"]
        return ["list"] + _walk_shape(payload[0])
    return [type(payload).__name__]


def _build_evidence(record: RequestRecord, hypothesis: AttackHypothesis, result: ExecutionResult) -> List[Dict[str, object]]:
    return [
        {"request_id": record.request_id},
        {"mutation": hypothesis.mutation_summary},
        {"status_code": result.status_code},
        {"response_diff": diff_summary(record.response_body or "", result.response_body or "")},
        {"response_excerpt": redact_value((result.response_body or "")[:400])},
    ]


def _owasp_mapping(attack_type: str) -> List[str]:
    mapping = {
        "IDOR": ["API1:2023 Broken Object Level Authorization"],
        "BOLA": ["API1:2023 Broken Object Level Authorization"],
        "auth_bypass": ["API5:2023 Broken Function Level Authorization"],
        "SSRF": ["API7:2023 Server Side Request Forgery"],
    }
    return mapping.get(attack_type, ["API8:2023 Security Misconfiguration"])


# ---------------------------------------------------------------------------
# JSON truncation for LLM payloads
# ---------------------------------------------------------------------------

def truncate_json_value(value: Any, max_str_len: int = 200, max_list_items: int = 3, max_depth: int = 5) -> Any:
    """Truncate a parsed JSON value to keep LLM payloads manageable."""
    if max_depth <= 0:
        return "...(truncated)..."
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= 30:  # max 30 keys per object
                out["...(truncated %d more keys)" % (len(value) - 30)] = "..."
                break
            out[k] = truncate_json_value(v, max_str_len, max_list_items, max_depth - 1)
        return out
    if isinstance(value, list):
        if len(value) <= max_list_items:
            return [truncate_json_value(item, max_str_len, max_list_items, max_depth - 1) for item in value]
        truncated = [truncate_json_value(item, max_str_len, max_list_items, max_depth - 1) for item in value[:max_list_items]]
        truncated.append("...(%d more items)" % (len(value) - max_list_items))
        return truncated
    if isinstance(value, str) and len(value) > max_str_len:
        return value[:max_str_len] + "...(truncated, %d chars total)" % len(value)
    return value


def _truncate_body_for_llm(body_str: str, max_chars: int = 3000) -> str:
    """Truncate a response body string for LLM consumption, preserving JSON structure."""
    if not body_str or len(body_str) <= max_chars:
        return body_str or ""
    try:
        parsed = json.loads(body_str)
        truncated = truncate_json_value(parsed)
        result = json.dumps(truncated, indent=2, ensure_ascii=False)
        if len(result) <= max_chars:
            return result
        # Still too long, truncate more aggressively
        truncated = truncate_json_value(parsed, max_str_len=80, max_list_items=2, max_depth=3)
        return json.dumps(truncated, indent=2, ensure_ascii=False)[:max_chars]
    except (json.JSONDecodeError, TypeError):
        return body_str[:max_chars] + "\n...(truncated)"


# ---------------------------------------------------------------------------
# LLM-based finding validation
# ---------------------------------------------------------------------------

_VALIDATION_SYSTEM_PROMPT = """You are a security analyst reviewing automated vulnerability scan results.
Your job is to compare the ORIGINAL API response (baseline) with the ATTACK response (from a mutated request)
and determine if the attack actually revealed a real security vulnerability or if it's a false positive.

CRITICAL RULE — SAME RESPONSE = FALSE POSITIVE:
If the attack response body is substantially the same as the original response body (same fields, same values, same user data), the attack DID NOT WORK. Mark it as false_positive regardless of what PII is in the response. The PII was already there in the original — the attack didn't expose anything new.

When IS it a real vulnerability:
- The attack response contains a DIFFERENT user's data (different user_id, different email, different name) than the original
- The attack response succeeds (2xx) when the mutation REMOVED authentication (and the original required auth)
- The attack response returns MORE data than the original (extra fields, extra records NOT explained by normal creation)
- The attack response shows a different credit/balance/role than the original AND this was caused by the mutation (mass assignment worked)
- The error response leaks internal details (stack traces, SQL queries, internal paths)
- An injection payload (SQL, NoSQL) returned data it shouldn't have (e.g., NoSQL $ne:null returned all records)
- SSRF: The attack used a URL field to point to an external probe URL (icanhazip.com, ifconfig.me, httpbin.org) and the response contains content from that probe (e.g., an IP address, httpbin JSON) that was NOT in the original response. This confirms the server fetched the attacker-controlled URL.

When is it NOT a vulnerability (FALSE POSITIVE):
- Response is identical or near-identical to the original — the mutation was ignored
- Response contains the same user's own PII — that's normal for authenticated endpoints
- The attack sent a body on a GET request — servers ignore GET bodies, nothing happened
- A 4xx error with a generic error message — the security control worked correctly
- Transport error or timeout — inconclusive, not a finding
- POST endpoint that CREATES resources returns a new/different ID — that's NORMAL behavior, not a vulnerability. Creating a ticket/order/report always generates a new ID. A different ID in the response does NOT mean the mutation worked unless the response contains ANOTHER USER'S data.
- The response structure is the same but auto-generated fields differ (id, created_at, updated_at, timestamps) — these change on every request, not because of the mutation

IMPORTANT — Understand the endpoint's PURPOSE:
- POST endpoints that create resources (orders, tickets, reports, comments) will ALWAYS return new IDs. A new ID is NOT evidence of a vulnerability.
- GET endpoints that return a specific resource — a different ID here IS suspicious (may indicate IDOR).
- POST to a /comment endpoint creates a new comment — so subsequent responses will have MORE comments. That's normal, not injection.
- If the response has more items/records than the original, ask: is this because the TEST ITSELF created data, or because the injection bypassed a filter? If the extra records belong to the SAME user and the endpoint is a creation endpoint, it's normal growth.
- For injection testing: a real NoSQL/SQL injection finding means the response contains data from OTHER users or data that shouldn't be accessible. Just getting a 200 OK with your own data back is NOT proof of injection — the server may have just stored the literal string.
- The question is always: does the response contain data belonging to a DIFFERENT USER or data the requester shouldn't have access to?

Be VERY strict. Compare the actual data values between original and attack responses. If user_id, email, name are the same in both, it's a false positive.

OUTPUT FORMAT:
You MUST respond with ONLY a valid JSON object. No markdown, no prose, no explanation.
Example: {"findings": [{"is_real_vulnerability": true, "severity": "high", "title": "IDOR on /api/orders", "reasoning": "...", "category": "IDOR"}]}"""

_VALIDATION_RESPONSE_SCHEMA = {
    "findings": [
        {
            "is_real_vulnerability": "boolean - true only if this is a confirmed real security issue",
            "severity": "critical|high|medium|low|none",
            "title": "short title for the finding (or 'False Positive' if not real)",
            "reasoning": "1-2 sentences explaining why this is or isn't a real vulnerability",
            "category": "IDOR|BOLA|auth_bypass|data_exposure|privilege_escalation|SSRF|false_positive"
        }
    ]
}


def validate_findings_with_llm(
    llm_client,
    record: RequestRecord,
    hypothesis: AttackHypothesis,
    result: ExecutionResult,
    preliminary_findings: List[Finding],
    config: RunConfig,
) -> Tuple[List[Finding], List[Dict]]:
    """Use LLM to validate findings AND review response for missed issues. Returns (validated_findings, validation_results)."""
    if not llm_client or not hasattr(llm_client, '_post_raw'):
        return preliminary_findings, []
    if not result.response_body and not preliminary_findings:
        return [], []

    original_body = _truncate_body_for_llm(record.response_body or "", 2500)
    attack_body = _truncate_body_for_llm(result.response_body or "", 2500)

    has_preliminary = len(preliminary_findings) > 0
    task_goal = (
        "Validate whether these preliminary findings represent real security vulnerabilities, AND check if the attack response reveals any additional security issues that were missed."
        if has_preliminary else
        "Compare the original and attack responses to determine if this attack revealed any security vulnerability. The automated heuristics found nothing, but review the responses carefully for issues they may have missed."
    )
    rules = [
        "If there are preliminary findings, return one entry per finding validating or rejecting it.",
        "ALSO: if you spot additional vulnerabilities not in the preliminary findings, add new entries with is_real_vulnerability=true.",
        "Set is_real_vulnerability to true ONLY if the attack actually bypassed a security control or exposed unauthorized data.",
        "If the attack response contains the SAME data as the original (same user, same resources), it's NOT a vulnerability.",
        "If the attack got a 4xx error, the security control worked — mark as false positive unless the error message itself leaks sensitive info.",
        "If the attack removed auth but still got 200 with data, that IS a real auth bypass vulnerability.",
        "If the attack changed a user/resource ID and got different user data back, that IS a real IDOR/BOLA.",
        "Be strict but thorough — reject false positives but don't miss real issues.",
    ]

    # Mask real domains in bodies sent to LLM
    real_host = record.host or ""
    if real_host and original_body:
        original_body = original_body.replace(real_host, _MASKED_HOST)
    if real_host and attack_body:
        attack_body = attack_body.replace(real_host, _MASKED_HOST)

    prompt = {
        "original_request": {
            "method": record.method,
            "path": record.path,
            "response_status": record.response_status,
            "response_body": original_body,
        },
        "attack": {
            "attack_type": hypothesis.attack_type,
            "severity": hypothesis.severity,
            "mutation_summary": hypothesis.mutation_summary,
            "rationale": hypothesis.rationale,
            "method": hypothesis.method,
            "url": _mask_url(hypothesis.url),
            "body_preview": _truncate_body_for_llm(hypothesis.body or "", 1000),
            "response_status": result.status_code,
            "response_body": attack_body,
            "execution_outcome": result.outcome,
            "execution_error": result.error or "",
        },
        "preliminary_findings": [
            {"title": f.title, "severity": f.severity, "attack_type": f.attack_type, "summary": f.summary}
            for f in preliminary_findings
        ] if preliminary_findings else [],
        "task": {
            "goal": task_goal,
            "rules": rules,
        },
        "response_schema": _VALIDATION_RESPONSE_SCHEMA,
    }

    try:
        raw, response_text = llm_client._post_raw(
            json.dumps(prompt, ensure_ascii=False),
            _VALIDATION_SYSTEM_PROMPT,
            config,
        )
        content, _ = _extract_llm_content(raw)
        parsed = _parse_validation_response(content)
        if not parsed:
            return preliminary_findings, []

        validated_findings = []
        validation_results = []

        # Process existing preliminary findings
        for i, finding in enumerate(preliminary_findings):
            validation = parsed[i] if i < len(parsed) else {"is_real_vulnerability": None, "reasoning": "No validation data"}
            validation_results.append(validation)
            if validation and validation.get("is_real_vulnerability") is True:
                finding.confidence = "high"
                finding.severity = validation.get("severity", finding.severity)
                finding.title = validation.get("title", finding.title)
                finding.summary = validation.get("reasoning", finding.summary)
                if validation.get("category") and validation["category"] != "false_positive":
                    finding.attack_type = validation["category"]
                validated_findings.append(finding)

        # Check for NEW findings the LLM discovered beyond preliminary ones
        for j in range(len(preliminary_findings), len(parsed)):
            extra = parsed[j]
            validation_results.append(extra)
            if extra and extra.get("is_real_vulnerability") is True:
                new_finding = Finding(
                    finding_id="finding-%s" % uuid.uuid4().hex[:12],
                    request_id=record.request_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    title=extra.get("title", "LLM-discovered vulnerability"),
                    attack_type=extra.get("category", hypothesis.attack_type),
                    severity=extra.get("severity", "medium"),
                    confidence="high",
                    endpoint=record.endpoint_key(),
                    summary=extra.get("reasoning", ""),
                    expected_signal=hypothesis.expected_signal,
                    owasp=_owasp_mapping(extra.get("category", hypothesis.attack_type)),
                    evidence=_build_evidence(record, hypothesis, result),
                    remediation="Review the response data and ensure proper authorization controls.",
                    reproduction_curl=build_curl_command(hypothesis),
                )
                validated_findings.append(new_finding)

        return validated_findings, validation_results
    except Exception:
        return preliminary_findings, []


def _extract_llm_content(raw: Dict) -> Tuple[str, str]:
    """Extract content from LLM response, handling both content and reasoning_content."""
    message = (raw.get("choices") or [{}])[0].get("message") or {}
    content = str(message.get("content") or "")
    reasoning = str(message.get("reasoning_content") or "")
    if content.strip():
        return content, reasoning
    if reasoning.strip():
        return reasoning, reasoning
    return "", ""


def _parse_validation_response(content: str) -> Optional[List[Dict]]:
    """Parse the LLM validation response. Handles JSON, markdown code blocks, and prose."""
    if not content.strip():
        return None
    normalized = content.strip()
    parsed = None

    # Try 1: Direct JSON
    try:
        parsed = json.loads(normalized)
    except json.JSONDecodeError:
        pass

    # Try 2: Extract from markdown code block
    if parsed is None:
        import re
        code_match = re.search(r"```(?:json)?\s*\n?([\s\S]*?)```", normalized)
        if code_match:
            try:
                parsed = json.loads(code_match.group(1).strip())
            except json.JSONDecodeError:
                pass

    # Try 3: Find first { to last }
    if parsed is None:
        start = normalized.find("{")
        end = normalized.rfind("}")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(normalized[start:end + 1])
            except json.JSONDecodeError:
                pass

    # Try 4: Find array [ to ]
    if parsed is None:
        start = normalized.find("[")
        end = normalized.rfind("]")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(normalized[start:end + 1])
            except json.JSONDecodeError:
                pass

    if parsed is None:
        return None

    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict) and "findings" in parsed:
        return parsed["findings"]
    if isinstance(parsed, dict) and "is_real_vulnerability" in parsed:
        return [parsed]
    return None

