from __future__ import annotations

import difflib
import json
import re
import uuid
from typing import Dict, List, Tuple

from .models import AttackHypothesis, ExecutionResult, Finding, RequestRecord
from .redaction import redact_string, redact_value

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
TOKEN_HINT_RE = re.compile(r"\b(?:eyJ[a-zA-Z0-9._\-]+|[A-F0-9]{24,}|[A-Za-z0-9_\-]{32,})\b")


def evaluate_result(
    record: RequestRecord,
    hypothesis: AttackHypothesis,
    result: ExecutionResult,
) -> List[Finding]:
    findings: List[Finding] = []
    if result.outcome == "token_expired":
        return findings
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
    secret_findings = detect_sensitive_leakage(record, hypothesis, result)
    findings.extend(secret_findings)
    return findings


def build_curl_command(hypothesis: AttackHypothesis) -> str:
    parts = ["curl", "-X", hypothesis.method.upper()]
    for key, value in sorted(hypothesis.headers.items()):
        parts.extend(["-H", "'%s: %s'" % (key, redact_string(value))])
    if hypothesis.body:
        parts.extend(["--data", "'%s'" % redact_string(hypothesis.body)])
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
    }
    return mapping.get(attack_type, ["API8:2023 Security Misconfiguration"])

