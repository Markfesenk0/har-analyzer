from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List

from .models import RequestRecord

SENSITIVE_KEYWORDS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api-key",
    "x-api-key",
    "phone",
    "email",
}

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(?:\+?\d[\d\-\s]{7,}\d)\b")
BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._\-+=/]+", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\b")
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9]{24,}\b")


def redact_string(value: str) -> str:
    redacted = value
    redacted = EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
    redacted = PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    redacted = BEARER_RE.sub("Bearer [REDACTED_TOKEN]", redacted)
    redacted = JWT_RE.sub("[REDACTED_JWT]", redacted)
    redacted = LONG_TOKEN_RE.sub("[REDACTED_SECRET]", redacted)
    return redacted


def redact_mapping(data: Dict[str, Any]) -> Dict[str, Any]:
    clean = {}
    for key, value in data.items():
        lower = key.lower()
        if any(keyword in lower for keyword in SENSITIVE_KEYWORDS):
            clean[key] = "[REDACTED]"
            continue
        clean[key] = redact_value(value)
    return clean


def redact_sequence(items: Iterable[Any]) -> List[Any]:
    return [redact_value(item) for item in items]


def maybe_redact_mapping(data: Dict[str, Any], enabled: bool) -> Dict[str, Any]:
    return redact_mapping(data) if enabled else deepcopy(data)


def maybe_redact_value(value: Any, enabled: bool) -> Any:
    return redact_value(value) if enabled else deepcopy(value)


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return redact_sequence(value)
    if isinstance(value, str):
        parsed = _try_parse_json(value)
        if isinstance(parsed, (dict, list)):
            return json.dumps(redact_value(parsed), ensure_ascii=False)
        return redact_string(value)
    return value


def redact_request_record(record: RequestRecord) -> RequestRecord:
    copy = deepcopy(record)
    copy.request_headers = redact_mapping(copy.request_headers)
    copy.response_headers = redact_mapping(copy.response_headers)
    copy.request_body = redact_value(copy.request_body)
    copy.response_body = redact_value(copy.response_body)
    return copy


def sanitize_har_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    return redact_mapping(payload)


def _try_parse_json(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None
