from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List
from urllib.parse import urlparse

from .models import RequestRecord
from .redaction import sanitize_har_payload

IGNORE_DOMAINS = {
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.net",
    "fbcdn.net",
    "crashlytics.com",
    "doubleclick.net",
    "app-measurement.com",
}

IGNORE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".css",
    ".js",
    ".ico",
    ".mp4",
    ".mov",
    ".webp",
    ".map",
}


def load_har(path: str) -> Dict[str, object]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_sanitized_har(input_path: str, output_path: str) -> None:
    payload = load_har(input_path)
    clean = sanitize_har_payload(payload)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(clean, indent=2, ensure_ascii=False), encoding="utf-8")


def export_filtered_records(
    input_path: str,
    output_path: str,
    target_domains: Iterable[str],
    excluded_patterns: Iterable[str] = (),
) -> None:
    records = filter_records(har_to_records(input_path), target_domains, excluded_patterns)
    payload = [record.to_dict() for record in records]
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def build_scoped_har_payload(payload: Dict[str, object], scoped_records: List[RequestRecord], sanitize: bool = True) -> Dict[str, object]:
    entry_indexes = {record.entry_index for record in scoped_records}
    copy_payload = json.loads(json.dumps(payload))
    log = copy_payload.get("log", {})
    entries = log.get("entries", [])
    log["entries"] = [entry for index, entry in enumerate(entries) if index in entry_indexes]
    if sanitize:
        return sanitize_har_payload(copy_payload)
    return copy_payload


def har_to_records(har_path: str) -> List[RequestRecord]:
    payload = load_har(har_path)
    entries = payload.get("log", {}).get("entries", [])
    out: List[RequestRecord] = []
    for index, entry in enumerate(entries):
        request = entry.get("request", {})
        response = entry.get("response", {}) or {}
        url = request.get("url", "")
        parsed = urlparse(url)
        headers = {item.get("name", ""): item.get("value", "") for item in request.get("headers", [])}
        host = headers.get("host", parsed.netloc)
        query_params = {item.get("name", ""): item.get("value", "") for item in request.get("queryString", [])}
        response_headers = {item.get("name", ""): item.get("value", "") for item in response.get("headers", [])}
        request_body = (request.get("postData", {}) or {}).get("text")
        response_body = _decode_response_body(response)
        record = RequestRecord(
            request_id="entry-%04d" % index,
            entry_index=index,
            started_at=entry.get("startedDateTime", ""),
            method=request.get("method", "GET").upper(),
            url=url,
            scheme=parsed.scheme or "https",
            host=host,
            path=parsed.path or "/",
            query_params=query_params,
            request_headers=headers,
            request_body=request_body,
            response_status=response.get("status"),
            response_headers=response_headers,
            response_body=response_body,
            duration_ms=float(entry.get("time", 0.0)),
            flags=sorted(_classify_record(host, parsed.path or "/", request.get("method", "GET").upper(), headers)),
        )
        out.append(record)
    return _dedupe_records(out)


def filter_records(records: Iterable[RequestRecord], target_domains: Iterable[str], excluded_patterns: Iterable[str]) -> List[RequestRecord]:
    targets = [domain.lower() for domain in target_domains if domain]
    excluded = [pattern for pattern in excluded_patterns if pattern]
    filtered = []
    for record in records:
        if targets and not _host_in_scope(record.host, targets):
            continue
        if any(pattern in record.path for pattern in excluded):
            continue
        if "static_asset" in record.flags or "tracking_domain" in record.flags or "preflight_request" in record.flags:
            continue
        filtered.append(record)
    return filtered


def _decode_response_body(response: Dict[str, object]) -> str:
    content = response.get("content", {}) or {}
    text = content.get("text")
    if not text:
        return ""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", "ignore")
        except Exception:
            return ""
    return str(text)


def _classify_record(host: str, path: str, method: str, headers: Dict[str, str]) -> List[str]:
    flags = []
    lower_path = path.lower()
    lower_host = host.lower()
    if any(lower_path.endswith(ext) for ext in IGNORE_EXTENSIONS):
        flags.append("static_asset")
    if any(domain in lower_host for domain in IGNORE_DOMAINS):
        flags.append("tracking_domain")
    if method.upper() == "OPTIONS":
        flags.append("preflight_request")
    if any(key.lower() == "authorization" for key in headers):
        flags.append("authorization_header_present")
    if re.search(r"/\d+(/|$)", path):
        flags.append("resource_identifier_present")
    return flags


def _dedupe_records(records: Iterable[RequestRecord], per_path_limit: int = 3) -> List[RequestRecord]:
    seen = set()
    path_counts: Dict[str, int] = defaultdict(int)
    filtered = []
    for record in records:
        key = (record.method, record.path, _stable_hash(record.response_body or ""))
        if key in seen:
            continue
        if path_counts[record.path] >= per_path_limit:
            continue
        seen.add(key)
        path_counts[record.path] += 1
        filtered.append(record)
    return filtered


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _host_in_scope(host: str, targets: List[str]) -> bool:
    lowered = host.lower()
    for target in targets:
        if lowered == target or lowered.endswith("." + target):
            return True
    return False
