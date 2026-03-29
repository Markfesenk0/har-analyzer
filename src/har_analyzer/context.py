from __future__ import annotations

import json
import re
from collections import Counter
from typing import Iterable, List

from .models import EndpointContext, RequestRecord


def build_endpoint_context(records: Iterable[RequestRecord], neighbor_window: int = 2) -> EndpointContext:
    record_list = list(records)
    auth_headers = set()
    cookies = set()
    params = Counter()
    resource_ids = set()
    roles = set()
    neighboring_requests = {}

    for index, record in enumerate(record_list):
        for header_name in record.request_headers:
            lowered = header_name.lower()
            if lowered in {"authorization", "x-api-key", "apikey"}:
                auth_headers.add(header_name)
        for header_name, header_value in record.response_headers.items():
            if header_name.lower() == "set-cookie":
                cookies.add(header_value.split(";", 1)[0].split("=", 1)[0])
        for key in record.query_params:
            params[key] += 1
        for candidate in _extract_json_keys(record.request_body):
            params[candidate] += 1
        for candidate in re.findall(r"/(\d+)(?:/|$)", record.path):
            resource_ids.add(candidate)
        if record.request_body:
            for role in re.findall(r'"(?:role|roles|permission|permissions)"\s*:\s*"([^"]+)"', record.request_body, re.IGNORECASE):
                roles.add(role)
        neighboring_requests[record.request_id] = _build_neighbor_context(record_list, index, neighbor_window)

    return EndpointContext(
        auth_header_names=sorted(auth_headers),
        cookies_seen=sorted(cookies),
        recurring_parameters=dict(sorted(params.items(), key=lambda item: (-item[1], item[0]))[:25]),
        resource_ids_seen=sorted(resource_ids)[:50],
        user_roles_seen=sorted(roles),
        neighboring_requests=neighboring_requests,
    )


def _extract_json_keys(body: str) -> Iterable[str]:
    if not body:
        return []
    try:
        payload = json.loads(body)
    except Exception:
        return []
    if isinstance(payload, dict):
        return payload.keys()
    return []


def _build_neighbor_context(records: List[RequestRecord], index: int, neighbor_window: int) -> List[dict]:
    if neighbor_window <= 0:
        return []
    start = max(0, index - neighbor_window)
    end = min(len(records), index + neighbor_window + 1)
    out = []
    for neighbor_index in range(start, end):
        if neighbor_index == index:
            continue
        record = records[neighbor_index]
        out.append(
            {
                "relative_position": neighbor_index - index,
                "method": record.method,
                "path": record.path,
                "normalized_path": record.normalized_path(),
                "response_status": record.response_status,
            }
        )
    return out
