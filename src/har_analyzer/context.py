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
    endpoint_groups = {}

    # Extract patterns from all requests
    auth_required_endpoints = []
    optional_auth_endpoints = []

    for index, record in enumerate(record_list):
        # Auth header detection
        has_auth = False
        for header_name in record.request_headers:
            lowered = header_name.lower()
            if lowered in {"authorization", "x-api-key", "apikey"}:
                auth_headers.add(header_name)
                has_auth = True

        # Track which endpoints require auth
        if has_auth:
            if record.response_status and record.response_status < 400:
                auth_required_endpoints.append(record.normalized_path())

        # Cookie detection
        for header_name, header_value in record.response_headers.items():
            if header_name.lower() == "set-cookie":
                cookies.add(header_value.split(";", 1)[0].split("=", 1)[0])

        # Parameter frequency tracking
        for key in record.query_params:
            params[key] += 1
        for candidate in _extract_json_keys(record.request_body):
            params[candidate] += 1

        # Resource ID extraction (numeric and UUIDs)
        for candidate in re.findall(r"/(\d+)(?:/|$)", record.path):
            resource_ids.add(candidate)
        for uuid_match in re.findall(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", record.path):
            resource_ids.add(uuid_match)

        # Role/permission detection
        if record.request_body:
            for role in re.findall(r'"(?:role|roles|permission|permissions)"\s*:\s*"([^"]+)"', record.request_body, re.IGNORECASE):
                roles.add(role)

        neighboring_requests[record.request_id] = _build_neighbor_context(record_list, index, neighbor_window)

    # Build endpoint groups (similar paths with same pattern)
    endpoint_groups = _group_similar_endpoints(record_list)

    # Generate API summary from patterns
    api_summary = _generate_api_summary(record_list, auth_headers, roles)

    # Analyze cross-endpoint data flows
    data_flows = _analyze_data_flows(record_list)

    return EndpointContext(
        auth_header_names=sorted(auth_headers),
        cookies_seen=sorted(cookies),
        recurring_parameters=dict(sorted(params.items(), key=lambda item: (-item[1], item[0]))[:25]),
        resource_ids_seen=sorted(resource_ids)[:50],
        user_roles_seen=sorted(roles),
        neighboring_requests=neighboring_requests,
        endpoint_groups=endpoint_groups,
        api_summary=api_summary,
        data_flows=data_flows,
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


def _group_similar_endpoints(records: List[RequestRecord]) -> dict:
    """
    Group endpoints by method and normalized path pattern.
    E.g., GET /users/1, GET /users/2 -> both are "GET /users/{id}"
    """
    groups = {}
    for record in records:
        endpoint_key = record.endpoint_key()  # "GET /path/123"
        normalized = record.normalized_path()  # "/path/{id}"

        if normalized not in groups:
            groups[normalized] = []
        groups[normalized].append(endpoint_key)

    # Convert to cleaner format
    return {norm: list(set(endpoints)) for norm, endpoints in groups.items()}


def _generate_api_summary(records: List[RequestRecord], auth_headers: set, roles: set) -> str:
    """
    Generate a human-readable summary of API patterns.
    """
    if not records:
        return ""

    # Collect stats
    methods = Counter(r.method for r in records)
    endpoints_with_auth = sum(1 for r in records if any(h.lower() in {"authorization", "x-api-key", "apikey"} for h in r.request_headers))
    success_count = sum(1 for r in records if r.response_status and 200 <= r.response_status < 300)

    summary_parts = []

    # API overview
    summary_parts.append("API Overview:")
    summary_parts.append(f"  - {len(records)} total requests captured")
    summary_parts.append(f"  - Methods: {', '.join(f'{m}({c})' for m, c in methods.most_common())}")
    summary_parts.append(f"  - Success rate: {success_count}/{len(records)} (2xx responses)")

    # Auth patterns
    if auth_headers:
        summary_parts.append(f"  - Authentication: Uses {', '.join(sorted(auth_headers))}")
    if endpoints_with_auth > 0:
        summary_parts.append(f"  - {endpoints_with_auth} endpoints require authentication")

    # User roles
    if roles:
        summary_parts.append(f"  - User roles observed: {', '.join(sorted(roles))}")

    # Response patterns
    has_json = any(r.response_body and (r.response_body.startswith("{") or r.response_body.startswith("[")) for r in records)
    if has_json:
        summary_parts.append("  - Responses: JSON formatted")

    return "\n".join(summary_parts)


def _analyze_data_flows(records: List[RequestRecord]) -> List[dict]:
    """
    Identify cross-endpoint data flows.
    E.g., response field user_id from GET /users becomes path parameter in GET /users/{id}/profile
    Returns list of detected flows: {"source_endpoint": "...", "target_endpoint": "...", "field": "...", "usage": "..."}
    """
    flows = []
    if len(records) < 2:
        return flows

    for i, source in enumerate(records):
        if not source.response_body:
            continue

        # Extract IDs and fields from response
        response_data = _extract_json_keys(source.response_body)
        response_values = _extract_json_values(source.response_body)

        # Check if these values appear in subsequent requests
        for target in records[i + 1 :]:
            for field in response_data:
                # Check in query parameters
                if field in target.query_params:
                    flows.append({
                        "source_endpoint": source.endpoint_key(),
                        "target_endpoint": target.endpoint_key(),
                        "field": field,
                        "usage": "query_parameter",
                    })

            # Check in path (simple check for numeric IDs)
            for value in response_values:
                if isinstance(value, (int, str)) and str(value) in target.path:
                    flows.append({
                        "source_endpoint": source.endpoint_key(),
                        "target_endpoint": target.endpoint_key(),
                        "field": str(value),
                        "usage": "path_parameter",
                    })

    # Deduplicate flows
    unique_flows = []
    seen = set()
    for flow in flows:
        key = (flow["source_endpoint"], flow["target_endpoint"], flow["field"], flow["usage"])
        if key not in seen:
            seen.add(key)
            unique_flows.append(flow)

    return unique_flows[:20]  # Limit to top 20 flows


def _extract_json_values(body: str) -> List:
    """Extract values from JSON body (not just keys)."""
    if not body:
        return []
    try:
        payload = json.loads(body)
        return _collect_values(payload)
    except Exception:
        return []


def _collect_values(obj, max_depth: int = 3) -> List:
    """Recursively collect leaf values from JSON object."""
    if max_depth <= 0:
        return []
    values = []
    if isinstance(obj, dict):
        for v in obj.values():
            values.extend(_collect_values(v, max_depth - 1))
    elif isinstance(obj, list):
        for item in obj[:10]:  # Limit list traversal
            values.extend(_collect_values(item, max_depth - 1))
    else:
        # Leaf value
        if isinstance(obj, (int, str)) and obj:
            values.append(obj)
    return values
