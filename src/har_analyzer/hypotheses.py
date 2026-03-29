from __future__ import annotations

import json
import os
import socket
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

from .models import AttackHypothesis, EndpointContext, RequestRecord, RunConfig


class LLMClient(object):
    def build_preview(
        self,
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
    ) -> Dict[str, object]:
        raise NotImplementedError

    def generate_hypotheses(
        self,
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
    ) -> List[AttackHypothesis]:
        raise NotImplementedError


class ProviderResponseError(RuntimeError):
    def __init__(
        self,
        message: str,
        debug_artifact_path: str = "",
        raw_content: str = "",
        status_code: Optional[int] = None,
        retry_after_seconds: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.debug_artifact_path = debug_artifact_path
        self.raw_content = raw_content
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


class BuiltinHeuristicClient(LLMClient):
    def build_preview(
        self,
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
    ) -> Dict[str, object]:
        return {
            "provider": "builtin",
            "model": config.model,
            "mode": "heuristic",
            "record": record.to_dict(),
            "context": context.to_dict(),
            "instruction": "Local heuristic mode. No external LLM request will be made.",
        }

    def generate_hypotheses(
        self,
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
    ) -> List[AttackHypothesis]:
        candidates: List[AttackHypothesis] = []
        resource_swap = _numeric_swap_hypothesis(record)
        if resource_swap:
            candidates.append(resource_swap)
        query_swaps = _query_param_hypotheses(record)
        candidates.extend(query_swaps)
        auth_tests = _auth_hypotheses(record)
        candidates.extend(auth_tests)
        return candidates[: config.per_endpoint_hypothesis_cap]


class OpenAICompatibleClient(LLMClient):
    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.supports_json_object_response_format: Optional[bool] = None
        self.last_provider_response_text = ""
        self.last_message_content = ""
        self.last_reasoning_content = ""
        self.last_debug_path = ""

    def build_preview(
        self,
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
    ) -> Dict[str, object]:
        include_response_format = self.supports_json_object_response_format is not False
        return self._build_preview(record, context, config, include_response_format=include_response_format)

    def _build_preview(
        self,
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
        include_response_format: bool,
    ) -> Dict[str, object]:
        prompt = _build_analysis_prompt(record, context, config)
        prompt = {
            "request": prompt["request"],
            "context": prompt["context"],
            "task": prompt["task"],
            "response_schema": prompt["response_schema"],
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
        }
        if include_response_format:
            payload["response_format"] = {"type": "json_object"}
        return {
            "provider": config.provider,
            "model": self.model,
            "url": self.base_url + "/chat/completions",
            "payload": payload,
        }

    def generate_hypotheses(
        self,
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
    ) -> List[AttackHypothesis]:
        preview = self.build_preview(record, context, config)
        raw, provider_response_text = self._post_with_retries(preview, record, context, config)
        content, reasoning_content = _extract_provider_message(raw)
        debug_path = _write_debug_artifact(config, record.request_id, provider_response_text, content, reasoning_content)
        self.last_provider_response_text = provider_response_text
        self.last_message_content = content
        self.last_reasoning_content = reasoning_content
        self.last_debug_path = debug_path
        parsed = _parse_json_payload(content, debug_path, provider_response_text)
        results = []
        for item in parsed.get("hypotheses", []):
            mutation = _resolve_mutation(record, item)
            results.append(
                AttackHypothesis(
                    hypothesis_id="hyp-%s" % uuid.uuid4().hex[:12],
                    original_request_id=record.request_id,
                    endpoint_key=record.endpoint_key(),
                    attack_type=item.get("attack_type", "unknown"),
                    severity=item.get("severity", "medium"),
                    expected_signal=item.get("expected_signal", ""),
                    rationale=item.get("rationale", ""),
                    method=mutation["method"],
                    url=mutation["url"],
                    headers=mutation["headers"],
                    body=mutation["body"],
                    mutation_summary=item.get("mutation_summary", ""),
                )
            )
        return results

    def _post_with_retries(
        self,
        preview: Dict[str, object],
        record: RequestRecord,
        context: EndpointContext,
        config: RunConfig,
    ) -> tuple[Dict[str, object], str]:
        headers = {"Authorization": "Bearer %s" % self.api_key, "Content-Type": "application/json"}
        busy_attempt = 0
        while True:
            try:
                raw, provider_response_text = _post_json(
                    preview["url"],
                    preview["payload"],
                    headers,
                    timeout_seconds=config.llm_timeout_seconds,
                )
            except ProviderResponseError as error:
                if self._should_retry_without_response_format(error, preview):
                    self.supports_json_object_response_format = False
                    preview = self._build_preview(record, context, config, include_response_format=False)
                    continue
                if self._should_retry_busy_error(error) and busy_attempt < config.llm_busy_retry_count:
                    delay = error.retry_after_seconds
                    if delay is None:
                        delay = config.llm_busy_retry_base_delay_seconds * (2 ** busy_attempt)
                    time.sleep(max(0.0, delay))
                    busy_attempt += 1
                    continue
                raise
            else:
                if "response_format" in preview["payload"]:
                    self.supports_json_object_response_format = True
                return raw, provider_response_text

    def _should_retry_without_response_format(self, error: ProviderResponseError, preview: Dict[str, object]) -> bool:
        payload = preview.get("payload", {})
        if not isinstance(payload, dict) or "response_format" not in payload:
            return False
        haystack = "%s\n%s" % (str(error), error.raw_content or "")
        lowered = haystack.lower()
        return "response format is not supported" in lowered or "json_object" in lowered

    def _should_retry_busy_error(self, error: ProviderResponseError) -> bool:
        if error.status_code == 429:
            return True
        lowered = ("%s\n%s" % (str(error), error.raw_content or "")).lower()
        return "model busy" in lowered or "retry later" in lowered or "too many requests" in lowered


def _system_prompt() -> str:
    return (
        "You are an API security analyst reviewing captured mobile application traffic for authorized security testing. "
        "Your goal is to propose only concrete, high-signal replay mutations that could reveal broken access control, "
        "object-level authorization issues, function-level authorization issues, token misuse, or excessive data exposure. "
        "Be conservative: if a request looks low-signal or non-actionable, return zero hypotheses. "
        "Do not pad the list, do not invent extra endpoints or parameters without evidence, and do not suggest generic checks "
        "that are not grounded in the supplied request and context. Return valid JSON only."
    )


def _build_analysis_prompt(record: RequestRecord, context: EndpointContext, config: RunConfig) -> Dict[str, object]:
    return {
        "request": _build_prompt_request(record, config),
        "context": _build_prompt_context(record, context),
        "task": {
            "goal": "Propose targeted replay mutations for this single API request.",
            "priority_areas": [
                "IDOR or BOLA",
                "broken function level authorization",
                "authorization bypass",
                "token misuse or token removal",
                "sensitive data exposure",
            ],
            "selection_rules": [
                "Return anywhere from 0 to %d hypotheses." % config.per_endpoint_hypothesis_cap,
                "Return 0 hypotheses when the request appears low-risk, informational, or not meaningfully mutable.",
                "Prefer a small number of high-confidence hypotheses over speculative coverage.",
                "Only include method or url changes when they are actually needed.",
                "For headers, include only changed, added, or removed keys in the changes object.",
                "Use null inside changes.headers to remove an original header.",
                "If the body does not change, omit it from changes.",
            ],
        },
        "response_schema": {
            "hypotheses": [
                {
                    "attack_type": "string",
                    "severity": "critical|high|medium|low",
                    "expected_signal": "string",
                    "rationale": "string",
                    "mutation_summary": "string",
                    "changes": {
                        "method": "optional string",
                        "url": "optional string",
                        "headers": {"optional_header_name": "optional string or null"},
                        "body": "optional string or null",
                    },
                }
            ]
        },
    }


def _build_prompt_context(record: RequestRecord, context: EndpointContext) -> Dict[str, Any]:
    prompt_context: Dict[str, Any] = {
        "neighboring_requests": context.neighboring_requests.get(record.request_id, []),
    }
    if context.auth_header_names:
        prompt_context["auth_header_names"] = list(context.auth_header_names)
    if context.recurring_parameters:
        prompt_context["recurring_parameters"] = dict(list(context.recurring_parameters.items())[:10])
    return prompt_context


def _build_prompt_request(record: RequestRecord, config: RunConfig) -> Dict[str, Any]:
    return {
        "method": record.method,
        "url": record.url,
        "host": record.host,
        "path": record.path,
        "normalized_path": record.normalized_path(),
        "query_params": dict(record.query_params),
        "request_headers": dict(record.request_headers),
        "request_body": _build_prompt_body(record.request_body, config),
        "response_status": record.response_status,
        "response_headers": dict(record.response_headers),
        "response_body": _build_prompt_body(record.response_body, config),
    }


def _build_prompt_body(value: Optional[str], config: RunConfig) -> Any:
    if value is None or value == "":
        return None
    raw = str(value)
    if len(raw) > config.max_body_chars:
        return {
            "format": _detect_body_format(raw),
            "truncated": True,
            "original_length": len(raw),
            "preview": raw[: config.truncated_body_chars],
            "note": (
                "Body exceeded %d chars, so only the first %d chars are included."
                % (config.max_body_chars, config.truncated_body_chars)
            ),
        }
    parsed = _try_parse_json(raw)
    if isinstance(parsed, (dict, list)):
        return parsed
    return raw


def _detect_body_format(value: str) -> str:
    parsed = _try_parse_json(value)
    if isinstance(parsed, (dict, list)):
        return "json"
    return "text"


def _try_parse_json(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None


def _resolve_mutation(record: RequestRecord, item: Dict[str, object]) -> Dict[str, object]:
    changes = item.get("changes", {})
    if not isinstance(changes, dict):
        changes = {}
    headers = dict(record.request_headers)
    header_changes = changes.get("headers")
    if isinstance(header_changes, dict):
        for key, value in header_changes.items():
            if value is None:
                headers.pop(key, None)
            else:
                headers[str(key)] = str(value)
    elif isinstance(item.get("headers"), dict):
        headers = dict(item.get("headers", {}))
    method = changes.get("method", item.get("method", record.method))
    url = changes.get("url", item.get("url", record.url))
    if "body" in changes:
        body = changes.get("body")
    else:
        body = item.get("body", record.request_body)
    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
    }


def get_llm_client(config: RunConfig) -> LLMClient:
    if config.provider == "builtin":
        return BuiltinHeuristicClient()
    if not config.llm_base_url or not config.llm_api_key:
        raise RuntimeError("Configured LLM provider '%s' requires HAR_ANALYZER_LLM_BASE_URL and HAR_ANALYZER_LLM_API_KEY." % config.provider)
    return OpenAICompatibleClient(config.llm_base_url, config.llm_api_key, config.model)


def _numeric_swap_hypothesis(record: RequestRecord) -> Optional[AttackHypothesis]:
    parts = record.path.strip("/").split("/")
    for index, part in enumerate(parts):
        if part.isdigit():
            mutated_parts = list(parts)
            mutated_parts[index] = str(int(part) + 1)
            new_path = "/" + "/".join(mutated_parts)
            new_url = record.url.replace(record.path, new_path, 1)
            return AttackHypothesis(
                hypothesis_id="hyp-%s" % uuid.uuid4().hex[:12],
                original_request_id=record.request_id,
                endpoint_key=record.endpoint_key(),
                attack_type="IDOR",
                severity="high",
                expected_signal="The server returns another resource instead of denying access.",
                rationale="A numeric resource identifier appears in the path and is a strong candidate for broken object authorization testing.",
                method=record.method,
                url=new_url,
                headers=dict(record.request_headers),
                body=record.request_body,
                mutation_summary="Incremented path identifier %s -> %s" % (part, mutated_parts[index]),
            )
    return None


def _query_param_hypotheses(record: RequestRecord) -> List[AttackHypothesis]:
    out = []
    for key, value in record.query_params.items():
        if value.isdigit():
            new_value = str(int(value) + 1)
            new_query = dict(record.query_params)
            new_query[key] = new_value
            base = record.url.split("?", 1)[0]
            query_string = "&".join("%s=%s" % (name, val) for name, val in sorted(new_query.items()))
            out.append(
                AttackHypothesis(
                    hypothesis_id="hyp-%s" % uuid.uuid4().hex[:12],
                    original_request_id=record.request_id,
                    endpoint_key=record.endpoint_key(),
                    attack_type="BOLA",
                    severity="high",
                    expected_signal="A different object's data is returned when an identifier parameter changes.",
                    rationale="The query parameter '%s' looks like a direct object reference." % key,
                    method=record.method,
                    url="%s?%s" % (base, query_string),
                    headers=dict(record.request_headers),
                    body=record.request_body,
                    mutation_summary="Incremented query parameter %s=%s -> %s" % (key, value, new_value),
                )
            )
    return out


def _auth_hypotheses(record: RequestRecord) -> List[AttackHypothesis]:
    out = []
    lowered = {key.lower(): key for key in record.request_headers}
    if "authorization" in lowered:
        headers = dict(record.request_headers)
        headers.pop(lowered["authorization"], None)
        out.append(
            AttackHypothesis(
                hypothesis_id="hyp-%s" % uuid.uuid4().hex[:12],
                original_request_id=record.request_id,
                endpoint_key=record.endpoint_key(),
                attack_type="auth_bypass",
                severity="medium",
                expected_signal="The endpoint still returns sensitive data without the Authorization header.",
                rationale="Replay without the authorization material to detect missing access control.",
                method=record.method,
                url=record.url,
                headers=headers,
                body=record.request_body,
                mutation_summary="Removed Authorization header",
            )
        )
    return out


def _post_json(url: str, payload: Dict[str, object], headers: Dict[str, str], timeout_seconds: float):
    body = json.dumps(payload).encode("utf-8")
    request = urllib_request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib_request.urlopen(request, timeout=timeout_seconds) as response:
            response_text = response.read().decode("utf-8")
            return json.loads(response_text), response_text
    except urllib_error.HTTPError as error:
        response_text = error.read().decode("utf-8", "ignore")
        retry_after_header = error.headers.get("Retry-After") if error.headers else None
        raise ProviderResponseError(
            "Provider returned HTTP %s: %s" % (error.code, response_text[:200]),
            raw_content=response_text,
            status_code=error.code,
            retry_after_seconds=_parse_retry_after_seconds(retry_after_header),
        )
    except socket.timeout:
        raise ProviderResponseError(
            "Provider request timed out after %.1f seconds." % timeout_seconds,
            raw_content="",
        )


def _parse_retry_after_seconds(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    try:
        return max(0.0, float(value.strip()))
    except (TypeError, ValueError):
        return None


def _extract_provider_message(raw: Dict[str, object]) -> tuple[str, str]:
    message = raw.get("choices", [{}])[0].get("message", {}) or {}
    content = str(message.get("content") or "")
    reasoning_content = str(message.get("reasoning_content") or "")
    if content.strip():
        return content, reasoning_content
    if reasoning_content.strip():
        return reasoning_content, reasoning_content
    return "", reasoning_content


def _parse_json_payload(content: str, debug_path: str, provider_response_text: str) -> Dict[str, object]:
    normalized = (content or "").strip()
    if not normalized:
        raise ProviderResponseError(
            "Provider returned an empty message content. Debug artifact: %s" % debug_path,
            debug_artifact_path=debug_path,
            raw_content=provider_response_text or content,
        )
    try:
        return json.loads(normalized)
    except json.JSONDecodeError:
        pass
    if normalized.startswith("```") and normalized.endswith("```"):
        stripped = normalized.strip("`")
        stripped = stripped.replace("json\n", "", 1).strip()
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    start = normalized.find("{")
    end = normalized.rfind("}")
    if start != -1 and end > start:
        candidate = normalized[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    raise ProviderResponseError(
        "Provider returned non-JSON content. Debug artifact: %s" % debug_path,
        debug_artifact_path=debug_path,
        raw_content=provider_response_text or normalized,
    )


def _write_debug_artifact(config: RunConfig, request_id: str, provider_response_text: str, content: str, reasoning_content: str = "") -> str:
    base_dir = config.run_artifact_dir or config.artifact_dir
    debug_dir = os.path.join(base_dir, "llm_debug")
    os.makedirs(debug_dir, exist_ok=True)
    path = os.path.join(debug_dir, "%s-%s.txt" % (request_id, config.provider))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("PROVIDER=%s\nMODEL=%s\n\n" % (config.provider, config.model))
        handle.write("RAW_PROVIDER_RESPONSE\n")
        handle.write(provider_response_text or "")
        handle.write("\n\nMODEL_MESSAGE_CONTENT\n")
        handle.write(content or "")
        if reasoning_content:
            handle.write("\n\nMODEL_REASONING_CONTENT\n")
            handle.write(reasoning_content)
    return path
