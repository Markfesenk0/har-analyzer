from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import RunConfig


PROVIDER_PRESETS: Dict[str, Dict[str, str]] = {
    "builtin": {
        "label": "Builtin Heuristics",
        "base_url": "",
        "description": "Local heuristic mode without external LLM calls.",
    },
    "deepinfra": {
        "label": "DeepInfra",
        "base_url": "https://api.deepinfra.com/v1/openai",
        "description": "OpenAI-compatible hosted inference via DeepInfra.",
    },
}


def autoload_env() -> None:
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    ]
    for path in candidates:
        if path.exists():
            _load_env_file(path)
            break


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_default_unsafe_unredacted() -> bool:
    return _env_bool("HAR_ANALYZER_UNSAFE_UNREDACTED_DEFAULT", False)


def get_supported_provider_options() -> List[Dict[str, str]]:
    return [
        {
            "value": name,
            "label": metadata["label"],
            "description": metadata["description"],
        }
        for name, metadata in PROVIDER_PRESETS.items()
    ]


def resolve_provider_base_url(provider: str, explicit_base_url: str = "") -> str:
    if provider == "builtin":
        return ""
    if explicit_base_url:
        return explicit_base_url.strip()
    env_value = os.getenv("HAR_ANALYZER_LLM_BASE_URL", "").strip()
    if env_value:
        return env_value
    return PROVIDER_PRESETS.get(provider, {}).get("base_url", "")


def _load_env_file(path: Path) -> None:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        os.environ[key] = value


def load_run_config(
    har_path: str,
    target_domains: Iterable[str],
    artifact_dir: str = "",
    allow_unsafe_artifacts: Optional[bool] = None,
    provider: str = "",
    model: str = "",
    llm_base_url: str = "",
    step_mode: bool = False,
) -> RunConfig:
    artifact_root = artifact_dir or os.getenv("HAR_ANALYZER_ARTIFACT_DIR", "artifacts")
    domains = [item.strip() for item in target_domains if item and item.strip()]
    return RunConfig(
        har_path=har_path,
        target_domains=domains,
        provider=provider or os.getenv("HAR_ANALYZER_LLM_PROVIDER", "builtin"),
        model=model or os.getenv("HAR_ANALYZER_MODEL", "builtin-heuristics"),
        langsmith_project=os.getenv("LANGCHAIN_PROJECT", "har-analyzer"),
        concurrency=int(os.getenv("HAR_ANALYZER_CONCURRENCY", "4")),
        per_endpoint_hypothesis_cap=int(os.getenv("HAR_ANALYZER_ENDPOINT_CAP", "10")),
        global_request_cap=int(os.getenv("HAR_ANALYZER_GLOBAL_CAP", "100")),
        inter_request_delay_ms=int(os.getenv("HAR_ANALYZER_INTER_REQUEST_DELAY_MS", "500")),
        excluded_path_patterns=_split_csv(os.getenv("HAR_ANALYZER_EXCLUDED_PATH_PATTERNS", "")),
        allow_unsafe_artifacts=get_default_unsafe_unredacted() if allow_unsafe_artifacts is None else allow_unsafe_artifacts,
        artifact_dir=artifact_root,
        database_path=os.getenv("HAR_ANALYZER_DB_PATH", os.path.join(artifact_root, "runs.sqlite3")),
        llm_base_url=resolve_provider_base_url(provider or os.getenv("HAR_ANALYZER_LLM_PROVIDER", "builtin"), llm_base_url),
        llm_api_key=os.getenv("HAR_ANALYZER_LLM_API_KEY", ""),
        llm_timeout_seconds=float(os.getenv("HAR_ANALYZER_LLM_TIMEOUT_SECONDS", "60")),
        llm_busy_retry_count=int(os.getenv("HAR_ANALYZER_LLM_BUSY_RETRY_COUNT", "2")),
        llm_busy_retry_base_delay_seconds=float(os.getenv("HAR_ANALYZER_LLM_BUSY_RETRY_BASE_DELAY_SECONDS", "2.0")),
        request_timeout_seconds=float(os.getenv("HAR_ANALYZER_REQUEST_TIMEOUT_SECONDS", "20")),
        ui_host=os.getenv("HAR_ANALYZER_UI_HOST", "127.0.0.1"),
        ui_port=int(os.getenv("HAR_ANALYZER_UI_PORT", "8765")),
        max_body_chars=int(os.getenv("HAR_ANALYZER_MAX_BODY_CHARS", "4000")),
        truncated_body_chars=int(os.getenv("HAR_ANALYZER_TRUNCATED_BODY_CHARS", "1000")),
        neighbor_context_window=int(os.getenv("HAR_ANALYZER_NEIGHBOR_CONTEXT_WINDOW", "2")),
        step_mode=step_mode or os.getenv("HAR_ANALYZER_STEP_MODE", "").lower() == "true",
        redact_by_default=_env_bool("HAR_ANALYZER_REDACT_BY_DEFAULT", False),
    )


def validate_langsmith_env() -> None:
    required = {
        "LANGCHAIN_TRACING_V2": os.getenv("LANGCHAIN_TRACING_V2", ""),
        "LANGCHAIN_API_KEY": os.getenv("LANGCHAIN_API_KEY", ""),
        "LANGCHAIN_PROJECT": os.getenv("LANGCHAIN_PROJECT", ""),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(
            "LangSmith tracing is required for scans and UI runs. Missing: %s"
            % ", ".join(sorted(missing))
        )


def validate_run_config(config: RunConfig) -> List[str]:
    """
    Validate configuration before running scan.
    Returns list of error messages (empty if valid).
    """
    errors = []

    # HAR file validation
    har_path = Path(config.har_path)
    if not har_path.exists():
        errors.append("HAR file not found: %s" % config.har_path)
    elif not config.har_path.endswith('.har'):
        errors.append("Expected .har file, got: %s" % config.har_path)

    # Domain validation
    if not config.target_domains:
        errors.append("No target domains specified")

    # Parameter validation
    if config.per_endpoint_hypothesis_cap <= 0:
        errors.append("per_endpoint_hypothesis_cap must be > 0")
    elif config.per_endpoint_hypothesis_cap > 100:
        errors.append("WARNING: per_endpoint_hypothesis_cap is very high (>100), may use excessive quota")

    if config.global_request_cap <= 0:
        errors.append("global_request_cap must be > 0")
    elif config.global_request_cap > 1000:
        errors.append("WARNING: global_request_cap is very high (>1000), may use excessive quota")

    if config.inter_request_delay_ms < 0:
        errors.append("inter_request_delay_ms cannot be negative")
    elif config.inter_request_delay_ms < 100:
        errors.append("WARNING: inter_request_delay_ms is very low (<100ms), may trigger rate limits")

    # LLM validation
    if config.provider != "builtin":
        if not config.llm_api_key:
            errors.append("API key required for provider '%s'" % config.provider)
        if not config.model:
            errors.append("Model must be specified for external LLM")

    # Timeout validation
    if config.llm_timeout_seconds <= 0:
        errors.append("llm_timeout_seconds must be > 0")
    if config.request_timeout_seconds <= 0:
        errors.append("request_timeout_seconds must be > 0")

    # Artifact directory validation
    artifact_path = Path(config.artifact_dir)
    try:
        artifact_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        errors.append("Cannot create artifact directory: %s" % e)

    return errors


autoload_env()
