from __future__ import annotations

import base64
import hashlib
import json as _json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import RunConfig, TokenInjectionRule


PROVIDER_PRESETS: Dict[str, Dict[str, str]] = {
    "deepinfra": {
        "label": "DeepInfra",
        "base_url": "https://api.deepinfra.com/v1/openai",
        "description": "Budget-friendly hosted inference. Recommended.",
    },
    "openai": {
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "description": "GPT-4o, GPT-4o-mini, and more.",
    },
    "anthropic": {
        "label": "Anthropic (Claude)",
        "base_url": "https://api.anthropic.com/v1",
        "description": "Claude Sonnet, Haiku, Opus via OpenAI-compatible proxy.",
    },
    "custom": {
        "label": "Custom (OpenAI-compatible)",
        "base_url": "",
        "description": "Any OpenAI-compatible API endpoint.",
    },
}


# ---------------------------------------------------------------------------
# Encrypted API key storage
# ---------------------------------------------------------------------------

_KEYS_DIR = Path.home() / ".har-analyzer"
_KEYS_FILE = _KEYS_DIR / "keys.json"


def _get_cipher_key() -> bytes:
    """Derive a machine-specific key from hostname + username."""
    import getpass
    import socket
    seed = (socket.gethostname() + "-" + getpass.getuser() + "-har-analyzer").encode()
    return hashlib.sha256(seed).digest()


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encrypt_api_key(plain: str) -> str:
    """XOR + base64 encode an API key."""
    if not plain:
        return ""
    encrypted = _xor_bytes(plain.encode("utf-8"), _get_cipher_key())
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_api_key(encrypted: str) -> str:
    """Reverse of encrypt_api_key."""
    if not encrypted:
        return ""
    try:
        raw = base64.b64decode(encrypted.encode("ascii"))
        return _xor_bytes(raw, _get_cipher_key()).decode("utf-8")
    except Exception:
        return ""


def save_api_key(provider: str, key: str) -> None:
    """Save an encrypted API key for a provider."""
    _KEYS_DIR.mkdir(parents=True, exist_ok=True)
    existing = {}
    if _KEYS_FILE.exists():
        try:
            existing = _json.loads(_KEYS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing[provider] = encrypt_api_key(key)
    _KEYS_FILE.write_text(_json.dumps(existing, indent=2), encoding="utf-8")


def load_api_key(provider: str) -> str:
    """Load a saved API key for a provider (decrypted)."""
    if not _KEYS_FILE.exists():
        return ""
    try:
        data = _json.loads(_KEYS_FILE.read_text(encoding="utf-8"))
        return decrypt_api_key(data.get(provider, ""))
    except Exception:
        return ""


def has_saved_key(provider: str) -> bool:
    """Check if a saved key exists for this provider."""
    return bool(load_api_key(provider))


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


def _build_token_injection_rules() -> List[TokenInjectionRule]:
    """
    Build token injection rules from environment variables.

    Supported environment variables:
    - HAR_ANALYZER_AUTH_TOKEN: Fresh authorization token to inject
      (applies to all requests with Authorization header)
    """
    rules = []

    # Check for primary auth token
    auth_token = os.getenv("HAR_ANALYZER_AUTH_TOKEN", "").strip()
    if auth_token:
        rules.append(
            TokenInjectionRule(
                header_name="Authorization",
                token_value=auth_token,
                applies_to_endpoints=[],  # Empty = applies to all
            )
        )

    return rules


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
    if provider in ("builtin", ""):
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
    api_key: str = "",
    step_mode: bool = False,
    hypotheses_only: bool = False,
) -> RunConfig:
    artifact_root = artifact_dir or os.getenv("HAR_ANALYZER_ARTIFACT_DIR", "artifacts")
    domains = [item.strip() for item in target_domains if item and item.strip()]

    # Build token injection rules from environment
    token_injection_rules = _build_token_injection_rules()

    # API key priority: explicit > saved > env var
    resolved_provider = provider or os.getenv("HAR_ANALYZER_LLM_PROVIDER", "deepinfra")
    resolved_key = api_key or load_api_key(resolved_provider) or os.getenv("HAR_ANALYZER_LLM_API_KEY", "")

    return RunConfig(
        har_path=har_path,
        target_domains=domains,
        provider=resolved_provider,
        model=model or os.getenv("HAR_ANALYZER_MODEL", ""),
        validation_model=os.getenv("HAR_ANALYZER_VALIDATION_MODEL", ""),
        concurrency=int(os.getenv("HAR_ANALYZER_CONCURRENCY", "4")),
        per_endpoint_hypothesis_cap=int(os.getenv("HAR_ANALYZER_ENDPOINT_CAP", "10")),
        global_request_cap=int(os.getenv("HAR_ANALYZER_GLOBAL_CAP", "100")),
        inter_request_delay_ms=int(os.getenv("HAR_ANALYZER_INTER_REQUEST_DELAY_MS", "500")),
        excluded_path_patterns=_split_csv(os.getenv("HAR_ANALYZER_EXCLUDED_PATH_PATTERNS", "")),
        allow_unsafe_artifacts=get_default_unsafe_unredacted() if allow_unsafe_artifacts is None else allow_unsafe_artifacts,
        artifact_dir=artifact_root,
        database_path=os.getenv("HAR_ANALYZER_DB_PATH", os.path.join(artifact_root, "runs.sqlite3")),
        llm_base_url=resolve_provider_base_url(resolved_provider, llm_base_url),
        llm_api_key=resolved_key,
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
        hypotheses_only=hypotheses_only,
        redact_by_default=_env_bool("HAR_ANALYZER_REDACT_BY_DEFAULT", False),
        token_injection_rules=token_injection_rules,
    )


def disable_langsmith_if_unconfigured() -> None:
    """Disable LangSmith tracing when credentials are not set, so langgraph
    doesn't attempt (and fail) to phone home."""
    if not os.getenv("LANGCHAIN_API_KEY"):
        os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")


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

    # Token injection validation
    from .token_injection import validate_token_injection_rules
    token_errors = validate_token_injection_rules(config.token_injection_rules)
    errors.extend(token_errors)

    return errors


autoload_env()
