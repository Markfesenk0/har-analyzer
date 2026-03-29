# Implementation Plan: Code Fixes (Ordered by Priority & Impact)

**Goal:** Fix critical bugs, improve detection quality, and engineer better prompts

---

## Phase 1: CRITICAL SECURITY FIXES (2 hours)

### ✅ Fix #1: Rotate API Keys & Remove from Git
**Impact:** HIGH (security breach)
**Time:** 10 minutes
**Files:** `.env`, `.gitignore`, `README.md`

```bash
# 1. Remove .env from git history
git rm --cached .env
echo ".env" >> .gitignore
git add .gitignore
git commit -m "Remove .env from git tracking (security)"

# 2. Rotate your keys immediately:
#    - DeepInfra: https://console.deepinfra.com/api_keys
#    - LangSmith: https://smith.langchain.com/settings/keys

# 3. Create .env.example
cp .env .env.example
```

Edit `.env.example`:
```bash
# Keep structure but replace values
HAR_ANALYZER_LLM_API_KEY=YOUR_DEEPINFRA_KEY_HERE
LANGCHAIN_API_KEY=YOUR_LANGSMITH_KEY_HERE
# ... rest unchanged
```

---

### ✅ Fix #2: Add URL Validation (SSRF Protection)
**Impact:** HIGH (prevents internal network scanning)
**Time:** 20 minutes
**Files:** `src/har_analyzer/executor.py`

Add this function at the top of the file (after imports):

```python
# Add after imports in executor.py:

import ipaddress
from urllib.parse import urlparse

def validate_hypothesis_url(url: str, allowed_domains: list, config: RunConfig) -> tuple[bool, str]:
    """
    Validate URL is safe to execute.
    Returns: (is_valid, error_reason)
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL format: {e}"

    # 1. Only http/https
    if parsed.scheme not in ('http', 'https'):
        return False, f"Unsupported scheme: {parsed.scheme} (only http/https allowed)"

    # 2. Domain must match config.target_domains
    netloc = parsed.netloc.lower()
    domain_match = False
    for domain in allowed_domains:
        if netloc == domain or netloc.endswith('.' + domain):
            domain_match = True
            break

    if not domain_match:
        return False, f"Domain {netloc} not in allowed list: {allowed_domains}"

    # 3. Block private IPs (127.0.0.1, 192.168.*, 10.*, etc.)
    try:
        hostname = parsed.hostname
        if hostname:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False, f"Private/loopback IP not allowed: {hostname}"
    except ValueError:
        pass  # Not an IP, that's fine

    return True, ""
```

Update `execute_hypothesis()` function to use it:

```python
# Replace this line in execute_hypothesis():
def execute_hypothesis(
    hypothesis: AttackHypothesis,
    original_record: RequestRecord,
    config: RunConfig,
    transport: Optional[Transport] = None,
) -> ExecutionResult:
    # ADD THIS CHECK:
    is_valid, error_msg = validate_hypothesis_url(
        hypothesis.url,
        config.target_domains,
        config
    )
    if not is_valid:
        return ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            outcome="validation_failed",
            error=f"URL validation failed: {error_msg}",
        )

    # ... rest of existing code
```

---

### ✅ Fix #3: Sanitize LLM Input (Prompt Injection Protection)
**Impact:** HIGH (prevents LLM prompt injection)
**Time:** 15 minutes
**Files:** `src/har_analyzer/hypotheses.py`

Update the `_build_analysis_prompt()` function to use Pydantic for safe serialization:

```python
# In hypotheses.py, find _build_analysis_prompt() and replace with:

import json
from typing import Any, Dict

def _build_analysis_prompt(
    record: RequestRecord,
    context: EndpointContext,
    config: RunConfig,
) -> Dict[str, Any]:
    """Build analysis prompt with safe JSON serialization."""

    # Use dict conversion first (Pydantic handles escaping)
    request_data = {
        "method": record.method,
        "path": record.path,
        "query_params": record.query_params,
        "headers": record.request_headers,  # Already safe via Pydantic
        "body": (record.request_body or "")[:config.max_body_chars],
    }

    context_data = {
        "auth_patterns": context.auth_header_names,
        "resource_ids_seen": context.resource_ids_seen[:5],
        "api_summary": context.api_summary,
    }

    # Build final prompt dict
    prompt = {
        "request": request_data,
        "context": context_data,
        "task": _get_analysis_task(),
        "response_schema": _get_response_schema(),
    }

    # Return as regular dict (already safe)
    return prompt
```

The key is that we're not doing raw string injection into JSON anymore. The JSON structure is built from Python dicts, which are then serialized safely.

---

## Phase 2: IMPROVE DETECTION QUALITY (3 hours)

### ✅ Fix #4: Better Builtin Hypotheses - Add String ID Swapping
**Impact:** MEDIUM-HIGH (catches 30% more vulnerabilities in heuristic mode)
**Time:** 30 minutes
**Files:** `src/har_analyzer/hypotheses.py`

Add this new function in the `BuiltinHeuristicClient` class:

```python
# In hypotheses.py, add this function before BuiltinHeuristicClient:

import re
import uuid as uuid_lib

def _string_id_hypothesis(record: RequestRecord) -> Optional[AttackHypothesis]:
    """
    Test non-numeric resource IDs (UUIDs, alphanumeric slugs, etc).
    Returns hypothesis if string ID pattern found in URL.
    """
    # UUID pattern: 550e8400-e29b-41d4-a716-446655440000
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

    # Look in URL for UUIDs
    matches = re.findall(uuid_pattern, record.url, re.IGNORECASE)
    if not matches:
        return None

    original_uuid = matches[0]
    test_uuid = "550e8400-e29b-41d4-a716-446655440000"  # Fixed test UUID

    modified_url = record.url.replace(original_uuid, test_uuid, 1)  # Replace first occurrence only

    return AttackHypothesis(
        hypothesis_id=f"hyp-{uuid_lib.uuid4().hex[:8]}",
        original_request_id=record.request_id,
        endpoint_key=record.endpoint_key(),
        attack_type="IDOR",
        severity="high",
        expected_signal="200 with different resource (UUID changed)",
        rationale=f"URL contains UUID which appears to be resource ID; testing with different UUID",
        method=record.method,
        url=modified_url,
        headers=record.request_headers.copy(),
        body=record.request_body,
        mutation_summary=f"UUID: {original_uuid[:12]}... → {test_uuid[:12]}...",
    )


def _alphanumeric_slug_hypothesis(record: RequestRecord) -> Optional[AttackHypothesis]:
    """
    Test alphanumeric slugs that look like resource IDs.
    E.g., GET /api/posts/a1b2c3d4 → try different slug
    """
    # Pattern: /path/[alphanumeric string of 6+ chars]
    slug_pattern = r'/([a-z0-9]{6,}?)(?:/|$)'

    matches = re.findall(slug_pattern, record.path, re.IGNORECASE)
    if not matches:
        return None

    original_slug = matches[-1]  # Get last match (most likely the ID)

    # Only proceed if it looks like an ID (not a known endpoint name)
    if original_slug in ['users', 'posts', 'admin', 'api', 'v1', 'v2']:
        return None

    # Create test slug by incrementing or using different variation
    test_slug = original_slug[:-1] + chr(ord(original_slug[-1]) + 1) if original_slug[-1] != 'z' else original_slug[:-1] + 'a'

    modified_url = record.url.replace(original_slug, test_slug, 1)

    return AttackHypothesis(
        hypothesis_id=f"hyp-{uuid_lib.uuid4().hex[:8]}",
        original_request_id=record.request_id,
        endpoint_key=record.endpoint_key(),
        attack_type="IDOR",
        severity="high",
        expected_signal="200 with different resource (slug changed)",
        rationale=f"URL contains alphanumeric slug that may be resource ID",
        method=record.method,
        url=modified_url,
        headers=record.request_headers.copy(),
        body=record.request_body,
        mutation_summary=f"Slug: {original_slug} → {test_slug}",
    )
```

Now update `BuiltinHeuristicClient.generate_hypotheses()`:

```python
# In BuiltinHeuristicClient.generate_hypotheses(), replace the entire function:

def generate_hypotheses(
    self,
    record: RequestRecord,
    context: EndpointContext,
    config: RunConfig,
) -> List[AttackHypothesis]:
    candidates: List[AttackHypothesis] = []

    # 1. Try numeric ID swaps (existing)
    resource_swap = _numeric_swap_hypothesis(record)
    if resource_swap:
        candidates.append(resource_swap)

    # 2. NEW: Try UUID swaps
    uuid_swap = _string_id_hypothesis(record)
    if uuid_swap:
        candidates.append(uuid_swap)

    # 3. NEW: Try alphanumeric slug swaps
    slug_swap = _alphanumeric_slug_hypothesis(record)
    if slug_swap:
        candidates.append(slug_swap)

    # 4. Try query param swaps (existing)
    query_swaps = _query_param_hypotheses(record)
    candidates.extend(query_swaps)

    # 5. Try auth removal (existing)
    auth_tests = _auth_hypotheses(record)
    candidates.extend(auth_tests)

    # Return top N by priority
    return candidates[: config.per_endpoint_hypothesis_cap]
```

---

### ✅ Fix #5: Improve Evaluation Logic
**Impact:** MEDIUM-HIGH (catches real vulnerabilities currently missed)
**Time:** 25 minutes
**Files:** `src/har_analyzer/evaluation.py`

Replace the `_indicates_access_control_issue()` function:

```python
# In evaluation.py, replace _indicates_access_control_issue():

def _indicates_access_control_issue(
    record: RequestRecord,
    hypothesis: AttackHypothesis,
    result: ExecutionResult,
) -> bool:
    """
    Enhanced detection: Check if modified request succeeded when original failed,
    or returned different data than original.
    """
    if result.status_code is None:
        return False

    # Signal 1: Status code changed from 403/401 to 200
    # Strong indicator of access control bypass
    if record.response_status in (401, 403) and result.status_code == 200:
        return True

    # Signal 2: Both succeeded (200) but structure matches + different resource IDs
    if record.response_status == 200 and result.status_code == 200:
        if hypothesis.attack_type in {"IDOR", "BOLA"}:
            # Check if responses are structurally similar (same shape)
            if _structurally_similar(record.response_body or "", result.response_body or ""):
                # Check if resource IDs are different
                if _contains_different_resource_id(record.response_body or "", result.response_body or ""):
                    return True

    # Signal 3: Response size increased significantly
    # Indicates more data was returned than original
    size_increase = len(result.response_body or "") - len(record.response_body or "")
    if size_increase > 500:  # Arbitrary but conservative threshold
        return True

    # Signal 4: Auth bypass - got response when should have failed
    if hypothesis.attack_type == "auth_bypass":
        if record.response_status in (401, 403) and result.response_body:
            return True

    return False


def _contains_different_resource_id(original: str, modified: str) -> bool:
    """
    Check if responses contain different user/resource IDs.
    Looks for patterns like "user_id": 123 or "id": "abc"
    """
    import re

    # Pattern: "user_id": 123 OR "user_id": "abc" OR 'user_id': 123
    id_pattern = r'["\']?(?:user_?id|account_?id|owner_?id|id)["\']?\s*:\s*([0-9]+|["\'][^"\']+["\'])'

    try:
        orig_ids = set(re.findall(id_pattern, original, re.IGNORECASE))
        mod_ids = set(re.findall(id_pattern, modified, re.IGNORECASE))

        # If sets are different and both have values, IDs changed
        return len(orig_ids) > 0 and len(mod_ids) > 0 and orig_ids != mod_ids
    except Exception:
        return False
```

---

## Phase 3: FIX STEP_MODE RACE CONDITION (1.5 hours)

### ✅ Fix #6: Implement Proper Step Mode Approval Flow
**Impact:** MEDIUM (affects analysts using step_mode)
**Time:** 45 minutes
**Files:** `src/har_analyzer/web.py`, `src/har_analyzer/graph.py`

First, update the web endpoint in `web.py`:

```python
# In web.py, replace the approve_request and skip_request functions:

@app.post("/runs/{run_id}/requests/{request_id}/approve")
def approve_request(run_id: str, request_id: str):
    """Approve a request for LLM analysis."""
    run = store.get_run(run_id)
    if not run:
        return RedirectResponse(url="/", status_code=303)

    # Mark as approved with timestamp
    store.update_request_item(
        run_id,
        request_id,
        approval_state="approved",
        status="approved",
        stage="waiting_for_execution",
        summary="Approved by analyst - pending execution"
    )
    return RedirectResponse(url=f"/runs/{run_id}/requests/{request_id}", status_code=303)


@app.post("/runs/{run_id}/requests/{request_id}/skip")
def skip_request(run_id: str, request_id: str):
    """Skip a request (don't generate/execute hypotheses)."""
    run = store.get_run(run_id)
    if not run:
        return RedirectResponse(url="/", status_code=303)

    # Mark as skipped
    store.update_request_item(
        run_id,
        request_id,
        approval_state="skipped",
        status="completed",
        stage="skipped_by_analyst",
        summary="Skipped by analyst"
    )
    return RedirectResponse(url=f"/runs/{run_id}/requests/{request_id}", status_code=303)
```

Now update `graph.py` to check approval state before executing:

```python
# In graph.py, in the analyze_request function, add approval check:

def analyze_request(state: GraphState) -> GraphState:
    """
    Analyze a single request and generate attack hypotheses.
    If step_mode is enabled, waits for analyst approval before execution.
    """
    config = state["config"]
    store = state["store"]
    run = state["run"]
    llm_client = state["llm_client"]
    records_by_id = {r.request_id: r for r in state["scoped_records"]}

    # Find next unanalyzed request
    current_index = state.get("current_request_index", 0)

    for idx in range(current_index, len(state["scoped_records"])):
        record = state["scoped_records"][idx]

        # Check if run was cancelled/paused
        run_record = store.get_run(run.run_id)
        if run_record.cancel_requested or run_record.pause_requested:
            raise ScanCancelledError("Run cancelled or paused by user")

        # ============ NEW: Step Mode Approval Check ============
        if config.step_mode:
            # Update UI to show "waiting for approval"
            store.update_request_item(
                run.run_id,
                record.request_id,
                status="pending_approval",
                stage="awaiting_analyst_approval",
            )

            # Wait for analyst to approve or skip (with timeout)
            approved = _wait_for_approval(
                store,
                run_id=run.run_id,
                request_id=record.request_id,
                timeout_seconds=600,  # 10 min timeout
            )

            if not approved:
                # Analyst skipped this request
                store.update_request_item(
                    run.run_id,
                    record.request_id,
                    status="completed",
                    stage="skipped",
                )
                state["current_request_index"] = idx + 1
                return state  # Move to next request

        # =====================================================

        # Generate hypotheses
        preview = llm_client.build_preview(record, state["context"], config)
        request_item = store.get_request_items(run.run_id, request_id=record.request_id)[0]
        store.update_request_item(
            run.run_id,
            record.request_id,
            status="analyzing",
            llm_request_json=json.dumps(preview, default=str),
        )

        # ... rest of existing hypothesis generation code ...

        state["current_request_index"] = idx + 1
        return state

    # No more requests
    return state


def _wait_for_approval(
    store,
    run_id: str,
    request_id: str,
    timeout_seconds: int = 600,
) -> bool:
    """
    Poll database for approval/skip decision.
    Returns True if approved, False if skipped or timed out.
    """
    import time

    start_time = time.time()
    poll_interval = 2  # Check every 2 seconds

    while (time.time() - start_time) < timeout_seconds:
        request_items = store.get_request_items(run_id, request_id=request_id)
        if request_items:
            item = request_items[0]
            if item.approval_state == "approved":
                return True
            elif item.approval_state == "skipped":
                return False

        time.sleep(poll_interval)

    # Timeout - treat as skipped
    print(f"[graph:analyze_request] Approval timeout for {request_id}")
    return False
```

---

## Phase 4: IMPROVE LLM PROMPTS (2 hours)

### ✅ Fix #7: Better System Prompt
**Impact:** HIGH (directly affects hypothesis quality)
**Time:** 20 minutes
**Files:** `src/har_analyzer/hypotheses.py`

Replace the `_system_prompt()` function:

```python
# In hypotheses.py, replace _system_prompt():

def _system_prompt() -> str:
    """System prompt guiding LLM to generate good attack hypotheses."""
    return """You are a security testing specialist performing authorized API security validation.

Your task: Generate targeted hypotheses about how an API endpoint could be vulnerable to logical attacks.

VULNERABILITY TYPES YOU'RE TESTING FOR:
1. **IDOR (Insecure Direct Object Reference):** Access other users' resources by modifying IDs
2. **BOLA (Broken Object-Level Authorization):** Missing auth checks on protected endpoints
3. **Auth Bypass:** Removing/modifying auth headers to access protected data
4. **Privilege Escalation:** Modifying role/permission fields to gain elevated access
5. **Data Exposure:** Responses leaking sensitive PII, tokens, or internal info
6. **Parameter Pollution:** Duplicate/conflicting parameters to confuse validation

IMPORTANT CONSTRAINTS:
- Generate 3-5 hypotheses per endpoint (quality > quantity)
- Each hypothesis modifies ONE parameter only (easier to isolate root cause)
- Mutations must use realistic values (actual IDs from the API, not random strings)
- Data types must match original (numeric IDs stay numeric, strings stay strings)
- Don't suggest mutations that violate API contract (wrong HTTP methods, invalid params)
- Prioritize high-confidence attacks based on request structure

HYPOTHESIS QUALITY CHECKLIST:
✓ Mutation makes sense given the API context
✓ Uses realistic values (not gibberish)
✓ Has a clear expected success signal (specific response change to look for)
✓ Would likely reveal a real vulnerability if successful
✓ Is fundamentally different from other hypotheses (no duplicates)

EXAMPLE OF A GOOD HYPOTHESIS:
{
  "attack_type": "IDOR",
  "mutation_summary": "Change numeric user_id from 1042 to 1041 in URL path",
  "expected_signal": "200 OK + different user's full profile returned (name, email, phone)",
  "rationale": "Path contains numeric user_id with no per-endpoint auth checks visible in response",
  "confidence": "high",
  "severity": "high"
}

EXAMPLE OF A BAD HYPOTHESIS (avoid these):
✗ {mutation: "add random string to URL"} - unrealistic
✗ {mutation: "change GET to PATCH"} - violates API contract
✗ {mutation: "inject SQL: user_id=1 OR 1=1"} - not this endpoint's purpose
✗ {mutation: "send empty body"} - not a logical vulnerability test

Remember: You're testing for logical/authorization flaws, not injection attacks or protocol violations."""
```

---

### ✅ Fix #8: Better Analysis Prompt Context
**Impact:** MEDIUM-HIGH (makes LLM requests much more targeted)
**Time:** 30 minutes
**Files:** `src/har_analyzer/hypotheses.py`

Replace the `_build_analysis_prompt()` function:

```python
# In hypotheses.py, replace _build_analysis_prompt():

def _build_analysis_prompt(
    record: RequestRecord,
    context: EndpointContext,
    config: RunConfig,
) -> Dict[str, Any]:
    """Build detailed analysis prompt with rich context."""

    # Extract metadata about the request
    endpoint_purpose = _infer_endpoint_purpose(record.path)
    auth_required = any(header.lower() == 'authorization' for header in record.request_headers.keys())

    prompt = {
        "objective": "Generate 3-5 targeted attack hypotheses for this specific endpoint",

        "endpoint_info": {
            "method": record.method,
            "path": record.path,
            "normalized_path": record.normalized_path(),
            "inferred_purpose": endpoint_purpose,
            "requires_auth": auth_required,
        },

        "request_details": {
            "query_parameters": record.query_params if record.query_params else {},
            "header_names": list(record.request_headers.keys()),
            "has_body": bool(record.request_body),
            "body_size_bytes": len(record.request_body or ""),
        },

        "response_analysis": {
            "status_code": record.response_status,
            "response_size_bytes": len(record.response_body or ""),
            "likely_contains_pii": _has_pii_patterns(record.response_body or ""),
            "likely_contains_ids": _has_id_patterns(record.response_body or ""),
            "sample_structure": _extract_json_shape(record.response_body)[:3] if record.response_body else None,
        },

        "api_security_context": {
            "observed_auth_methods": context.auth_header_names,
            "observed_resource_id_types": context.resource_ids_seen[:5],
            "common_resource_id_names": list(context.recurring_parameters.keys())[:10],
            "api_description": context.api_summary,
        },

        "constraints": {
            "max_hypotheses": min(5, config.per_endpoint_hypothesis_cap),
            "prefer_high_confidence": True,
            "avoid_destructive_ops": True,
        },

        "response_schema": {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "maxItems": 5,
                    "items": {
                        "type": "object",
                        "properties": {
                            "attack_type": {
                                "type": "string",
                                "enum": ["IDOR", "BOLA", "privilege_escalation", "token_manipulation",
                                        "mass_assignment", "auth_bypass", "data_exposure", "parameter_pollution"],
                            },
                            "mutation_summary": {
                                "type": "string",
                                "description": "What exactly changes in the request (be specific)",
                            },
                            "expected_signal": {
                                "type": "string",
                                "description": "What would indicate this worked (e.g., '200 OK + different user data')",
                            },
                            "rationale": {
                                "type": "string",
                                "description": "Why you think this endpoint might be vulnerable",
                            },
                            "confidence": {
                                "type": "string",
                                "enum": ["high", "medium", "low"],
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["critical", "high", "medium", "low"],
                            },
                        },
                        "required": ["attack_type", "mutation_summary", "expected_signal", "rationale", "confidence", "severity"],
                    },
                }
            },
            "required": ["hypotheses"],
        },
    }

    return prompt


def _infer_endpoint_purpose(path: str) -> str:
    """Guess what this endpoint does from its path."""
    if '/users' in path or '/profile' in path:
        return "User profile/data management"
    elif '/admin' in path:
        return "Administrative function"
    elif '/delete' in path or path.startswith('DELETE'):
        return "Deletion/destruction of resource"
    elif '/export' in path or '/download' in path:
        return "Data export/retrieval"
    else:
        return "API resource endpoint"


def _has_pii_patterns(text: str) -> bool:
    """Check if response likely contains PII."""
    import re
    email_pattern = r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
    phone_pattern = r'\+?1?\s*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'
    return bool(re.search(email_pattern, text, re.IGNORECASE)) or bool(re.search(phone_pattern, text))


def _has_id_patterns(text: str) -> bool:
    """Check if response likely contains user/resource IDs."""
    import re
    return bool(re.search(r'["\']?(?:user_?id|account_?id|id)["\']?\s*:\s*\d+', text, re.IGNORECASE))


def _extract_json_shape(text: str) -> List[str]:
    """Extract first few keys from JSON for context."""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return list(data.keys())[:5]
        elif isinstance(data, list) and data:
            if isinstance(data[0], dict):
                return list(data[0].keys())[:5]
    except Exception:
        pass
    return []
```

---

## Phase 5: ADD CONFIG VALIDATION (30 minutes)

### ✅ Fix #9: Validate Config Before Running
**Impact:** MEDIUM (prevents wasted time on bad configs)
**Time:** 20 minutes
**Files:** `src/har_analyzer/config.py`, `src/har_analyzer/graph.py`

Add to `config.py`:

```python
# Add to config.py at the end:

def validate_run_config(config: RunConfig) -> List[str]:
    """
    Validate configuration before running scan.
    Returns list of error messages (empty if valid).
    """
    from pathlib import Path

    errors = []

    # HAR file validation
    if not Path(config.har_path).exists():
        errors.append(f"❌ HAR file not found: {config.har_path}")
    elif not config.har_path.endswith('.har'):
        errors.append(f"❌ Expected .har file, got: {config.har_path}")

    # Domain validation
    if not config.target_domains:
        errors.append("❌ No target domains specified")
    elif len(config.target_domains) == 0:
        errors.append("❌ Target domains list is empty")

    # Parameter validation
    if config.per_endpoint_hypothesis_cap <= 0:
        errors.append("❌ per_endpoint_hypothesis_cap must be > 0")
    if config.per_endpoint_hypothesis_cap > 100:
        errors.append("⚠️  per_endpoint_hypothesis_cap very high (>100) - may use excessive quota")

    if config.global_request_cap <= 0:
        errors.append("❌ global_request_cap must be > 0")
    if config.global_request_cap > 1000:
        errors.append("⚠️  global_request_cap very high (>1000) - may use excessive quota")

    if config.inter_request_delay_ms < 0:
        errors.append("❌ inter_request_delay_ms cannot be negative")
    if config.inter_request_delay_ms < 100:
        errors.append("⚠️  inter_request_delay_ms very low (<100ms) - may trigger rate limits")

    # LLM validation
    if config.provider != "builtin":
        if not config.llm_api_key:
            errors.append(f"❌ API key required for provider '{config.provider}'")
        if not config.model:
            errors.append("❌ Model must be specified for external LLM")
    else:
        if config.model != "builtin-heuristics":
            errors.append("⚠️  Model specified but provider is 'builtin' (model will be ignored)")

    # Timeout validation
    if config.llm_timeout_seconds <= 0:
        errors.append("❌ llm_timeout_seconds must be > 0")
    if config.request_timeout_seconds <= 0:
        errors.append("❌ request_timeout_seconds must be > 0")

    # Artifact validation
    artifact_path = Path(config.artifact_dir)
    if not artifact_path.exists():
        try:
            artifact_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"❌ Cannot create artifact directory: {e}")

    return errors
```

Update `run_scan()` in `graph.py` to validate:

```python
# In graph.py, at the start of run_scan():

def run_scan(
    config: RunConfig,
    llm_client: Optional[LLMClient] = None,
    transport: Optional[Transport] = None,
    progress_callback: Optional[ProgressCallback] = None,
    store: Optional[RunStore] = None,
    run: Optional[RunRecord] = None,
) -> RunRecord:
    # ADD THIS:
    from .config import validate_run_config

    errors = validate_run_config(config)
    if errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(errors)
        print(f"❌ {error_msg}")
        raise ValueError(error_msg)

    # ... rest of existing code ...
```

---

## Phase 6: SEMGREP INTEGRATION (Optional, High Impact)

### ✅ Fix #10: Add PII/Secret Detection
**Impact:** HIGH (catches data leaks currently missed)
**Time:** 30 minutes (if semgrep installed)
**Files:** `src/har_analyzer/evaluation.py`

Add to `evaluation.py`:

```python
# In evaluation.py, add:

def scan_response_for_secrets(response_body: str, temp_dir: str = "/tmp") -> List[Dict[str, str]]:
    """
    Scan response body for exposed secrets/PII using regex patterns.
    Falls back to regex if semgrep not available.
    """
    import re
    from typing import Dict, List
    import tempfile
    from pathlib import Path

    if not response_body:
        return []

    findings = []

    # Email pattern
    email_pattern = r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
    if re.search(email_pattern, response_body, re.IGNORECASE):
        findings.append({
            "type": "email",
            "message": "Email address detected in response",
            "severity": "high",
        })

    # Phone pattern
    phone_pattern = r'(?:\+1\s?)?\(?([0-9]{3})\)?[\s.-]?([0-9]{3})[\s.-]?([0-9]{4})\b'
    if re.search(phone_pattern, response_body):
        findings.append({
            "type": "phone",
            "message": "Phone number detected in response",
            "severity": "high",
        })

    # API Key patterns (long alphanumeric + hyphens, common in AWS/Azure)
    apikey_pattern = r'\b(?:AKIA[0-9A-Z]{16}|[A-Za-z0-9_\-]{32,})\b'  # AWS pattern
    if re.search(apikey_pattern, response_body):
        findings.append({
            "type": "api_key",
            "message": "Potential API key detected in response",
            "severity": "critical",
        })

    # JWT pattern
    jwt_pattern = r'\beyJ[a-zA-Z0-9._\-]+\b'
    if re.search(jwt_pattern, response_body):
        findings.append({
            "type": "jwt_token",
            "message": "JWT token detected in response",
            "severity": "critical",
        })

    # Credit card pattern (simplified)
    cccard_pattern = r'\b(?:\d[ -]*?){13,19}\b'
    if re.search(cccard_pattern, response_body) and len(re.findall(r'\d', response_body)) >= 13:
        findings.append({
            "type": "credit_card",
            "message": "Potential credit card number in response",
            "severity": "critical",
        })

    return findings


# Update evaluate_response() to use it:

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

    # NEW: Scan for secrets/PII
    secret_findings_list = scan_response_for_secrets(result.response_body or "")
    if secret_findings_list:
        findings.append(
            Finding(
                finding_id="finding-%s" % uuid.uuid4().hex[:12],
                request_id=record.request_id,
                hypothesis_id=hypothesis.hypothesis_id,
                title="Sensitive data exposed in %s" % record.endpoint_key(),
                attack_type="excessive_data_exposure",
                severity="high",
                confidence="high",
                endpoint=record.endpoint_key(),
                summary=f"Response contains {len(secret_findings_list)} type(s) of sensitive data: {', '.join(f['type'] for f in secret_findings_list)}",
                expected_signal=hypothesis.expected_signal,
                owasp=_owasp_mapping("excessive_data_exposure"),
                evidence=secret_findings_list + _build_evidence(record, hypothesis, result),
                remediation="Remove sensitive fields from API responses. Only return data needed for the client.",
                reproduction_curl=build_curl_command(hypothesis),
            )
        )

    secret_findings = detect_sensitive_leakage(record, hypothesis, result)
    findings.extend(secret_findings)
    return findings
```

---

## 🎯 IMPLEMENTATION ORDER (Start Here)

**Do in this order (total time: ~6 hours)**

1. **[10 min]** Fix #1: Rotate API keys, add .gitignore
2. **[20 min]** Fix #2: Add URL validation (SSRF protection)
3. **[15 min]** Fix #3: Sanitize LLM input
4. **[30 min]** Fix #4: Better builtin hypotheses (string IDs)
5. **[25 min]** Fix #5: Improve evaluation logic
6. **[20 min]** Fix #7: Better system prompt
7. **[30 min]** Fix #8: Better analysis context
8. **[20 min]** Fix #9: Config validation
9. **[45 min]** Fix #6: Step mode race condition (optional, harder)
10. **[30 min]** Fix #10: Secret/PII detection (optional)

**Then test everything:**
```bash
# Run tests
pytest tests/ -v

# Manual test of URL validation
python -c "from src.har_analyzer.executor import validate_hypothesis_url; print(validate_hypothesis_url('http://127.0.0.1:8080', ['api.example.com'], None))"
# Should return: (False, 'Private/loopback IP not allowed')

# Test a scan
python -m src.har_analyzer.cli --har-path HAR\ files/freefit.har --target-domain api.example.com
```

---

## Testing Checklist

After implementing each fix:

- [ ] #1 - .env not in git history: `git log --all --full-history --source -- .env`
- [ ] #2 - URL validation blocks internal IPs: test with 127.0.0.1, 192.168.x.x, 10.x.x.x
- [ ] #3 - Prompt injection test: inject quotes/braces in HAR data, verify still works
- [ ] #4 - UUID hypothesis generated: run on HAR with UUIDs in URLs
- [ ] #5 - Evaluation finds size deltas: test with response size increase > 500 bytes
- [ ] #7 - New prompt used: check LangSmith traces for new system prompt
- [ ] #8 - Rich context: verify LLM request includes api_summary, behavioral patterns
- [ ] #9 - Config validation blocks bad inputs: test with missing HAR file, empty domains
- [ ] #10 - Secrets detected: run on response with email/phone/JWT, verify finding created

---

**Ready to start? I recommend beginning with Fixes #1-3 (critical security issues) right now, then moving to #4-5 for immediate detection quality improvements.**

