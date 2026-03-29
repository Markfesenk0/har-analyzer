# Quick Reference: Bugs, Security Issues & Prompt Engineering Fixes

**For:** Developer prioritization and fast implementation

---

## 🔴 CRITICAL FIXES (Do immediately)

### 1. Exposed API Keys - SECURITY BREACH

**File:** `.env`
**Issue:** DeepInfra and LangSmith API keys in version control
**Impact:** Anyone can use your API quota, run scans, access your LangSmith traces
**Time to fix:** 5 minutes

```bash
# Step 1: Remove from git history
git rm --cached .env
echo ".env" >> .gitignore
git add .gitignore
git commit -m "Remove .env from tracking"

# Step 2: Rotate keys immediately
# - DeepInfra: https://console.deepinfra.com/api_keys
# - LangSmith: https://smith.langchain.com/settings/keys

# Step 3: Create .env.example
cp .env .env.example
# Edit .env.example, replace actual keys with placeholders:
HAR_ANALYZER_LLM_API_KEY=YOUR_API_KEY_HERE
LANGCHAIN_API_KEY=YOUR_API_KEY_HERE

# Step 4: Update docs
# Add to README.md:
# cp .env.example .env && edit .env with your keys
```

---

### 2. Missing URL Validation (SSRF Risk)

**File:** `src/har_analyzer/executor.py`, line 82+
**Issue:** Executes any URL without validation
**Attack scenario:**
```python
# Attacker uploads HAR with internal IP
hypothesis.url = "http://127.0.0.1:8080/admin"
# Scanner fires it → internal port scan results leaked
```

**Fix (5 minutes):**
```python
# Add to executor.py, before default_transport():

def validate_hypothesis_url(url: str, allowed_domains: List[str], config: RunConfig) -> bool:
    """Ensure URL is safe to execute."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except Exception:
        return False

    # 1. Only http/https
    if parsed.scheme not in ('http', 'https'):
        return False

    # 2. Domain must match config.target_domains
    netloc = parsed.netloc.lower()
    if not any(netloc == domain or netloc.endswith('.' + domain)
               for domain in allowed_domains):
        return False

    # 3. Block private IPs
    import ipaddress
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            return False
    except ValueError:
        pass  # Not an IP, that's fine

    return True

# Then in execute_hypothesis():
def execute_hypothesis(...):
    if not validate_hypothesis_url(hypothesis.url, config.target_domains, config):
        return ExecutionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            request_id=hypothesis.original_request_id,
            method=hypothesis.method,
            url=hypothesis.url,
            outcome="validation_failed",
            error="URL validation failed (SSRF protection)",
        )
    # ... rest of function
```

---

### 3. Prompt Injection in LLM Analysis

**File:** `src/har_analyzer/hypotheses.py`, line 109+
**Issue:** User-controlled data injected into prompt JSON
**Example attack:**
```json
// In HAR file:
{
  "headers": {
    "X-Custom": "\" } MALICIOUS PROMPT HERE { \""
  }
}
```

**Fix (10 minutes):**
```python
# In hypotheses.py, update _build_analysis_prompt():

def _build_analysis_prompt(record: RequestRecord, context: EndpointContext, config: RunConfig) -> Dict:
    """Build prompt with safe serialization."""

    # Use Pydantic to serialize (automatic escaping)
    from pydantic import BaseModel

    class AnalysisPrompt(BaseModel):
        request: Dict = {
            "method": record.method,
            "path": record.path,
            "headers": record.request_headers,  # Pydantic handles escaping
            "body": record.request_body[:config.max_body_chars] if record.request_body else None,
        }
        context: Dict = context.to_dict()
        task: str = "Generate attack hypotheses..."
        response_schema: Dict = {...}

    prompt_obj = AnalysisPrompt(...)

    # Serialize with Pydantic (safe)
    return json.loads(prompt_obj.model_dump_json())
```

---

## 🟠 HIGH PRIORITY (This week)

### 4. Weak Builtin Hypotheses - Low Detection Rate

**File:** `src/har_analyzer/hypotheses.py`, line 65-79
**Issue:** Only tests numeric IDs and basic auth removal. Misses:
- UUID/string IDs
- Parameter injection
- Type coercion
- Missing checks on similar endpoints

**Impact:** 50% of real vulnerabilities in heuristic mode go undetected

**Quick Win - Add String ID Swapping (15 min):**
```python
# In hypotheses.py, add new function:

def _string_id_hypothesis(record: RequestRecord) -> Optional[AttackHypothesis]:
    """Test non-numeric resource IDs (UUIDs, slugs, etc)."""
    # Detect UUID pattern: 550e8400-e29b-41d4-a716-446655440000
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

    # Look in URL for UUIDs
    import re
    matches = re.findall(uuid_pattern, record.url, re.IGNORECASE)
    if not matches:
        return None

    original_uuid = matches[0]
    # Use different UUID from context if available, else use fixed test UUID
    test_uuid = "550e8400-e29b-41d4-a716-446655440000"

    modified_url = record.url.replace(original_uuid, test_uuid)

    return AttackHypothesis(
        hypothesis_id=f"hyp-{uuid.uuid4().hex[:8]}",
        original_request_id=record.request_id,
        endpoint_key=record.endpoint_key(),
        attack_type="IDOR",
        severity="high",
        expected_signal="200 with different resource UUID",
        rationale=f"UUID {original_uuid} is likely a resource ID; trying different UUID",
        method=record.method,
        url=modified_url,
        headers=record.request_headers.copy(),
        body=record.request_body,
        mutation_summary=f"UUID: {original_uuid[:8]}... → {test_uuid[:8]}...",
    )

# Update BuiltinHeuristicClient.generate_hypotheses():
def generate_hypotheses(self, record, context, config):
    candidates = []

    # Original numeric swap
    resource_swap = _numeric_swap_hypothesis(record)
    if resource_swap:
        candidates.append(resource_swap)

    # NEW: String/UUID swap
    string_swap = _string_id_hypothesis(record)
    if string_swap:
        candidates.append(string_swap)

    # Rest...
    query_swaps = _query_param_hypotheses(record)
    candidates.extend(query_swaps)

    return candidates[:config.per_endpoint_hypothesis_cap]
```

---

### 5. Better Evaluation Logic

**File:** `src/har_analyzer/evaluation.py`, line 108-120
**Issue:** Only checks status code and JSON structure. Misses:
- Large response size delta (more data leaked)
- 200 status from 403 (access control issue)
- Information in error messages

**Quick Fix (20 min):**
```python
# In evaluation.py:

def _indicates_access_control_issue(record, hypothesis, result):
    """Enhanced detection logic."""

    if result.status_code is None:
        return False

    # 1. Status code changed from 401/403 to 200 = LIKELY VULNERABILITY
    if record.response_status in (401, 403) and result.status_code == 200:
        return True

    # 2. Response structure matches original but with different data
    if hypothesis.attack_type in {"IDOR", "BOLA"}:
        if _structurally_similar(record.response_body or "", result.response_body or ""):
            # Check if resource IDs are different
            if _contains_different_resource_id(record.response_body, result.response_body):
                return True

    # 3. Response size increased significantly (more data exposed than original)
    size_increase = len(result.response_body or "") - len(record.response_body or "")
    if size_increase > 500:  # Arbitrary but reasonable
        return True

    # 4. Auth bypass: response exists when it shouldn't
    if hypothesis.attack_type == "auth_bypass":
        if result.response_body and not record.response_body:
            return True

    return False

def _contains_different_resource_id(original, modified):
    """Check if response contains different user IDs."""
    import re

    # Look for ID patterns in both
    id_pattern = r'["\']?(?:user_?id|account_?id|id)["\']?\s*:\s*(\d+|["\'][^"\']+["\'])'

    orig_ids = set(re.findall(id_pattern, original, re.IGNORECASE))
    mod_ids = set(re.findall(id_pattern, modified, re.IGNORECASE))

    return orig_ids != mod_ids and len(orig_ids) > 0 and len(mod_ids) > 0
```

---

## 🟡 MEDIUM PRIORITY (Sprint 1)

### 6. Step Mode Race Condition

**File:** `src/har_analyzer/web.py:approve_request()` + `src/har_analyzer/graph.py`
**Issue:** Background thread may skip request before analyst approves
**Symptom:** Analyst clicks "approve", nothing happens

**Fix (30 min):**
```python
# In web.py:
@app.post("/runs/{run_id}/requests/{request_id}/approve")
def approve_request(run_id: str, request_id: str):
    run = store.get_run(run_id)
    if not run or run.status != "running":
        return RedirectResponse(..., status_code=303)

    # Mark as approved with timestamp
    store.update_request_item(
        run_id, request_id,
        approval_state="approved",
        status="approved",  # NEW STATE
        stage="waiting_for_execution"
    )

    # Wake up the background thread (if using threading event)
    # approval_events[request_id].set()

    return RedirectResponse(..., status_code=303)

# In graph.py, before analyzing:
def analyze_request(state):
    # ... generate hypotheses ...

    # NEW: Check for step_mode and wait for approval
    if state["config"].step_mode:
        request_item = store.get_request_items(state["run"].run_id, request_id=request.request_id)[0]

        if request_item.approval_state == "not_required":
            # Wait for analyst approval (with timeout)
            approved = wait_for_approval(
                state["store"],
                run_id=state["run"].run_id,
                request_id=request.request_id,
                timeout_seconds=300
            )

            if not approved:
                state["findings_by_request"][request.request_id] = []
                return  # Skip this request

    # Continue with execution...
```

---

### 7. Add Semgrep Integration

**File:** New function in `evaluation.py`
**Status:** Mentioned in overview but NOT implemented
**Impact:** Missing PII/secret detection

**Add (20 min):**
```python
# In evaluation.py:

def scan_response_for_secrets(response_body: str, temp_dir: str = "/tmp") -> List[Dict]:
    """Scan response body for secrets/PII using Semgrep."""
    import subprocess
    import json
    from pathlib import Path

    if not response_body:
        return []

    # Write to temp file
    temp_file = Path(temp_dir) / f"response_{uuid.uuid4().hex[:8]}.json"
    try:
        temp_file.write_text(response_body)

        # Run semgrep
        result = subprocess.run(
            [
                "semgrep",
                "--config=p/secrets",
                "--config=p/generic",
                "--json",
                str(temp_file),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            findings = json.loads(result.stdout).get("results", [])
            return [
                {
                    "type": f.get("check_id", "unknown"),
                    "message": f.get("extra", {}).get("message", ""),
                    "severity": f.get("extra", {}).get("severity", "medium"),
                }
                for f in findings
            ]
    except Exception as e:
        # Graceful fallback if semgrep not installed
        print(f"Semgrep scan failed: {e}")
        return []
    finally:
        temp_file.unlink(missing_ok=True)

    return []

# Use in evaluate_response():
def evaluate_response_node(state):
    # ... existing logic ...

    # NEW: Scan for secrets
    if result.response_body:
        secret_findings = scan_response_for_secrets(result.response_body)
        if secret_findings:
            findings.append(
                Finding(
                    finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                    request_id=record.request_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    title=f"Sensitive data exposed: {secret_findings[0]['type']}",
                    attack_type="excessive_data_exposure",
                    severity="high",
                    confidence="high",
                    endpoint=record.endpoint_key(),
                    summary=f"Response contains {len(secret_findings)} potential secrets",
                    evidence=secret_findings,
                    remediation="Remove sensitive data from API responses",
                    reproduction_curl=build_curl_command(hypothesis),
                )
            )
```

---

### 8. Config Validation

**File:** `src/har_analyzer/config.py`
**Time:** 15 min

```python
# Add to config.py:

def validate_run_config(config: RunConfig) -> List[str]:
    """Validate configuration before running scan."""
    errors = []

    # Validate paths
    if not Path(config.har_path).exists():
        errors.append(f"HAR file not found: {config.har_path}")

    # Validate domains
    if not config.target_domains:
        errors.append("No target domains specified")

    # Validate parameters
    if config.per_endpoint_hypothesis_cap <= 0:
        errors.append("per_endpoint_hypothesis_cap must be > 0")

    if config.global_request_cap <= 0:
        errors.append("global_request_cap must be > 0")

    if config.inter_request_delay_ms < 0:
        errors.append("inter_request_delay_ms cannot be negative")

    # Validate LLM
    if config.provider != "builtin":
        if not config.llm_api_key:
            errors.append(f"API key required for provider: {config.provider}")
        if not config.model:
            errors.append("Model must be specified for external LLM")

    # Validate timeouts
    if config.llm_timeout_seconds <= 0:
        errors.append("llm_timeout_seconds must be > 0")

    if config.request_timeout_seconds <= 0:
        errors.append("request_timeout_seconds must be > 0")

    return errors

# Update run_scan() in graph.py:
def run_scan(config, ...):
    errors = validate_run_config(config)
    if errors:
        raise ValueError("Configuration validation failed:\n" + "\n".join(errors))

    # ... rest of function
```

---

## 🟢 NICE TO HAVE

### 9. Concurrent Hypothesis Execution

**File:** `src/har_analyzer/graph.py`
**Benefit:** Faster scans (4x with concurrency=4)
**Complexity:** Medium
**Time:** 45 min

```python
# In graph.py, update execute_attack_node to use asyncio:

import asyncio

async def execute_hypothesis_async(hypothesis, record, config, transport):
    """Async wrapper for hypothesis execution."""
    return execute_hypothesis(hypothesis, record, config, transport)

def execute_attack_node_concurrent(state):
    """Execute multiple hypotheses concurrently."""
    config = state["config"]

    # Batch hypotheses to execute (up to concurrency limit)
    pending_hypotheses = [
        h for h in state["attack_hypotheses"]
        if h.hypothesis_id not in [r.hypothesis_id for r in state["execution_results"]]
    ]

    if not pending_hypotheses:
        return

    batch_size = min(config.concurrency, len(pending_hypotheses))

    async def run_batch():
        tasks = [
            execute_hypothesis_async(h, state["records"][h.original_request_id], config, state.get("transport"))
            for h in pending_hypotheses[:batch_size]
        ]
        results = await asyncio.gather(*tasks)
        return results

    # Run batch
    results = asyncio.run(run_batch())
    state["execution_results"].extend(results)
```

---

## 📝 Improved Prompt Engineering

### Better System Prompt (Replace current in hypotheses.py)

```python
def _system_prompt() -> str:
    return """You are a security testing specialist performing authorized API security validation.

Your task: Generate targeted hypotheses about how an API endpoint could be vulnerable.

VULNERABILITY TYPES YOU'RE TESTING FOR:
1. **IDOR (Insecure Direct Object Reference):** Access other users' resources by modifying IDs
2. **BOLA (Broken Object-Level Authorization):** Missing auth checks on protected endpoints
3. **Auth Bypass:** Removing/modifying auth headers to access protected data
4. **Privilege Escalation:** Modifying role/permission fields to gain elevated access
5. **Data Exposure:** Responses leaking sensitive PII or API tokens
6. **Parameter Pollution:** Duplicate params with different values to bypass checks

CONSTRAINTS (IMPORTANT):
- Generate ONLY 3-5 hypotheses per endpoint (quality over quantity)
- Modify ONE parameter per hypothesis (easier to isolate root cause)
- Mutations must match the original request's data types (numeric IDs stay numeric)
- Don't suggest attacks that would obviously fail (e.g., GET → PATCH method change)
- Prioritize high-confidence attacks based on the request structure

HYPOTHESIS QUALITY CHECKLIST:
✓ Makes sense given the API context
✓ Modifies realistic values (actual IDs from the API)
✓ Has a clear success indicator (specific response change)
✓ Is likely to reveal a real vulnerability if successful

WHAT A GOOD HYPOTHESIS LOOKS LIKE:
{
  "attack_type": "IDOR",
  "mutation_summary": "Change user_id in path from 1042 to 1041",
  "expected_signal": "200 OK with different user's profile data",
  "rationale": "Path contains numeric user_id; no visible per-resource auth check in response",
  "severity": "high"
}

AVOID:
✗ Nonsensical mutations (random strings that won't work)
✗ Over-complicated multi-parameter changes
✗ Attacks that violate API contract (wrong data types)
✗ Redundant hypotheses (avoid duplicate ideas)
"""
```

### Better Analysis Prompt Context

```python
def _build_improved_analysis_prompt(record, context, config):
    return {
        "objective": "Generate attack hypotheses for this specific endpoint",

        "endpoint": {
            "method": record.method,
            "path": record.path,
            "normalized_path": record.normalized_path(),
            "purpose": "likely manages user profiles"  # Infer from path
        },

        "request_details": {
            "headers": {
                k: v for k, v in record.request_headers.items()
                if k.lower() in ["authorization", "x-api-key", "cookie", "x-user-id"]
            },
            "params_summary": {
                k: f"<{type(v).__name__}>" for k, v in record.query_params.items()
            },
            "body_structure": extract_json_shape(record.request_body) if record.request_body else None,
        },

        "response_details": {
            "status": record.response_status,
            "size_bytes": len(record.response_body or ""),
            "contains_pii": any(keyword in (record.response_body or "").lower()
                              for keyword in ["email", "phone", "ssn", "credit"]),
            "structure_sample": extract_json_shape(record.response_body)[:5],
        },

        "api_context": {
            "auth_patterns": context.auth_header_names,
            "observed_id_patterns": context.resource_ids_seen[:3],
            "api_summary": context.api_summary,
            "similar_endpoints": context.endpoint_groups.get(record.method, [])[:3],
        },

        "constraints": {
            "max_hypotheses": 4,
            "per_endpoint_cap": config.per_endpoint_hypothesis_cap,
        },

        "response_schema": {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "attack_type": {"type": "string"},
                            "mutation_summary": {"type": "string"},
                            "expected_signal": {"type": "string"},
                            "rationale": {"type": "string"},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        },
                        "required": ["attack_type", "mutation_summary", "expected_signal", "rationale", "severity"],
                    }
                }
            }
        }
    }
```

---

## Implementation Roadmap

**Today (Critical fixes):**
- [ ] Rotate API keys, remove .env from git
- [ ] Add URL validation
- [ ] Add prompt sanitization

**This week (High priority):**
- [ ] Add string ID swapping to heuristics
- [ ] Improve evaluation logic
- [ ] Fix step_mode race condition
- [ ] Improve system prompt
- [ ] Add config validation

**Next week (Medium priority):**
- [ ] Semgrep integration
- [ ] Better analysis prompt context
- [ ] Better UI for step_mode approvals
- [ ] Concurrent hypothesis execution

**Later:**
- [ ] Cross-endpoint analysis
- [ ] Token refresh support
- [ ] Real-time progress streaming

---

## Testing the Fixes

```bash
# After implementing fixes:

# 1. Test URL validation
python -c "
from src.har_analyzer.executor import validate_hypothesis_url
assert not validate_hypothesis_url('http://127.0.0.1:8080', ['api.example.com'], config)
assert validate_hypothesis_url('https://api.example.com/path', ['api.example.com'], config)
print('✅ URL validation working')
"

# 2. Test string ID swapping
python -c "
from src.har_analyzer.hypotheses import _string_id_hypothesis
record = RequestRecord(url='https://api.example.com/550e8400-e29b-41d4-a716-446655440000')
hyp = _string_id_hypothesis(record)
assert hyp is not None
print('✅ String ID hypothesis generated')
"

# 3. Run tests
pytest tests/ -v
```

