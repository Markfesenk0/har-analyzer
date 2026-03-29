# HAR Analyzer: Comprehensive Codebase Review

**Date:** 2026-03-28
**Status:** Pre-Alpha (0.1.0)

---

## Part 1: UI Overview & Requirements for UXPilot.ai

### Current UI State
You have a **functional but minimalist Jinja2 template-based HTML UI** with:
- Landing page (index.html) for configuring new scans
- Run detail page (run_detail.html) showing real-time progress
- Request detail page (request_detail.html) for drilling into individual requests
- Inline CSS (no external framework)
- Simple form-based controls
- Basic data tables

### UI/UX Requirements for UXPilot.ai

#### 1. **Landing/Configuration Page** (`index.html`)
- **Purpose:** Users select a HAR file, specify target domains, configure scan parameters
- **Key Elements:**
  - HAR file picker (dropdown or file upload)
  - Multi-select for target domains (with suggestion from HAR hosts)
  - Toggle: "Allow unsafe artifacts" (affects redaction behavior)
  - LLM provider selection (Builtin heuristics vs OpenAI-compatible vs Custom)
  - Model selector (dropdown, populated based on provider)
  - Toggle: "Step mode" (manual approval before LLM analysis per request)
  - **Suggested Sections:**
    - Hero section explaining the tool's purpose
    - Form with clear field organization (grouped: file, scope, LLM config, advanced)
    - Recent runs list on right sidebar
    - Quick-start guide or tips

#### 2. **Run Progress/Detail Page** (`run_detail.html`)
- **Purpose:** Monitor a scan in progress, review individual requests and hypotheses
- **Key Elements:**
  - Run summary (status, progress bars for requests/findings)
  - Request list (sortable, filterable by status/stage)
  - Per-request sidebar showing:
    - Original request/response from HAR
    - LLM hypotheses generated
    - Execution results (actual responses)
    - Findings (vulnerabilities detected)
  - Pause/Resume/Cancel buttons
  - Live update mechanism (polling or WebSocket)
  - **Suggested Features:**
    - Timeline view of hypothesis generation → execution → evaluation
    - Visual indicators (badges/colors) for status (queued, approved, executing, found_issue)
    - Expandable request cards with before/after diffs
    - Search/filter by endpoint, attack type, severity

#### 3. **Request Detail Page** (`request_detail.html`)
- **Purpose:** Deep dive into one request's analysis workflow
- **Key Elements:**
  - Original request (method, URL, headers, body) in a formatted code block
  - Original response (status, headers, body, highlighted sensitive data)
  - LLM analysis section:
    - Prompt sent to LLM (debug artifact link)
    - Hypotheses generated (card view with mutation summary, severity)
  - Execution section:
    - For each hypothesis, show:
      - Mutation applied (diff view)
      - Actual response (status, size delta, highlighted changes)
      - Outcome (access control issue? Data leak?)
  - Findings section:
    - Confirmed vulnerabilities with evidence
    - Remediation guidance
    - Curl reproduction command

#### 4. **Additional UI Requirements**
- **Dark mode toggle** (brand uses warm earth tones; dark version needed)
- **Mobile responsiveness** (current grid layout doesn't scale well)
- **Search/filtering across runs and requests**
- **Export findings** (JSON, CSV, PDF report)
- **Vulnerability timeline view** (showing what endpoints were tested, when)
- **Comparison view** (side-by-side original vs. modified request)

---

## Part 2: Bugs & Problems Found

### 🔴 **CRITICAL ISSUES**

#### 1. **Exposed API Keys in `.env` File**
**Location:** `.env`
**Severity:** CRITICAL
**Issue:** DeepInfra API key and LangSmith API key hardcoded in version control
**Impact:** Anyone with access to the repo can use your API quota or run unauthorized scans
**Fix:**
```bash
# Add to .gitignore
.env
.env.local
*.local

# Create .env.example instead
HAR_ANALYZER_LLM_PROVIDER=deepinfra
HAR_ANALYZER_LLM_BASE_URL=https://api.deepinfra.com/v1/openai
HAR_ANALYZER_LLM_API_KEY=YOUR_API_KEY_HERE
# ... etc
```

#### 2. **No Input Validation on URL Execution**
**Location:** `executor.py:default_transport()`
**Issue:** URLs are executed directly from hypothesis objects without validating:
- Scheme (http/https only, not gopher/file/etc)
- Target domain (could be overridden to attack internal services)
- No rate limiting per target domain
**Fix:**
```python
def validate_hypothesis_url(url: str, allowed_domains: List[str]) -> bool:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    # Verify domain matches config.target_domains
    if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
        return False
    return True
```

#### 3. **Prompt Injection Risk in LLM Analysis**
**Location:** `hypotheses.py:_build_analysis_prompt()`
**Issue:** RequestRecord data (headers, body) is injected directly into prompt JSON without sanitization
**Scenario:**
```
User uploads HAR with header:
X-Custom: "... close json block. } malicious code here {"
This breaks the JSON contract and could prompt-inject the LLM.
```
**Fix:** Use Pydantic JSON serialization with `model_validate_json()` strict mode

#### 4. **Race Condition in `step_mode` Approval Flow**
**Location:** `web.py:/runs/{run_id}/requests/{request_id}/approve`, `graph.py`
**Issue:** Analyst clicks "approve" but background scan thread may have already moved past that request
**Impact:** Approval is silently ignored; no feedback to analyst
**Fix:**
```python
# In web.py approve_request():
store.update_request_item(..., approval_state="approved")
# In graph.py, before calling LLM in analyze_request:
if config.step_mode and item.approval_state != "approved":
    # Wait for approval or timeout
    timeout_result = wait_for_approval(item.request_id, timeout_seconds=300)
    if not timeout_result:
        return {"status": "skipped", "reason": "approval timeout"}
```

#### 5. **No Timeout Handling for Hung Requests**
**Location:** `executor.py:default_transport()`
**Issue:** Uses `urllib` with timeout, but if API hangs on slow response, entire scan stalls
**Better Approach:** Add timeout to entire execution phase, cancel stuck hypotheses
```python
# Use asyncio with timeout per hypothesis execution
import asyncio
await asyncio.wait_for(execute_hypothesis(...), timeout=10)
```

---

### 🟠 **HIGH PRIORITY ISSUES**

#### 6. **Weak Hypothesis Mutation Logic**
**Location:** `hypotheses.py:_numeric_swap_hypothesis()`, `_query_param_hypotheses()`, `_auth_hypotheses()`
**Issue:** Builtin heuristics are too naive:
- Only swaps numeric IDs (misses UUIDs, string identifiers)
- Doesn't test parameter injection (e.g., `user_id=1 OR 1=1`)
- Doesn't test type coercion attacks (e.g., `id={"admin":1}`)
**Impact:** Many real vulnerabilities are missed in heuristic mode
**Improvement:**
```python
def _string_id_swap_hypothesis(...):
    # Detect string IDs that look like user identifiers
    if "user" in field_name or "account" in field_name:
        # Try swapping with other observed IDs from context
        for other_id in context.resource_ids_seen:
            if type(other_id) == type(original_id):
                yield hypothesis_with_swap(other_id)

def _injection_hypothesis(...):
    # Add basic injection tests
    payloads = [
        " OR 1=1",
        '"}]',  # JSON array break
        "../../etc/passwd",  # Path traversal
    ]
    for payload in payloads:
        yield hypothesis_with_payload(payload)
```

#### 7. **Insufficient Context Passed to LLM**
**Location:** `hypotheses.py:_build_analysis_prompt()`
**Issue:** Context passed to LLM is sparse:
- No cross-endpoint data flow analysis (e.g., "endpoint A returns user_id which endpoint B accepts")
- No temporal ordering (which requests were made in sequence?)
- No observed success/failure patterns from previous requests
**Fix:**
```python
context_summary = """
Observed patterns in this API:
- When auth succeeds, response includes: user_id, token
- GET endpoints return 403 when user_id is wrong
- POST endpoints return 400 for invalid fields
- DELETE endpoints don't validate authorization (found on 3/5 tested)

This request ({method} {path}) likely:
1. Accepts user_id as path param (seen in {n} other endpoints)
2. May return user data if ID is modified
"""
```

#### 8. **No Deduplication Across Runs**
**Location:** All modules
**Issue:** If you run the same HAR twice, it re-tests all hypotheses (wastes quota)
**Fix:**
```python
# In persistence.py, add hypothesis dedup:
def has_hypothesis_been_tested(run_id: str, endpoint_key: str, attack_type: str,
                                mutation_hash: str) -> bool:
    # Check database for exact match across all historical runs
    pass
```

#### 9. **Context Window Overflow Not Handled**
**Location:** `graph.py`, `hypotheses.py`
**Issue:** If HAR file has 1000+ requests and context includes all neighbors, prompt becomes huge and hits token limits
**Fix:**
```python
# In context.py:
def build_endpoint_context(..., max_context_tokens: int = 4000):
    context_items = []
    token_count = 0
    for item in all_items:
        if token_count > max_context_tokens:
            break  # Truncate
        context_items.append(item)
        token_count += estimate_tokens(item)
```

#### 10. **Evaluation Logic Misses Common Vulnerabilities**
**Location:** `evaluation.py:_indicates_access_control_issue()`
**Issue:** Only checks status code and response shape:
- Misses **delayed responses** that indicate backend processing auth check
- Misses **partial access** (returns some data but hides sensitive fields)
- Misses **information disclosure** in error messages
**Better logic:**
```python
def _indicates_access_control_issue(...):
    # 1. Response code changed from 403 to 200 → likely IDOR
    if record.response_status == 403 and result.status_code == 200:
        return True

    # 2. Response structure matches original but with different IDs
    if _structurally_similar(...) and _contains_different_resource_id(...):
        return True

    # 3. Response size increased significantly (more data exposed)
    if result.body_size_delta > 500:  # Arbitrary but reasonable
        return True

    return False
```

---

### 🟡 **MEDIUM PRIORITY ISSUES**

#### 11. **Token Refresh Not Implemented**
**Location:** `executor.py:detect_expired_bearer()`
**Issue:** Detects expired tokens but doesn't refresh them
**Note from overview:** "Optionally: if re-auth credentials are provided in config, attempt token refresh"
**Not implemented** - HAR tokens often expire before scan completes
**Fix:** Add re-auth flow to RunConfig

#### 12. **Semgrep Integration Missing**
**Location:** `HAR_Scanner_Overview.md` mentions it, but not in actual code
**Issue:** Overview describes semgrep scanning for secrets/PII
**Not found in:** `evaluation.py`, `executor.py`, or anywhere else
**Impact:** Missing critical PII detection
**Add:**
```python
def scan_for_secrets_with_semgrep(response_body: str, temp_dir: str) -> List[Dict]:
    import subprocess, json
    # Write body to temp file
    # Run: semgrep --config=p/secrets --json temp_file
    # Parse and return findings
```

#### 13. **No Concurrent Hypothesis Execution**
**Location:** `graph.py:execute_attack_node()` loops sequentially
**Issue:** With `concurrency=4` in config, actually runs 1 at a time
**Fix:** Use `asyncio` or `ThreadPoolExecutor` to batch hypotheses

#### 14. **Database Schema Doesn't Fully Track State**
**Location:** `persistence.py`
**Issue:** RequestRunItem schema missing fields:
- `skipped_reason` (why was this request skipped?)
- `llm_retry_count` (did LLM fail and retry?)
- `token_refresh_attempted` (did token refresh occur?)
These make post-hoc analysis of runs difficult

#### 15. **No Logging of Rejected Hypotheses**
**Location:** `graph.py:_route_after_analyze()`
**Issue:** If LLM generates 15 hypotheses but budget cap is 10, which 5 were rejected?
**Impact:** Analyst can't see why certain attack vectors weren't tested
**Fix:** Persist all hypotheses (including rejected ones) with rejection_reason

#### 16. **Report Generation Always Overwrites**
**Location:** `reporting.py`
**Issue:** If you re-run a scan on same domain, old report is lost
**Fix:** Archive old reports or add timestamp to filename

#### 17. **No Rate Limit Adaptation**
**Location:** `executor.py:default_transport()`
**Issue:** Uses fixed inter_request_delay_ms, doesn't adapt if target returns 429 (rate limit)
**Fix:**
```python
if result.status_code == 429:
    retry_after = result.response_headers.get("Retry-After", "60")
    config.inter_request_delay_ms = int(retry_after) * 1000
```

---

### 🟢 **LOW PRIORITY ISSUES**

#### 18. **No Progress Streaming for Large HAR Files**
**Location:** `web.py:_background_scan()` prints to stdout
**Issue:** UI doesn't see progress updates in real-time (would need WebSocket or polling)
**Current:** Only refreshes every few seconds
**Better:** Implement SSE (Server-Sent Events) for live updates

#### 19. **Redaction Not Applied to Response Bodies in UI**
**Location:** `web.py:/runs/{run_id}/requests/{request_id}`
**Issue:** If `redact_by_default=true`, templates still show PII in response bodies
**Fix:** Apply redaction in response serialization step

#### 20. **No Diff View in Templates**
**Location:** `request_detail.html`
**Issue:** Shows original request and modified hypothesis, but doesn't highlight **what changed**
**Fix:** Add side-by-side diff view with highlighting

#### 21. **No Bulk Operations**
**Location:** UI only allows approve/skip one request at a time
**Feature:** "Approve next 10", "Skip all GET endpoints", etc.

#### 22. **Missing Configuration Validation**
**Location:** `config.py:load_run_config()`
**Issue:** Doesn't validate:
- LLM provider exists
- Model name is valid for provider
- per_endpoint_hypothesis_cap > 0
- har_path exists and is readable
**Fix:**
```python
def validate_config(config: RunConfig) -> List[str]:
    errors = []
    if config.per_endpoint_hypothesis_cap <= 0:
        errors.append("per_endpoint_hypothesis_cap must be > 0")
    if not Path(config.har_path).exists():
        errors.append(f"HAR file not found: {config.har_path}")
    return errors
```

---

## Part 3: Prompt Engineering & LLM Integration Improvements

### Current Prompt Strategy Issues

#### **A. System Prompt is Generic**
**Location:** `hypotheses.py:_system_prompt()`
**Current:**
```
"You are an authorized QA automation system..."
```
**Problems:**
1. Too brief - doesn't establish context about API security patterns
2. Doesn't explain what a "good" hypothesis looks like
3. Doesn't constrain creativity (LLM may generate unrealistic attacks)

**Improved:**
```python
def _system_prompt():
    return """You are a security testing specialist performing authorized API security validation.

Your task is to generate hypotheses about how an API endpoint might be vulnerable to:
- IDOR (insecure direct object reference): accessing other users' data by modifying IDs
- BOLA (broken object-level authorization): missing auth checks on protected endpoints
- Auth bypass: removing/modifying auth headers to access protected data
- Privilege escalation: modifying role/permission fields to gain admin access
- Data exposure: responses leaking sensitive PII or tokens

CONSTRAINTS:
- Only modify one parameter per hypothesis (easier to isolate cause of vulnerability)
- Mutations must be realistic based on the original request structure
- Don't suggest hypotheses that would definitely fail (e.g., changing method to unsupported verb)
- Prioritize high-confidence attacks (structural ID swaps > random injection attempts)

EXAMPLES OF GOOD HYPOTHESES:
1. "User ID in path is numeric. Try ID of different user. Signal: 200 + user profile"
2. "Auth header is Bearer token. Try removing it. Signal: different response vs 401"
3. "POST body has 'role': 'user'. Try changing to 'admin'. Signal: elevated permissions"
"""
```

#### **B. Analysis Prompt Missing Critical Context**
**Location:** `hypotheses.py:_build_analysis_prompt()`
**Current:** Sends bare request/context JSON
**Missing:**
- What attack types have already been tested on similar endpoints?
- What succeeded/failed in the past?
- What's the logical flow of the API?

**Improved Structure:**
```python
def _build_analysis_prompt(record, context, config):
    return {
        "instruction": "Analyze this API endpoint for common security flaws...",
        "endpoint": {
            "method": record.method,
            "path": record.path,
            "normalized_path": record.normalized_path(),  # /users/{id}/profile
        },
        "request_sample": {
            "headers": record.request_headers,
            "query_params": record.query_params,
            "body": record.request_body,
        },
        "response_sample": {
            "status": record.response_status,
            "size_bytes": len(record.response_body or ""),
            "content_preview": (record.response_body or "")[:500],
        },
        "api_context": {
            "auth_patterns_observed": context.auth_header_names,
            "resource_id_patterns": context.resource_ids_seen[:5],
            "previous_findings_on_similar_endpoints": [...],  # NEW
            "api_summary": context.api_summary,
        },
        "constraints": {
            "max_hypotheses": 5,
            "prefer_high_confidence": True,
            "avoid_destructive_operations": True,
        },
        "response_schema": {...}
    }
```

#### **C. No Feedback Loop**
**Current:** LLM generates hypotheses once; if they all fail, no lesson learned
**Better:**
```python
def generate_hypotheses_with_feedback(record, context, config):
    # Get initial hypotheses
    hypotheses = llm.generate(record, context, config)

    # After execution, check results
    confirmed_findings = evaluate_hypotheses(hypotheses, results)

    # If NO findings, ask LLM "why might this endpoint still be vulnerable?"
    if not confirmed_findings and config.enable_hypothesis_refinement:
        refined = llm.generate(
            record,
            context + {"previous_hypotheses_failed": hypotheses},
            config
        )
        hypotheses.extend(refined)

    return hypotheses
```

#### **D. LLM Response Parsing is Fragile**
**Location:** `hypotheses.py:_parse_json_payload()`
**Issue:**
- One malformed JSON → entire hypothesis generation fails
- No retry with corrective prompting
- Exceptions swallowed with generic error

**Improved:**
```python
def parse_json_payload_with_recovery(response_text: str, schema: Type[T]) -> T:
    """Parse with automatic correction attempts."""
    attempts = 0
    while attempts < 3:
        try:
            parsed = json.loads(response_text)
            return schema.model_validate(parsed)
        except json.JSONDecodeError as e:
            # Try to fix common issues
            if attempts == 0:
                response_text = fix_common_json_errors(response_text)
            elif attempts == 1:
                response_text = extract_json_from_markdown(response_text)
            else:
                raise ProviderResponseError(f"Failed to parse after {attempts} attempts")
            attempts += 1

def fix_common_json_errors(text: str) -> str:
    # Remove markdown code fences
    text = text.replace("```json", "").replace("```", "")
    # Fix trailing commas
    text = re.sub(r',(\s*[}\]])', r'\1', text)
    return text.strip()
```

---

## Part 4: Request Review Process Improvements

### Current Flow Issues

#### **Problem 1: No Pre-Execution Review**
**Current:** Hypotheses are generated and immediately executed
**Issue:** LLM might generate unrealistic attacks that waste API quota
**Better:**
```
1. Generate hypotheses (without executing)
2. [If step_mode] Wait for analyst approval of hypothesis
3. Execute approved hypothesis
4. Evaluate result
```

#### **Problem 2: Batch Execution Lacks Granularity**
**Current:** Hypothesis is "approved" at request level, but you have 10 hypotheses
**Better:**
```
UI should allow:
- Approve specific hypothesis (not just the whole request)
- Skip specific hypothesis
- Adjust expected_signal before approval
- View LLM reasoning (debug artifact)
```

#### **Problem 3: No Triage/Filtering Before Review**
**Issue:** If LLM generates 100 hypotheses across 20 requests, analyst must review all
**Better:** Add confidence scoring and filter low-confidence ones:
```python
@dataclass
class AttackHypothesis:
    ...
    confidence: Literal["high", "medium", "low"] = "medium"
    reasoning: str  # Why this attack might work
```

#### **Problem 4: No Feedback on Rejected Hypotheses**
**Current:** If analyst skips a hypothesis, no reason is stored
**Better:**
```python
@dataclass
class RejectionRecord:
    hypothesis_id: str
    reason: Literal["unrealistic", "already_tested", "out_of_scope", "other"]
    notes: str  # Free-form feedback

# Use this feedback to improve future hypothesis generation
```

---

## Part 5: Context Enrichment Gaps

### What's Missing

#### **1. Cross-Endpoint Data Flow Analysis**
**Current:** Each endpoint analyzed in isolation
**Missing:** Understanding that:
- Endpoint A returns `user_id=123`
- Endpoint B accepts `user_id` as path param
- Therefore endpoint B is a likely target for IDOR

**Fix:**
```python
def analyze_endpoint_relationships(records: List[RequestRecord]) -> Dict[str, List[str]]:
    """Map which response fields become request params elsewhere."""
    response_fields = {}
    for record in records:
        try:
            body = json.loads(record.response_body or "{}")
            for key in body.keys():
                if key not in response_fields:
                    response_fields[key] = []
                response_fields[key].append(record.endpoint_key())
        except:
            pass

    # Now find endpoints that use these as params
    param_usage = {}
    for record in records:
        for param in record.query_params:
            if param in response_fields:
                param_usage[param] = response_fields[param]

    return param_usage
```

#### **2. Behavioral Patterns Not Extracted**
**Current:** Just lists auth headers, parameters
**Missing:**
- "All GET endpoints return 403 when auth is missing"
- "DELETE endpoints don't check authorization"
- "POST returns 400 for invalid JSON, not 200 with error message"

**Fix:**
```python
def extract_behavioral_patterns(records: List[RequestRecord]) -> Dict[str, str]:
    patterns = {}

    # Pattern 1: Auth behavior
    no_auth_responses = [r for r in records if not r.request_headers.get("Authorization")]
    if no_auth_responses:
        status_codes = [r.response_status for r in no_auth_responses]
        if all(s == 403 for s in status_codes):
            patterns["auth_required"] = "All endpoints require Authorization header (return 403)"

    # Pattern 2: Method behavior
    delete_endpoints = [r for r in records if r.method == "DELETE"]
    if delete_endpoints:
        patterns["delete_endpoints"] = f"Found {len(delete_endpoints)} DELETE endpoints"
        # Check if any returned 200 without actual deletion (auth bypass signal)

    return patterns
```

#### **3. User Role / Session Context Not Captured**
**Current:** Doesn't track "this HAR was captured as admin user"
**Missing:** Multi-role support for testing privilege escalation
**Note:** Overview mentions "Multi-user session support" as future work

#### **4. Temporal Ordering Lost**
**Current:** Treats all requests as simultaneous
**Missing:** Understanding that:
- Requests 1-5 were setup (login, create resource)
- Requests 6-10 were the actual API interaction
- Request 11 was cleanup

---

## Part 6: Summary of Recommendations by Priority

### ✅ **Do First (This Week)**
1. **Move API keys to .env.local and .gitignore** (security critical)
2. **Add URL validation to executor** (prevents SSRF)
3. **Improve builtin hypotheses** (more intelligent swaps, injections)
4. **Add config validation** (fail fast on bad setup)
5. **Engineer better system prompt** (bigger impact on finding quality)

### 📋 **Do Next (Sprint 1)**
1. Implement step_mode approval flow correctly (race condition fix)
2. Add semgrep integration for PII/secret detection
3. Improve evaluation logic (more vulnerability detection)
4. Add hypothesis-level approval UI
5. Implement concurrent hypothesis execution

### 🚀 **Do Later (Sprint 2+)**
1. Implement token refresh logic
2. Add cross-endpoint analysis
3. Implement feedback loop (refine hypotheses based on results)
4. Add WebSocket progress streaming to UI
5. Build better context extraction (behavioral patterns, role tracking)

---

## Key Metrics to Track

For your UXPilot.ai brief, here's what the UI should surface:

```
Run Metrics:
- Total requests analyzed: 50
- Hypotheses generated: 285
- Hypotheses executed: 107 (37% - limited by budget/dedup)
- Findings confirmed: 8
- False positive rate: 12% (manual review data)
- Token usage: 14,500 / 20,000

Per-Endpoint Metrics:
- GET /api/users/{id}: 15 hypotheses, 3 findings (IDOR)
- POST /api/posts: 12 hypotheses, 0 findings
- DELETE /api/admin: 8 hypotheses, 5 findings (auth bypass)
```

Make sure the UI can display these clearly for analyst review.
