# Project Overview: Automated HAR-based API Vulnerability Scanner

## Objective
Build an agentic workflow to automate the discovery of logical vulnerabilities (e.g., BOLA/IDOR, PII leaks, broken access control) in mobile and web applications. The tool ingests `.har` (HTTP Archive) files captured via **HTTP Toolkit**, filters for target domains, uses an LLM to generate attack hypotheses, executes those hypotheses against the live API, and evaluates the responses to generate a structured vulnerability report.

---

## Tech Stack

| Component | Library/Tool |
|---|---|
| Language | Python 3.11+ |
| Agent Framework | LangGraph (stateful, cyclical agent routing) |
| Data Validation | Pydantic v2 (structured LLM output contracts) |
| HTTP Execution | `httpx` (async, connection pooling, timeout control) |
| HAR Parsing | `haralyzer` + `json` |
| Response Scanning | `semgrep` (secret/PII pattern matching in response bodies) |
| Observability | LangSmith (LangGraph trace logging and node inspection) |

---

## Architecture: LangGraph State Machine

The core design principle: **the LLM only outputs structured data (Pydantic models). Python functions do all execution.** The LLM never writes or runs code.

---

### 1. The Shared State

```python
from pydantic import BaseModel
from typing import TypedDict

class EndpointBudget(BaseModel):
    endpoint_key: str           # e.g. "POST /api/users/profile"
    hypotheses_fired: int = 0
    max_hypotheses: int = 10    # configurable per endpoint
    seen_payload_hashes: set[str] = set()  # dedup via normalized request hash

class AttackHypothesis(BaseModel):
    original_request_id: str
    attack_type: Literal[
        "IDOR", "BOLA", "privilege_escalation", "token_manipulation",
        "mass_assignment", "rate_limit_bypass", "parameter_pollution",
        "auth_bypass", "excessive_data_exposure"
    ]
    modified_request: dict      # headers, method, url, body
    expected_signal: str        # e.g. "200 instead of 403", "other user's email in response"
    severity: Literal["critical", "high", "medium", "low"]

class ScannerState(TypedDict):
    har_data: list[dict]                    # cleaned, filtered API calls
    target_domains: list[str]               # user-provided domains to test
    endpoint_context: dict                  # global context: auth patterns, recurring params, roles
    current_request_index: int
    endpoint_budgets: dict[str, EndpointBudget]  # per-endpoint request budget
    attack_hypotheses: list[AttackHypothesis]
    execution_results: list[dict]           # httpx responses
    vulnerabilities_found: list[dict]       # confirmed findings
```

---

### 2. The Nodes

#### Node A: `filter_traffic` (Python)
- **Input:** Raw HAR file path + `target_domains`
- **Action:**
  - Strip non-target domains
  - Remove static assets (images, CSS, fonts, analytics endpoints, known CDN/ad/tracking domains)
  - Normalize and deduplicate requests by method + path template
- **Output:** Populates `har_data` with clean API calls only

#### Node B: `enrich_context` (Python + LLM)
- **Input:** Full cleaned `har_data`
- **Action:**
  - Python pass: extract auth patterns (Bearer/cookie/API key), recurring parameter names (`user_id`, `account_id`, `role`), distinct user roles observed, resource ID patterns
  - LLM pass: summarize the API's apparent purpose, identify high-value endpoint groups, flag cross-endpoint data flows (e.g. "this endpoint exposes `user_id` which is used as path param elsewhere")
- **Output:** Populates `endpoint_context` — passed to every subsequent LLM call as background

#### Node C: `analyze_request` (LLM)
- **Input:** Single API request from `har_data` + `endpoint_context`
- **Action:** Identifies attack vectors for this specific endpoint. Outputs a list of `AttackHypothesis` objects — each with a modified request, the expected signal for a "hit", and severity.
- **Output:** Appends to `attack_hypotheses`; initializes `EndpointBudget` for this endpoint

#### Node D: `execute_attack` (Python)
- **Input:** Next unexecuted `AttackHypothesis`
- **Guards:**
  - Check `EndpointBudget.hypotheses_fired < max_hypotheses`
  - Hash the normalized request (method + path + sorted params + body keys); skip if hash in `seen_payload_hashes`
  - Configurable inter-request delay (default 500ms) to avoid DoS appearance
- **Action:** Fire request via `httpx` (async). Capture: status code, headers, body, response time, size delta vs. original HAR response
- **Output:** Appends to `execution_results`

#### Node E: `evaluate_response` (LLM)
- **Input:** `AttackHypothesis` + corresponding `execution_result` + original HAR response for that endpoint
- **Action:**
  - **Differential analysis:** compare response body structure to the original HAR response. Structural match on a different resource ID = strong IDOR signal.
  - **Semgrep scan:** run secret/PII patterns against response body (API keys, emails, tokens, SSNs, credit card patterns)
  - LLM judgment: did the `expected_signal` fire? Was sensitive data returned that shouldn't be?
- **Output:** If confirmed finding, appends to `vulnerabilities_found` with evidence

#### Node F: `generate_report` (Python + LLM)
- **Input:** `vulnerabilities_found`
- **Action:** Formats a Markdown report structured around **OWASP API Security Top 10** categories. Each finding includes:
  - Vulnerability class + severity
  - Affected endpoint
  - Request/response diff (evidence)
  - Reproduction `curl` command
  - Suggested remediation
- **Output:** Writes `report.md` to disk

---

### 3. Routing (Edges)

```
START
  → filter_traffic
  → enrich_context
  → analyze_request
  → execute_attack
  → evaluate_response
  → [conditional]
        if more hypotheses for current endpoint AND budget not exhausted → execute_attack
        elif more requests in har_data → increment index → analyze_request
        else → generate_report
  → END
```

---

### 4. Per-Endpoint Request Budgeting

Each endpoint gets its own `EndpointBudget` instance rather than a single global cap. This prevents one complex endpoint (e.g. `/api/admin/users`) from consuming the entire run budget, while ensuring simpler endpoints still get tested.

```python
DEFAULT_MAX_HYPOTHESES_PER_ENDPOINT = 10

def should_fire(hypothesis: AttackHypothesis, budgets: dict) -> bool:
    key = hypothesis.original_request_id
    budget = budgets.get(key, EndpointBudget(endpoint_key=key))
    payload_hash = hash_request(hypothesis.modified_request)
    if budget.hypotheses_fired >= budget.max_hypotheses:
        return False
    if payload_hash in budget.seen_payload_hashes:
        return False  # dedup: don't retry equivalent payloads
    return True
```

---

### 5. Observability with LangSmith

Every node execution is automatically traced via LangSmith, giving you:
- Per-node latency and token usage
- The exact prompt sent to the LLM for each `analyze_request` / `evaluate_response` call
- Full state diffs between nodes
- Replay of any specific run for debugging

Set up:
```bash
export LANGCHAIN_TRACING_V2=true
export LANGCHAIN_API_KEY=<your-key>
export LANGCHAIN_PROJECT="har-vuln-scanner"
```

No code changes needed — LangGraph integrates with LangSmith automatically when these env vars are set.

---

### 6. Secret & PII Detection (Semgrep)

After each `execute_attack`, the response body is scanned using Semgrep rules from the `secrets` and `generic` rulesets:

```python
import subprocess, json

def semgrep_scan_response(body: str, tmp_path: str) -> list[dict]:
    with open(tmp_path, "w") as f:
        f.write(body)
    result = subprocess.run(
        ["semgrep", "--config=p/secrets", "--config=p/generic", "--json", tmp_path],
        capture_output=True, text=True
    )
    findings = json.loads(result.stdout).get("results", [])
    return findings
```

Findings feed directly into `evaluate_response` as additional evidence.

---

### 7. Token Expiry Handling

HAR JWTs are often short-lived. Before firing any request, the executor should:
1. Decode the JWT (no verification needed — just inspect `exp`)
2. If expired: mark the result as `INCONCLUSIVE_TOKEN_EXPIRED` rather than treating a 401 as "access control working correctly"
3. Optionally: if re-auth credentials are provided in config, attempt token refresh before firing

---

### 8. LLM Prompt Strategy

Prompts frame the tool as an **authorized QA automation system performing access control validation** — this is accurate and reduces refusal rates on safety-filtered cloud models.

If cloud model refusal rates are too high (especially for token manipulation or privilege escalation hypotheses), the architecture supports swapping the LLM endpoint to a local model via **Ollama** — the LangGraph node just targets a different `ChatOpenAI`-compatible endpoint. No other code changes needed.

---

### 9. LLM Provider Abstraction

- Nodes call llm.complete(prompt, response_model) — they don't know or care which backend is running
- Adding a new provider = implement one class, no node changes
- Structured output (Pydantic) works consistently across providers

Abstract class example:

from abc import ABC, abstractmethod
from pydantic import BaseModel
from typing import Type, TypeVar

T = TypeVar("T", bound=BaseModel)

# --- Abstract Class Definition ---

class BaseLLMProvider(ABC):
    """
    All LLM providers must implement this interface.
    Nodes only interact with this — never with provider SDKs directly.
    """

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Raw text completion. Used internally."""
        ...

    def structured_complete(self, system_prompt: str, user_prompt: str, response_model: Type[T]) -> T:
        """
        Complete and parse into a Pydantic model.
        Adds JSON schema instruction to system prompt automatically.
        Retries once on parse failure with corrective prompt.
        """
        schema = response_model.model_json_schema()
        augmented_system = (
            f"{system_prompt}\n\n"
            f"Respond ONLY with valid JSON matching this schema:\n{schema}\n"
            f"No explanation, no markdown fences, just JSON."
        )
        raw = self.complete(augmented_system, user_prompt)
        try:
            return response_model.model_validate_json(raw)
        except Exception as e:
            # One retry with corrective context
            correction_prompt = (
                f"Your previous response failed validation: {e}\n"
                f"Original response: {raw}\n"
                f"Return corrected JSON only."
            )
            raw2 = self.complete(augmented_system, correction_prompt)
            return response_model.model_validate_json(raw2)

# --- DeepInfra (OpenAI-compatible endpoint) ---
class DeepInfraProvider(BaseLLMProvider):
    def __init__(self, model: str, api_key: str):
        # DeepInfra exposes an OpenAI-compatible API
        self.client = OpenAI(
            base_url="https://api.deepinfra.com/v1/openai",
            api_key=api_key,
        )
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content


# --- Custom/Local LLM ---
# Adapt this to whatever your custom LLM expects.
# If it's OpenAI-compatible, just subclass DeepInfraProvider with your base_url.
# If it has a custom schema, implement complete() accordingly.
import httpx

class CustomLLMProvider(BaseLLMProvider):
    def __init__(self, base_url: str, api_key: str = None, model: str = None):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        response = httpx.post(
            f"{self.base_url}/v1/chat/completions",  # adjust path as needed
            json=payload,
            headers=self.headers,
            timeout=60,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

---

## Output Example: Report Structure

```markdown
# API Vulnerability Report — app.example.com
Generated: 2025-XX-XX | Scope: api.example.com

## Summary
| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 3 |

---

## Finding 1 — IDOR via User ID Substitution [CRITICAL]
**Category:** OWASP API3:2023 - Broken Object Level Authorization
**Endpoint:** GET /api/v1/users/{id}/profile

**Evidence:**
- Original request used `user_id=1042` (authenticated user)
- Modified request used `user_id=1041`
- Response: 200 OK — returned full profile of a different user including email, phone, address

**Reproduction:**
\`\`\`bash
curl -H "Authorization: Bearer <token>" https://api.example.com/api/v1/users/1041/profile
\`\`\`

**Suggested Fix:** Validate that the authenticated user's ID matches the requested resource ID server-side. Never rely on client-supplied IDs without authorization checks.
```

---

## Future Extensions (Not in Scope v1)

- **Multi-user session support:** run the same endpoint with tokens from two different user roles to catch horizontal privilege escalation
- **OpenAPI/Swagger ingestion:** supplement HAR with the app's API spec to discover undocumented endpoints
- **CI integration:** run as a GitHub Action against a staging environment on each deploy
