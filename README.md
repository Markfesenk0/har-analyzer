# HAR Analyzer

API security scanner that finds vulnerabilities by replaying and mutating HTTP traffic from HAR files.

I spend a lot of time poking at Android apps, looking at their API traffic, testing for broken access controls, injections, the usual stuff. A lot of that work is repetitive: capture the traffic, swap some IDs, remove an auth header, see what happens. So I built this to automate the boring parts. Point it at a HAR file, pick the domains you care about, and let it generate and test attack hypotheses across every endpoint.

It uses an LLM to figure out what's worth testing on each endpoint (IDOR, auth bypass, injection, mass assignment, SSRF, etc.), fires the mutated requests, then sends the results back to the LLM to separate real findings from false positives.

## Screenshots

> Coming soon

## How it works

1. **Load a HAR file** and scope it to specific target domains
2. **Analyse each endpoint** with an LLM that generates targeted attack hypotheses based on the request structure, parameters, and response data
3. **Execute the attacks** by sending mutated requests to the live API
4. **Validate findings** with a second LLM pass that compares the attack response against the original baseline to filter out false positives
5. **Report** confirmed vulnerabilities with full evidence, reproduction cURL commands, and OWASP mapping

There's also a hypotheses-only mode if you just want the analysis without firing live requests.

## Features

- Hypothesis generation for IDOR, BOLA, auth bypass, mass assignment, SQL/NoSQL injection, SSRF, rate limiting, business logic flaws
- Two-pass LLM validation to cut down on false positives
- Built-in heuristic mode that works without an API key (numeric ID swapping, UUID swapping, slug swapping, auth header removal)
- Web UI with live scan progress, per-hypothesis timeline, and request/response diffs
- Request console for manually replaying or tweaking requests right from the UI
- Notes system for annotating findings, requests, or entire runs
- Approval queue for reviewing hypotheses before they get executed
- Reports page with filtering by severity and export to JSON/Markdown
- Cross-endpoint intelligence: if NoSQL injection works on one endpoint, it prioritises that on others
- SSRF detection using public probe URLs (icanhazip.com, httpbin.org)
- Rate limit testing on authentication endpoints
- Token injection to replace expired JWTs in old HAR captures
- Secret/PII scanning in responses (API keys, JWTs, emails, phone numbers, credit cards, AWS keys)
- Automatic input sanitization before sending data to the LLM
- Encrypted API key storage on disk
- Works with any OpenAI-compatible LLM provider (DeepInfra, OpenAI, Anthropic, or custom)

## Quick start

### Prerequisites

- Python 3.11+
- An API key from [DeepInfra](https://deepinfra.com), OpenAI, Anthropic, or any OpenAI-compatible provider

### Install

```bash
git clone https://github.com/YOUR_USERNAME/har-analyzer.git
cd har-analyzer
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e .
```

### Configure

```bash
cp .env.example .env
# Edit .env with your API key and preferred model
```

### Run

```bash
python -m uvicorn src.har_analyzer.web:app --host 127.0.0.1 --port 8766
# Open http://127.0.0.1:8766
```

### Capture a HAR file

1. Open Chrome DevTools (F12), go to the Network tab
2. Check "Preserve log"
3. Use the target app
4. Right-click in the Network tab and "Save all as HAR with content"
5. Drop the `.har` file in the `HAR files/` directory

## Configuration

All settings can be configured through the web UI when starting a scan, or via environment variables in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `HAR_ANALYZER_LLM_PROVIDER` | `deepinfra` | Provider: `deepinfra`, `openai`, `anthropic`, `custom` |
| `HAR_ANALYZER_MODEL` | | Model for hypothesis generation |
| `HAR_ANALYZER_VALIDATION_MODEL` | (same as above) | Model for finding validation (can be cheaper) |
| `HAR_ANALYZER_LLM_API_KEY` | | API key for the provider |
| `HAR_ANALYZER_CONCURRENCY` | `4` | Parallel hypothesis execution |
| `HAR_ANALYZER_ENDPOINT_CAP` | `10` | Max hypotheses per endpoint |
| `HAR_ANALYZER_GLOBAL_CAP` | `100` | Max total attack requests per scan |
| `HAR_ANALYZER_INTER_REQUEST_DELAY_MS` | `500` | Delay between requests (ms) |
| `HAR_ANALYZER_STEP_MODE` | `false` | Require manual approval before each endpoint |
| `HAR_ANALYZER_AUTH_TOKEN` | | Fresh JWT to replace expired tokens from the HAR |
| `HAR_ANALYZER_LLM_TIMEOUT_SECONDS` | `60` | LLM request timeout |
| `HAR_ANALYZER_REDACT_BY_DEFAULT` | `false` | Auto-redact sensitive data in stored artifacts |

See [.env.example](.env.example) for the full list.

## Supported providers

Works with any OpenAI-compatible API. Tested with:

| Provider | Recommended models | Notes |
|----------|-------------------|-------|
| DeepInfra | `Qwen/Qwen3.5-122B-A10B`, `Llama-3.3-70B-Instruct-Turbo` | Low refusal rate for security content, fast, cheap |
| OpenAI | `gpt-4o`, `gpt-4o-mini` | Works well, pricier |
| Anthropic | `claude-sonnet-4-6` | Via OpenAI-compatible proxy |

You can use different models for hypothesis generation vs. finding validation. The validation step just compares JSON responses, so a cheaper/smaller model works fine there.

## Web UI pages

| Page | What it does |
|------|-------------|
| Dashboard | Scan overview, severity distribution, recent runs |
| New Scan | Pick a HAR, scope domains, choose provider/model, configure scan mode |
| Run Detail | Live scan progress with per-endpoint status and hypothesis timeline |
| Request Detail | Deep dive into a single endpoint: baseline, each hypothesis, LLM reasoning, diffs |
| Approval Queue | Review and approve/reject hypotheses before execution (step mode) |
| Reports | Browse all findings across runs, filter by severity |
| Notes | Persistent annotations on runs, requests, or hypotheses |
| Settings | View current configuration |
| Console | Send arbitrary HTTP requests through a server-side proxy (Ctrl+K) |

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## Project structure

```
src/har_analyzer/
  web.py              # FastAPI web UI and API routes
  graph.py            # Scan workflow orchestrator
  hypotheses.py       # LLM hypothesis generation and prompt engineering
  evaluation.py       # Finding validation and false positive filtering
  executor.py         # HTTP request execution, rate limit testing, SSRF protection
  models.py           # Data models (RunConfig, AttackHypothesis, Finding, etc.)
  config.py           # Configuration loading and API key encryption
  persistence.py      # SQLite storage for runs, hypotheses, findings, notes
  har.py              # HAR file parsing and domain filtering
  context.py          # Endpoint context building (neighbors, auth patterns, parameter analysis)
  redaction.py        # PII/secret redaction
  reporting.py        # Report generation (Markdown + JSON)
  token_injection.py  # JWT token refresh for stale HAR files
  token_registry.py   # Token discovery and tracking across requests
  templates/          # Jinja2 HTML templates
tests/                # pytest suite
```

## Tech stack

- Python, FastAPI, LangGraph
- Any OpenAI-compatible LLM API
- Jinja2 templates, vanilla JS
- SQLite

## Tested against

Built and tested against [OWASP crAPI](https://github.com/OWASP/crAPI), an intentionally vulnerable API. Successfully detected IDOR, NoSQL injection, auth bypass, broken function-level authorization, SSRF, and data exposure vulnerabilities.

## License

MIT
