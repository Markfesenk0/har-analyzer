# UI Specification for UXPilot.ai - HAR Analyzer

**Project:** HAR Analyzer - Automated API Vulnerability Scanner
**Current UI:** Jinja2 HTML templates with inline CSS (functional but minimalist)
**Target:** Modern, professional UI for security analysts
**Tech Stack:** FastAPI backend, Jinja2 templates (can be upgraded to React/Vue if needed)

---

## Overview

The HAR Analyzer is a web application that helps security analysts discover logical vulnerabilities in APIs by:
1. Uploading HTTP Archive (HAR) files captured from real app usage
2. Generating attack hypotheses using LLM or heuristics
3. Executing those hypotheses against the API
4. Reporting confirmed vulnerabilities

The UI needs to support both **automated workflows** and **human-in-the-loop review** (step_mode).

---

## Page 1: Dashboard / Landing (Home)

### Purpose
Users configure and launch new scans, see history of previous runs.

### Layout
```
┌─────────────────────────────────────────────────────────────┐
│ [← Back] HAR Analyzer                                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ╔═══════════════════════════════════════╗  ┌───────────────┐
│  ║  NEW SCAN                             ║  │ RECENT RUNS   │
│  ║  ────────────────────────────────────  ║  │ ─────────────  │
│  ║  📄 Select HAR File                   ║  │ □ Run #1 (6h) │
│  ║  [HAR files dropdown ▼]               ║  │   23 findings │
│  ║                                        ║  │               │
│  ║  🎯 Target Domains                    ║  │ □ Run #2 (1d) │
│  ║  [Search] api.example.com             ║  │   5 findings  │
│  ║  [x] app.example.com                  ║  │               │
│  ║  [x] staging.example.com              ║  │ [View All]    │
│  ║                                        ║  └───────────────┘
│  ║  ⚙️  LLM Configuration                 │
│  ║  Provider: [OpenAI ▼]                 │
│  ║  Model: [gpt-4 ▼]                     │
│  ║                                        │
│  ║  Advanced Options                      │
│  ║  [►] Show / Hide                      │
│  ║                                        │
│  ║  [Start Scan] →                       │
│  ╚═══════════════════════════════════════╝
└─────────────────────────────────────────────────────────────┘
```

### Elements

#### **Section 1A: HAR File Selection**
- **Dropdown menu** showing available HAR files in `/HAR files/` directory
- **File upload** button alternative ("Or upload a file...")
- **File size displayed** next to filename (e.g., "freefit.har (2.3 MB)")
- **Preview on hover:** Shows first few requests (method, domains)

#### **Section 1B: Target Domain Selection**
- **Multi-select input** with autocomplete
- **Suggestions** auto-populated from HAR file's hosts (e.g., "Detected: api.example.com")
- **Remove button** (x) for each selected domain
- **All domains button** ("Use all detected")
- **Validation:** Warns if no domains selected

#### **Section 1C: LLM Configuration**
- **Provider selector:** Dropdown with options:
  - "Builtin Heuristics" (no LLM call, runs locally)
  - "OpenAI"
  - "DeepInfra"
  - "Custom Endpoint"
- **Model selector:** Updates based on provider
  - If "Builtin": Hidden (automatic)
  - If "OpenAI": [gpt-4-turbo, gpt-4, gpt-3.5-turbo]
  - If "DeepInfra": [meta-llama/llama-3.1-405b, mistral-large, etc.]
- **API Key field:** Placeholder "Uses env vars if available"

#### **Section 1D: Advanced Options (Collapsed by Default)**
- **Toggle:** "Step Mode" (require analyst approval before hypothesis execution)
  - Helpful tooltip: "Review generated attacks before firing them"
- **Toggle:** "Allow Unsafe Artifacts" (don't redact PII in outputs)
- **Slider:** Hypothesis per endpoint cap (default: 10, range: 1-50)
- **Slider:** Global request cap (default: 100, range: 10-500)
- **Slider:** Inter-request delay (default: 500ms, range: 100-5000ms)

#### **Section 1E: Recent Runs Sidebar**
- **List of last 5 runs** with:
  - Run ID (shortened UUID)
  - Time elapsed
  - Status badge (✅ Complete, 🔄 In Progress, ⏸ Paused, ❌ Failed)
  - Findings count with severity indicator
  - Quick action buttons: [View] [Resume/Retry]

### Actions
- **[Start Scan]** → Validates inputs, creates run, redirects to Run Detail page
- **[View All]** → Shows full runs history (paginated, filterable)
- **Provider/Model change** → Updates available options

### Validation & Errors
```
Error states:
- "No HAR file selected" → Red border on dropdown
- "No domains selected" → Disable [Start Scan], show warning
- "Model not available for provider" → Show warning
- "Invalid API key format" → Show on blur

Success: User clicks [Start Scan] → Redirects to /runs/{run_id}
```

---

## Page 2: Run Detail / In-Progress View

### Purpose
Monitor scan progress, review requests, approve hypotheses (if step_mode=true).

### Layout
```
┌────────────────────────────────────────────────────────────────┐
│ [← Back to Home] Run #a1b2c3d4          [⏸ Pause] [🔄 Resume]│
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│ Status Bar                                                       │
│ ████████████████░░░░░░░░░░░░░░░░░░░░░░░  45% Complete         │
│ Processed: 23/50 requests  |  Findings: 8  |  Est. 5m remaining  │
│                                                                  │
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Left Panel: Request List          Right Panel: Request Details │
│  ──────────────────────────────     ─────────────────────────── │
│  [Search/Filter ▼]                  📍 GET /api/users/1        │
│                                      Status: ⏳ ANALYZING       │
│  ✅ GET /api/users/123              Generated: 12 hypotheses   │
│     8 findings                                                  │
│  ⏳ POST /api/posts                  Original Request:          │
│     (approvals pending)              Method: GET               │
│                                      URL: https://api...       │
│  ⏸ DELETE /api/admin/users          Headers: Authorization...  │
│                                                                 │
│  ⭕ PATCH /api/profile               Response (200):           │
│                                      {                         │
│                                        "id": 123,              │
│                                        "email": "user@..."     │
│                                      }                         │
│                                                                 │
│                                      Generated Hypotheses:      │
│                                      [1] Try ID 124 (High)      │
│                                          [Approve] [Skip]       │
│                                      [2] Remove auth header     │
│                                          [Approve] [Skip]       │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### Key Elements

#### **Top Bar: Progress & Controls**
- **Run ID** (clickable to copy)
- **Status badge:** Complete / In Progress / Paused / Failed
- **Time elapsed** and **estimated time remaining**
- **Findings count** with severity breakdown (1 Critical, 2 High, 5 Medium)
- **Control buttons:**
  - [⏸ Pause Scan]
  - [🔄 Resume] (if paused)
  - [🛑 Cancel] (confirmation dialog)

#### **Progress Bar**
- Visual indicator: **requests processed / total requests**
- Color coding:
  - Blue = processing
  - Green = complete
  - Yellow = pending approval
- **Counts:** "23/50 requests analyzed, 8 findings"

#### **Left Panel: Request List**
- **Sortable/Filterable table:**
  - Columns: Status | Method | Path | Hypotheses | Findings
  - **Filters:**
    - Status (queued, analyzing, approved, executed, findings, skipped, error)
    - Method (GET, POST, PUT, PATCH, DELETE)
    - Has findings (yes/no)
    - Approval state (pending, approved, skipped)
  - **Sort by:** Status, findings count, request order

- **Row item styling:**
  - **✅ Green** = Complete, findings found
  - **⏳ Blue** = In progress
  - **⭕ Yellow** = Pending approval (step_mode)
  - **⏸ Gray** = Skipped
  - **❌ Red** = Error
  - **Findings badge:** Shows count (e.g., "8 findings")

#### **Right Panel: Request Details**
- **Request Header:** Endpoint (method + path), Status, H ypothesis count

- **Sections (collapsible):**
  1. **Original Request**
     - Method, URL, query params, headers, body
     - Syntax highlighting for JSON/XML
  2. **Original Response**
     - Status code, headers, body
     - Highlight sensitive patterns (emails, tokens)
  3. **Generated Hypotheses** (if not yet executed)
     - Card for each hypothesis:
       - Attack type badge (IDOR, BOLA, auth_bypass, etc.)
       - Severity badge (Critical, High, Medium, Low)
       - Mutation summary ("Try user_id=456")
       - Expected signal ("200 OK with user profile")
       - LLM reasoning (if available)
       - [Approve] [Skip] [View Details] buttons
  4. **Execution History** (once hypotheses run)
     - For each hypothesis:
       - Hypothesis details
       - Actual response status/headers/body
       - Outcome (access_control_issue, data_leaked, no_issue)
  5. **Findings** (if confirmed)
     - Vulnerability title, severity, OWASP category
     - Evidence (request/response diff)
     - Remediation suggestions

### Approval Workflow (when step_mode=true)

**State Machine:**
1. Request analyzed → Hypotheses generated → **Yellow pill "Pending Approval"**
2. Analyst reviews hypothesis details
3. Analyst clicks [Approve] → **Blue pill "Approved"** → Hypothesis executes
4. Or analyst clicks [Skip] → **Gray pill "Skipped"** → Hypothesis not executed
5. After execution → Shows response/outcome

**UI Affordances:**
- **Approval timeout indicator:** "Approval expires in 5m" if step_mode timeout is set
- **Bulk approval:** Quick action "Approve all pending" if multiple hypotheses exist
- **Quick skip buttons:** "Skip all low-confidence" filter

### Actions
- **[Approve]** hypothesis → Queues for execution
- **[Skip]** hypothesis → Marks as skipped, records reason in dropdown
- **[View Details]** → Expands hypothesis to show LLM reasoning and debug info
- **Click row** → Updates right panel with that request's details
- **[⏸ Pause]** → Pauses execution, saves state
- **[🔄 Resume]** → Resumes from pause
- **[🛑 Cancel]** → Stops scan (confirmation: "Discard in-progress work?")

### Real-time Updates
- **Progress bar** updates every 2 seconds
- **Request status** changes reflected immediately
- **New findings** appear highlighted in findings count
- **WebSocket or polling** for live updates (recommended: SSE)

---

## Page 3: Request Detail / Deep Dive

### Purpose
Analyst reviews single request in detail, sees all hypotheses, execution results, and findings.

### Layout
```
┌───────────────────────────────────────────────────────────┐
│ [← Back to Run] GET /api/users/123                        │
├───────────────────────────────────────────────────────────┤
│                                                             │
│ Status: ✅ COMPLETE   |   8 Hypotheses   |   3 Findings    │
│                                                             │
│ ╔════════════════════════════════════╗                     │
│ ║ ORIGINAL REQUEST                    ║                     │
│ ║ ──────────────────────────────────  ║                     │
│ ║ GET /api/v1/users/123 HTTP/1.1     ║                     │
│ ║                                     ║                     │
│ ║ Authorization: Bearer eyJhbGc...   ║  (Click to hide)    │
│ ║ Content-Type: application/json     ║                     │
│ ║ User-Agent: Mozilla...              ║                     │
│ ╚════════════════════════════════════╝                     │
│                                                             │
│ ╔════════════════════════════════════╗                     │
│ ║ ORIGINAL RESPONSE (200 OK)          ║                     │
│ ║ ──────────────────────────────────  ║                     │
│ ║ {                                   ║                     │
│ ║   "id": 123,                        ║  📋 Diff view       │
│ ║   "email": "alice@... [PII]         ║  🔍 Raw            │
│ ║   "phone": "+1 555... [PII]         ║                     │
│ ║   "role": "user"                    ║                     │
│ ║ }                                   ║                     │
│ ╚════════════════════════════════════╝                     │
│                                                             │
│ HYPOTHESES TIMELINE                                        │
│ ────────────────────────────────────                       │
│                                                             │
│ [1] IDOR: Try user_id=124 ┌─────────────────┐             │
│     Severity: HIGH         │ Expected: 200 + │             │
│     Status: ✅ EXECUTED    │ different user  │             │
│                            └─────────────────┘             │
│     📤 Modified Request:    📥 Response:                     │
│     GET /api/users/124     Status: 200 OK                  │
│     [same headers]         {id: 124, email...} ✅ MATCH    │
│                            [Diff view] [Raw]               │
│                                                             │
│     📋 FINDING CONFIRMED:                                   │
│     "IDOR via User ID Substitution"                        │
│     └─ Different user's profile returned                  │
│                                                             │
│ [2] Remove Auth Header     ┌─────────────────┐             │
│     Severity: CRITICAL      │ Expected: 401   │             │
│     Status: ✅ EXECUTED     │ Unauthorized    │             │
│                             └─────────────────┘             │
│     📤 Modified Request:    📥 Response:                     │
│     GET /api/users/123     Status: 403 Forbidden           │
│     [no Authorization]     (Auth working)                   │
│                                                             │
│     ✅ No vulnerability                                     │
│                                                             │
│ [3] Parameter Injection... [collapsed]                     │
│                                                             │
└───────────────────────────────────────────────────────────┘
```

### Key Elements

#### **Header**
- **Breadcrumb:** Run ID → Endpoint
- **Endpoint:** Method + Path
- **Summary badges:**
  - Status (Complete, In Progress, Error)
  - Hypotheses count
  - Findings count

#### **Original Request Block**
- **Format:** Code block with syntax highlighting
- **Copy button** (📋)
- **Show/Hide toggle** for sensitive headers
- **Highlighted values:** Authorization, API keys

#### **Original Response Block**
- **Format:** Code block with syntax highlighting
- **Tabs:** Formatted JSON | Raw | Headers
- **Redaction markers** for PII [EMAIL_REDACTED], [PHONE_REDACTED]
- **Size indicator:** "Response size: 1.2 KB"

#### **Hypotheses Timeline**
- **Vertical timeline view** (or accordion cards)
- **For each hypothesis:**
  - **Header:** Attack type badge | Severity badge | Status indicator
  - **Expected signal box:** What indicates success
  - **Modified request:** Side-by-side diff with original
  - **Actual response:** With status code
  - **Outcome:** "✅ MATCH - Vulnerability confirmed" OR "❌ No issue"
  - **Evidence:** If finding, show what was detected
  - **Debug link:** [View LLM prompt & reasoning]

#### **Findings Section**
- **List of confirmed vulnerabilities** for this request
- **Each finding shows:**
  - Title
  - OWASP category
  - Severity + Confidence
  - Remediation steps
  - Curl reproduction command
  - Edit button (analyst can adjust findings)

### Actions
- **[Copy]** request/response blocks
- **[Diff view]** toggles between unified/side-by-side diff
- **[Raw]** shows unformatted response
- **[Collapse/Expand]** hypothesis cards
- **[View LLM prompt]** → Opens modal with debug artifact
- **[Edit finding]** → Edit title/remediation
- **[Delete finding]** → Remove false positive
- **[Back to Run]** → Returns to run detail page

---

## Page 4: Reports / Findings Export

### Purpose
View final vulnerability report, export in multiple formats.

### Layout
```
┌──────────────────────────────────────────────────────────┐
│ Run #a1b2c3d4 - Report                                   │
│ Generated: 2025-03-28 14:32 UTC                           │
├──────────────────────────────────────────────────────────┤
│                                                            │
│ 📊 SUMMARY                                                 │
│ ────────────────────────────────────────────────────────  │
│ Critical:  1  │  High: 2  │  Medium: 5  │  Low: 3         │
│ Endpoints tested: 23  |  Vulnerabilities: 11               │
│                                                            │
│ [Download JSON] [Download PDF] [Download CSV] [Copy URL]  │
│                                                            │
├──────────────────────────────────────────────────────────┤
│                                                            │
│ CRITICAL FINDINGS                                          │
│                                                            │
│ [1] IDOR via User ID Substitution                         │
│     Endpoint: GET /api/users/{id}                         │
│     OWASP: API3:2023                                      │
│     Evidence:                                              │
│     - Modified user_id from 1042 → 1041                   │
│     - Received full profile of different user             │
│     Fix: Validate authenticated user owns resource        │
│                                                            │
│     Reproduction:                                          │
│     curl -H "Authorization: Bearer..." \                  │
│          https://api.example.com/api/users/1041           │
│                                                            │
│ HIGH FINDINGS                                              │
│ [2] Mass Assignment Attack...                             │
│ [3] Token Manipulation...                                 │
│                                                            │
│ MEDIUM FINDINGS                                            │
│ [4-8] ...                                                  │
│                                                            │
└──────────────────────────────────────────────────────────┘
```

### Sections
1. **Summary stats:** Severity breakdown, endpoints tested, etc.
2. **Export options:** JSON, PDF, CSV buttons
3. **Finding listings:** Grouped by severity, expandable
4. **Each finding includes:**
   - Title
   - Affected endpoint
   - OWASP category
   - Severity/Confidence
   - Evidence details
   - Remediation steps
   - Curl reproduction

### Actions
- **[Download PDF]** → Generates and downloads report.pdf
- **[Download JSON]** → Downloads findings as structured JSON
- **[Download CSV]** → For Excel/spreadsheet import
- **[Copy link]** → Generates shareable URL (if enabled)

---

## Component Library

### Common UI Components

#### **Badges**
```
Status:     ✅ Complete  |  🔄 In Progress  |  ⏸ Paused  |  ❌ Failed
Severity:   🔴 Critical  |  🟠 High  |  🟡 Medium  |  🟢 Low
Method:     GET  |  POST  |  PUT  |  PATCH  |  DELETE
Type:       IDOR  |  BOLA  |  Auth Bypass  |  ...
```

#### **Buttons**
- Primary: "Start Scan", "Approve", "Execute"
- Secondary: "Skip", "View Details", "Download"
- Danger: "Cancel Scan", "Delete"

#### **Code Blocks**
- Syntax highlighting for JSON, XML, curl, etc.
- Copy button
- Line numbers (optional)
- Collapsible sections

#### **Tables**
- Sortable columns
- Filterable
- Pagination (20 rows/page)
- Row hover effects

#### **Modals/Dialogs**
- Confirmation dialogs (Cancel Scan, Delete, etc.)
- Debug artifact viewer (code block in modal)
- Edit finding dialog

---

## Color Palette

From current design (warm earth tones):
```
Primary:      #165a57 (teal-green)
Primary Dark: #0f4644
Accent:       #b86736 (burnt orange)
Success:      #2d8a3a (dark green)
Warning:      #d97706 (amber)
Danger:       #a64b3a (brick red)
Background:   #f4efe8 (cream)
Surface:      #fffaf3 (off-white)
Text:         #201913 (dark brown)
Muted:        #6a5a4c (taupe)
```

---

## Mobile Responsiveness

**Breakpoints:**
- **Mobile (< 640px):** Stack panels vertically, collapse tables to card view
- **Tablet (640-1024px):** Adapt grid, maintain 2-column layout
- **Desktop (> 1024px):** Full layout with sidebars

**Key adaptations:**
- Collapse left sidebar on mobile (hamburger menu)
- Full-width request/response blocks
- Swipe/scroll for code blocks
- Sticky header with scroll

---

## Accessibility Requirements

- ♿ WCAG 2.1 Level AA compliance
- Keyboard navigation (Tab, Enter, Escape)
- Color not the only indicator (also use icons/text)
- Sufficient contrast ratios (7:1 for text)
- ARIA labels for interactive elements
- Screen reader support for tables/modals

---

## Performance Considerations

- **Pagination:** Load 20 requests at a time (avoid DOM bloat)
- **Real-time updates:** SSE or short-polling (not WebSocket unless necessary)
- **Code block syntax highlighting:** Client-side (Prism.js or similar)
- **Report generation:** Server-side (PDF/CSV), cache results
- **Image optimization:** No external images (use SVG icons)

---

## Next Steps for UXPilot.ai

When providing this spec to UXPilot.ai:
1. Clarify desired **framework/tech stack** (keep Jinja2 or upgrade to React?)
2. Ask about **design system** (component library, storybook, etc.)
3. Confirm **animation preferences** (micro-interactions, transitions, etc.)
4. Discuss **dark mode** support and implementation
5. Agree on **iteration timeline** (wireframes → mockups → implementation)
6. Specify any **existing brand guidelines** (fonts, spacing, etc.)

---

## Current Template Files

Your existing templates to be redesigned:
1. `src/har_analyzer/templates/index.html` → Dashboard / Landing
2. `src/har_analyzer/templates/run_detail.html` → Run Progress View
3. `src/har_analyzer/templates/request_detail.html` → Request Deep Dive

Suggested new templates:
4. `reports.html` → Reports/Findings View
5. `components/` directory for reusable components (badge, button, code-block, etc.)
