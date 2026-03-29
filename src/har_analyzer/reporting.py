from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Iterable, Tuple

from .models import Finding, RunRecord
from .redaction import redact_value


def write_reports(run: RunRecord, findings: Iterable[Finding], unsafe: bool = False) -> Tuple[str, str]:
    findings_list = list(findings)
    Path(run.artifact_dir).mkdir(parents=True, exist_ok=True)
    json_path = os.path.join(run.artifact_dir, "%s-findings.json" % run.run_id)
    markdown_path = os.path.join(run.artifact_dir, "%s-report.md" % run.run_id)

    serializable = [finding.to_dict() for finding in findings_list]
    if not unsafe:
        serializable = redact_value(serializable)
    Path(json_path).write_text(json.dumps(serializable, indent=2, ensure_ascii=False), encoding="utf-8")
    Path(markdown_path).write_text(_render_markdown(run, serializable), encoding="utf-8")
    return markdown_path, json_path


def _render_markdown(run: RunRecord, findings) -> str:
    counter = Counter(item.get("severity", "unknown").lower() for item in findings)
    lines = [
        "# HAR Analyzer Report",
        "",
        "Generated Run: %s" % run.run_id,
        "Status: %s" % run.status,
        "Scope: %s" % ", ".join(run.target_domains),
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity in ["critical", "high", "medium", "low", "unknown"]:
        count = counter.get(severity, 0)
        if count:
            lines.append("| %s | %d |" % (severity.title(), count))
    if not findings:
        lines.append("| None | 0 |")
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                "",
                "## Finding %d - %s" % (index, finding.get("title", "Untitled")),
                "",
                "**Category:** %s" % ", ".join(finding.get("owasp", [])),
                "**Severity:** %s" % finding.get("severity", "unknown"),
                "**Endpoint:** %s" % finding.get("endpoint", ""),
                "",
                "**Summary:** %s" % finding.get("summary", ""),
                "",
                "**Expected Signal:** %s" % finding.get("expected_signal", ""),
                "",
                "**Reproduction:**",
                "```bash",
                finding.get("reproduction_curl", ""),
                "```",
                "",
                "**Remediation:** %s" % finding.get("remediation", ""),
                "",
                "**Evidence:**",
                "```json",
                json.dumps(finding.get("evidence", []), indent=2, ensure_ascii=False),
                "```",
            ]
        )
    return "\n".join(lines) + "\n"

