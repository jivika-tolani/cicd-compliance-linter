"""
linter/reporter.py

Renders a ScanResult two ways:
  1. A human-readable terminal report (falls back to plain ANSI if
     `rich` isn't installed, so the tool degrades gracefully).
  2. An audit-ready Markdown block written to $GITHUB_STEP_SUMMARY
     when running inside GitHub Actions.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List

from linter.scanner import ScanResult, Finding

try:
    from rich.console import Console
    from rich.table import Table
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


_SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "warning": "yellow",
}

_ANSI_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "warning": "\033[33m",
}
_ANSI_RESET = "\033[0m"


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    from linter.config import SEVERITY_ORDER
    order = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (order.get(f.severity, 99), f.file, f.line))


def print_terminal_report(result: ScanResult, strict: bool = False) -> None:
    findings = _sorted_findings(result.findings)

    if _RICH_AVAILABLE:
        console = Console()
        console.rule("[bold]CI/CD Compliance & Quality Linter[/bold]")
        console.print(
            f"Files scanned: [bold]{result.files_scanned}[/bold]   "
            f"Files skipped: {result.files_skipped}   "
            f"Total violations: [bold]{result.total_violations}[/bold]"
        )
        if not findings:
            console.print("[bold green]No violations found. Repository is clean.[/bold green]")
            return

        table = Table(show_lines=False)
        table.add_column("File", overflow="fold")
        table.add_column("Line", justify="right")
        table.add_column("Severity")
        table.add_column("Violation", overflow="fold")
        table.add_column("GRC Control(s)", overflow="fold")

        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity, "white")
            table.add_row(
                f.file,
                str(f.line) if f.line else "-",
                f"[{color}]{f.severity.upper()}[/{color}]",
                f"{f.violation}  [dim]({f.rule_id})[/dim]",
                ", ".join(f.grc_controls),
            )
        console.print(table)
    else:
        print("=" * 70)
        print("CI/CD Compliance & Quality Linter")
        print("=" * 70)
        print(
            f"Files scanned: {result.files_scanned}   "
            f"Files skipped: {result.files_skipped}   "
            f"Total violations: {result.total_violations}"
        )
        if not findings:
            print("No violations found. Repository is clean.")
            return
        for f in findings:
            color = _ANSI_COLOR.get(f.severity, "")
            print(
                f"{color}[{f.severity.upper()}]{_ANSI_RESET} {f.file}:{f.line or '-'} "
                f"— {f.violation} ({f.rule_id})"
            )
            print(f"    Controls: {', '.join(f.grc_controls)}")
            print(f"    Fix: {f.remediation}")


def write_github_step_summary(result: ScanResult) -> None:
    """
    If running inside GitHub Actions, append a Markdown audit report
    to the file referenced by $GITHUB_STEP_SUMMARY so it renders
    directly in the PR / run summary view.
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    findings = _sorted_findings(result.findings)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = []
    lines.append("## 🛡️ Compliance & Quality Audit Report")
    lines.append("")
    lines.append(f"**Audit Timestamp (UTC):** {timestamp}")
    lines.append(f"**Files Scanned:** {result.files_scanned}  ")
    lines.append(f"**Total Violations:** {result.total_violations}")
    lines.append("")

    if not findings:
        lines.append("✅ **No violations found.** Repository meets baseline compliance checks.")
    else:
        lines.append("| File | Line | Severity | Violation | Mapped GRC Control | Suggested Remediation |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            controls = "<br>".join(f.grc_controls)
            violation = f"{f.violation} (`{f.rule_id}`)"
            line_no = str(f.line) if f.line else "—"
            lines.append(
                f"| `{f.file}` | {line_no} | **{f.severity.upper()}** | {violation} | "
                f"{controls} | {f.remediation} |"
            )

    with open(summary_path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def export_json(result: ScanResult, output_path: str) -> None:
    payload = {
        "audit_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "total_violations": result.total_violations,
        "findings": [f.to_dict() for f in _sorted_findings(result.findings)],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
