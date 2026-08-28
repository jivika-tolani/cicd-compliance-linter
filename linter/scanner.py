"""
linter/scanner.py

Walks a target directory, applies the rules from rules.py to every
scannable file, and returns a structured list of findings plus
summary counters. This module has no knowledge of terminal formatting
or GitHub-specific output — that's reporter.py's job.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any

from linter import config
from linter import rules as rules_module


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    rule_id: str
    violation: str
    grc_controls: List[str]
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    findings: List[Finding]
    files_scanned: int
    files_skipped: int

    @property
    def total_violations(self) -> int:
        return len(self.findings)

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]


def _is_ignored_dir(dirname: str) -> bool:
    return dirname in config.IGNORE_DIRS or dirname.endswith(".egg-info")


def _iter_scannable_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if not _is_ignored_dir(d)]
        for filename in filenames:
            if filename in config.IGNORE_FILES:
                continue
            full_path = Path(dirpath) / filename
            yield full_path


def _read_text(path: Path) -> List[str] | None:
    try:
        if path.stat().st_size > config.MAX_FILE_SIZE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.readlines()
    except (OSError, UnicodeDecodeError):
        return None


def _scan_generic_file(path: Path, rel_path: str, lines: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for line_no, line in enumerate(lines, start=1):
        for rule in rules_module.LINE_RULES:
            matched = False
            if rule.pattern is not None and rule.pattern.search(line):
                matched = True
            elif rule.extra_check is not None and rule.extra_check(line):
                matched = True
            if matched:
                findings.append(
                    Finding(
                        file=rel_path,
                        line=line_no,
                        severity=rule.severity,
                        rule_id=rule.rule_id,
                        violation=rule.title,
                        grc_controls=rule.grc_controls,
                        remediation=rule.remediation,
                    )
                )
    return findings


def _scan_requirements_txt(rel_path: str, lines: List[str]) -> List[Finding]:
    rule = rules_module.RULE_UNPINNED_DEPENDENCY
    findings = []
    for item in rules_module.parse_requirements_txt(lines):
        findings.append(
            Finding(
                file=rel_path,
                line=item["line_no"],
                severity=rule.severity,
                rule_id=rule.rule_id,
                violation=f"Unpinned dependency '{item['package']}' ({item['reason']})",
                grc_controls=rule.grc_controls,
                remediation=rule.remediation,
            )
        )
    return findings


def _scan_package_json(rel_path: str, lines: List[str]) -> List[Finding]:
    rule = rules_module.RULE_UNPINNED_DEPENDENCY
    content = "".join(lines)
    findings = []
    for item in rules_module.parse_package_json(content):
        findings.append(
            Finding(
                file=rel_path,
                line=0,  # package.json findings are field-level, not line-level
                severity=rule.severity,
                rule_id=rule.rule_id,
                violation=(
                    f"Unpinned dependency '{item['package']}' in {item['section']} "
                    f"({item['reason']})"
                ),
                grc_controls=rule.grc_controls,
                remediation=rule.remediation,
            )
        )
    return findings


def scan_directory(root_path: str) -> ScanResult:
    root = Path(root_path).resolve()
    findings: List[Finding] = []
    files_scanned = 0
    files_skipped = 0

    for full_path in _iter_scannable_files(root):
        rel_path = str(full_path.relative_to(root))
        filename = full_path.name
        ext = full_path.suffix

        is_dependency_file = filename in config.DEPENDENCY_FILES
        is_scannable_ext = ext in config.SCANNABLE_EXTENSIONS

        if not (is_dependency_file or is_scannable_ext):
            continue

        lines = _read_text(full_path)
        if lines is None:
            files_skipped += 1
            continue

        files_scanned += 1

        if filename == "requirements.txt":
            findings.extend(_scan_requirements_txt(rel_path, lines))
            # requirements.txt is still worth a generic pass (e.g. an
            # accidentally pasted token in a comment).
            findings.extend(_scan_generic_file(full_path, rel_path, lines))
        elif filename == "package.json":
            findings.extend(_scan_package_json(rel_path, lines))
        else:
            findings.extend(_scan_generic_file(full_path, rel_path, lines))

    return ScanResult(findings=findings, files_scanned=files_scanned, files_skipped=files_skipped)
