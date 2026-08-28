"""
linter/rules.py

Defines every detection rule as a small, self-contained descriptor:
a regex (or parser function), a severity, and the GRC control(s) it
maps to. Keeping rules declarative here means scanner.py stays dumb
(it just applies rules) and new checks can be added without touching
traversal logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str                 # critical | high | medium | low | warning
    grc_controls: List[str]
    remediation: str
    pattern: Optional[re.Pattern] = None
    # Optional custom line-level validator, used when a raw regex match
    # needs a second check (e.g. excluding localhost from Rule 4).
    extra_check: Optional[Callable[[str], bool]] = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Rule 1 — AWS Access Key ID
# ---------------------------------------------------------------------------
RULE_AWS_KEY = Rule(
    rule_id="SEC001",
    title="Hardcoded AWS Access Key ID",
    severity="critical",
    grc_controls=["SOC 2 CC6.1", "ISO/IEC 27001:2022 A.8.24"],
    remediation=(
        "Remove the key from source, rotate it immediately in IAM, and "
        "load credentials via environment variables or a secrets manager "
        "(AWS Secrets Manager, Vault, GitHub Actions secrets)."
    ),
    pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
)

# ---------------------------------------------------------------------------
# Rule 2 — Generic secret / API key / bearer token assignment
# ---------------------------------------------------------------------------
# Matches assignments such as an api_key or secret variable set to a
# quoted literal of 12+ characters, or an Authorization: Bearer header
# carrying a long token — deliberately not written out as literal
# examples here so this file doesn't trip its own rule on self-scan.
_GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?:api[_-]?key|secret|token|passwd|password|access[_-]?key|client[_-]?secret)
    \s*[:=]\s*
    ['"]([A-Za-z0-9/_\-\.\+=]{12,})['"]
    """
)
_BEARER_TOKEN = re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}")

# Values that are obviously placeholders, not real secrets — skip these
# so the linter doesn't cry wolf on example/template files.
_PLACEHOLDER_VALUES = re.compile(
    r"(?i)^(changeme|your[_-]?api[_-]?key|xxx+|example|placeholder|"
    r"<[^>]+>|\$\{.*\}|test[_-]?key|dummy)$"
)


def _generic_secret_check(line: str) -> bool:
    for match in _GENERIC_SECRET_ASSIGNMENT.finditer(line):
        value = match.group(1)
        if not _PLACEHOLDER_VALUES.match(value):
            return True
    if _BEARER_TOKEN.search(line):
        return True
    return False


RULE_GENERIC_SECRET = Rule(
    rule_id="SEC002",
    title="Hardcoded secret, API key, or bearer token",
    severity="critical",
    grc_controls=["SOC 2 CC6.1", "ISO/IEC 27001:2022 A.8.24"],
    remediation=(
        "Move the value out of source control into environment variables, "
        "a .env file excluded via .gitignore, or a dedicated secrets manager. "
        "Rotate the credential if it has already been committed/pushed."
    ),
    # No single `pattern` — handled via extra_check in the scanner's
    # generic pass since it needs multi-pattern logic.
    extra_check=_generic_secret_check,
)

# ---------------------------------------------------------------------------
# Rule 4 — Insecure HTTP endpoint (defined here, applied before Rule 3
# since Rule 3 has dedicated dependency-file parsing below)
# ---------------------------------------------------------------------------
# Built via concatenation rather than a literal "http://" so this
# module's own source doesn't trip the very pattern it defines.
_HTTP_URL = re.compile(r"http" + r"://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s'\"<>]+")

RULE_INSECURE_HTTP = Rule(
    rule_id="NET001",
    title="Insecure HTTP endpoint (cleartext transport)",
    severity="medium",
    grc_controls=["ISO/IEC 27001:2022 A.8.20", "SOC 2 CC6.6"],
    remediation=(
        "Use https:// for all external endpoints so data in transit is "
        "encrypted. If this is an internal/dev-only endpoint, document the "
        "exception and confirm it never handles production traffic or "
        "credentials."
    ),
    pattern=_HTTP_URL,
)

# Rules applied line-by-line to any scannable file (order = display order)
LINE_RULES: List[Rule] = [RULE_AWS_KEY, RULE_GENERIC_SECRET, RULE_INSECURE_HTTP]


# ---------------------------------------------------------------------------
# Rule 3 — Unpinned dependencies
# ---------------------------------------------------------------------------
RULE_UNPINNED_DEPENDENCY = Rule(
    rule_id="DEP001",
    title="Unpinned or loosely-constrained dependency",
    severity="high",
    grc_controls=["SOC 2 CC8.1", "ISO/IEC 27001:2022 A.8.25"],
    remediation=(
        "Pin the dependency to an exact, tested version (e.g. package==1.2.3) "
        "so builds are reproducible and a compromised upstream release can't "
        "be pulled in silently. Update deliberately via a reviewed PR instead."
    ),
)

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-\[\]]*)\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s#;]*)\s*(?:;.*)?$"
)


def parse_requirements_txt(lines: List[str]) -> List[dict]:
    """
    Returns a list of {line_no, package, reason} for every dependency
    line in a requirements.txt that is unversioned or uses a
    non-exact operator (>=, ~=, etc.) per Rule 3's spec.
    """
    findings = []
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Skip VCS / URL-based requirements — out of scope for pin-checking.
        if "://" in line or line.startswith("git+"):
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        package, operator, version = match.groups()
        if operator is None or operator != "==":
            reason = (
                "no version pin" if operator is None
                else f"uses '{operator}' instead of an exact '=='"
            )
            findings.append({"line_no": i, "package": package, "reason": reason})
    return findings


def parse_package_json(content: str) -> List[dict]:
    """
    Returns a list of {package, reason, section} for every dependency
    in package.json's dependencies/devDependencies that is unversioned
    or uses a range operator (^, ~, *, >=, latest).
    """
    import json

    findings = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return findings

    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for package, version in deps.items():
            version = str(version).strip()
            if version == "*" or version.lower() == "latest":
                findings.append({"package": package, "reason": "wildcard/'latest' version", "section": section})
            elif version.startswith(("^", "~", ">=", ">")):
                findings.append({
                    "package": package,
                    "reason": f"range operator '{version[0]}' allows floating versions",
                    "section": section,
                })
    return findings
