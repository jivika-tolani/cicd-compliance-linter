"""
linter/config.py

Central configuration: directories to ignore during traversal, file
extensions considered "scannable text", and severity level ordering
used for sorting findings and computing exit codes.
"""

from __future__ import annotations

# Directories that are never scanned. Matched against any path
# component, so "node_modules" excludes it anywhere in the tree.
IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "site-packages",
    ".eggs",
    ".egg-info",
    # Test fixtures intentionally contain fabricated violations to
    # verify detection logic (see tests/test_scanner.py) — they are
    # not production code and must never be treated as findings
    # against this repo's own compliance gate.
    "fixtures",
}

# Specific filenames to skip even if they otherwise match a scannable
# extension (e.g. lockfiles that legitimately pin exact hashes and are
# too large/noisy to line-scan).
IGNORE_FILES = {
    "package-lock.json",
    "poetry.lock",
    "Pipfile.lock",
}

# Extensions treated as generic scannable source/text for secret and
# insecure-endpoint detection (Rules 1, 2, 4).
#
# Note: .md is deliberately excluded. Documentation legitimately quotes
# example secrets/URLs (e.g. this project's own README explaining what
# NET001 detects), which produces noisy false positives against docs
# rather than real source. A doc-aware scanner would need to distinguish
# prose/code-fence context from an actual assignment — out of scope here.
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".yml", ".yaml", ".json", ".env", ".sh", ".bash", ".zsh",
    ".txt", ".cfg", ".ini", ".toml",
}

# Files handled by dedicated dependency parsers (Rule 3) rather than
# the generic line scanner.
DEPENDENCY_FILES = {
    "requirements.txt",
    "package.json",
}

# Severity ordering, low index = most severe. Used both for display
# ordering and for the --strict exit-code decision.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning"]

# Maximum file size (bytes) to attempt to read as text. Prevents the
# scanner from choking on stray binary files that slipped past the
# extension filter.
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB
