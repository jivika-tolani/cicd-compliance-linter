"""
tests/test_scanner.py

Unit tests for the scanning engine. Uses the fixtures in
tests/fixtures/ to verify both the "clean repo → 0 findings" and
"bad repo → catches every intentional violation" paths, plus the
CLI's exit-code behavior via main.determine_exit_code.
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from linter.scanner import scan_directory
from linter import rules as rules_module
from main import determine_exit_code

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "clean_repo"
    repo.mkdir()
    shutil.copy(FIXTURES_DIR / "clean_code.py", repo / "app.py")
    shutil.copy(FIXTURES_DIR / "clean_requirements.txt", repo / "requirements.txt")
    return repo


@pytest.fixture
def bad_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "bad_repo"
    repo.mkdir()
    shutil.copy(FIXTURES_DIR / "bad_secrets.py", repo / "config.py")
    shutil.copy(FIXTURES_DIR / "bad_requirements.txt", repo / "requirements.txt")
    return repo


class TestCleanRepo:
    def test_no_findings(self, clean_repo):
        result = scan_directory(str(clean_repo))
        assert result.total_violations == 0

    def test_files_were_actually_scanned(self, clean_repo):
        result = scan_directory(str(clean_repo))
        assert result.files_scanned == 2

    def test_exit_code_is_zero(self, clean_repo):
        result = scan_directory(str(clean_repo))
        assert determine_exit_code(result, strict=False) == 0


class TestBadRepo:
    def test_finds_violations(self, bad_repo):
        result = scan_directory(str(bad_repo))
        assert result.total_violations > 0

    def test_detects_aws_key(self, bad_repo):
        result = scan_directory(str(bad_repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert rules_module.RULE_AWS_KEY.rule_id in rule_ids

    def test_detects_generic_secret(self, bad_repo):
        result = scan_directory(str(bad_repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert rules_module.RULE_GENERIC_SECRET.rule_id in rule_ids

    def test_detects_insecure_http(self, bad_repo):
        result = scan_directory(str(bad_repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert rules_module.RULE_INSECURE_HTTP.rule_id in rule_ids

    def test_detects_unpinned_dependencies(self, bad_repo):
        result = scan_directory(str(bad_repo))
        unpinned = [f for f in result.findings if f.rule_id == rules_module.RULE_UNPINNED_DEPENDENCY.rule_id]
        # requests, flask, django, click — all 4 lines in bad_requirements.txt are unpinned
        assert len(unpinned) == 4

    def test_every_finding_has_a_grc_mapping(self, bad_repo):
        result = scan_directory(str(bad_repo))
        for finding in result.findings:
            assert len(finding.grc_controls) > 0

    def test_exit_code_is_one(self, bad_repo):
        result = scan_directory(str(bad_repo))
        assert determine_exit_code(result, strict=False) == 1


class TestRequirementsParsing:
    def test_pinned_dependency_is_clean(self):
        findings = rules_module.parse_requirements_txt(["requests==2.31.0\n"])
        assert findings == []

    def test_unversioned_dependency_is_flagged(self):
        findings = rules_module.parse_requirements_txt(["requests\n"])
        assert len(findings) == 1
        assert findings[0]["package"] == "requests"

    def test_ge_operator_is_flagged(self):
        findings = rules_module.parse_requirements_txt(["flask>=2.0\n"])
        assert len(findings) == 1

    def test_comments_and_blank_lines_are_ignored(self):
        findings = rules_module.parse_requirements_txt(["# a comment\n", "\n", "requests==2.31.0\n"])
        assert findings == []


class TestPackageJsonParsing:
    def test_pinned_dependency_is_clean(self):
        content = '{"dependencies": {"lodash": "4.17.21"}}'
        assert rules_module.parse_package_json(content) == []

    def test_caret_range_is_flagged(self):
        content = '{"dependencies": {"lodash": "^4.17.21"}}'
        findings = rules_module.parse_package_json(content)
        assert len(findings) == 1
        assert findings[0]["package"] == "lodash"

    def test_wildcard_is_flagged(self):
        content = '{"devDependencies": {"eslint": "*"}}'
        findings = rules_module.parse_package_json(content)
        assert len(findings) == 1
