#!/usr/bin/env python3
"""
CI/CD Compliance & Quality Linter — CLI entry point.

Usage:
    python main.py --path . --output-json audit.json --strict

Exit codes:
    0  — clean repo, or (non-strict) only warnings found
    1  — one or more critical/high/medium violations found
         (or, with --strict, any finding at all)
"""

from __future__ import annotations

import argparse
import sys

from linter.scanner import scan_directory
from linter import reporter


BLOCKING_SEVERITIES = {"critical", "high", "medium", "low"}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compliance-linter",
        description="Scan a repository for secrets, unpinned dependencies, and insecure endpoints, "
                    "mapped to ISO/IEC 27001:2022 and SOC 2 controls.",
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Root directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--output-json",
        metavar="FILE",
        help="Write a machine-readable audit JSON to FILE for ingestion into SIEM/GRC tooling.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat 'warning'-severity findings as blocking too (exit 1 on any finding).",
    )
    return parser


def determine_exit_code(result, strict: bool) -> int:
    if result.total_violations == 0:
        return 0
    if strict:
        return 1
    blocking = [f for f in result.findings if f.severity in BLOCKING_SEVERITIES]
    return 1 if blocking else 0


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    result = scan_directory(args.path)

    reporter.print_terminal_report(result, strict=args.strict)
    reporter.write_github_step_summary(result)

    if args.output_json:
        reporter.export_json(result, args.output_json)
        print(f"\nJSON audit report written to: {args.output_json}")

    exit_code = determine_exit_code(result, args.strict)
    if exit_code != 0:
        print(
            f"\n❌ Compliance gate FAILED — {result.total_violations} violation(s) found. "
            f"Merge blocked."
        )
    else:
        print("\n✅ Compliance gate PASSED.")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
