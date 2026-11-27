"""Command line interface for agent-perm-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import SEVERITY_RANK, VERSION, scan_manifests

TOOL = "agent-perm-guard"


def _print_json(payload) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=True))


def _print_report(report: dict) -> None:
    summary = report["summary"]
    print("%s %s  scan  %d manifest(s)" % (TOOL, VERSION, summary["manifests"]))
    for index, manifest in enumerate(report["manifests"], start=1):
        risk = manifest["risk"]
        print(
            "manifest %d/%d  %-46s risk=%-3d grade=%-1s tools=%d findings=%d"
            % (index, summary["manifests"], manifest["path"], risk["score"], risk["grade"], manifest["tools"], risk["total"])
        )
        for finding in manifest["findings"]:
            print(
                "  %-6s %-26s tool=%-14s %s"
                % (finding["severity"].upper(), finding["code"], finding["tool"] or "-", finding["message"])
            )
    print(
        "summary: %d manifest(s), %d finding(s): %d high, %d medium, %d low; max risk=%d grade=%s"
        % (
            summary["manifests"],
            summary["findings"],
            summary["counts"]["high"],
            summary["counts"]["medium"],
            summary["counts"]["low"],
            summary["max_risk_score"],
            summary["max_grade"],
        )
    )


def _gate(report: dict, fail_on: str) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_RANK[fail_on]
    count = sum(
        1
        for manifest in report["manifests"]
        for finding in manifest["findings"]
        if SEVERITY_RANK[finding["severity"]] >= threshold
    )
    if count:
        print("FAIL: %d finding(s) at or above severity %r" % (count, fail_on), file=sys.stderr)
        return 1
    print("PASS: no finding at or above severity %r" % fail_on)
    return 0


def _cmd_scan(args) -> int:
    report = scan_manifests(args.paths)
    report["paths"] = args.paths
    if args.json:
        _print_json(report)
    else:
        _print_report(report)
    return _gate(report, args.fail_on)


def _cmd_report(args) -> int:
    report = scan_manifests(args.paths)
    report["paths"] = args.paths
    if args.json:
        _print_json(report)
        return 0
    _print_report(report)
    fixes = []
    for manifest in report["manifests"]:
        for finding in manifest["findings"]:
            if finding["fix"] and (finding["code"], finding["fix"]) not in fixes:
                fixes.append((finding["code"], finding["fix"]))
    if fixes:
        print("least-privilege fixes:")
        for code, fix in fixes:
            print("  %-26s %s" % (code, fix))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Audit AI agent tool manifests (JSON/YAML) for risky permissions (stdlib-only).",
    )
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, handler, help_text in (
        ("scan", _cmd_scan, "audit manifests and print risk findings"),
        ("report", _cmd_report, "findings plus least-privilege fix suggestions"),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("paths", nargs="+", help="manifest files or directories (JSON/YAML)")
        sub.add_argument("--json", action="store_true", help="emit JSON")
        sub.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 when a finding at or above this severity exists")
        sub.set_defaults(func=handler)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print("error: path not found: %s" % exc, file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error: cannot parse manifest: %s" % exc, file=sys.stderr)
        return 2
