"""Cyberwall command-line interface."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from cyberwall.core.evaluator import decide
from cyberwall.core.lint import lint_policy
from cyberwall.core.models import Request, SessionState
from cyberwall.core.policy import PolicyError, load_policy_text, policy_json_schema_text
from cyberwall.evidence.report import render_last, render_summary
from cyberwall.evidence.store import EvidenceStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberwall")
    commands = parser.add_subparsers(dest="command", required=True)

    evaluate = commands.add_parser("eval", help="evaluate one JSON tool request")
    evaluate.add_argument("--policy", type=Path, required=True)
    evaluate.add_argument("--tool", required=True)
    evaluate.add_argument("--args", default="{}", help="tool arguments as a JSON object")
    evaluate.add_argument("--session-id", default="")
    evaluate.add_argument("--task-id", default="")

    policy = commands.add_parser("policy", help="policy operations")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    lint = policy_commands.add_parser("lint", help="check policy structure and broad rules")
    lint.add_argument("path", type=Path)

    commands.add_parser("schema", help="print the JSON Schema for policy files")

    report = commands.add_parser("report", help="render local evidence")
    report.add_argument("report_kind", choices=("last", "summary"))
    report.add_argument("--database", type=Path, required=True)
    report.add_argument("--format", choices=("markdown", "json"), default="markdown")

    evidence = commands.add_parser("evidence", help="verify local evidence integrity")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    verify = evidence_commands.add_parser("verify", help="recompute the evidence hash chain")
    verify.add_argument("--database", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "schema":
        print(policy_json_schema_text())
        return 0
    if args.command in {"report", "evidence"}:
        if not args.database.is_file():
            print(f"cyberwall: evidence database not found: {args.database}", file=sys.stderr)
            return 2
        try:
            with EvidenceStore(args.database) as store:
                if args.command == "report":
                    events = store.events()
                    renderer = render_last if args.report_kind == "last" else render_summary
                    print(renderer(events, args.format))
                    return 0
                verified = store.verify()
        except (OSError, sqlite3.Error, ValueError) as error:
            print(f"cyberwall: evidence error: {error}", file=sys.stderr)
            return 2
        print("evidence chain: valid" if verified else "evidence chain: INVALID")
        return 0 if verified else 1
    try:
        policy = load_policy_text(
            args.policy.read_text(encoding="utf-8")
            if args.command == "eval"
            else args.path.read_text(encoding="utf-8")
        )
    except (OSError, PolicyError) as error:
        print(f"cyberwall: policy error: {error}", file=sys.stderr)
        return 2

    if args.command == "policy":
        issues = lint_policy(policy)
        for issue in issues:
            prefix = f"{issue.severity.upper()} {issue.code}"
            if issue.rule_id:
                prefix += f" rule={issue.rule_id}"
            print(f"{prefix}: {issue.message}")
        if not issues:
            print("policy: no issues")
        return 1 if any(issue.severity == "error" for issue in issues) else 0

    try:
        request_args = json.loads(args.args)
        request = Request(
            tool=args.tool,
            args=request_args,
            session_id=args.session_id,
            task_id=args.task_id,
        )
    except json.JSONDecodeError as error:
        print(
            f"cyberwall: invalid request JSON at line {error.lineno}, column {error.colno}",
            file=sys.stderr,
        )
        return 2
    except (ValidationError, ValueError):
        print("cyberwall: invalid request fields or arguments", file=sys.stderr)
        return 2
    result = decide(request, policy, SessionState())
    print(json.dumps(result.model_dump(mode="json"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
