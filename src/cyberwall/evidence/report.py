"""Redacted Markdown and JSON views of the local evidence store."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any


def render_last(events: list[dict[str, Any]], output_format: str = "markdown") -> str:
    if output_format not in {"markdown", "json"}:
        raise ValueError("format must be markdown or json")
    if not events:
        payload: dict[str, Any] = {"event": None}
    else:
        payload = {"event": events[-1]}
    if output_format == "json":
        return json.dumps(payload, sort_keys=True, indent=2)
    event = payload["event"]
    if event is None:
        return "No evidence events found."
    verb = "BLOCKED" if event["decision"] == "DENY" else event["decision"]
    return "\n".join(
        (
            f"{verb}  {event['tool']}  rule={event['rule_id'] or 'default'}",
            f"  reason       : {event['reason_code']}",
            f"  session      : sha256:{event['session_id']}"
            if event["session_id"]
            else "  session      : (none)",
            f"  args         : sha256:{event['args_sha256']}",
            f"  policy       : sha256:{event['policy_sha256']}",
            f"  evidence id  : {event['event_id']}",
        )
    )


def render_summary(events: list[dict[str, Any]], output_format: str = "markdown") -> str:
    if output_format not in {"markdown", "json"}:
        raise ValueError("format must be markdown or json")
    decisions = Counter(event["decision"] for event in events)
    reasons = Counter(event["reason_code"] for event in events)
    tools = Counter(event["tool"] for event in events)
    payload = {
        "event_count": len(events),
        "decisions": dict(sorted(decisions.items())),
        "reason_codes": dict(sorted(reasons.items())),
        "tools": dict(sorted(tools.items())),
    }
    if output_format == "json":
        return json.dumps(payload, sort_keys=True, indent=2)
    lines = [
        "# Cyberwall evidence summary",
        "",
        f"Events: {payload['event_count']}",
        "",
        "## Decisions",
        "",
        "| Decision | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {name} | {count} |" for name, count in payload["decisions"].items())
    lines.extend(("", "## Reason codes", "", "| Reason | Count |", "|---|---:|"))
    lines.extend(f"| {name} | {count} |" for name, count in payload["reason_codes"].items())
    lines.extend(("", "## Tools", "", "| Tool | Count |", "|---|---:|"))
    lines.extend(f"| {name} | {count} |" for name, count in payload["tools"].items())
    return "\n".join(lines)
