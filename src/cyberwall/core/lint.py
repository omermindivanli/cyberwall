"""Deterministic structural policy checks; no user-supplied regular expressions."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Effect, Policy, Rule


@dataclass(frozen=True)
class LintIssue:
    code: str
    severity: str
    rule_id: str | None
    message: str


def _selector(rule: Rule) -> tuple[object, ...]:
    return (
        rule.tool,
        rule.paths,
        rule.hosts,
        rule.executables,
        rule.when,
        rule.unverified_args,
        rule.argument_patterns,
    )


def lint_policy(policy: Policy) -> tuple[LintIssue, ...]:
    issues: list[LintIssue] = []
    seen: dict[tuple[object, ...], Rule] = {}
    for rule in sorted(policy.rules, key=lambda item: item.id):
        if rule.effect == Effect.ALLOW:
            broad = any(pattern in {"**", "*", "/**"} for pattern in rule.paths)
            broad = broad or any(pattern == "*" for pattern in rule.hosts)
            broad = broad or any(pattern in {"*", "**"} for pattern in rule.executables)
            broad = broad or any(pattern in {"*", "**"} for pattern in rule.argument_patterns)
            if broad:
                issues.append(
                    LintIssue(
                        "BROAD_ALLOW",
                        "warning",
                        rule.id,
                        "allow rule has an unrestricted path, host, executable, or argument glob",
                    )
                )
        selector = _selector(rule)
        previous = seen.get(selector)
        if previous is not None and previous.effect != rule.effect:
            issues.append(
                LintIssue(
                    "RULE_CONFLICT",
                    "warning",
                    rule.id,
                    f"selector also matches rule {previous.id} with effect {previous.effect.value}",
                )
            )
        elif previous is not None:
            issues.append(
                LintIssue(
                    "DUPLICATE_RULE",
                    "warning",
                    rule.id,
                    f"duplicates selector in rule {previous.id}",
                )
            )
        else:
            seen[selector] = rule
    return tuple(issues)
