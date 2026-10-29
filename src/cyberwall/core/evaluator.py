"""Pure policy evaluation with fixed deny-overrides semantics."""

from __future__ import annotations

import ipaddress
from fnmatch import fnmatchcase

from .models import (
    Decision,
    DecisionKind,
    Effect,
    Policy,
    Request,
    Rule,
    SessionState,
    ToolClass,
    thaw_json,
)
from .normalize import COMMAND_KEYS, normalize_path_pattern, normalize_request, path_glob_match


def _tool_matches(rule_tool: str | tuple[str, ...] | None, tool: str) -> bool:
    if rule_tool is None:
        return True
    candidates = (rule_tool,) if isinstance(rule_tool, str) else rule_tool
    return any(
        candidate.endswith("*") and tool.startswith(candidate[:-1]) or candidate == tool
        for candidate in candidates
    )


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:].lower()
        return host.endswith(suffix) and host != suffix[1:]
    if "/" in pattern:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return pattern.lower().rstrip(".") == host
    return False


def _rule_matches(
    rule: Rule,
    request: Request,
    paths: tuple[str, ...],
    hosts: tuple[str, ...],
    argv: tuple[str, ...],
    session: SessionState,
) -> bool:
    if not _tool_matches(rule.tool, request.tool):
        return False
    if rule.when is not None and not set(rule.when.session_has).issubset(session.flags):
        return False
    if rule.paths:
        if not paths:
            return False
        outcomes = [any(path_glob_match(pattern, path) for pattern in rule.paths) for path in paths]
        if not (any(outcomes) if rule.effect == Effect.DENY else all(outcomes)):
            return False
    if rule.hosts:
        if not hosts:
            return False
        outcomes = [any(_host_matches(pattern, host) for pattern in rule.hosts) for host in hosts]
        if not (any(outcomes) if rule.effect == Effect.DENY else all(outcomes)):
            return False
    if rule.executables or rule.argument_patterns:
        if not argv:
            return False
        executable = argv[0].rsplit("/", 1)[-1]
        if executable not in rule.executables:
            return False
        if any(
            not any(fnmatchcase(argument, pattern) for pattern in rule.argument_patterns)
            for argument in argv[1:]
        ):
            return False
    if rule.unverified_args == "allow" and not (paths or hosts or rule.executables):
        return True
    return True


def _invariant_reason(
    request: Request,
    tool_class: ToolClass,
    paths: tuple[str, ...],
    argv: tuple[str, ...],
    flags: tuple[str, ...],
    policy: Policy,
) -> str | None:
    if request.tool in {"terminal", "execute_code"} and argv:
        executable = argv[0].rsplit("/", 1)[-1]
        if executable == "cyberwall":
            return "SELF_PROTECTION_EXEC"
    if request.tool in {"write_file", "patch", "edit_file"}:
        protected = ("/.hermes/", "/cyberwall/", "/cyberwall.yaml", "/cyberwall.db", "/approvals")
        if any(any(segment in path for segment in protected) for path in paths):
            return "SELF_PROTECTION_WRITE"
    if tool_class == ToolClass.READ:
        if any(
            path_glob_match(normalize_path_pattern(pattern, policy), path)
            for pattern in policy.sensitive_paths
            for path in paths
        ):
            return "SENSITIVE_PATH_READ"
    if "EXEC_CAPABLE_FLAG" in flags and request.tool == "terminal":
        return "EXEC_CAPABLE_FLAG"
    if "URL_USERINFO" in flags:
        return "URL_USERINFO"
    return None


def decide(request: Request, policy: Policy, session: SessionState | None = None) -> Decision:
    """Decide without I/O, clocks, randomness, or mutable global state."""
    current_session = session or SessionState()
    try:
        if not request.tool or not isinstance(request.args, str):
            return Decision(decision=DecisionKind.DENY, reason_code="MALFORMED_REQUEST")
        paths, hosts, argv, flags = normalize_request(request, policy)
    except Exception:
        return Decision(decision=DecisionKind.DENY, reason_code="MALFORMED_REQUEST")

    tool_class = dict(policy.tools).get(request.tool)
    classified = tool_class.tool_class if tool_class else ToolClass.UNKNOWN
    invariant = _invariant_reason(request, classified, paths, argv, flags, policy)
    if invariant:
        return Decision(
            decision=DecisionKind.DENY,
            rule_id="compiled-invariant",
            reason_code=invariant,
            tool_class=classified,
            normalized_paths=paths,
            hosts=hosts,
            argv=argv,
            flags=flags,
        )

    if (
        policy.flow.block_egress_when
        and set(policy.flow.block_egress_when).issubset(current_session.flags)
        and classified in policy.flow.egress_classes
    ):
        effect = policy.flow.effect
        result = DecisionKind.DENY if effect == Effect.DENY else DecisionKind.REQUIRE_APPROVAL
        return _decision(
            result,
            "flow.egress_after_taint",
            "EGRESS_AFTER_TAINT",
            classified,
            paths,
            hosts,
            argv,
            flags,
            policy,
        )

    matching = [
        rule
        for rule in policy.rules
        if _rule_matches(rule, request, paths, hosts, argv, current_session)
    ]
    matching.sort(key=lambda rule: rule.id)
    if "SHELL_METACHARACTER" in flags and not any(
        rule.allow_shell_metacharacters for rule in matching
    ):
        return _decision(
            DecisionKind.DENY,
            "compiled-invariant",
            "SHELL_METACHARACTER",
            classified,
            paths,
            hosts,
            argv,
            flags,
            policy,
        )
    selected = next(
        (
            rule
            for effect in (Effect.DENY, Effect.REQUIRE_APPROVAL, Effect.ALLOW)
            for rule in matching
            if rule.effect == effect
        ),
        None,
    )
    if selected:
        result = {
            Effect.DENY: DecisionKind.DENY,
            Effect.REQUIRE_APPROVAL: DecisionKind.REQUIRE_APPROVAL,
            Effect.ALLOW: DecisionKind.ALLOW,
        }[selected.effect]
        if not (paths or hosts) and request.args != "{}":
            args_object = thaw_json(request.args)
            command_args_verified = (
                bool(argv)
                and bool(selected.executables)
                and isinstance(args_object, dict)
                and all(str(key).lower() in COMMAND_KEYS for key in args_object)
            )
            if not command_args_verified and selected.unverified_args != "allow":
                result = DecisionKind.DENY
                return _decision(
                    result,
                    selected.id,
                    "ARGS_UNVERIFIED",
                    classified,
                    paths,
                    hosts,
                    argv,
                    ("ARGS_UNVERIFIED",),
                    policy,
                )
            if not command_args_verified:
                flags = tuple(sorted((*flags, "ARGS_UNVERIFIED")))
        return _decision(
            result,
            selected.id,
            f"RULE_{selected.effect.value.upper()}",
            classified,
            paths,
            hosts,
            argv,
            flags,
            policy,
        )

    result = DecisionKind.DENY if policy.default == Effect.DENY else DecisionKind.ALLOW
    return _decision(
        result,
        None,
        "DEFAULT_DENY" if result == DecisionKind.DENY else "DEFAULT_ALLOW",
        classified,
        paths,
        hosts,
        argv,
        flags,
        policy,
    )


def _decision(
    kind: DecisionKind,
    rule_id: str | None,
    reason: str,
    tool_class: ToolClass,
    paths: tuple[str, ...],
    hosts: tuple[str, ...],
    argv: tuple[str, ...],
    flags: tuple[str, ...],
    policy: Policy,
) -> Decision:
    if policy.mode == "audit" and kind in {DecisionKind.DENY, DecisionKind.REQUIRE_APPROVAL}:
        return Decision(
            decision=DecisionKind.ALLOW,
            rule_id=rule_id,
            reason_code=reason,
            would_block=True,
            tool_class=tool_class,
            normalized_paths=paths,
            hosts=hosts,
            argv=argv,
            flags=flags,
        )
    return Decision(
        decision=kind,
        rule_id=rule_id,
        reason_code=reason,
        tool_class=tool_class,
        normalized_paths=paths,
        hosts=hosts,
        argv=argv,
        flags=flags,
    )
