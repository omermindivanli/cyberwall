from __future__ import annotations

import builtins

import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from cyberwall.core.evaluator import decide
from cyberwall.core.lint import lint_policy
from cyberwall.core.models import (
    DecisionKind,
    Effect,
    FlowPolicy,
    Policy,
    Request,
    Rule,
    RuleWhen,
    SessionFlag,
    SessionState,
    ToolClass,
    ToolDefinition,
)
from cyberwall.core.normalize import normalize_host, normalize_request, path_glob_match
from cyberwall.core.policy import PolicyError, load_policy_text, policy_json_schema


def policy(rules: tuple[Rule, ...] = (), mode: str = "enforce") -> Policy:
    return Policy(
        version=1,
        mode=mode,
        variables={"HOME": "/home/agent", "WORKSPACE": "/workspace"},
        tools={
            "read_file": ToolDefinition.model_validate({"class": "read"}),
            "write_file": ToolDefinition.model_validate({"class": "write"}),
            "terminal": ToolDefinition.model_validate({"class": "exec"}),
            "web_extract": ToolDefinition.model_validate({"class": "network"}),
            "memory": ToolDefinition.model_validate({"class": "memory"}),
        },
        sensitive_paths=("**/.env", "**/.ssh/**", "**/*.pem", "~/.aws/**"),
        rules=rules,
        flow=FlowPolicy(
            block_egress_when=(
                SessionFlag.SENSITIVE_DATA_READ,
                SessionFlag.UNTRUSTED_CONTENT_SEEN,
            )
        ),
    )


def test_default_deny_and_unknown_tool() -> None:
    result = decide(Request(tool="unknown_tool", args={}), policy())
    assert result.decision == DecisionKind.DENY
    assert result.reason_code == "DEFAULT_DENY"
    assert result.tool_class == ToolClass.UNKNOWN


def test_allow_path_positive_and_traversal_blocked() -> None:
    allowed = Rule(
        id="workspace-read", effect=Effect.ALLOW, tool="read_file", paths=("/workspace/**",)
    )
    configured = policy((allowed,))
    good = decide(
        Request(tool="read_file", args={"path": "${WORKSPACE}/notes/todo.txt"}), configured
    )
    bad = decide(
        Request(tool="read_file", args={"path": "${WORKSPACE}/../.ssh/id_rsa"}), configured
    )
    assert good.decision == DecisionKind.ALLOW
    assert good.normalized_paths == ("/workspace/notes/todo.txt",)
    assert bad.decision == DecisionKind.DENY


def test_deny_overrides_approval_and_allow_independent_of_order() -> None:
    allow = Rule(id="allow", effect=Effect.ALLOW, tool="web_extract", hosts=("*.example.com",))
    approval = Rule(
        id="approval",
        effect=Effect.REQUIRE_APPROVAL,
        tool="web_extract",
        hosts=("api.example.com",),
    )
    deny = Rule(id="deny", effect=Effect.DENY, tool="web_extract", hosts=("api.example.com",))
    outputs = {
        decide(
            Request(tool="web_extract", args={"url": "https://api.example.com/x"}), policy(order)
        ).decision
        for order in ((allow, approval, deny), (deny, allow, approval), (approval, deny, allow))
    }
    assert outputs == {DecisionKind.DENY}


def test_approval_precedes_allow() -> None:
    rules = (
        Rule(id="allow", effect=Effect.ALLOW, tool="memory"),
        Rule(id="ask", effect=Effect.REQUIRE_APPROVAL, tool="memory"),
    )
    result = decide(Request(tool="memory", args={}), policy(rules))
    assert result.decision == DecisionKind.REQUIRE_APPROVAL
    assert result.rule_id == "ask"


def test_audit_never_blocks_and_marks_would_block() -> None:
    result = decide(Request(tool="unknown_tool", args={}), policy(mode="audit"))
    assert result.decision == DecisionKind.ALLOW
    assert result.would_block is True


def test_taint_flow_denies_egress_when_all_flags_present() -> None:
    state = SessionState(
        flags=frozenset({SessionFlag.UNTRUSTED_CONTENT_SEEN, SessionFlag.SENSITIVE_DATA_READ})
    )
    result = decide(
        Request(tool="web_extract", args={"url": "https://collector.invalid"}), policy(), state
    )
    assert result.decision == DecisionKind.DENY
    assert result.reason_code == "EGRESS_AFTER_TAINT"


def test_every_path_in_allow_must_fit_but_deny_matches_any() -> None:
    allowed = Rule(id="allow", effect=Effect.ALLOW, tool="write_file", paths=("/workspace/**",))
    denied = Rule(id="deny-outside", effect=Effect.DENY, tool="write_file", paths=("/etc/**",))
    request = Request(tool="write_file", args={"paths": ["/workspace/a", "/etc/hosts"]})
    result = decide(request, policy((allowed, denied)))
    assert result.decision == DecisionKind.DENY
    assert result.rule_id == "deny-outside"


def test_unverified_arguments_require_explicit_allow() -> None:
    request = Request(tool="memory", args={"note": "some opaque value"})
    implicit = decide(request, policy((Rule(id="memory", effect=Effect.ALLOW, tool="memory"),)))
    explicit = decide(
        request,
        policy(
            (Rule(id="memory-ok", effect=Effect.ALLOW, tool="memory", unverified_args="allow"),)
        ),
    )
    assert implicit.decision == DecisionKind.DENY
    assert implicit.reason_code == "ARGS_UNVERIFIED"
    assert explicit.decision == DecisionKind.ALLOW
    assert "ARGS_UNVERIFIED" in explicit.flags


def test_compiled_invariants_cannot_be_overridden() -> None:
    allow = Rule(id="allow-sensitive", effect=Effect.ALLOW, tool="read_file", paths=("**",))
    result = decide(
        Request(tool="read_file", args={"path": "/home/agent/.aws/credentials"}), policy((allow,))
    )
    assert result.decision == DecisionKind.DENY
    assert result.reason_code == "SENSITIVE_PATH_READ"


def test_shell_metacharacters_require_explicit_rule_opt_in() -> None:
    request = Request(tool="terminal", args={"command": "echo safe; echo second"})
    allow = Rule(id="terminal", effect=Effect.ALLOW, tool="terminal", unverified_args="allow")
    blocked = decide(request, policy((allow,)))
    opted_in = decide(
        request,
        policy((allow.model_copy(update={"allow_shell_metacharacters": True}),)),
    )
    assert blocked.decision == DecisionKind.DENY
    assert blocked.reason_code == "SHELL_METACHARACTER"
    assert opted_in.decision == DecisionKind.ALLOW


def test_policy_linter_reports_broad_allow_and_conflict() -> None:
    issues = lint_policy(
        policy(
            (
                Rule(id="allow-everything", effect=Effect.ALLOW, tool="web_extract", hosts=("*",)),
                Rule(id="deny-everything", effect=Effect.DENY, tool="web_extract", hosts=("*",)),
            )
        )
    )
    assert {issue.code for issue in issues} == {"BROAD_ALLOW", "RULE_CONFLICT"}


def test_request_and_policy_snapshot_input_mutations() -> None:
    args = {"nested": {"path": "/workspace/file"}}
    request = Request(tool="read_file", args=args)
    args["nested"]["path"] = "/etc/passwd"
    assert "workspace" in request.args

    tools = {"read_file": ToolDefinition.model_validate({"class": "read"})}
    configured = Policy(version=1, tools=tools)
    tools.clear()
    assert dict(configured.tools)["read_file"].tool_class == ToolClass.READ


def test_normalizers_cover_url_trick_idna_ipv6_and_shell() -> None:
    assert normalize_host("https://ok.com@evil.com/a") == ("evil.com", True)
    assert normalize_host("ExAmPlE.COM.") == ("example.com", False)
    assert normalize_host("https://[2001:db8::1]/") == ("2001:db8::1", False)
    assert normalize_host("https://bücher.example") == ("xn--bcher-kva.example", False)
    result = decide(
        Request(tool="terminal", args={"command": "echo hello; cyberwall approve x"}), policy()
    )
    assert result.decision == DecisionKind.DENY
    assert result.reason_code == "SHELL_METACHARACTER"


def test_ip_literal_hosts_require_an_explicit_cidr_rule() -> None:
    request = Request(tool="web_extract", args={"url": "https://192.0.2.8/"})
    exact = Rule(id="exact", effect=Effect.ALLOW, tool="web_extract", hosts=("192.0.2.8",))
    cidr = Rule(id="cidr", effect=Effect.ALLOW, tool="web_extract", hosts=("192.0.2.0/24",))
    assert decide(request, policy((exact,))).decision == DecisionKind.DENY
    assert decide(request, policy((cidr,))).decision == DecisionKind.ALLOW


def test_glob_supports_recursive_and_single_segment_wildcards() -> None:
    assert path_glob_match("/workspace/**/file?.txt", "/workspace/a/b/file1.txt")
    assert not path_glob_match("/workspace/*/file.txt", "/workspace/a/b/file.txt")


def test_policy_loader_rejects_unknown_keys_and_unsafe_yaml() -> None:
    with pytest.raises(PolicyError):
        load_policy_text("version: 1\nmode: enforce\nunknown: true\n")
    with pytest.raises(PolicyError):
        load_policy_text("!!python/object/apply:os.system ['echo unsafe']")
    with pytest.raises(PolicyError):
        load_policy_text(
            "version: 1\nmode: enforce\ndefault: deny\nrules:\n"
            "  - id: memory\n    effect: allow\n    unverified_args: alow\n"
        )
    assert "additionalProperties" in str(policy_json_schema())
    schema = policy_json_schema()
    assert schema["properties"]["tools"]["type"] == "object"
    assert schema["properties"]["variables"]["type"] == "object"


def test_json_schema_agrees_with_policy_model_for_modes_and_defaults() -> None:
    schema = policy_json_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    cases = (
        ({"version": 1}, True),
        ({"version": 1, "mode": "enforce", "default": "deny"}, True),
        ({"version": 1, "mode": "enforce", "default": "allow"}, False),
        ({"version": 1, "default": "allow"}, False),
        ({"version": 1, "mode": "audit", "default": "allow"}, True),
        ({"version": 1, "mode": "unknown", "default": "deny"}, False),
    )
    for document, valid in cases:
        assert validator.is_valid(document) is valid
        if valid:
            Policy.model_validate(document)
        else:
            with pytest.raises(ValidationError):
                Policy.model_validate(document)


def test_core_decision_does_not_open_files(monkeypatch: pytest.MonkeyPatch) -> None:
    configured = policy()
    request = Request(tool="web_extract", args={"url": "https://docs.example.com"})

    def fail_open(*args: object, **kwargs: object) -> object:
        raise AssertionError("core attempted file I/O")

    monkeypatch.setattr(builtins, "open", fail_open)
    assert decide(request, configured).decision == DecisionKind.DENY


@given(st.text(min_size=1, max_size=80))
def test_malformed_path_is_deterministically_denied(path: str) -> None:
    configured = policy()
    request = Request(tool="read_file", args={"path": path})
    assert decide(request, configured) == decide(request, configured)


@given(
    st.lists(
        st.text(
            alphabet=st.characters(blacklist_characters="/$~", blacklist_categories=("Cs",)),
            max_size=12,
        ),
        max_size=8,
    )
)
def test_path_normalization_is_idempotent(parts: list[str]) -> None:
    configured = policy()
    path = "/workspace/" + "/".join(parts)
    request = Request(tool="read_file", args={"path": path})
    normalized = normalize_request(request, configured)[0][0]
    second = normalize_request(Request(tool="read_file", args={"path": normalized}), configured)[0][
        0
    ]
    assert normalized == second


@given(st.permutations(["allow", "deny", "require_approval"]))
def test_rule_order_independence(effects: tuple[str, ...]) -> None:
    rules = tuple(Rule(id=effect, effect=Effect(effect), tool="memory") for effect in effects)
    result = decide(Request(tool="memory", args={}), policy(rules))
    assert result.decision == DecisionKind.DENY


def test_rules_without_tool_selector_and_session_condition() -> None:
    global_allow = Rule(id="global", effect=Effect.ALLOW)
    requires_taint = Rule(
        id="tainted-only",
        effect=Effect.DENY,
        when=RuleWhen(session_has=(SessionFlag.UNTRUSTED_CONTENT_SEEN,)),
    )
    request = Request(tool="some_tool", args={})
    assert decide(request, policy((global_allow,))).decision == DecisionKind.ALLOW
    assert decide(request, policy((global_allow, requires_taint))).decision == DecisionKind.ALLOW
    tainted = SessionState(flags=frozenset({SessionFlag.UNTRUSTED_CONTENT_SEEN}))
    result = decide(request, policy((global_allow, requires_taint)), tainted)
    assert result.decision == DecisionKind.DENY


def test_path_and_host_selectors_need_matching_arguments() -> None:
    path_rule = Rule(id="path", effect=Effect.ALLOW, tool="read_file", paths=("/workspace/**",))
    host_rule = Rule(id="host", effect=Effect.ALLOW, tool="web_extract", hosts=("docs.example",))
    no_path = decide(Request(tool="read_file", args={}), policy((path_rule,)))
    wrong_path = decide(
        Request(tool="read_file", args={"path": "/tmp/a"}),
        policy((Rule(id="deny-tmp", effect=Effect.DENY, tool="read_file", paths=("/etc/**",)),)),
    )
    no_host = decide(Request(tool="web_extract", args={}), policy((host_rule,)))
    wrong_host = decide(
        Request(tool="web_extract", args={"url": "https://other.invalid"}), policy((host_rule,))
    )
    results = (no_path, wrong_path, no_host, wrong_host)
    assert all(item.decision == DecisionKind.DENY for item in results)


def test_terminal_allowlist_matches_executable_and_each_argument() -> None:
    rule = Rule(
        id="terminal-echo",
        effect=Effect.ALLOW,
        tool="terminal",
        executables=("echo",),
        argument_patterns=("hello*",),
    )
    allowed = decide(
        Request(tool="terminal", args={"command": "echo hello-world"}), policy((rule,))
    )
    blocked_executable = decide(
        Request(tool="terminal", args={"command": "rm hello-world"}), policy((rule,))
    )
    blocked_argument = decide(
        Request(tool="terminal", args={"command": "echo secret.txt"}), policy((rule,))
    )
    missing_command = decide(Request(tool="terminal", args={}), policy((rule,)))
    assert allowed.decision == DecisionKind.ALLOW
    assert blocked_executable.decision == DecisionKind.DENY
    assert blocked_argument.decision == DecisionKind.DENY
    assert missing_command.decision == DecisionKind.DENY


def test_attached_exec_capable_flag_is_blocked_but_benign_flag_is_allowed() -> None:
    rule = Rule(
        id="node-readonly",
        effect=Effect.ALLOW,
        tool="terminal",
        executables=("node",),
        argument_patterns=("--version", "--eval=*"),
    )
    benign = decide(Request(tool="terminal", args={"command": "node --version"}), policy((rule,)))
    dangerous = decide(
        Request(tool="terminal", args={"command": "node --eval=console.log(123)"}),
        policy((rule,)),
    )
    assert benign.decision == DecisionKind.ALLOW
    assert dangerous.decision == DecisionKind.DENY
    assert dangerous.reason_code == "EXEC_CAPABLE_FLAG"


def test_argument_patterns_cannot_approve_a_tool_by_name_alone() -> None:
    rule = Rule(id="terminal", effect=Effect.ALLOW, argument_patterns=("terminal",))
    assert (
        decide(Request(tool="terminal", args={"command": "rm -rf /"}), policy((rule,))).decision
        == DecisionKind.DENY
    )
    assert decide(Request(tool="browser", args={}), policy((rule,))).decision == DecisionKind.DENY


def test_mismatched_tool_selector_and_invalid_cidr_host_deny() -> None:
    mismatched = Rule(id="other-tool", effect=Effect.ALLOW, tool="write_file")
    request = Request(tool="read_file", args={"path": "/workspace/a"})
    assert decide(request, policy((mismatched,))).decision == DecisionKind.DENY
    invalid_host_rule = Rule(
        id="cidr",
        effect=Effect.ALLOW,
        tool="web_extract",
        hosts=("192.0.2.0/24",),
    )
    invalid_host = Request(tool="web_extract", args={"url": "https://docs.example"})
    assert decide(invalid_host, policy((invalid_host_rule,))).decision == DecisionKind.DENY


def test_audit_default_allow_and_approval_flow() -> None:
    audit_allow = Policy(version=1, mode="audit", default=Effect.ALLOW)
    allowed = decide(Request(tool="unknown", args={}), audit_allow)
    assert allowed.decision == DecisionKind.ALLOW
    assert allowed.reason_code == "DEFAULT_ALLOW"

    state = SessionState(
        flags=frozenset({SessionFlag.UNTRUSTED_CONTENT_SEEN, SessionFlag.SENSITIVE_DATA_READ})
    )
    flow = FlowPolicy(
        block_egress_when=(
            SessionFlag.UNTRUSTED_CONTENT_SEEN,
            SessionFlag.SENSITIVE_DATA_READ,
        ),
        effect=Effect.REQUIRE_APPROVAL,
    )
    configured = policy().model_copy(update={"flow": flow})
    approval = decide(
        Request(tool="web_extract", args={"url": "https://collector.invalid"}), configured, state
    )
    assert approval.decision == DecisionKind.REQUIRE_APPROVAL


def test_compiled_invariants_cover_exec_write_and_userinfo() -> None:
    cases = (
        (
            Request(tool="terminal", args={"command": "cyberwall approve abc"}),
            "SELF_PROTECTION_EXEC",
        ),
        (
            Request(tool="write_file", args={"path": "/workspace/.hermes/config.yaml"}),
            "SELF_PROTECTION_WRITE",
        ),
        (Request(tool="terminal", args={"command": "python -c print(1)"}), "EXEC_CAPABLE_FLAG"),
        (Request(tool="terminal", args={"command": "python -cprint(1)"}), "EXEC_CAPABLE_FLAG"),
        (Request(tool="web_extract", args={"url": "https://u:p@evil.invalid"}), "URL_USERINFO"),
    )
    for request, expected in cases:
        result = decide(request, policy((Rule(id="allow", effect=Effect.ALLOW),)))
        assert result.decision == DecisionKind.DENY
        assert result.reason_code == expected


def test_malformed_inputs_fail_closed() -> None:
    configured = policy()
    malformed = Request(tool="read_file", args={}).model_copy(update={"args": object()})
    assert decide(malformed, configured).reason_code == "MALFORMED_REQUEST"
    for path in ("~private/file", "${MISSING}/file"):
        request = Request(tool="read_file", args={"path": path})
        assert decide(request, configured).decision == DecisionKind.DENY
    relative = Request(tool="read_file", args={"path": "relative/file"})
    assert decide(relative, Policy(version=1)).decision == DecisionKind.DENY
    for url in ("https:///missing", "https://bad%host.invalid"):
        request = Request(tool="web_extract", args={"url": url})
        assert decide(request, configured).decision == DecisionKind.DENY
    command = Request(tool="terminal", args={"command": "echo 'unfinished"})
    assert decide(command, configured).decision == DecisionKind.DENY
    for args in (
        {"path": "~/.ssh/key"},
        {"path": ["/workspace/a", 7]},
        {"path": None},
    ):
        request = Request(tool="read_file", args=args)
        assert decide(request, Policy(version=1)).decision == DecisionKind.DENY


def test_path_glob_memoization_branch() -> None:
    assert path_glob_match("/a/**/**/b", "/a/x/y/b")


def test_parent_segments_at_root_stay_at_root() -> None:
    request = Request(tool="read_file", args={"path": "/../../workspace/a"})
    assert normalize_request(request, policy())[0] == ("/workspace/a",)
