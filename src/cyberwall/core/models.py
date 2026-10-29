"""Immutable inputs and outputs for Cyberwall's deterministic policy engine."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class DecisionKind(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ToolClass(StrEnum):
    READ = "read"
    WRITE = "write"
    EXEC = "exec"
    NETWORK = "network"
    MEMORY = "memory"
    PRIVILEGED = "privileged"
    UNKNOWN = "unknown"


class SessionFlag(StrEnum):
    UNTRUSTED_CONTENT_SEEN = "untrusted_content_seen"
    SENSITIVE_DATA_READ = "sensitive_data_read"


JsonScalar = str | int | float | bool | None


def _freeze_json(value: Any) -> str:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("arguments must be a JSON object with string keys")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def thaw_json(value: str) -> Any:
    """Return a detached JSON-shaped copy of the immutable canonical argument string."""
    return json.loads(value)


class Request(FrozenModel):
    tool: str = Field(min_length=1, max_length=256)
    args: str = "{}"
    session_id: str = Field(default="", max_length=512)
    task_id: str = Field(default="", max_length=512)

    @field_validator("args", mode="before")
    @classmethod
    def freeze_args(cls, value: Any) -> Any:
        return _freeze_json(value)


class ToolDefinition(FrozenModel):
    tool_class: ToolClass = Field(alias="class")


class RuleWhen(FrozenModel):
    session_has: tuple[SessionFlag, ...] = ()


class Rule(FrozenModel):
    id: str = Field(min_length=1, max_length=128)
    effect: Effect
    tool: str | tuple[str, ...] | None = None
    paths: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    when: RuleWhen | None = None
    unverified_args: str | None = None
    allow_shell_metacharacters: bool = False
    argument_patterns: tuple[str, ...] = ()


class FlowPolicy(FrozenModel):
    block_egress_when: tuple[SessionFlag, ...] = ()
    egress_classes: tuple[ToolClass, ...] = (ToolClass.NETWORK, ToolClass.EXEC)
    effect: Effect = Effect.DENY


class UntrustedSources(FrozenModel):
    classes: tuple[ToolClass, ...] = ()
    paths: tuple[str, ...] = ()


class Policy(FrozenModel):
    version: int = Field(ge=1)
    mode: str = "enforce"
    default: Effect = Effect.DENY
    on_evidence_failure: str = "block"
    variables: tuple[tuple[str, str], ...] = ()
    tools: tuple[tuple[str, ToolDefinition], ...] = ()
    sensitive_paths: tuple[str, ...] = ()
    untrusted_sources: UntrustedSources = Field(default_factory=UntrustedSources)
    rules: tuple[Rule, ...] = ()
    flow: FlowPolicy = Field(default_factory=FlowPolicy)

    @field_validator("variables", mode="before")
    @classmethod
    def freeze_variables(cls, value: Any) -> Any:
        return tuple(sorted(value.items())) if isinstance(value, dict) else value

    @field_validator("tools", mode="before")
    @classmethod
    def freeze_tools(cls, value: Any) -> Any:
        return tuple(sorted(value.items())) if isinstance(value, dict) else value

    @field_validator("on_evidence_failure")
    @classmethod
    def valid_evidence_failure_mode(cls, value: str) -> str:
        if value not in {"block", "allow"}:
            raise ValueError("on_evidence_failure must be block or allow")
        return value

    @field_validator("mode")
    @classmethod
    def valid_mode(cls, value: str) -> str:
        if value not in {"audit", "enforce"}:
            raise ValueError("mode must be audit or enforce")
        return value

    @field_validator("default")
    @classmethod
    def enforce_default_deny(cls, value: Effect, info: Any) -> Effect:
        if info.data.get("mode", "enforce") == "enforce" and value != Effect.DENY:
            raise ValueError("default must be deny in enforce mode")
        return value


class SessionState(FrozenModel):
    flags: frozenset[SessionFlag] = frozenset()


class Decision(FrozenModel):
    decision: DecisionKind
    rule_id: str | None = None
    reason_code: str
    would_block: bool = False
    tool_class: ToolClass = ToolClass.UNKNOWN
    normalized_paths: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    argv: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
