"""Hermes adapter plugin entrypoint; imported only by Hermes plugin loading."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
from pathlib import Path
from typing import Any

from cyberwall.core.evaluator import decide
from cyberwall.core.models import DecisionKind, Request, SessionState
from cyberwall.core.policy import load_policy_text
from cyberwall.evidence.store import EvidenceStore, append_with_failure_policy

logger = logging.getLogger("cyberwall.hermes")
_DEFAULT_POLICY = "~/.config/cyberwall/policy.yaml"
_DEFAULT_EVIDENCE = "~/.local/state/cyberwall/evidence.sqlite3"


def _configured_path(ctx: Any, name: str, default: str) -> Path:
    value = ctx.get_config(name, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid Cyberwall path setting")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("Cyberwall paths must be absolute or home-relative")
    return path


def _read_policy(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("policy must be a regular file")
        chunks: list[bytes] = []
        remaining = 1_048_577
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > 1_048_576:
            raise ValueError("policy exceeds the size limit")
        return content
    finally:
        os.close(descriptor)


def register(ctx: Any) -> None:
    """Register a final-argument policy gate. Missing/broken policy blocks by default."""

    def check_final_tool_call(
        tool_name: str, args: dict[str, Any], **kwargs: Any
    ) -> dict[str, str] | None:
        try:
            policy_path = _configured_path(ctx, "policy_path", _DEFAULT_POLICY)
            evidence_path = _configured_path(ctx, "evidence_path", _DEFAULT_EVIDENCE)
            raw_policy = _read_policy(policy_path)
            policy_text = raw_policy.decode("utf-8")
            policy = load_policy_text(policy_text)
            evidence_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            request = Request(
                tool=tool_name,
                args=args,
                session_id=str(kwargs.get("session_id", "")),
                task_id=str(kwargs.get("task_id", "")),
            )
            decision = decide(request, policy, SessionState())
            with EvidenceStore(evidence_path) as store:
                decision = append_with_failure_policy(
                    store,
                    request,
                    decision,
                    policy,
                    policy_sha256=hashlib.sha256(raw_policy).hexdigest(),
                    integration="hermes",
                )
            if decision.decision == DecisionKind.DENY:
                return {"action": "block", "message": "Blocked by Cyberwall policy"}
            if decision.decision == DecisionKind.REQUIRE_APPROVAL:
                return {"action": "block", "message": "Cyberwall approval is required"}
            return None
        except Exception:
            # Do not log policy contents, arguments, or exception text. Hermes must receive a veto.
            logger.error("Cyberwall policy check failed; tool call blocked")
            return {
                "action": "block",
                "message": "Blocked because Cyberwall could not verify policy",
            }

    ctx.register_hook("pre_tool_call_final", check_final_tool_call)
