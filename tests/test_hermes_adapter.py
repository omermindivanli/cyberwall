from __future__ import annotations

from pathlib import Path
from typing import Any

from cyberwall.adapters.hermes.plugin import register


class FakeContext:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.hooks: dict[str, Any] = {}

    def get_config(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback


def _policy(path: Path, body: str | None = None) -> Path:
    policy_text = body or (
        "version: 1\n"
        "default: deny\n"
        "tools:\n"
        "  sample_tool:\n"
        "    class: read\n"
        "rules:\n"
        "  - id: allow-sample\n"
        "    effect: allow\n"
        "    tool: sample_tool\n"
    )
    path.write_text(policy_text, encoding="utf-8")
    return path


def _hook(policy: Path, evidence: Path):
    ctx = FakeContext({"policy_path": str(policy), "evidence_path": str(evidence)})
    register(ctx)
    assert set(ctx.hooks) == {"pre_tool_call_final"}
    return ctx.hooks["pre_tool_call_final"]


def test_hermes_adapter_registers_final_hook_and_allows_matching_policy(tmp_path: Path) -> None:
    hook = _hook(_policy(tmp_path / "policy.yaml"), tmp_path / "events.sqlite3")

    assert hook("sample_tool", {}, session_id="s", task_id="t") is None


def test_hermes_adapter_blocks_denied_tool_and_records_evidence(tmp_path: Path) -> None:
    hook = _hook(_policy(tmp_path / "policy.yaml"), tmp_path / "events.sqlite3")

    result = hook("unknown_tool", {"path": "/tmp/private"})

    assert result == {"action": "block", "message": "Blocked by Cyberwall policy"}


def test_hermes_adapter_fails_closed_when_policy_is_missing(tmp_path: Path) -> None:
    hook = _hook(tmp_path / "missing-policy.yaml", tmp_path / "events.sqlite3")

    result = hook("sample_tool", {})

    assert result == {
        "action": "block",
        "message": "Blocked because Cyberwall could not verify policy",
    }
