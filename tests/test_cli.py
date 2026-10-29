from __future__ import annotations

import json
from pathlib import Path

from cyberwall.cli import main
from cyberwall.core.models import Decision, DecisionKind, Request, ToolClass
from cyberwall.evidence.store import EvidenceStore


def test_eval_command_prints_deterministic_decision_json(tmp_path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("version: 1\nmode: enforce\ndefault: deny\n", encoding="utf-8")
    result = main(["eval", "--policy", str(policy_path), "--tool", "unknown", "--args", "{}"])
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["decision"] == "DENY"
    assert output["reason_code"] == "DEFAULT_DENY"


def test_invalid_request_does_not_echo_raw_arguments(tmp_path, capsys) -> None:
    secret = "CANARY-CLI-REQUEST-SECRET"
    result = main(
        [
            "eval",
            "--policy",
            str(tmp_path / "policy.yaml"),
            "--tool",
            "read_file",
            "--args",
            f'{{"secret":"{secret}","not_json":NaN}}',
        ]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert secret not in captured.out + captured.err


def test_invalid_policy_does_not_echo_raw_values(tmp_path, capsys) -> None:
    secret = "CANARY-CLI-POLICY-SECRET"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(f"version: 1\nmode: enforce\nsecret: {secret}\n", encoding="utf-8")
    result = main(["eval", "--policy", str(policy_path), "--tool", "read_file", "--args", "{}"])
    captured = capsys.readouterr()
    assert result == 2
    assert secret not in captured.out + captured.err


def test_malformed_yaml_does_not_echo_raw_values(tmp_path, capsys) -> None:
    secret = "CANARY-MALFORMED-YAML-SECRET"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        f"version: 1\nsecret: {secret}\n  invalid: indentation\n", encoding="utf-8"
    )
    result = main(["eval", "--policy", str(policy_path), "--tool", "read_file", "--args", "{}"])
    captured = capsys.readouterr()
    assert result == 2
    assert secret not in captured.out + captured.err


def test_policy_lint_warns_about_overbroad_allow(tmp_path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "version: 1\nmode: enforce\ndefault: deny\ntools:\n"
        "  web_extract:\n    class: network\nrules:\n"
        "  - id: everything\n    effect: allow\n    tool: web_extract\n    hosts: ['*']\n",
        encoding="utf-8",
    )
    result = main(["policy", "lint", str(policy_path)])
    assert result == 0
    assert "BROAD_ALLOW" in capsys.readouterr().out


def test_schema_command_prints_json_schema(capsys) -> None:
    assert main(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["properties"]["tools"]["type"] == "object"
    checked_in_schema = Path(__file__).parents[1] / "schemas" / "policy.schema.json"
    assert json.loads(checked_in_schema.read_text(encoding="utf-8")) == schema


def test_evidence_report_and_verify_commands_are_redacted(tmp_path, capsys) -> None:
    database = tmp_path / "evidence.db"
    canary = "CANARY-REPORT-11"
    request = Request(tool="read_file", args={"path": f"/workspace/{canary}"})
    decision = Decision(
        decision=DecisionKind.DENY,
        reason_code="SENSITIVE_PATH_READ",
        tool_class=ToolClass.READ,
        normalized_paths=(f"/workspace/{canary}",),
    )
    with EvidenceStore(database) as store:
        store.append(request, decision, policy_sha256="d" * 64, mode="enforce")

    assert main(["report", "last", "--database", str(database)]) == 0
    last_output = capsys.readouterr().out
    assert "BLOCKED  read_file" in last_output
    assert canary not in last_output

    assert main(["report", "summary", "--database", str(database), "--format", "json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["event_count"] == 1
    assert summary["decisions"] == {"DENY": 1}

    assert main(["evidence", "verify", "--database", str(database)]) == 0
    assert capsys.readouterr().out == "evidence chain: valid\n"
