from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from pydantic import ValidationError

from cyberwall.core.evaluator import decide
from cyberwall.core.models import Decision, DecisionKind, Policy, Request, ToolClass
from cyberwall.evidence.store import EvidenceStore, append_with_failure_policy


def sample_decision() -> Decision:
    return Decision(
        decision=DecisionKind.DENY,
        reason_code="DEFAULT_DENY",
        tool_class=ToolClass.UNKNOWN,
        normalized_paths=("/tmp/CANARY-CREDENTIAL-77/secret.txt",),
        hosts=("CANARY-CREDENTIAL-77.invalid",),
        argv=("/tmp/CANARY-CREDENTIAL-77",),
    )


def test_canary_secret_never_reaches_sqlite_bytes(tmp_path) -> None:
    database = tmp_path / "evidence.db"
    canary = "CANARY-CREDENTIAL-77"
    request = Request(
        tool=canary,
        args={"url": f"https://{canary}.invalid/{canary}", "path": f"/tmp/{canary}/secret.txt"},
        session_id=canary,
        task_id=canary,
    )
    decision = sample_decision()
    with EvidenceStore(database) as store:
        store.append(request, decision, policy_sha256="a" * 64, mode="enforce")
        assert store.verify()
        assert store.events()[0]["integration"] == "standalone"
        persisted_bytes = b"".join(
            path.read_bytes() for path in tmp_path.iterdir() if path.is_file()
        )
        assert canary.encode() not in persisted_bytes
    database_bytes = database.read_bytes()
    assert hashlib.sha256(request.args.encode()).hexdigest().encode() in database_bytes


def test_tamper_detection_fails_after_row_edit(tmp_path) -> None:
    database = tmp_path / "evidence.db"
    with EvidenceStore(database) as store:
        store.append(
            Request(tool="read_file", args={"path": "/tmp/file"}),
            sample_decision(),
            policy_sha256="b" * 64,
            mode="enforce",
        )
        assert store.verify()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE events SET event_json = replace(event_json, 'DEFAULT_DENY', 'ALLOW')"
        )
    with EvidenceStore(database) as store:
        assert not store.verify()


def test_concurrent_writers_keep_chain_valid(tmp_path) -> None:
    database = tmp_path / "evidence.db"
    stores = [EvidenceStore(database) for _ in range(8)]
    barrier = Barrier(len(stores))

    def append(worker: int) -> list[str]:
        store = stores[worker]
        barrier.wait()
        event_ids = []
        for index in range(8):
            request = Request(tool="read_file", args={"path": f"/workspace/{worker}-{index}.txt"})
            event_ids.append(
                store.append(
                    request, decide(request, _policy()), policy_sha256="c" * 64, mode="enforce"
                )
            )
        return event_ids

    try:
        with ThreadPoolExecutor(max_workers=len(stores)) as executor:
            event_ids = [
                event
                for worker_ids in executor.map(append, range(len(stores)))
                for event in worker_ids
            ]
        assert len(set(event_ids)) == 64
        for store in stores:
            assert store.verify()
            assert len(store.events()) == 64
    finally:
        for store in stores:
            store.close()


def test_tamper_detection_fails_after_internal_row_deletion(tmp_path) -> None:
    database = tmp_path / "evidence.db"
    with EvidenceStore(database) as store:
        for index in range(3):
            request = Request(tool="read_file", args={"path": f"/workspace/{index}.txt"})
            store.append(
                request, decide(request, _policy()), policy_sha256="f" * 64, mode="enforce"
            )
        assert store.verify()
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM events WHERE seq = 2")
    with EvidenceStore(database) as store:
        assert not store.verify()


def test_evidence_failure_policy_blocks_enforce_and_allows_audit(tmp_path, monkeypatch) -> None:
    request = Request(tool="write_file", args={"path": "/workspace/output.txt"})
    allowed = Decision(
        decision=DecisionKind.ALLOW, reason_code="RULE_ALLOW", tool_class=ToolClass.WRITE
    )
    denied = Decision(
        decision=DecisionKind.DENY, reason_code="RULE_DENY", tool_class=ToolClass.WRITE
    )
    store = EvidenceStore(tmp_path / "evidence.db")

    def fail(*args, **kwargs):
        raise OSError("synthetic unwritable evidence store")

    monkeypatch.setattr(store, "append", fail)
    enforced = append_with_failure_policy(
        store, request, allowed, Policy(version=1), policy_sha256="e" * 64
    )
    assert enforced.decision == DecisionKind.DENY
    assert enforced.reason_code == "EVIDENCE_FAILURE"

    with pytest.raises(ValidationError, match="Input should be 'block'"):
        Policy(version=1, on_evidence_failure="allow")

    audit = append_with_failure_policy(
        store, request, denied, Policy(version=1, mode="audit"), policy_sha256="e" * 64
    )
    assert audit.decision == DecisionKind.ALLOW
    assert audit.would_block is True
    assert "GUARD_ERROR" in audit.flags
    store.close()


def _policy():
    from cyberwall.core.models import Policy

    return Policy(version=1)
