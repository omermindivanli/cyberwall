"""SQLite WAL evidence log with an append-only hash chain."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from cyberwall.core.models import Decision, DecisionKind, Policy, Request

ZERO_HASH = "0" * 64


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _fingerprint(values: tuple[str, ...]) -> list[str]:
    return ["sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest() for value in values]


def _fingerprint_identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""


def _event_payload(
    request: Request, decision: Decision, policy_sha256: str, mode: str
) -> dict[str, Any]:
    if mode not in {"audit", "enforce"}:
        raise ValueError("mode must be audit or enforce")
    if len(policy_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in policy_sha256
    ):
        raise ValueError("policy_sha256 must be a lowercase SHA-256 hex digest")
    now = datetime.now(UTC).isoformat(timespec="microseconds")
    return {
        "event_id": "evt_" + uuid4().hex,
        "correlation_id": "cor_" + uuid4().hex,
        "ts": now,
        "session_id": _fingerprint_identifier(request.session_id),
        "task_id": _fingerprint_identifier(request.task_id),
        "integration": "hermes",
        "tool": request.tool if decision.tool_class.value != "unknown" else "unknown",
        "tool_class": decision.tool_class.value,
        "normalized_paths": _fingerprint(decision.normalized_paths),
        "hosts": _fingerprint(decision.hosts),
        "argv0": _fingerprint((decision.argv[0],))[0] if decision.argv else None,
        "args_sha256": hashlib.sha256(request.args.encode("utf-8")).hexdigest(),
        "decision": decision.decision.value,
        "would_block": decision.would_block,
        "rule_id": decision.rule_id,
        "reason_code": decision.reason_code,
        "policy_sha256": policy_sha256,
        "mode": mode,
        "taint_flags": [],
        "flags": list(decision.flags),
    }


class EvidenceStore:
    """Thread-safe evidence writer; stored fields are allowlisted and payloads are hashed."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "seq INTEGER PRIMARY KEY, event_json TEXT NOT NULL, "
            "prev_hash TEXT NOT NULL, hash TEXT NOT NULL)"
        )
        self._connection.commit()

    def append(
        self,
        request: Request,
        decision: Decision,
        *,
        policy_sha256: str,
        mode: str,
    ) -> str:
        """Append a redacted decision event and return its event ID."""
        event = _event_payload(request, decision, policy_sha256, mode)
        encoded = _canonical(event).decode("ascii")
        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
                previous = row[0] if row else ZERO_HASH
                digest = hashlib.sha256(
                    previous.encode("ascii") + encoded.encode("ascii")
                ).hexdigest()
                cursor.execute(
                    "INSERT INTO events(event_json, prev_hash, hash) VALUES (?, ?, ?)",
                    (encoded, previous, digest),
                )
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise
        return event["event_id"]

    def verify(self) -> bool:
        """Recompute every row link and detect edits, deletion, or reordering."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT event_json, prev_hash, hash FROM events ORDER BY seq"
            ).fetchall()
        previous = ZERO_HASH
        for event_json, stored_previous, stored_hash in rows:
            if stored_previous != previous:
                return False
            actual = hashlib.sha256(
                previous.encode("ascii") + event_json.encode("ascii")
            ).hexdigest()
            if actual != stored_hash:
                return False
            previous = stored_hash
        return True

    def events(self) -> list[dict[str, Any]]:
        """Return parsed allowlisted events for reports and local inspection."""
        with self._lock:
            rows = self._connection.execute("SELECT event_json FROM events ORDER BY seq").fetchall()
        return [json.loads(row[0]) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> EvidenceStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def append_with_failure_policy(
    store: EvidenceStore,
    request: Request,
    decision: Decision,
    policy: Policy,
    *,
    policy_sha256: str,
) -> Decision:
    """Persist a decision or apply the configured evidence-failure policy fail-closed."""
    try:
        store.append(request, decision, policy_sha256=policy_sha256, mode=policy.mode)
        return decision
    except Exception:
        if policy.mode == "audit":
            return Decision(
                decision=DecisionKind.ALLOW,
                rule_id=decision.rule_id,
                reason_code="GUARD_ERROR",
                would_block=decision.decision != DecisionKind.ALLOW or decision.would_block,
                tool_class=decision.tool_class,
                normalized_paths=decision.normalized_paths,
                hosts=decision.hosts,
                argv=decision.argv,
                flags=tuple(sorted(set((*decision.flags, "GUARD_ERROR")))),
            )
        if policy.on_evidence_failure == "allow":
            return decision
        return Decision(
            decision=DecisionKind.DENY,
            rule_id="compiled-invariant",
            reason_code="EVIDENCE_FAILURE",
            tool_class=decision.tool_class,
            normalized_paths=decision.normalized_paths,
            hosts=decision.hosts,
            argv=decision.argv,
            flags=tuple(sorted(set((*decision.flags, "GUARD_ERROR")))),
        )
