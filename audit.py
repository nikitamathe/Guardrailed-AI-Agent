"""Structured audit trail with an append-only, hash-chained log store.

Milestone M4 — Logging, Telemetry & Audit Trail.

Provides two pieces:

1. ``AuditEvent`` — a Pydantic schema describing a single structured audit
   record. Every event carries a SHA-256 hash computed over its canonical
   payload chained to the previous event's hash, giving tamper evidence.

2. ``HashChainedAuditLog`` — an append-only, cryptographically chained file
   writer. Events are written as single JSON lines in append mode (never
   truncated), each hash-chained to the prior record. ``verify()`` replays
   the file and re-computes the hashes to detect tampering, truncation or
   reordering.

PII handling: an optional ``sanitizer`` callable is applied to the serialized
event payload (e.g. ``RAGLogEngine.sanitize``) *before* hashing and before it is
written to disk, so sensitive fields never reach the audit file as raw values.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AuditEvent(BaseModel):
    """A single structured audit record (Pydantic schema).

    Each event carries a SHA-256 hash computed over its canonical payload
    chained to the previous event's ``prev_hash``. The hash is populated by
    :meth:`with_chain` before the event is written to the store.
    """

    event_id: str = Field(default_factory=lambda: hashlib.sha256(os.urandom(16)).hexdigest()[:16])
    timestamp: str = Field(default_factory=_utcnow)
    stage: str
    status: str
    actor: Optional[str] = None
    action: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = Field(default="")
    hash: str = Field(default="")

    def _canonical_payload(self) -> Dict[str, Any]:
        """Ordered, JSON-stable payload used as the hash input."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "stage": self.stage,
            "status": self.status,
            "actor": self.actor,
            "action": self.action,
            "details": self.details,
        }

    def with_chain(self, prev_hash: str) -> "AuditEvent":
        """Return a copy of this event chained to ``prev_hash`` (hash computed)."""
        raw = json.dumps(
            {"prev_hash": prev_hash, "payload": self._canonical_payload()},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.model_copy(update={"prev_hash": prev_hash, "hash": digest})

    def to_record(self) -> Dict[str, Any]:
        """Full serializable record including chain + hash."""
        return {
            **self._canonical_payload(),
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


class HashChainedAuditLog:
    """Append-only, hash-chained structured audit store.

    Each record is written as one JSON object on its own line in append mode.
    Every record stores the hash of the previous record plus its own hash,
    forming an immutable chain that exposes tampering on ``verify()``.
    """

    def __init__(
        self,
        log_path: str = "audit/audit.log",
        sanitizer: Optional[Callable[[str], str]] = None,
    ):
        self.log_path = log_path
        self.sanitizer = sanitizer
        self._lock = threading.Lock()
        self._fh: Optional[Any] = None
        self._offset = 0

    # -- public API ----------------------------------------------------------
    def append(
        self,
        stage: str,
        status: str,
        action: Optional[str] = None,
        actor: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Sanitize, chain and append a new audit event; return it."""
        safe_details = self._sanitize_details(details or {})
        event = AuditEvent(stage=stage, status=status, action=action, actor=actor, details=safe_details)
        with self._lock:
            prev_hash = self._last_hash()
            chained = event.with_chain(prev_hash)
            line = json.dumps(chained.to_record(), sort_keys=True, default=str) + "\n"
            self._ensure_open()
            self._fh.write(line)
            self._fh.flush()
            try:
                os.fsync(self._fh.fileno())
            except OSError:
                pass
            self._offset += len(line.encode("utf-8"))
        return chained

    def verify(self) -> tuple[bool, List[str]]:
        """Replay the file and verify the hash chain is intact.

        Returns ``(ok, problems)`` where ``problems`` lists human-readable
        inconsistencies (tampering, truncation, duplicate hashes).
        """
        problems: List[str] = []
        prev_hash = ""
        seen_hashes: set = set()
        try:
            with open(self.log_path, "r", encoding="utf-8") as fh:
                for lineno, raw in enumerate(fh, start=1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        rec = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        problems.append(f"line {lineno}: invalid JSON ({exc})")
                        continue
                    record_hash = rec.get("hash")
                    if record_hash is None:
                        problems.append(f"line {lineno}: missing hash")
                        continue
                    if record_hash in seen_hashes:
                        problems.append(f"line {lineno}: duplicate hash")
                    seen_hashes.add(record_hash)
                    payload_to_hash = json.dumps(
                        {"prev_hash": rec.get("prev_hash", ""), "payload": {
                            "event_id": rec.get("event_id"),
                            "timestamp": rec.get("timestamp"),
                            "stage": rec.get("stage"),
                            "status": rec.get("status"),
                            "actor": rec.get("actor"),
                            "action": rec.get("action"),
                            "details": rec.get("details"),
                        }},
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                    expected = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()
                    if expected != record_hash:
                        problems.append(f"line {lineno}: hash mismatch (tampering)")
                    prev_hash = record_hash
        except FileNotFoundError:
            return True, []
        return not problems, problems

    def read_all(self) -> List[Dict[str, Any]]:
        """Return every stored record (raw, unsanitized keys already clean)."""
        records: List[Dict[str, Any]] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if raw:
                        records.append(json.loads(raw))
        except FileNotFoundError:
            return []
        return records

    # -- internals -----------------------------------------------------------
    def _last_hash(self) -> str:
        """Read the final record's hash without loading the whole file."""
        try:
            with open(self.log_path, "r", encoding="utf-8") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                # scan backwards for the last complete line
                chunk = b""
                pos = size
                while pos > 0:
                    pos = max(0, pos - 4096)
                    fh.seek(pos)
                    chunk = fh.read(size - pos).encode("utf-8", errors="replace")
                    lines = chunk.split(b"\n")
                    if len(lines) >= 2 and lines[-2].strip():
                        last = lines[-2].decode("utf-8", errors="replace")
                        break
                else:
                    return ""
                try:
                    return json.loads(last).get("hash", "")
                except json.JSONDecodeError:
                    return ""
        except FileNotFoundError:
            return ""

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize string values in ``details`` before chaining."""
        if self.sanitizer is None:
            return details
        cleaned: Dict[str, Any] = {}
        for key, value in details.items():
            if isinstance(value, str):
                cleaned[key] = self.sanitizer(value)
            elif isinstance(value, dict):
                cleaned[key] = self._sanitize_details(value)
            elif isinstance(value, list):
                cleaned[key] = [
                    self._sanitize_details(item) if isinstance(item, dict)
                    else (self.sanitizer(item) if isinstance(item, str) else item)
                    for item in value
                ]
            else:
                cleaned[key] = value
        return cleaned

    def _ensure_open(self):
        if self._fh is not None:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)
        # open append-only; never truncate
        self._fh = open(self.log_path, "a", encoding="utf-8")
        self._offset = os.path.getsize(self.log_path)
