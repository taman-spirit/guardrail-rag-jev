"""A tamper-evident audit log.

Every check, review decision and policy change is one record. Each record carries the hash of the
one before it, so editing, removing or reordering any record breaks the chain from that point on,
and ``verify()`` says where. This makes the log evidence rather than a claim; it does not make it
immutable, so keep a copy of the latest hash (``head()``) somewhere the log's writer cannot reach,
or ship records to a SIEM as they are written.

What the log keeps of the checked text is a setting (``audit.store_content``):
``none``, ``hash`` (SHA-256 only), ``redacted`` (detector matches masked; the default) or ``full``.
An audit log that stores personal data in clear is itself a personal-data store.

Two backends: ``jsonl`` (one file, one process) and ``sqlite`` (safe across worker processes).
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import sqlite3
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol

log = logging.getLogger(__name__)

GENESIS = "0" * 64


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(record: Mapping[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _seal(record: dict[str, Any], prev: str) -> dict[str, Any]:
    record["prev_hash"] = prev
    record["hash"] = hashlib.sha256((prev + _canonical({k: v for k, v in record.items() if k != "hash"})).encode("utf-8")).hexdigest()
    return record


def _new(kind: str, seq: int, fields: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "seq": seq,
        "id": uuid.uuid4().hex,
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "type": kind,
        **{k: v for k, v in fields.items() if v is not None},
    }


class AuditLog(Protocol):
    def record(self, kind: str, **fields: Any) -> dict[str, Any]: ...

    def query(
        self, *, kind: str | None = None, surface: str | None = None, decision: str | None = None,
        ref: str | None = None, limit: int = 100, before_seq: int | None = None,
    ) -> list[dict[str, Any]]: ...

    def verify(self) -> dict[str, Any]: ...

    def head(self) -> dict[str, Any]: ...


def _check(records: Iterator[dict[str, Any]]) -> dict[str, Any]:
    prev = GENESIS
    count = 0
    expected_seq = 1
    for rec in records:
        count += 1
        if rec.get("seq") != expected_seq:
            return {"ok": False, "count": count, "broken_at": rec.get("seq"), "reason": f"expected seq {expected_seq}, found {rec.get('seq')}"}
        if rec.get("prev_hash") != prev:
            return {"ok": False, "count": count, "broken_at": rec.get("seq"), "reason": "prev_hash does not match the previous record"}
        body = {k: v for k, v in rec.items() if k != "hash"}
        digest = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
        if digest != rec.get("hash"):
            return {"ok": False, "count": count, "broken_at": rec.get("seq"), "reason": "record content does not match its hash"}
        prev = rec["hash"]
        expected_seq += 1
    return {"ok": True, "count": count, "head": prev}


def _matches(rec: Mapping[str, Any], kind: str | None, surface: str | None, decision: str | None, ref: str | None) -> bool:
    if kind and rec.get("type") != kind and not str(rec.get("type", "")).startswith(kind + "."):
        return False
    if surface and rec.get("surface") != surface:
        return False
    if decision and rec.get("decision") != decision:
        return False
    if ref and ref not in (rec.get("check_id"), rec.get("review_id"), *(str(v) for v in (rec.get("ref") or {}).values())):
        return False
    return True


class _Forwarder:
    """Posts records to a collector in the background. Best effort: a slow SIEM never slows a check."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=10000)
        threading.Thread(target=self._run, name="audit-forwarder", daemon=True).start()

    def put(self, record: dict[str, Any]) -> None:
        try:
            self.q.put_nowait(record)
        except queue.Full:
            log.warning("audit forwarder queue full; record %s not forwarded", record.get("seq"))

    def _run(self) -> None:
        while True:
            record = self.q.get()
            try:
                req = urllib.request.Request(self.url, data=_canonical(record).encode("utf-8"), method="POST",
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as exc:  # noqa: BLE001
                log.warning("audit forward failed: %s", exc)


class JsonlAuditLog:
    """Append-only JSON Lines file. One writing process per file."""

    def __init__(self, path: str | Path, *, forward_to: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS
        if self.path.exists():
            last = None
            for last in self._iter():
                pass
            if last is not None:
                self._seq, self._prev = int(last["seq"]), str(last["hash"])
        self._forward = _Forwarder(forward_to) if forward_to else None

    def _iter(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def record(self, kind: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            rec = _seal(_new(kind, self._seq + 1, fields), self._prev)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(rec) + "\n")
            self._seq, self._prev = rec["seq"], rec["hash"]
        if self._forward:
            self._forward.put(rec)
        return rec

    def query(self, *, kind=None, surface=None, decision=None, ref=None, limit=100, before_seq=None) -> list[dict[str, Any]]:
        out = [r for r in self._iter() if _matches(r, kind, surface, decision, ref) and (before_seq is None or r["seq"] < before_seq)]
        return list(reversed(out[-limit:]))

    def verify(self) -> dict[str, Any]:
        return _check(self._iter())

    def head(self) -> dict[str, Any]:
        return {"seq": self._seq, "hash": self._prev}


class SqliteAuditLog:
    """SQLite table with the same chain. Writers serialise on a write lock, so several worker
    processes can share one database file."""

    def __init__(self, path: str | Path, *, forward_to: str | None = None) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self._conn() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, id TEXT, ts TEXT, type TEXT, "
                "surface TEXT, decision TEXT, check_id TEXT, body TEXT NOT NULL, hash TEXT NOT NULL)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS audit_type ON audit(type)")
            db.execute("CREATE INDEX IF NOT EXISTS audit_check ON audit(check_id)")
        self._forward = _Forwarder(forward_to) if forward_to else None

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def record(self, kind: str, **fields: Any) -> dict[str, Any]:
        db = self._conn()
        for attempt in range(5):
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
                seq, prev = (row[0], row[1]) if row else (0, GENESIS)
                rec = _seal(_new(kind, seq + 1, fields), prev)
                db.execute(
                    "INSERT INTO audit (seq, id, ts, type, surface, decision, check_id, body, hash) VALUES (?,?,?,?,?,?,?,?,?)",
                    (rec["seq"], rec["id"], rec["ts"], rec["type"], rec.get("surface"), rec.get("decision"),
                     rec.get("check_id"), _canonical(rec), rec["hash"]),
                )
                db.execute("COMMIT")
                break
            except sqlite3.OperationalError:
                db.execute("ROLLBACK") if db.in_transaction else None
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
        if self._forward:
            self._forward.put(rec)
        return rec

    def query(self, *, kind=None, surface=None, decision=None, ref=None, limit=100, before_seq=None) -> list[dict[str, Any]]:
        sql, args = "SELECT body FROM audit WHERE 1=1", []
        if before_seq is not None:
            sql += " AND seq < ?"
            args.append(before_seq)
        if surface:
            sql += " AND surface = ?"
            args.append(surface)
        if decision:
            sql += " AND decision = ?"
            args.append(decision)
        sql += " ORDER BY seq DESC"
        out: list[dict[str, Any]] = []
        for (body,) in self._conn().execute(sql, args):
            rec = json.loads(body)
            if _matches(rec, kind, None, None, ref):
                out.append(rec)
                if len(out) >= limit:
                    break
        return out

    def verify(self) -> dict[str, Any]:
        return _check(json.loads(b) for (b,) in self._conn().execute("SELECT body FROM audit ORDER BY seq"))

    def head(self) -> dict[str, Any]:
        row = self._conn().execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return {"seq": row[0], "hash": row[1]} if row else {"seq": 0, "hash": GENESIS}


class MemoryAuditLog(JsonlAuditLog):
    """For tests: the same chain, kept in memory."""

    def __init__(self) -> None:  # noqa: D107 - no file
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS
        self.records: list[dict[str, Any]] = []
        self._forward = None

    def _iter(self) -> Iterator[dict[str, Any]]:
        yield from list(self.records)

    def record(self, kind: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            rec = _seal(_new(kind, self._seq + 1, fields), self._prev)
            self.records.append(rec)
            self._seq, self._prev = rec["seq"], rec["hash"]
        return rec


def open_audit_log(backend: str, path: str, *, forward_to: str | None = None) -> AuditLog:
    if backend == "jsonl":
        return JsonlAuditLog(path, forward_to=forward_to)
    if backend == "sqlite":
        return SqliteAuditLog(path, forward_to=forward_to)
    if backend == "memory":
        return MemoryAuditLog()
    raise ValueError(f"audit.backend must be jsonl, sqlite or memory, not {backend!r}")
