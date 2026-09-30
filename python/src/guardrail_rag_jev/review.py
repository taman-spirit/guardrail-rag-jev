"""The review queue, reviewer overrides and ingest jobs, in one SQLite file.

A held or removed item waits here for a person. The reviewer's decision does two things:

* it settles that item: ``approve`` releases it, ``reject`` keeps it out, ``edit`` releases the
  reviewer's corrected text instead;
* it becomes an **override** keyed by the content's hash, so the same text is not sent to the model
  again. Overrides are scoped: ``document`` (shared by ingest and context, so a chunk approved at
  indexing also passes at retrieval), ``query`` and ``answer``.

A decision is also posted to ``review.webhook_url``, signed with HMAC-SHA256 when a secret is set,
so the indexing pipeline can index an approved document without polling.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

log = logging.getLogger(__name__)

DECISIONS = ("approve", "reject", "edit")
STATUS_OF = {"approve": "approved", "reject": "rejected", "edit": "edited"}


def scope_of(surface: str) -> str:
    return "document" if surface in ("ingest", "context") else surface


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True, slots=True)
class Override:
    decision: str
    replacement: str | None
    review_id: str | None


class ReviewStore:
    def __init__(self, path: str | Path, *, webhook_url: str | None = None, webhook_secret: str | None = None) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self._local = threading.local()
        self._shared: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        db = self._conn()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT, status TEXT, surface TEXT, scope TEXT,
                content_hash TEXT, content TEXT, language TEXT, decision TEXT, reason TEXT,
                violations TEXT, verdict TEXT, ref TEXT, tenant TEXT, profile TEXT, check_id TEXT,
                decided_by TEXT, decided_at TEXT, note TEXT, final_content TEXT
            );
            CREATE INDEX IF NOT EXISTS reviews_status ON reviews(status, created_at);
            CREATE INDEX IF NOT EXISTS reviews_hash ON reviews(scope, content_hash);
            CREATE TABLE IF NOT EXISTS overrides (
                tenant TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL, content_hash TEXT NOT NULL,
                decision TEXT NOT NULL, replacement TEXT, review_id TEXT, created_at TEXT, created_by TEXT,
                PRIMARY KEY (tenant, scope, content_hash)
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT, status TEXT, total INTEGER, done INTEGER,
                summary TEXT, results TEXT, error TEXT, callback_url TEXT, tenant TEXT, profile TEXT
            );
            """
        )

    def _q(self, sql: str, args: tuple | list = (), *, fetch: str = "none") -> Any:
        """Run one statement and read its result before letting go of the connection.

        A file database gives every thread its own connection. The in-memory one (tests, embedding)
        is a single connection shared across threads, so every use of it is serialised here: two
        threads interleaving on one sqlite3 connection fail with "bad parameter or other API misuse".
        """
        shared = self.path == ":memory:"
        if shared:
            self._lock.acquire()
        try:
            cur = self._conn().execute(sql, args)
            if fetch == "one":
                row = cur.fetchone()
                return _row(cur, row) if row else None
            if fetch == "all":
                return [_row(cur, r) for r in cur.fetchall()]
            if fetch == "tuples":
                return cur.fetchall()
            return cur.rowcount
        finally:
            if shared:
                self._lock.release()

    def _conn(self) -> sqlite3.Connection:
        if self.path == ":memory:":
            if self._shared is None:
                self._shared = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
            return self._shared
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    # -- queue ----------------------------------------------------------

    def enqueue(
        self,
        *,
        surface: str,
        content: str | None,
        content_hash: str,
        decision: str,
        reason: str,
        violations: list[dict[str, Any]],
        verdict: Mapping[str, Any],
        ref: Mapping[str, Any],
        language: str,
        check_id: str,
        tenant: str = "",
        profile: str = "",
    ) -> str:
        """Queue an item. The same content already pending in the same scope is not queued twice:
        the existing item's id is returned."""
        scope = scope_of(surface)
        with self._lock:
            row = self._q(
                "SELECT id FROM reviews WHERE scope=? AND content_hash=? AND status='pending' AND tenant=?",
                (scope, content_hash, tenant), fetch="one",
            )
            if row:
                return str(row["id"])
            rid = "rv_" + uuid.uuid4().hex[:20]
            now = _now()
            self._q(
                "INSERT INTO reviews (id, created_at, updated_at, status, surface, scope, content_hash, content, language,"
                " decision, reason, violations, verdict, ref, tenant, profile, check_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, now, now, "pending", surface, scope, content_hash, content, language, decision, reason,
                 json.dumps(violations, ensure_ascii=False), json.dumps(verdict, ensure_ascii=False, default=str),
                 json.dumps(dict(ref), ensure_ascii=False, default=str), tenant, profile, check_id),
            )
            return rid

    def get(self, review_id: str) -> dict[str, Any] | None:
        return self._q("SELECT * FROM reviews WHERE id=?", (review_id,), fetch="one")

    def list(self, *, status: str | None = "pending", surface: str | None = None, tenant: str | None = None,
             limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM reviews WHERE 1=1", []
        for col, val in (("status", status), ("surface", surface), ("tenant", tenant)):
            if val:
                sql += f" AND {col}=?"
                args.append(val)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        return self._q(sql, args, fetch="all")

    def counts(self, tenant: str | None = None) -> dict[str, int]:
        sql = "SELECT status, COUNT(*) FROM reviews" + (" WHERE tenant=?" if tenant else "") + " GROUP BY status"
        return {s: n for s, n in self._q(sql, (tenant,) if tenant else (), fetch="tuples")}

    def decide(self, review_id: str, decision: str, *, reviewer: str, note: str = "", content: str | None = None) -> dict[str, Any]:
        """Settle an item and record the override."""
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}")
        if decision == "edit" and not content:
            raise ValueError("an edit decision needs the corrected content")
        with self._lock:
            item = self.get(review_id)
            if item is None:
                raise KeyError(review_id)
            if item["status"] != "pending":
                raise ValueError(f"review {review_id} is already {item['status']}")
            now = _now()
            final = content if decision == "edit" else (item["content"] if decision == "approve" else None)
            self._q(
                "UPDATE reviews SET status=?, updated_at=?, decided_by=?, decided_at=?, note=?, final_content=? WHERE id=?",
                (STATUS_OF[decision], now, reviewer, now, note, final, review_id),
            )
            self._q(
                "INSERT OR REPLACE INTO overrides (tenant, scope, content_hash, decision, replacement, review_id, created_at, created_by)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (item["tenant"] or "", item["scope"], item["content_hash"], STATUS_OF[decision],
                 content if decision == "edit" else None, review_id, now, reviewer),
            )
        decided = self.get(review_id) or {}
        self._notify({"event": "review.decided", "review": _public(decided)})
        return decided

    # -- overrides -------------------------------------------------------

    def override(self, surface: str, content_hash: str, tenant: str = "") -> Override | None:
        row = self._q(
            "SELECT decision, replacement, review_id FROM overrides WHERE tenant=? AND scope=? AND content_hash=?",
            (tenant or "", scope_of(surface), content_hash), fetch="one",
        )
        return Override(row["decision"], row["replacement"], row["review_id"]) if row else None

    def clear_override(self, surface: str, content_hash: str, tenant: str = "") -> bool:
        return self._q(
            "DELETE FROM overrides WHERE tenant=? AND scope=? AND content_hash=?", (tenant or "", scope_of(surface), content_hash)
        ) > 0

    # -- retention -------------------------------------------------------

    def purge(self, days: int) -> int:
        """Drop the text of items decided more than ``days`` ago. The decision and the hash stay."""
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return self._q(
            "UPDATE reviews SET content=NULL, final_content=NULL WHERE status!='pending' AND decided_at < ? AND content IS NOT NULL",
            (cutoff,),
        )

    # -- jobs ------------------------------------------------------------

    def job_create(self, *, total: int, callback_url: str | None, tenant: str = "", profile: str = "") -> str:
        jid = "job_" + uuid.uuid4().hex[:20]
        now = _now()
        self._q(
            "INSERT INTO jobs (id, created_at, updated_at, status, total, done, callback_url, tenant, profile) VALUES (?,?,?,?,?,?,?,?,?)",
            (jid, now, now, "queued", total, 0, callback_url, tenant, profile),
        )
        return jid

    def job_update(self, job_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = _now()
        for key in ("summary", "results"):
            if key in fields and not isinstance(fields[key], str):
                fields[key] = json.dumps(fields[key], ensure_ascii=False, default=str)
        cols = ", ".join(f"{k}=?" for k in fields)
        self._q(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), job_id))

    def job_get(self, job_id: str, *, with_results: bool = True) -> dict[str, Any] | None:
        job = self._q("SELECT * FROM jobs WHERE id=?", (job_id,), fetch="one")
        if not job:
            return None
        if not with_results:
            job.pop("results", None)
        return job

    # -- webhook ---------------------------------------------------------

    def notify(self, payload: Mapping[str, Any], url: str | None = None) -> None:
        self._notify(payload, url)

    def _notify(self, payload: Mapping[str, Any], url: str | None = None) -> None:
        target = url or self.webhook_url
        if not target:
            return
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "guardrail-rag-jev"}
        if self.webhook_secret:
            sig = hmac.new(self.webhook_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Guardrail-Signature"] = f"sha256={sig}"

        def send() -> None:
            try:
                urllib.request.urlopen(urllib.request.Request(target, data=body, method="POST", headers=headers), timeout=10).close()
            except Exception as exc:  # noqa: BLE001 - a webhook outage never blocks a decision
                log.warning("webhook to %s failed: %s", target, exc)

        threading.Thread(target=send, name="review-webhook", daemon=True).start()


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    """For webhook receivers: check ``X-Guardrail-Signature``."""
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header or "")


def _row(cur: sqlite3.Cursor, row: tuple) -> dict[str, Any]:
    item = {d[0]: v for d, v in zip(cur.description, row)}
    for key in ("violations", "verdict", "ref", "summary", "results"):
        if isinstance(item.get(key), str):
            try:
                item[key] = json.loads(item[key])
            except json.JSONDecodeError:
                pass
    return item


def _public(item: Mapping[str, Any]) -> dict[str, Any]:
    """What a webhook receiver needs; the verdict details stay in the store."""
    keys = ("id", "status", "surface", "scope", "content_hash", "final_content", "ref", "tenant", "profile",
            "decided_by", "decided_at", "note", "check_id")
    return {k: item.get(k) for k in keys}
