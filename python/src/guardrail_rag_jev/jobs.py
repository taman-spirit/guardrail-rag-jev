"""Ingest jobs: large batches checked in the background.

Two backends, chosen by ``jobs.backend`` in the config:

``local`` (default)  the service runs jobs in its own threads and keeps them in the review database.
                     Fine for one instance; a restart loses a job that was running.
``redis``            the service only enqueues. ``guardrail-rag-jev worker`` processes, as many as
                     you run, take jobs from Redis, write progress and results back, and call the
                     job's callback. A job whose worker died is put back on the queue after
                     ``stale_after`` seconds without progress.

    jobs: {backend: redis, url: "redis://redis:6379/0", prefix: grj, result_ttl: 604800}
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, Sequence

if TYPE_CHECKING:  # pragma: no cover
    from .guard import Guard

log = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class JobBackend(Protocol):
    def submit(self, items: Sequence[Mapping[str, Any]], *, callback_url: str | None, tenant: str, profile: str) -> str: ...

    def get(self, job_id: str, *, with_results: bool = True) -> dict[str, Any] | None: ...


def process(guard: "Guard", job_id: str, items: list[dict[str, Any]], *, tenant: str | None,
            progress: Callable[[int], None]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Check a job's items in batches, reporting progress; the results and a count per decision."""
    from .guard import _compact

    results: list[dict[str, Any]] = []
    batch = max(1, guard.config.concurrency * 4)
    for start in range(0, len(items), batch):
        results += [_compact(r) for r in guard.check_documents(items[start:start + batch], tenant=tenant)]
        progress(len(results))
    summary: dict[str, int] = {}
    for r in results:
        summary[r["decision"]] = summary.get(r["decision"], 0) + 1
    return results, summary


def finish(guard: "Guard", job_id: str, *, tenant: str | None, callback_url: str | None,
           results: list[dict[str, Any]] | None = None, summary: dict[str, int] | None = None,
           error: str | None = None) -> None:
    """Audit the outcome and call the job's callback."""
    if error is None:
        guard.audit.record("job.done", job_id=job_id, summary=summary, tenant=tenant or "", profile=guard.profile)
        payload: dict[str, Any] = {"event": "job.done", "job_id": job_id, "summary": summary, "results": results}
    else:
        guard.audit.record("job.failed", job_id=job_id, error=error, tenant=tenant or "", profile=guard.profile)
        payload = {"event": "job.failed", "job_id": job_id, "error": error}
    if callback_url:
        guard.reviews.notify(payload, callback_url)


class LocalJobs:
    """Jobs run in the service's own threads, kept in the review database."""

    def __init__(self, guard: "Guard", *, workers: int = 2) -> None:
        self.guard = guard
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="guard-jobs")

    def submit(self, items, *, callback_url, tenant, profile) -> str:
        job_id = self.guard.reviews.job_create(total=len(items), callback_url=callback_url, tenant=tenant, profile=profile)
        self._pool.submit(self._run, job_id, [dict(i) for i in items], callback_url, tenant)
        return job_id

    def get(self, job_id, *, with_results=True):
        return self.guard.reviews.job_get(job_id, with_results=with_results)

    def _run(self, job_id: str, items: list[dict[str, Any]], callback_url: str | None, tenant: str | None) -> None:
        store = self.guard.reviews
        store.job_update(job_id, status="running")
        try:
            results, summary = process(self.guard, job_id, items, tenant=tenant, progress=lambda n: store.job_update(job_id, done=n))
            store.job_update(job_id, status="done", summary=summary, results=results)
            finish(self.guard, job_id, tenant=tenant, callback_url=callback_url, results=results, summary=summary)
        except Exception as exc:  # noqa: BLE001 - reported, not raised into a thread
            log.exception("job %s failed", job_id)
            store.job_update(job_id, status="failed", error=str(exc))
            finish(self.guard, job_id, tenant=tenant, callback_url=callback_url, error=str(exc))

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class RedisJobs:
    """Jobs in Redis, processed by ``guardrail-rag-jev worker``.

    Keys: ``<prefix>:queue`` (waiting job ids), ``<prefix>:processing`` (taken), and per job
    ``<prefix>:job:<id>`` (a hash: status, total, done, summary, error, callback_url, tenant,
    profile, timestamps), ``:items`` and ``:results`` (JSON).
    """

    def __init__(self, url: str | None = None, *, prefix: str = "grj", result_ttl: int = 7 * 24 * 3600,
                 stale_after: int = 600, client: Any = None) -> None:
        if client is None:
            import redis  # type: ignore[import-untyped]

            client = redis.Redis.from_url(url or "redis://localhost:6379/0", decode_responses=True)
        self.r = client
        self.prefix = prefix
        self.result_ttl = result_ttl
        self.stale_after = stale_after

    def _k(self, *parts: str) -> str:
        return ":".join((self.prefix, *parts))

    def submit(self, items, *, callback_url, tenant, profile) -> str:
        job_id = "job_" + uuid.uuid4().hex[:20]
        now = _now()
        pipe = self.r.pipeline()
        pipe.hset(self._k("job", job_id), mapping={
            "id": job_id, "status": "queued", "total": len(items), "done": 0, "created_at": now, "updated_at": now,
            "callback_url": callback_url or "", "tenant": tenant or "", "profile": profile or "",
        })
        pipe.set(self._k("job", job_id, "items"), json.dumps([dict(i) for i in items], ensure_ascii=False))
        pipe.rpush(self._k("queue"), job_id)
        pipe.execute()
        return job_id

    def get(self, job_id, *, with_results=True):
        data = self.r.hgetall(self._k("job", job_id))
        if not data:
            return None
        job: dict[str, Any] = dict(data)
        for key in ("total", "done"):
            job[key] = int(job.get(key) or 0)
        job["summary"] = json.loads(job["summary"]) if job.get("summary") else None
        job["error"] = job.get("error") or None
        job["callback_url"] = job.get("callback_url") or None
        if with_results:
            raw = self.r.get(self._k("job", job_id, "results"))
            job["results"] = json.loads(raw) if raw else None
        return job

    # -- worker side ---------------------------------------------------

    def take(self, timeout: int = 1) -> str | None:
        """Move one job id from the queue to processing; None when the queue stayed empty."""
        return self.r.blmove(self._k("queue"), self._k("processing"), timeout, "LEFT", "RIGHT")

    def update(self, job_id: str, **fields: Any) -> None:
        fields["updated_at"] = _now()
        self.r.hset(self._k("job", job_id), mapping={k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in fields.items()})

    def complete(self, job_id: str, *, results: list[dict[str, Any]] | None, summary: dict[str, int] | None, error: str | None) -> None:
        pipe = self.r.pipeline()
        if error is None:
            pipe.set(self._k("job", job_id, "results"), json.dumps(results, ensure_ascii=False), ex=self.result_ttl)
            pipe.hset(self._k("job", job_id), mapping={"status": "done", "summary": json.dumps(summary), "updated_at": _now()})
        else:
            pipe.hset(self._k("job", job_id), mapping={"status": "failed", "error": error, "updated_at": _now()})
        pipe.delete(self._k("job", job_id, "items"))
        pipe.expire(self._k("job", job_id), self.result_ttl)
        pipe.lrem(self._k("processing"), 0, job_id)
        pipe.execute()

    def requeue_stale(self) -> list[str]:
        """Put back on the queue the jobs whose worker stopped reporting progress."""
        moved = []
        for job_id in self.r.lrange(self._k("processing"), 0, -1):
            updated = self.r.hget(self._k("job", job_id), "updated_at")
            try:
                age = time.time() - datetime.fromisoformat(updated).timestamp() if updated else self.stale_after + 1
            except ValueError:
                age = self.stale_after + 1
            if age > self.stale_after and self.r.lrem(self._k("processing"), 1, job_id):
                self.r.hset(self._k("job", job_id), mapping={"status": "queued", "updated_at": _now()})
                self.r.rpush(self._k("queue"), job_id)
                moved.append(job_id)
        return moved

    def run_one(self, guard_for: Callable[[str], "Guard"], job_id: str) -> None:
        job = self.get(job_id, with_results=False) or {}
        raw = self.r.get(self._k("job", job_id, "items"))
        items = json.loads(raw) if raw else []
        guard = guard_for(job.get("profile") or "")
        tenant = job.get("tenant") or None
        self.update(job_id, status="running")
        try:
            results, summary = process(guard, job_id, items, tenant=tenant, progress=lambda n: self.update(job_id, done=n))
            self.complete(job_id, results=results, summary=summary, error=None)
            finish(guard, job_id, tenant=tenant, callback_url=job.get("callback_url"), results=results, summary=summary)
        except Exception as exc:  # noqa: BLE001
            log.exception("job %s failed", job_id)
            self.complete(job_id, results=None, summary=None, error=str(exc))
            finish(guard, job_id, tenant=tenant, callback_url=job.get("callback_url"), error=str(exc))


def run_worker(guard: "Guard", backend: RedisJobs, *, stop: threading.Event | None = None, once: bool = False) -> int:
    """Take and process jobs until ``stop`` is set (or, with ``once``, until the queue is empty)."""
    stop = stop or threading.Event()
    done = 0
    last_sweep = 0.0
    while not stop.is_set():
        if time.monotonic() - last_sweep > 30:
            for job_id in backend.requeue_stale():
                log.warning("requeued stale job %s", job_id)
            last_sweep = time.monotonic()
        job_id = backend.take(timeout=1)
        if job_id is None:
            if once:
                break
            continue
        backend.run_one(guard.for_profile, job_id)
        done += 1
    return done


def build_jobs(guard: "Guard") -> JobBackend:
    spec = dict(guard.config.jobs or {})
    kind = spec.pop("backend", "local")
    if kind == "local":
        return LocalJobs(guard, workers=int(spec.get("workers", 2)))
    if kind == "redis":
        return RedisJobs(spec.get("url"), prefix=str(spec.get("prefix", "grj")), result_ttl=int(spec.get("result_ttl", 7 * 24 * 3600)),
                         stale_after=int(spec.get("stale_after", 600)))
    raise ValueError(f"jobs.backend must be local or redis, not {kind!r}")
