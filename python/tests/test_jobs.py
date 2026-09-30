"""Ingest jobs on Redis, processed by workers."""

import threading
import time

import pytest

from guardrail_rag_jev import Config, Guard
from guardrail_rag_jev.audit import MemoryAuditLog
from guardrail_rag_jev.jobs import RedisJobs, run_worker
from guardrail_rag_jev.review import ReviewStore

from conftest import scripted

fakeredis = pytest.importorskip("fakeredis")
TABLE = {"INJECT": {"ipi": 0.92}}


def make(redis_client, **cfg):
    config = Config.from_dict({"state_path": None, **cfg})
    backend = RedisJobs(client=redis_client, stale_after=1)
    guard = Guard(config, provider=scripted(TABLE), audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"), jobs=backend)
    return guard, backend


def test_the_service_enqueues_and_workers_process():
    r = fakeredis.FakeRedis(decode_responses=True)
    service, backend = make(r)
    job_id = service.submit_job([{"text": "ok", "chunk_id": "1"}, {"text": "INJECT", "chunk_id": "2"}], tenant="bank")
    assert service.job(job_id)["status"] == "queued" and r.llen("grj:queue") == 1

    worker, worker_backend = make(r)  # another process, the same Redis
    assert run_worker(worker, worker_backend, once=True) == 1
    job = service.job(job_id)
    assert job["status"] == "done" and job["done"] == 2 and job["summary"] == {"pass": 1, "remove": 1}
    assert job["results"][1]["violations"][0]["category"] == "ipi" and job["tenant"] == "bank"
    assert r.llen("grj:processing") == 0 and not r.exists(f"grj:job:{job_id}:items")
    assert worker.audit.query(kind="job.done")


def test_a_job_whose_worker_died_is_requeued():
    r = fakeredis.FakeRedis(decode_responses=True)
    service, backend = make(r)
    job_id = service.submit_job([{"text": "ok"}])
    assert backend.take() == job_id  # a worker takes it, then dies
    backend.update(job_id, status="running")
    time.sleep(1.2)
    assert backend.requeue_stale() == [job_id]
    assert service.job(job_id)["status"] == "queued" and r.lrange("grj:queue", 0, -1) == [job_id]


def test_workers_share_the_queue():
    r = fakeredis.FakeRedis(decode_responses=True)
    service, _ = make(r)
    ids = [service.submit_job([{"text": f"doc {i}"}]) for i in range(6)]
    stop = threading.Event()
    counts = []
    threads = []
    for _ in range(2):
        g, b = make(r)
        t = threading.Thread(target=lambda g=g, b=b: counts.append(run_worker(g, b, stop=stop)))
        t.start()
        threads.append(t)
    for _ in range(200):
        if all(service.job(i)["status"] == "done" for i in ids):
            break
        time.sleep(0.02)
    stop.set()
    for t in threads:
        t.join(timeout=5)
    assert all(service.job(i)["status"] == "done" for i in ids) and sum(counts) == 6


def test_worker_command_refuses_the_local_backend(capsys, tmp_path, monkeypatch):
    from guardrail_rag_jev.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["worker", "--offline", "--once"]) == 2
