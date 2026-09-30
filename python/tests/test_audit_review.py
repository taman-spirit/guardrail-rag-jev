import json

import pytest

from guardrail_rag_jev import JsonlAuditLog, ReviewStore, SqliteAuditLog, verify_signature


@pytest.mark.parametrize("kind", ["jsonl", "sqlite"])
def test_the_chain_verifies_and_survives_a_reopen(tmp_path, kind):
    path = tmp_path / ("a.jsonl" if kind == "jsonl" else "a.db")
    log = JsonlAuditLog(path) if kind == "jsonl" else SqliteAuditLog(path)
    for i in range(5):
        log.record("check", surface="query", decision="pass", check_id=f"c{i}")
    again = JsonlAuditLog(path) if kind == "jsonl" else SqliteAuditLog(path)
    again.record("check", surface="query", decision="remove", check_id="c5")
    result = again.verify()
    assert result == {"ok": True, "count": 6, "head": again.head()["hash"]}
    assert [r["check_id"] for r in again.query(kind="check", limit=2)] == ["c5", "c4"]
    assert again.query(decision="remove")[0]["seq"] == 6


def test_editing_a_record_breaks_the_chain_there(tmp_path):
    path = tmp_path / "a.jsonl"
    log = JsonlAuditLog(path)
    for i in range(4):
        log.record("check", decision="remove", check_id=f"c{i}")
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["decision"] = "pass"  # someone makes a removal look like a pass
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    result = JsonlAuditLog(path).verify()
    assert not result["ok"] and result["broken_at"] == 2 and "hash" in result["reason"]


def test_deleting_a_record_breaks_the_chain(tmp_path):
    path = tmp_path / "a.jsonl"
    log = JsonlAuditLog(path)
    for i in range(4):
        log.record("check", check_id=f"c{i}")
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")
    assert JsonlAuditLog(path).verify()["broken_at"] == 4


def _item(store, text="t", **kw):
    return store.enqueue(surface=kw.get("surface", "ingest"), content=text, content_hash=f"h-{text}", decision="review",
                         reason="r", violations=[{"category": "ipi"}], verdict={}, ref={"doc_id": "d"}, language="vi",
                         check_id="c", tenant=kw.get("tenant", ""))


def test_the_same_pending_text_is_queued_once():
    s = ReviewStore(":memory:")
    assert _item(s) == _item(s)
    assert _item(s, tenant="bank") != _item(s)
    assert s.counts() == {"pending": 2}


def test_decisions_become_scoped_overrides():
    s = ReviewStore(":memory:")
    rid = _item(s, surface="ingest")
    s.decide(rid, "edit", reviewer="lan", content="fixed")
    o = s.override("context", "h-t")  # document scope covers retrieval too
    assert o.decision == "edited" and o.replacement == "fixed"
    assert s.override("answer", "h-t") is None
    with pytest.raises(ValueError, match="corrected content"):
        s.decide(_item(s, "u"), "edit", reviewer="lan")


def test_webhook_signature_round_trip():
    body = b'{"event":"review.decided"}'
    import hashlib, hmac
    header = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_signature("secret", body, header) and not verify_signature("other", body, header)


def test_purge_drops_old_decided_text_but_keeps_the_record():
    s = ReviewStore(":memory:")
    rid = _item(s)
    s.decide(rid, "approve", reviewer="r")
    s._conn().execute("UPDATE reviews SET decided_at='2000-01-01T00:00:00+00:00'")
    assert s.purge(30) == 1
    item = s.get(rid)
    assert item["content"] is None and item["status"] == "approved" and item["content_hash"] == "h-t"
