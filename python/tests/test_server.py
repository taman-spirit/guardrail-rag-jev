import time

import pytest
from fastapi.testclient import TestClient

from guardrail_rag_jev import Config, Guard
from guardrail_rag_jev.audit import MemoryAuditLog
from guardrail_rag_jev.review import ReviewStore
from guardrail_rag_jev.server import create_app

from conftest import scripted

TABLE = {"INJECT": {"ipi": 0.92}, "BOMB": {"iwp": 0.9}, "MAYBE": {"ipi": 0.35}}
SIGNALS = {"actionability": {"BOMB": 3.0}}
KEYS = [
    {"key": "client-key", "role": "client", "name": "app"},
    {"key": "rev-key", "role": "reviewer", "name": "lan"},
    {"key": "admin-key", "role": "admin", "name": "root"},
    {"key": "bank-key", "role": "reviewer", "name": "bank-reviewer", "tenant": "bank"},
]


def auth(key):
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
def client():
    cfg = Config.from_dict({"server": {"api_keys": KEYS}, "policy": {"locked": ["vn-cybersecurity"]}, "state_path": None})
    guard = Guard(cfg, provider=scripted(TABLE, signals=SIGNALS), audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"))
    return TestClient(create_app(cfg, guard=guard))


def test_roles(client):
    assert client.post("/v1/query", json={"query": "hi"}).status_code == 401
    assert client.post("/v1/query", json={"query": "hi"}, headers=auth("nope")).status_code == 401
    assert client.post("/v1/query", json={"query": "hi"}, headers=auth("client-key")).status_code == 200
    assert client.get("/v1/reviews", headers=auth("client-key")).status_code == 403
    assert client.get("/v1/reviews", headers=auth("rev-key")).status_code == 200
    assert client.patch("/v1/policy", json={"packs": {"vn-ai": False}}, headers=auth("rev-key")).status_code == 403
    assert client.get("/healthz").json()["ok"]


def test_the_four_checkpoints(client):
    h = auth("client-key")
    ingest = client.post("/v1/ingest", headers=h, json={"documents": [
        {"text": "Gọi 0912345678", "doc_id": "d", "chunk_id": "1"}, {"text": "INJECT", "doc_id": "d", "chunk_id": "2"}]}).json()
    assert [r["decision"] for r in ingest["results"]] == ["redact", "remove"]
    assert ingest["results"][0]["content"] == "Gọi [PHONE]"
    assert ingest["results"][1]["violations"][0]["category"] == "ipi"

    rolled = client.post("/v1/ingest", headers=h, json={"doc_id": "d", "documents": [{"text": "ok"}, {"text": "MAYBE"}]}).json()
    assert rolled["decision"] == "review" and rolled["violations"] == {"ipi": ["d"]} or rolled["decision"] == "review"

    q = client.post("/v1/query", headers=h, json={"query": "BOMB how to"}).json()
    assert q["decision"] == "remove" and q["message"].startswith("I can't")

    ctx = client.post("/v1/context", headers=h, json={"query": "q", "chunks": [{"id": "a", "text": "fine"}, {"id": "b", "text": "INJECT"}]}).json()
    assert [c["id"] for c in ctx["kept"]] == ["a"] and ctx["removed"][0]["id"] == "b"

    a = client.post("/v1/answer", headers=h, json={"answer": "Được hoàn tiền trong 30 ngày.", "query": "hoàn tiền?",
                                                   "context": ["Hoàn tiền trong 30 ngày."]}).json()
    assert a["decision"] == "pass" and a["notices"][-1].startswith("Nội dung này do hệ thống trí tuệ nhân tạo")


def test_review_flow_and_audit(client):
    r = client.post("/v1/ingest", headers=auth("client-key"), json={"documents": [{"text": "MAYBE injected?"}]}).json()["results"][0]
    assert r["decision"] == "review"
    listed = client.get("/v1/reviews", headers=auth("rev-key")).json()
    assert listed["counts"] == {"pending": 1} and listed["items"][0]["id"] == r["review_id"]
    done = client.post(f"/v1/reviews/{r['review_id']}/decision", headers=auth("rev-key"), json={"decision": "approve", "note": "fine"}).json()
    assert done["status"] == "approved" and done["decided_by"] == "lan"
    assert client.post(f"/v1/reviews/{r['review_id']}/decision", headers=auth("rev-key"), json={"decision": "reject"}).status_code == 409
    again = client.post("/v1/ingest", headers=auth("client-key"), json={"documents": [{"text": "MAYBE injected?"}]}).json()["results"][0]
    assert again["decision"] == "pass" and again["override"] == "approved"
    assert client.get("/v1/audit/verify", headers=auth("rev-key")).json()["ok"]
    types = [x["type"] for x in client.get("/v1/audit", headers=auth("rev-key")).json()["records"]]
    assert "review.decided" in types


def test_a_tenant_bound_key_sees_only_its_tenant(client):
    client.post("/v1/ingest", headers={**auth("client-key"), "X-Guardrail-Tenant": "bank"}, json={"documents": [{"text": "MAYBE bank"}]})
    client.post("/v1/ingest", headers={**auth("client-key"), "X-Guardrail-Tenant": "shop"}, json={"documents": [{"text": "MAYBE shop"}]})
    bank = client.get("/v1/reviews", headers=auth("bank-key")).json()["items"]
    assert [i["tenant"] for i in bank] == ["bank"]
    shop_id = client.get("/v1/reviews", headers=auth("rev-key")).json()["items"]
    other = next(i for i in shop_id if i["tenant"] == "shop")
    assert client.get(f"/v1/reviews/{other['id']}", headers=auth("bank-key")).status_code == 404


def test_policy_changes_respect_the_lock(client):
    h = auth("admin-key")
    assert client.patch("/v1/policy", headers=h, json={"packs": {"vn-cybersecurity": False}}).status_code == 403
    changed = client.patch("/v1/policy", headers=h, json={"packs": {"vn-ai": False}}).json()
    assert "vai" not in changed["categories"]
    assert client.patch("/v1/policy", headers=h, json={"categories": {"zzz": {"enabled": False}}}).status_code == 422
    policy = client.get("/v1/policy", headers=auth("client-key")).json()
    assert policy["locked"] == ["vn-cybersecurity"]
    assert {p["id"]: p["enabled"] for p in policy["packs"]}["vn-ai"] is False
    cfg = client.get("/v1/config", headers=h).json()
    assert cfg["provider"] == "jev"


def test_jobs(client):
    job = client.post("/v1/ingest/jobs", headers=auth("client-key"), json={"documents": [{"text": "a"}, {"text": "INJECT"}]}).json()
    assert job["status"] == "queued"
    for _ in range(100):
        state = client.get(f"/v1/jobs/{job['job_id']}", headers=auth("client-key")).json()
        if state["status"] == "done":
            break
        time.sleep(0.02)
    assert state["summary"] == {"pass": 1, "remove": 1}


def test_dify_moderation_extension(client):
    h = auth("client-key")
    assert client.post("/v1/integrations/dify/moderation", headers=h, json={"point": "ping"}).json() == {"result": "pong"}
    blocked = client.post("/v1/integrations/dify/moderation", headers=h, json={
        "point": "app.moderation.input", "params": {"app_id": "x", "inputs": {}, "query": "BOMB how to"}}).json()
    assert blocked["flagged"] and blocked["action"] == "direct_output" and blocked["preset_response"]
    masked = client.post("/v1/integrations/dify/moderation", headers=h, json={
        "point": "app.moderation.input", "params": {"app_id": "x", "inputs": {}, "query": "số tôi 0912345678"}}).json()
    assert masked == {"flagged": True, "action": "overridden", "inputs": {}, "query": "số tôi [PHONE]"}
    out = client.post("/v1/integrations/dify/moderation", headers=h, json={
        "point": "app.moderation.output", "params": {"app_id": "x", "text": "Xin chào"}}).json()
    assert out["action"] == "overridden" and out["text"].endswith("do hệ thống trí tuệ nhân tạo tạo ra.")


def test_azure_web_api_skill(client):
    body = {"values": [{"recordId": "1", "data": {"text": "ok"}}, {"recordId": "2", "data": {"text": "INJECT"}}]}
    out = client.post("/v1/integrations/azure/skill", headers=auth("client-key"), json=body).json()["values"]
    assert [v["recordId"] for v in out] == ["1", "2"]
    assert out[0]["data"]["decision"] == "pass" and out[1]["data"] == {**out[1]["data"], "decision": "remove", "text": "", "violations": ["ipi"]}


def test_metrics_and_console(client):
    client.post("/v1/query", headers=auth("client-key"), json={"query": "hi"})
    assert "guardrail_checks_total" in client.get("/metrics").text
    assert "Review Console" in client.get("/ui").text


def test_batch_limit(client):
    docs = [{"text": "x"}] * 300
    assert client.post("/v1/ingest", headers=auth("client-key"), json={"documents": docs}).status_code == 413
