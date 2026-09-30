"""Four-eyes review and single sign-on."""

import time

import pytest
from fastapi.testclient import TestClient

from guardrail_rag_jev import Config
from guardrail_rag_jev.server import create_app

from conftest import make_guard, scripted

TABLE = {"MAYBE": {"ipi": 0.35}, "SOV": {"vsv": 0.35}}


def test_a_two_person_item_needs_two_different_reviewers_to_release():
    g = make_guard(scripted(TABLE), config=Config.from_dict({"review": {"two_person": ["vsv"]}}))
    held = g.check_document("SOV maybe a claim")
    item = g.reviews.get(held.review_id)
    assert item["required_approvals"] == 2
    first = g.decide_review(held.review_id, "approve", reviewer="lan")
    assert first["status"] == "pending" and [a["reviewer"] for a in first["approvals"]] == ["lan"]
    with pytest.raises(ValueError, match="second reviewer"):
        g.decide_review(held.review_id, "approve", reviewer="lan")
    assert g.check_document("SOV maybe a claim").decision == "review"  # not released yet
    done = g.decide_review(held.review_id, "approve", reviewer="nam")
    assert done["status"] == "approved" and done["decided_by"] == "lan,nam"
    assert g.check_document("SOV maybe a claim").decision == "pass"
    kinds = [r["type"] for r in g.audit.query(kind="review")]
    assert kinds == ["review.decided", "review.approval"]


def test_an_edit_restarts_the_count_and_one_reject_settles():
    g = make_guard(scripted(TABLE), config=Config.from_dict({"review": {"two_person": ["ingest"]}}))
    a = g.check_document("MAYBE one").review_id
    g.decide_review(a, "approve", reviewer="lan")
    g.decide_review(a, "edit", reviewer="nam", content="one, cleaned")
    assert g.reviews.get(a)["status"] == "pending"
    done = g.decide_review(a, "approve", reviewer="lan")
    assert done["status"] == "edited" and done["final_content"] == "one, cleaned"
    b = g.check_document("MAYBE two").review_id
    assert g.decide_review(b, "reject", reviewer="lan")["status"] == "rejected"
    ordinary = make_guard(scripted(TABLE)).check_document("MAYBE three")
    assert ordinary.review_id and make_guard(scripted(TABLE)).reviews  # one approval is the default


jwt = pytest.importorskip("jwt")


@pytest.fixture(scope="module")
def keys():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm
    import json

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    public_jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    return private, {"keys": [public_jwk]}


def token(private, **claims):
    body = {"iss": "https://sso.example.vn/realms/acme", "aud": "guardrail", "exp": int(time.time()) + 300,
            "preferred_username": "lan", **claims}
    return jwt.encode(body, private, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
def client(keys):
    _, jwks = keys
    cfg = Config.from_dict({"server": {
        "api_keys": [{"key": "client-key", "role": "client"}],
        "oidc": {"issuer": "https://sso.example.vn/realms/acme", "audience": "guardrail", "jwks": jwks,
                 "roles_claim": "realm_access.roles", "tenant_claim": "tenant",
                 "role_map": {"gr-reviewer": "reviewer", "gr-admin": "admin"}}}})
    g = make_guard(scripted(TABLE), config=cfg)
    return TestClient(create_app(cfg, guard=g))


def test_sso_tokens_map_to_roles_and_tenants(client, keys):
    private, _ = keys
    reviewer = token(private, realm_access={"roles": ["gr-reviewer", "other"]}, tenant="bank")
    h = {"Authorization": f"Bearer {reviewer}"}
    assert client.get("/v1/reviews", headers=h).status_code == 200
    assert client.patch("/v1/policy", headers=h, json={"packs": {"vn-ai": False}}).status_code == 403
    client.post("/v1/ingest", headers={"Authorization": "Bearer client-key", "X-Guardrail-Tenant": "shop"},
                json={"documents": [{"text": "MAYBE shop"}]})
    assert client.get("/v1/reviews", headers=h).json()["items"] == []  # bound to its tenant
    admin = token(private, realm_access={"roles": ["gr-admin"]})
    assert client.patch("/v1/policy", headers={"Authorization": f"Bearer {admin}"}, json={"packs": {"vn-ai": False}}).status_code == 200


def test_bad_tokens_are_refused(client, keys):
    private, _ = keys
    for bad in (token(private, aud="other", realm_access={"roles": ["gr-admin"]}),
                token(private, exp=int(time.time()) - 3600, realm_access={"roles": ["gr-admin"]}),
                token(private, realm_access={"roles": ["nobody"]})):
        assert client.get("/v1/reviews", headers={"Authorization": f"Bearer {bad}"}).status_code == 401
    from cryptography.hazmat.primitives.asymmetric import rsa
    forged = token(rsa.generate_private_key(public_exponent=65537, key_size=2048), realm_access={"roles": ["gr-admin"]})
    assert client.get("/v1/reviews", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
