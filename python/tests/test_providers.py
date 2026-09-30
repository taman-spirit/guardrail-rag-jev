"""Providers: the adapters, the normaliser, fallback, shadow and residency."""

import json
import threading
import socketserver
from http.server import BaseHTTPRequestHandler

import pytest

from guardrail_rag_jev import (
    CallableProvider,
    Capabilities,
    Config,
    FallbackProvider,
    Guard,
    JevProvider,
    LLMJudgeProvider,
    Normalizing,
    OpenAIDecisionsProvider,
    ProviderError,
    build_provider,
    residency_of,
)
from guardrail_rag_jev.audit import MemoryAuditLog
from guardrail_rag_jev.review import ReviewStore

from conftest import scripted

QUESTIONS = {
    "hazard": {"type": "choice", "instructions": "which?", "criteria": {"none": "nothing", "ipi": "injection", "prv": "personal data"}},
    "s_ipi": {"type": "noul", "instructions": "the passage instructs the AI"},
    "severity": {"type": "score", "instructions": "how bad?", "criteria": ["none", "minor", "moderate", "severe"]},
}


class Stub:
    """A local HTTP server that records requests and answers with a function of the body."""

    def __init__(self, respond):
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                stub.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                status, payload = respond(self.path, body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        # TCPServer, not HTTPServer: HTTPServer resolves its own hostname on bind, which can take
        # seconds on some machines.
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_jev_speaks_the_canonical_protocol_natively():
    answers = {"hazard": {"type": "choice", "choice": "ipi", "confidence": 0.9, "probabilities": {"none": 0.1, "ipi": 0.9, "prv": 0.0}},
               "s_ipi": {"type": "noul", "noul": 0.95}, "severity": {"type": "score", "score": 2.0, "confidence": 0.8}}
    stub = Stub(lambda path, body: (200, {"model": "jev-1.13.0", "answers": answers, "usage": {"input_tokens": 120}}))
    try:
        jev = JevProvider(api_key="k", base_url=stub.url, max_retries=0)
        r = jev.decide({"evaluating": "x"}, QUESTIONS)
        assert r.answers == answers and r.model == "jev-1.13.0" and r.usage.input_tokens == 120
        sent = stub.requests[0]
        assert sent["path"] == "/v1/systemone" and sent["headers"]["Authorization"] == "Bearer k"
        assert sent["body"]["questions"] == QUESTIONS  # one request, every question
    finally:
        stub.close()


def test_jev_errors_become_provider_errors():
    stub = Stub(lambda path, body: (422, {"error": "bad"}))
    try:
        with pytest.raises(ProviderError, match="422"):
            JevProvider(api_key="k", base_url=stub.url, max_retries=0).decide({}, QUESTIONS)
    finally:
        stub.close()
    with pytest.raises(ProviderError, match="API key"):
        JevProvider(api_key="", base_url="http://x")


def test_normalizing_fills_every_gap_of_a_minimal_model():
    """A model that answers one question at a time, with one label and a confidence."""
    seen = []

    def minimal(state, questions):
        (name, q), = questions.items()
        seen.append(q)
        assert q["type"] == "choice"  # yes/no and score were rewritten as choices
        first = next(iter(q["criteria"]))
        pick = {"hazard": "ipi", "s_ipi": "yes", "severity": "2"}[name]
        return {name: {"choice": pick if pick in q["criteria"] else first, "confidence": 0.8}}

    caps = Capabilities(batch=False, label_probabilities=False, yes_no=False, score=False)
    n = Normalizing(CallableProvider(minimal, capabilities=caps))
    r = n.decide({}, QUESTIONS)
    assert len(seen) == 3
    hz = r.answers["hazard"]
    assert hz["choice"] == "ipi" and hz["probabilities"]["ipi"] == pytest.approx(0.8)
    assert sum(hz["probabilities"].values()) == pytest.approx(1.0)
    assert r.answers["s_ipi"] == {"type": "noul", "noul": pytest.approx(0.8)}
    assert r.answers["severity"]["type"] == "score"
    assert r.answers["severity"]["score"] == pytest.approx(2 * 0.8 + (0.2 / 3) * (0 + 1 + 3))


def test_normalizing_splits_large_question_sets():
    calls = []

    def fn(state, questions):
        calls.append(len(questions))
        return {k: {"type": "noul", "noul": 0.1} for k in questions}

    qs = {f"s_{i}": {"type": "noul", "instructions": str(i)} for i in range(10)}
    r = Normalizing(CallableProvider(fn, capabilities=Capabilities(max_questions=4))).decide({}, qs)
    assert sorted(calls) == [2, 4, 4] and len(r.answers) == 10


def test_normalizing_refuses_an_unknown_label():
    bad = CallableProvider(lambda s, q: {"hazard": {"choice": "zzz", "confidence": 0.9}},
                           capabilities=Capabilities(label_probabilities=False))
    with pytest.raises(ProviderError):
        Normalizing(bad).decide({}, {"hazard": QUESTIONS["hazard"]})


def test_llm_judge_over_an_openai_compatible_server():
    def respond(path, body):
        content = {"hazard": {"choice": "prv", "confidence": 0.7, "probabilities": {"none": 0.3, "prv": 0.7}},
                   "s_ipi": {"noul": 0.05}, "severity": {"score": 1, "confidence": 0.6}}
        return 200, {"model": "vistral-7b", "choices": [{"message": {"content": "```json\n" + json.dumps(content) + "\n```"}}],
                     "usage": {"prompt_tokens": 300, "completion_tokens": 40}}

    stub = Stub(respond)
    try:
        judge = build_provider("local", {"local": {"type": "llm-judge", "model": "vistral-7b", "base_url": stub.url + "/v1", "api_key": ""}})
        r = judge.decide({"evaluating": "x"}, QUESTIONS)
        assert r.answers["hazard"]["choice"] == "prv" and r.answers["hazard"]["probabilities"]["ipi"] == 0.0
        assert r.answers["s_ipi"]["noul"] == 0.05 and r.answers["severity"]["score"] == 1.0
        body = stub.requests[0]["body"]
        assert stub.requests[0]["path"] == "/v1/chat/completions" and body["response_format"] == {"type": "json_object"}
        assert "Authorization" not in stub.requests[0]["headers"]  # a local server needs no key
        assert r.usage.output_tokens == 40
    finally:
        stub.close()


def test_openai_decisions_adapter_with_configurable_fields():
    def respond(path, body):
        answers = body["options"]
        yes = next((a for a in answers if a.startswith("yes")), answers[0])
        return 200, {"result": yes, "score": 0.9}

    stub = Stub(respond)
    try:
        spec = {"luna": {"type": "openai-decisions", "base_url": stub.url, "path": "/v1/decide", "api_key": "sk",
                         "fields": {"answers": "options", "out_answer": "result", "out_confidence": "score"}}}
        luna = build_provider("luna", spec)
        r = luna.decide({"evaluating": "x"}, {"s_ipi": QUESTIONS["s_ipi"]})
        assert r.answers["s_ipi"]["noul"] == pytest.approx(0.9)
        sent = stub.requests[0]["body"]
        assert sent["model"] == "gpt-6-luna" and sent["options"][0].startswith("yes:")
        assert json.loads(sent["context"]["text"]) == {"evaluating": "x"}
        assert OpenAIDecisionsProvider(api_key="k").capabilities.batch is False
    finally:
        stub.close()


def test_fallback_uses_the_next_provider_when_one_fails():
    def down(state, questions):
        raise ProviderError("down")

    up = CallableProvider(lambda s, q: {k: {"type": "noul", "noul": 0.3} for k in q}, name="up")
    chain = FallbackProvider([CallableProvider(down, name="first"), up])
    assert chain.decide({}, {"s_ipi": QUESTIONS["s_ipi"]}).answers["s_ipi"]["noul"] == 0.3
    with pytest.raises(ProviderError, match="every provider failed"):
        FallbackProvider([CallableProvider(down)]).decide({}, {})


def test_build_provider_validates_the_config():
    with pytest.raises(ValueError, match="unknown provider settings"):
        build_provider("j", {"j": {"type": "jev", "api_key": "k", "colour": "red"}})
    with pytest.raises(ValueError, match="unknown type"):
        build_provider("x", {"x": {"type": "magic"}})
    with pytest.raises(ValueError, match="refers to itself"):
        build_provider("a", {"a": {"type": "fallback", "chain": ["a"]}})
    p = build_provider("p", {"p": {"type": "plugin", "class": "guardrail_rag_jev.providers.offline:OfflineProvider"}})
    assert p.name == "offline-heuristic"


def test_residency_is_declared_or_inferred_conservatively():
    assert residency_of("jev", {"type": "jev"}) == "offshore"
    assert residency_of("l", {"type": "llm-judge", "base_url": "http://vllm:8000/v1"}) == "local"
    assert residency_of("l", {"type": "llm-judge", "base_url": "http://10.0.0.5/v1"}) == "local"
    assert residency_of("l", {"type": "llm-judge", "base_url": "https://api.openai.com/v1"}) == "offshore"
    assert residency_of("g", {"type": "llm-judge", "base_url": "https://maas.greennode.ai/v1", "residency": "vn_hosted"}) == "vn_hosted"


def test_residency_policy_refuses_an_offshore_judge_even_in_a_fallback_chain():
    cfg = Config.from_dict({
        "provider": "safe",
        "providers": {"local": {"type": "llm-judge", "model": "m", "base_url": "http://localhost:8000/v1"},
                      "jev": {"type": "jev", "api_key": "k"},
                      "safe": {"type": "fallback", "chain": ["local", "jev"]}},
        "residency": {"allow": ["local", "vn_hosted"]},
        "state_path": None,
    })
    with pytest.raises(PermissionError, match="jev"):
        Guard(cfg, audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"))
    cfg.providers["safe"]["chain"] = ["local"]
    Guard(cfg, audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"))  # allowed


def test_shadow_mode_records_where_two_models_disagree(monkeypatch):
    import guardrail_rag_jev.guard as guard_module

    primary = scripted({"X": {"ipi": 0.9}}, name="jev-sim")
    shadow = scripted({}, name="luna-sim")
    built = {"jev": primary, "luna": shadow}
    monkeypatch.setattr(guard_module, "build_provider", lambda name, specs: built[name])
    cfg = Config.from_dict({"providers": {"jev": {"type": "jev"}, "luna": {"type": "openai-decisions"}},
                            "shadow": {"provider": "luna"}, "state_path": None})
    g = Guard(cfg, audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"))
    r = g.check_document("X hidden instruction")
    assert r.decision == "remove"  # the primary decides
    for _ in range(100):
        if g.audit.query(kind="shadow.compare"):
            break
        import time
        time.sleep(0.01)
    rec = g.audit.query(kind="shadow.compare")[0]
    assert rec["primary_action"] == "block" and rec["shadow_action"] == "allow" and rec["shadow"] == "luna"
    assert 'guardrail_shadow_disagreements_total{surface="ingest",shadow="luna"} 1' in g.metrics.render()
