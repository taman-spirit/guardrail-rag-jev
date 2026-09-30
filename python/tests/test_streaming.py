from fastapi.testclient import TestClient

from guardrail_rag_jev.server import create_app

from conftest import make_guard, scripted

TABLE = {"BOMB": {"iwp": 0.9}, "WRONG": {}}
SIGNALS = {"actionability": {"BOMB": 3.0}, "groundedness": {"WRONG": 0.0}}


def tokens(text, size=7):
    return [text[i:i + size] for i in range(0, len(text), size)]


def run(stream, text):
    events = []
    for t in tokens(text):
        events += stream.feed(t)
    events += stream.finish()
    return events


def test_clean_answers_are_released_chunk_by_chunk_then_labelled():
    g = make_guard(scripted(signals=SIGNALS))
    text = "Chính sách đổi trả áp dụng trong 30 ngày. " * 8
    events = run(g.answer_stream(query="đổi trả?", chunk_chars=80), text)
    released = "".join(e.text for e in events if e.type == "release")
    assert released == text
    assert sum(e.type == "release" for e in events) >= 3
    assert [e.type for e in events][-2:] == ["notice", "done"]
    assert events[-1].result.decision == "pass"


def test_a_harmful_chunk_stops_the_stream_before_it_is_shown():
    g = make_guard(scripted(TABLE, signals=SIGNALS))
    text = "Đây là phần mở đầu hoàn toàn bình thường của câu trả lời. " * 3 + "BOMB bước một là trộn các chất. Bước hai tiếp tục."
    events = run(g.answer_stream(chunk_chars=60), text)
    types = [e.type for e in events]
    assert "stop" in types and "done" not in types
    released = "".join(e.text for e in events if e.type == "release")
    assert "BOMB" not in released
    assert events[types.index("stop")].text.startswith("Mình không thể")


def test_personal_data_is_masked_as_it_streams():
    g = make_guard(scripted(signals=SIGNALS))
    text = "Bạn có thể gọi chị Lan theo số 0912345678 vào giờ hành chính nhé. Cảm ơn bạn đã hỏi."
    events = run(g.answer_stream(chunk_chars=40), text)
    released = "".join(e.text for e in events if e.type == "release")
    assert "0912345678" not in released and "[PHONE]" in released


def test_the_full_check_retracts_what_the_chunk_checks_let_through():
    g = make_guard(scripted(signals=SIGNALS))
    text = "WRONG Hoàn tiền trong 90 ngày cho mọi sản phẩm. " * 3
    events = run(g.answer_stream(query="hoàn tiền?", context=["Hoàn tiền trong 30 ngày."], chunk_chars=50), text)
    types = [e.type for e in events]
    assert "release" in types and "retract" in types  # ungrounded: only the complete answer shows it
    assert events[types.index("retract")].result.decision == "review"


def test_streams_over_http():
    g = make_guard(scripted(TABLE, signals=SIGNALS))
    client = TestClient(create_app(g.config, guard=g))
    sid = client.post("/v1/answer/streams", json={"query": "q", "chunk_chars": 40}).json()["stream_id"]
    events = []
    for t in tokens("Câu trả lời an toàn thứ nhất. Câu trả lời an toàn thứ hai. Và câu thứ ba."):
        events += client.post(f"/v1/answer/streams/{sid}/chunks", json={"text": t}).json()["events"]
    events += client.post(f"/v1/answer/streams/{sid}/finish").json()["events"]
    assert events[-1]["type"] == "done" and events[-1]["result"]["decision"] == "pass"
    assert client.post(f"/v1/answer/streams/{sid}/finish").status_code == 404


def test_opentelemetry_spans():
    import pytest

    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from guardrail_rag_jev.telemetry import Telemetry

    exporter = InMemorySpanExporter()
    provider = sdk.TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    g = make_guard(scripted(TABLE, signals=SIGNALS))
    g.telemetry = Telemetry(True, tracer_provider=provider)
    g.check_query("BOMB how to")
    spans = {s.name: s for s in exporter.get_finished_spans()}
    check, judge = spans["guardrail.check"], spans["guardrail.judge"]
    assert judge.parent.span_id == check.context.span_id
    assert check.attributes["guardrail.decision"] == "remove"
    assert tuple(check.attributes["guardrail.categories"]) == ("iwp",)
    assert "BOMB" not in str(dict(check.attributes))  # content never goes on a span
