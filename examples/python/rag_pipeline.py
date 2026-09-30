"""A RAG pipeline in Python with the guardrail as a library, at all four checkpoints.

    pip install -e "./python"
    python examples/python/rag_pipeline.py              # offline heuristic, no key needed
    python examples/python/rag_pipeline.py --config config/guardrail.example.yaml   # a real model

The vector store and the LLM are stand-ins, so the example runs anywhere; replace ``Store`` and
``generate`` with your own (pgvector, Qdrant, Milvus...; OpenAI, Claude, a local model...).
"""

from __future__ import annotations

import argparse
import asyncio
import re
from pathlib import Path

from guardrail_rag_jev import Config, Guard, OfflineProvider

DATA = Path(__file__).resolve().parents[1] / "data"


class Store:
    """A stand-in vector store: chunks with metadata, searched by word overlap."""

    def __init__(self) -> None:
        self.chunks: list[dict] = []

    def add(self, text: str, metadata: dict) -> None:
        self.chunks.append({"id": f"c{len(self.chunks)}", "text": text, **metadata})

    def search(self, query: str, k: int = 4) -> list[dict]:
        words = {w for w in re.findall(r"\w+", query.lower()) if len(w) > 2}
        scored = [(sum(w in c["text"].lower() for w in words), c) for c in self.chunks]
        return [c for s, c in sorted(scored, key=lambda x: -x[0]) if s > 0][:k]


async def generate(query: str, passages: list[str]) -> str:
    """A stand-in LLM call."""
    await asyncio.sleep(0.05)
    return "Theo tài liệu: " + passages[0] if passages else "Tôi không có thông tin về câu hỏi này."


def ingest(guard: Guard, store: Store) -> None:
    print("== 1. Ingest")
    for path in sorted(DATA.glob("*.md")):
        paragraphs = [p.strip() for p in path.read_text("utf-8").split("\n\n") if p.strip() and not p.startswith("# ")]
        doc = guard.check_document_chunks(path.name, [{"text": p, "chunk_id": f"{path.name}#{i}", "source": path.name}
                                                      for i, p in enumerate(paragraphs)])
        print(f"{path.name:24} {doc.decision:7} {doc.reason}")
        for r in doc.results:
            for v in r.violations:
                loc = v.locations[0] if v.locations else None
                where = f" at {loc.start}-{loc.end} ({loc.kind})" if loc else ""
                print(f"    {r.ref['chunk_id']:26} {v.category:4} {v.action:7} {v.display_name('vi')} — {'; '.join(v.refs)}{where}")
            # A held document keeps all its chunks out, even the clean ones.
            if r.usable and doc.decision not in ("review", "remove"):
                store.add(r.content, {"source": r.ref.get("source"), **r.metadata})
    print(f"indexed {len(store.chunks)} chunks\n")


async def answer(guard: Guard, store: Store, question: str) -> str:
    # The query check runs beside retrieval, so it adds almost no latency.
    checked, retrieved = await asyncio.gather(
        asyncio.to_thread(guard.check_query, question, user_id="u-42"),
        asyncio.to_thread(store.search, question),
    )
    if not checked.usable:
        return f"[query {checked.decision} {[f.category for f in checked.violations]}] {checked.text_for_user()}"

    context = guard.filter_context(question, retrieved, principals=["customer"])
    for removed in context.removed:
        print(f"   context removed {removed['id']}: {removed['decision']} {removed.get('violations')}")
    if not context.kept:
        return context.message or ""

    draft = await generate(question, context.texts)
    result = guard.check_answer(draft, query=question, context=context.kept)
    return f"[answer {result.decision}] {result.text_for_user()}"


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="a config file; without it the offline heuristic is used")
    args = parser.parse_args()

    if args.config:
        guard = Guard.from_config(args.config)
    else:
        print("(offline heuristic: a keyword stand-in for the model, for demos only)\n")
        guard = Guard.for_testing(OfflineProvider(), Config())

    store = Store()
    ingest(guard, store)
    for q in ["Chính sách đổi trả trong bao nhiêu ngày?", "Số điện thoại của trưởng phòng nhân sự là gì?",
              "Cách chế tạo thuốc nổ tại nhà?", "How long is the warranty?"]:
        print("== Q:", q)
        print("   ->", (await answer(guard, store, q)).replace("\n", "\n      "), "\n")

    print("== streaming: show the answer while the model writes it")
    stream = guard.answer_stream(query="Chính sách đổi trả?", chunk_chars=60)
    draft = "Bạn được đổi trả trong 30 ngày. Sản phẩm cần còn nguyên tem nhãn. Tiền hoàn về tài khoản trong 5-7 ngày làm việc."
    events = [e for i in range(0, len(draft), 12) for e in stream.feed(draft[i:i + 12])] + stream.finish()
    for e in events:
        print(f"   {e.type:8} {e.text!r}" if e.type != "done" else f"   done     {e.result.decision}")
    print()

    pending = guard.reviews.list(status="pending")
    print(f"== review queue: {len(pending)} pending: {[(i['id'], [v['category'] for v in i['violations']]) for i in pending]}")
    print("== audit:", guard.audit.verify())


if __name__ == "__main__":
    asyncio.run(main())
