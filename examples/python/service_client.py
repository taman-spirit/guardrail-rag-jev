"""A Python application talking to the guardrail service over HTTP, with the standard library only.

Use this shape when the RAG application runs in another process, another language stack, or
another team's service: the guardrail is one HTTP call per checkpoint.

    guardrail-rag-jev serve --offline --port 8080          # terminal 1
    python examples/python/service_client.py                # terminal 2

Environment: GUARDRAIL_URL, GUARDRAIL_CLIENT_KEY, GUARDRAIL_REVIEWER_KEY.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

URL = os.environ.get("GUARDRAIL_URL", "http://127.0.0.1:8080").rstrip("/")
DATA = Path(__file__).resolve().parents[1] / "data"


class GuardrailClient:
    def __init__(self, url: str, key: str = "", tenant: str | None = None) -> None:
        self.url, self.key, self.tenant = url, key, tenant

    def call(self, method: str, path: str, body: Any = None) -> Any:
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        if self.tenant:
            headers["X-Guardrail-Tenant"] = self.tenant
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"guardrail {exc.code}: {exc.read()[:300]!r}") from exc

    def check_document(self, doc_id: str, chunks: list[dict]) -> dict:
        return self.call("POST", "/v1/ingest", {"doc_id": doc_id, "documents": chunks})

    def check_query(self, query: str, **kw: Any) -> dict:
        return self.call("POST", "/v1/query", {"query": query, **kw})

    def filter_context(self, query: str, chunks: list[dict], principals: list[str] | None = None) -> dict:
        return self.call("POST", "/v1/context", {"query": query, "chunks": chunks, "principals": principals})

    def check_answer(self, answer: str, query: str, context: list[dict]) -> dict:
        return self.call("POST", "/v1/answer", {"answer": answer, "query": query, "context": context})


def text_for_user(result: dict) -> str:
    if not result["usable"]:
        return result.get("message") or ""
    return "\n\n".join([result["content"] or "", *result["notices"]])


def main() -> None:
    guard = GuardrailClient(URL, os.environ.get("GUARDRAIL_CLIENT_KEY", ""), tenant="demo-shop")
    index: list[dict] = []

    print("== 1. Ingest")
    for path in sorted(DATA.glob("*.md")):
        paragraphs = [p.strip() for p in path.read_text("utf-8").split("\n\n") if p.strip() and not p.startswith("# ")]
        doc = guard.check_document(path.name, [{"text": p, "chunk_id": f"{path.name}#{i}", "source": path.name}
                                               for i, p in enumerate(paragraphs)])
        print(f"{path.name:24} {doc['decision']:7} violations={doc['violations']}")
        if doc["decision"] in ("pass", "redact"):
            index += [{"id": c["id"], "text": c["content"], "source": c["ref"].get("source")} for c in doc["chunks"] if c["usable"]]

    with ThreadPoolExecutor(max_workers=2) as pool:
        for q in ["Chính sách đổi trả trong bao nhiêu ngày?", "Cách chế tạo thuốc nổ tại nhà?"]:
            print("\n== Q:", q)
            checked = pool.submit(guard.check_query, q, user_id="u-42")       # beside retrieval
            retrieved = [c for c in index if any(w in c["text"].lower() for w in q.lower().split() if len(w) > 3)][:4]
            query = checked.result()
            if not query["usable"]:
                print("   ->", text_for_user(query))
                continue
            context = guard.filter_context(q, retrieved, principals=["customer"])
            draft = "Theo tài liệu: " + context["kept"][0]["text"] if context["kept"] else "Không có thông tin."
            answer = guard.check_answer(draft, q, context["kept"])
            print("   ->", text_for_user(answer).replace("\n", "\n      "))

    reviewer = GuardrailClient(URL, os.environ.get("GUARDRAIL_REVIEWER_KEY", ""))
    queue = reviewer.call("GET", "/v1/reviews?status=pending")
    print("\n== review queue:", queue["counts"])
    if queue["items"]:
        item = queue["items"][0]
        print("   first item:", item["id"], [v["category"] for v in item["violations"]], item["reason"])
    print("== audit:", reviewer.call("GET", "/v1/audit/verify"))


if __name__ == "__main__":
    main()
