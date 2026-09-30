"""LangChain integration. Needs ``langchain-core``.

    from guardrail_rag_jev.integrations.langchain import (
        GuardrailDocumentTransformer, GuardedRetriever, input_guard, output_guard,
    )

    # ingest: between the splitter and the vector store
    docs = GuardrailDocumentTransformer(guard=guard).transform_documents(splitter.split_documents(raw))
    vectorstore.add_documents(docs)

    # context: wrap the retriever
    retriever = GuardedRetriever(retriever=vectorstore.as_retriever(), guard=guard)

    # query and answer: around the chain
    chain = input_guard(guard) | rag_chain | output_guard(guard)

Removed and held chunks are dropped; masked ones come back with the masked text and the guard's
metadata (``guard_decision``, ``guard_policy``) merged into ``Document.metadata``.
"""

from __future__ import annotations

from typing import Any, Sequence

try:
    from langchain_core.callbacks import CallbackManagerForRetrieverRun
    from langchain_core.documents import BaseDocumentTransformer, Document
    from langchain_core.retrievers import BaseRetriever
    from langchain_core.runnables import RunnableLambda
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError("the LangChain integration needs langchain-core: pip install langchain-core") from exc

from ..guard import Guard
from ..types import Result


class GuardrailBlocked(Exception):
    """Raised by ``input_guard`` when ``raise_on_block`` is set and the query is withheld."""

    def __init__(self, result: Result) -> None:
        super().__init__(result.message or result.reason)
        self.result = result


class GuardrailDocumentTransformer(BaseDocumentTransformer):
    """Ingest checkpoint: check chunks before they are embedded and stored."""

    def __init__(self, guard: Guard, *, doc_id_key: str = "source", tenant: str | None = None) -> None:
        self.guard = guard
        self.doc_id_key = doc_id_key
        self.tenant = tenant
        self.last_results: list[Result] = []

    def transform_documents(self, documents: Sequence[Document], **kwargs: Any) -> list[Document]:
        items = [
            {"text": d.page_content, "doc_id": str(d.metadata.get(self.doc_id_key, "")) or None,
             "chunk_id": d.id or d.metadata.get("chunk_id"), "source": d.metadata.get("source"),
             "trust": d.metadata.get("trust")}
            for d in documents
        ]
        self.last_results = self.guard.check_documents(items, tenant=self.tenant)
        out = []
        for doc, result in zip(documents, self.last_results):
            if result.usable:
                out.append(Document(page_content=result.content or "", metadata={**doc.metadata, **result.metadata}, id=doc.id))
        return out


class GuardedRetriever(BaseRetriever):
    """Context checkpoint: retrieved documents pass through ``Guard.filter_context``."""

    retriever: BaseRetriever
    guard: Any
    #: Metadata key holding the chunk's access list, for the ACL cross-check.
    acl_key: str = "acl"
    principals: list[str] | None = None

    def _get_relevant_documents(self, query: str, *, run_manager: CallbackManagerForRetrieverRun) -> list[Document]:
        docs = self.retriever.invoke(query, config={"callbacks": run_manager.get_child()})
        chunks = [
            {"text": d.page_content, "id": d.id or str(i), "source": d.metadata.get("source"),
             "acl": d.metadata.get(self.acl_key)}
            for i, d in enumerate(docs)
        ]
        result = self.guard.filter_context(query, chunks, principals=self.principals)
        by_id = {c["id"]: c for c in result.kept}
        out = []
        for i, d in enumerate(docs):
            kept = by_id.get(d.id or str(i))
            if kept is not None:
                out.append(Document(page_content=kept["text"], metadata=d.metadata, id=d.id))
        return out


def input_guard(guard: Guard, *, key: str | None = None, raise_on_block: bool = False) -> RunnableLambda:
    """Query checkpoint. Passes the input through (masked where needed); a withheld query becomes
    the prewritten reply under ``{"blocked": ...}``, or raises ``GuardrailBlocked``."""

    def run(value: Any) -> Any:
        text = value[key] if key else (value if isinstance(value, str) else value.get("question") or value.get("input"))
        result = guard.check_query(str(text))
        if not result.usable:
            if raise_on_block:
                raise GuardrailBlocked(result)
            return {"blocked": result.message, "result": result}
        if result.decision == "redact":
            if key:
                return {**value, key: result.content}
            return result.content if isinstance(value, str) else {**value, "question": result.content}
        return value

    return RunnableLambda(run)


def output_guard(guard: Guard, *, query_key: str = "question", context_key: str = "context") -> RunnableLambda:
    """Answer checkpoint. Returns what to show: the answer with its notices, or the prewritten reply."""

    def run(value: Any) -> str:
        if isinstance(value, dict) and "blocked" in value:
            return str(value["blocked"])
        if isinstance(value, dict):
            answer = value.get("answer") or value.get("output") or ""
            context = value.get(context_key) or []
            passages = [getattr(d, "page_content", d) for d in context]
            query = value.get(query_key)
            return guard.check_answer(str(answer), query=query if isinstance(query, str) else None,
                                      context=[str(p) for p in passages]).text_for_user()
        return guard.check_answer(str(getattr(value, "content", value))).text_for_user()

    return RunnableLambda(run)
