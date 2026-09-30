"""LlamaIndex integration. Needs ``llama-index-core``.

    from guardrail_rag_jev.integrations.llamaindex import GuardrailTransform, GuardrailPostprocessor

    # ingest: last transformation before the embedding
    pipeline = IngestionPipeline(transformations=[SentenceSplitter(), GuardrailTransform(guard=guard), embed_model])

    # context: after retrieval, before synthesis
    query_engine = index.as_query_engine(node_postprocessors=[GuardrailPostprocessor(guard=guard)])

    # answer: check the response before showing it
    response = query_engine.query(question)
    shown = guard.check_answer(str(response), query=question,
                               context=[n.get_content() for n in response.source_nodes]).text_for_user()
"""

from __future__ import annotations

from typing import Any, Sequence

try:
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
    from llama_index.core.schema import BaseNode, NodeWithScore, QueryBundle, TransformComponent
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError("the LlamaIndex integration needs llama-index-core: pip install llama-index-core") from exc


class GuardrailTransform(TransformComponent):
    """Ingest checkpoint: drops held and removed nodes, masks the rest where needed, and writes the
    guard's metadata onto each node."""

    guard: Any
    tenant: str | None = None

    def __call__(self, nodes: Sequence[BaseNode], **kwargs: Any) -> list[BaseNode]:
        items = [
            {"text": n.get_content(), "chunk_id": n.node_id, "doc_id": n.ref_doc_id,
             "source": n.metadata.get("file_name") or n.metadata.get("source"), "trust": n.metadata.get("trust")}
            for n in nodes
        ]
        results = self.guard.check_documents(items, tenant=self.tenant)
        out = []
        for node, result in zip(nodes, results):
            if not result.usable:
                continue
            if result.decision == "redact" and hasattr(node, "set_content"):
                node.set_content(result.content or "")
            node.metadata.update({k: v for k, v in result.metadata.items() if not isinstance(v, list)})
            out.append(node)
        return out


class GuardrailPostprocessor(BaseNodePostprocessor):
    """Context checkpoint: retrieved nodes pass through ``Guard.filter_context``."""

    guard: Any
    principals: list[str] | None = None
    acl_key: str = "acl"

    @classmethod
    def class_name(cls) -> str:
        return "GuardrailPostprocessor"

    def _postprocess_nodes(self, nodes: list[NodeWithScore], query_bundle: QueryBundle | None = None) -> list[NodeWithScore]:
        query = query_bundle.query_str if query_bundle else None
        chunks = [{"text": n.node.get_content(), "id": n.node.node_id, "acl": n.node.metadata.get(self.acl_key)} for n in nodes]
        result = self.guard.filter_context(query, chunks, principals=self.principals)
        kept = {c["id"]: c["text"] for c in result.kept}
        out = []
        for n in nodes:
            if n.node.node_id in kept:
                if kept[n.node.node_id] != n.node.get_content() and hasattr(n.node, "set_content"):
                    n.node.set_content(kept[n.node.node_id])
                out.append(n)
        return out
