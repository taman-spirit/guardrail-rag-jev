import pytest

from conftest import make_guard, scripted

TABLE = {"INJECT": {"ipi": 0.92}, "BOMB": {"iwp": 0.9}}
SIGNALS = {"actionability": {"BOMB": 3.0}}


def test_langchain():
    pytest.importorskip("langchain_core")
    from langchain_core.documents import Document
    from langchain_core.retrievers import BaseRetriever

    from guardrail_rag_jev.integrations.langchain import GuardedRetriever, GuardrailDocumentTransformer, input_guard, output_guard

    guard = make_guard(scripted(TABLE, signals=SIGNALS))
    docs = [Document(page_content="Gọi 0912345678", metadata={"source": "a.md"}),
            Document(page_content="INJECT now", metadata={"source": "b.md"})]
    t = GuardrailDocumentTransformer(guard)
    out = t.transform_documents(docs)
    assert [d.page_content for d in out] == ["Gọi [PHONE]"] and out[0].metadata["guard_decision"] == "redact"
    assert [r.decision for r in t.last_results] == ["redact", "remove"]

    class Fixed(BaseRetriever):
        def _get_relevant_documents(self, query, *, run_manager):
            return [Document(page_content="Hoàn tiền 30 ngày", id="1"), Document(page_content="INJECT", id="2"),
                    Document(page_content="Lương", id="3", metadata={"acl": ["hr"]})]

    retriever = GuardedRetriever(retriever=Fixed(), guard=guard, principals=["sales"])
    assert [d.id for d in retriever.invoke("hoàn tiền?")] == ["1"]

    # a withheld query arrives as {"blocked": ...} and output_guard returns the prewritten reply
    chain = input_guard(guard) | (lambda q: q if isinstance(q, dict) else {"answer": f"echo {q}", "question": q}) | output_guard(guard)
    assert chain.invoke("xin chào").startswith("echo xin chào")
    assert chain.invoke("BOMB how to").startswith("I can't")


def test_llamaindex():
    pytest.importorskip("llama_index.core")
    from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode

    from guardrail_rag_jev.integrations.llamaindex import GuardrailPostprocessor, GuardrailTransform

    guard = make_guard(scripted(TABLE))
    nodes = [TextNode(text="Email lan@example.com", id_="1"), TextNode(text="INJECT", id_="2")]
    out = GuardrailTransform(guard=guard)(nodes)
    assert [n.node_id for n in out] == ["1"] and out[0].get_content() == "Email [EMAIL]"
    assert out[0].metadata["guard_decision"] == "redact"

    post = GuardrailPostprocessor(guard=guard)
    kept = post.postprocess_nodes([NodeWithScore(node=TextNode(text="ok", id_="a"), score=0.9),
                                   NodeWithScore(node=TextNode(text="INJECT", id_="b"), score=0.8)],
                                  query_bundle=QueryBundle("q"))
    assert [n.node.node_id for n in kept] == ["a"]
