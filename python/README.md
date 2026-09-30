# guardrail-rag-jev (Python)

Content guardrails for RAG systems: documents before indexing, user queries, retrieved passages and
generated answers, checked against one policy with toggleable Viet Nam law packs. The judging model
is pluggable: TypeSafe Jev by default, the OpenAI Decisions API, or any OpenAI-compatible model you
host yourself.

Full documentation: [English](../README.md) · [Tiếng Việt](../README.vi.md)

```bash
pip install "guardrail-rag-jev[server]"
export JEV_API_KEY=...
```

```python
from guardrail_rag_jev import Guard

guard = Guard.from_config("guardrail.yaml")

r = guard.check_document(text, doc_id="handbook.pdf", chunk_id="p3")   # ingest
r.decision        # 'pass' | 'redact' | 'review' | 'remove'
r.content         # the text to index (masked where needed), None when held or removed
r.violations      # every violation, with its legal basis and location

ctx = guard.filter_context(question, retrieved_chunks)                 # context
answer = guard.check_answer(draft, query=question, context=ctx.kept)   # answer
print(answer.text_for_user())
```

Service: `guardrail-rag-jev serve --config guardrail.yaml`. Demo without a key:
`guardrail-rag-jev serve --offline`.
