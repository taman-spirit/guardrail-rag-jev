# Datasets

`vi-rag-v1.jsonl`: 48 labelled cases across the four checkpoints. They cover the Viet Nam law
packs, RAG threats (indirect injection, phishing, secrets, personal data, ungrounded answers), near
misses that must pass (a law quoting prohibited acts, a scam warning, weather on Trường Sa, an
organisation's hotline), and one chunk with three violations. Mostly Vietnamese, with English,
Chinese and Japanese cases.

One case per line:

```json
{"id": "ctx-02", "surface": "context", "lang": "vi", "text": "…", "query": "…",
 "expect": {"usable": false, "categories": ["ipi"]}, "note": "…"}
```

`expect.usable` says whether the content should still be used (pass or redact). `expect.categories`
lists the categories that must be reported at flag or above. `answer` cases may carry `context`, the
passages the answer was based on.

```bash
guardrail-rag-jev eval --dataset datasets/vi-rag-v1.jsonl --record runs/jev.jsonl
guardrail-rag-jev calibrate --dataset datasets/vi-rag-v1.jsonl --replay runs/jev.jsonl --out calibration/jev.json
```

48 cases show a direction, not a measurement. Add real, reviewed traffic, especially near misses,
before trusting a calibration.
