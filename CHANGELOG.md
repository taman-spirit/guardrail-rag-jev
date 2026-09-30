# Changelog

## 0.1.0 (2026-09-30)

First release.

- Four checkpoints for RAG: `ingest` (chunks before indexing), `query`, `context` (retrieved
  passages) and `answer`, each with its own enforcement: pass, redact, review or remove.
- Every violation in a piece of content is reported, with its legal or standard basis: multi-label
  questions per category, and located to the paragraph (ingest) or the exact span (detectors).
- Policy: `standard-rag-v1` (20 categories, including indirect prompt injection, malicious content
  and ACL mismatches) and three toggleable Viet Nam packs: `vn-cybersecurity`, `vn-ai`,
  `vn-personal-data`. Categories can be switched off, rescaled or locked; runtime changes are
  validated, persisted and audited.
- Pluggable judging model: `jev` (default), `openai-decisions` (experimental), `llm-judge` (any
  OpenAI-compatible model, including self-hosted), `fallback`, `plugin`; a normaliser fills the
  capability gaps; shadow mode audits disagreements between two models; per-provider calibration
  overlays; data-residency control.
- Deterministic detectors for Vietnamese identifiers (CCCD, phone, bank account, passport, social
  insurance, licence plate), cards, secrets and hidden characters; masking, link defanging, allow
  and deny patterns.
- Review queue with approve, reject and edit; decisions become content-hash overrides; signed
  webhooks; retention purge. Tamper-evident audit log (JSON Lines or SQLite) with SIEM forwarding.
- Service (FastAPI): checkpoints, batches, ingest jobs, reviews, audit, policy, profiles and tenants,
  role-based keys, Dify moderation extension, Azure AI Search custom skill, Prometheus metrics,
  review console.
- Go client, LangChain and LlamaIndex integrations, Bedrock and Open WebUI examples, Docker.
