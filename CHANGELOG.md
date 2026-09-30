# Changelog

## 0.2.0 (2026-09-30)

- Self-hosted safety classifiers: `sea-guard`, `granite-guardian` and `classifier` (one yes/no
  criterion per request, probabilities from token log-probabilities) and `llama-guard` (S1-S14
  mapped to the policy's categories). `routed` splits a question set between providers by name. The
  normaliser now asks a choice label by label for models without choice questions, and asks
  identical questions once.
- Streamed answers: `Guard.answer_stream()` and `/v1/answer/streams` release checked text chunk by
  chunk, stop on a violating chunk, and retract what was shown when the complete answer fails.
- Four-eyes review: `review.two_person` makes chosen surfaces or categories need two different
  reviewers to release; rejecting needs one. `review.approval` is audited and posted.
- Single sign-on: OpenID Connect access tokens, verified against the provider's JWKS, with roles and
  tenants mapped from claims (`server.oidc`).
- OpenTelemetry: `guardrail.check` and `guardrail.judge` spans (`telemetry.otel`).
- Distributed ingest jobs: `jobs.backend: redis` and `guardrail-rag-jev worker`, with stale jobs
  requeued; `docker compose --profile workers`.
- Evaluation and calibration: `datasets/vi-rag-v1.jsonl` (48 labelled cases), `eval` (with
  `--record` / `--replay`) and `calibrate`, which writes a per-provider calibration overlay.
- Go client: `StartAnswerStream`, `Feed`, `Finish`.

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
