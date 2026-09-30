# HTTP API

The service is `guardrail-rag-jev serve`. OpenAPI is served at `/docs` and `/openapi.json`.

## Authentication

`Authorization: Bearer <key>`. Each key has a role:

| Role | Can use |
| --- | --- |
| `client` | checkpoints, ingest jobs, `GET /v1/policy` |
| `reviewer` | everything a client can, plus reviews and the audit log |
| `admin` | everything, plus policy changes and `GET /v1/config` |

A key bound to a tenant (`tenant:` in `server.api_keys`) records its checks under that tenant and
sees only that tenant's reviews, jobs and audit records. Unbound keys may send
`X-Guardrail-Tenant`. `X-Guardrail-Profile` (or `profile` in the body) selects a profile.

With no keys configured the service is open. Use that for local development only.

## The result object

Every checkpoint returns results of this shape:

```json
{
  "id": "chk_…",
  "surface": "ingest",
  "decision": "redact",
  "usable": true,
  "content": "Liên hệ chị Lan qua [PHONE].",
  "language": "vi",
  "message": null,
  "notices": [],
  "violations": [
    {
      "category": "prv",
      "name": "Quyền riêng tư và dữ liệu cá nhân",
      "names": {"en": "Privacy and personal data", "vi": "Quyền riêng tư và dữ liệu cá nhân"},
      "pack": "standard-rag-v1",
      "action": "review",
      "probability": 1.0,
      "refs": ["AILuminate prv", "Luật Bảo vệ dữ liệu cá nhân (Luật số 91/2025/QH15)"],
      "source": "detector:vn_phone",
      "locations": [{"start": 20, "end": 30, "kind": "detector:vn_phone", "excerpt": "Liên hệ chị Lan qua [PHONE]."}]
    }
  ],
  "redactions": [{"detector": "vn_phone", "category": "prv", "start": 20, "end": 30, "replacement": "[PHONE]"}],
  "review_id": null,
  "override": null,
  "reason": "action review (prv): sensitive spans masked",
  "would_decision": null,
  "metadata": {"guard_decision": "redact", "guard_policy": "standard-rag-v1@1.0.0+…#…", "guard_checked_at": "…"},
  "provider": "jev",
  "verdict": {"action": "review", "route": "redact", "signals": {}, "applied_rules": [], "degraded": false, "…": "…"}
}
```

| Field | Meaning |
| --- | --- |
| `decision` | `pass` (use as is), `redact` (use `content`, masked), `review` (held until a person approves), `remove` (dropped) |
| `usable` | `decision` is `pass` or `redact` |
| `content` | the text to use; `null` when held or removed |
| `message` | for a withheld query or answer: the prewritten reply, in `language` |
| `notices` | text to show with a used answer: a disclaimer, the AI label, a fixed affirmation |
| `violations` | every category at flag or above, strongest first, each with its basis and locations |
| `would_decision` | in shadow mode, what enforcement would have done |
| `metadata` | ingest only: write it next to the chunk in the vector store |

## Checkpoints

| Method and path | Body | Returns |
| --- | --- | --- |
| `POST /v1/ingest` | `{"documents": [Chunk], "doc_id"?}` | `{"results": [Result]}`, or with `doc_id` a document roll-up `{"doc_id", "decision", "reason", "violations": {category: [chunk ids]}, "chunks": [Result]}` |
| `POST /v1/ingest/jobs` | `{"documents": [Chunk], "callback_url"?}` | `202 {"job_id", "status": "queued"}` |
| `GET /v1/jobs/{id}` | | `{"status", "total", "done", "summary", "results"}` |
| `POST /v1/query` | `{"query", "user_id"?, "session_id"?, "language"?, "metadata"?}` | Result |
| `POST /v1/context` | `{"query"?, "chunks": [Chunk], "principals"?, "language"?}` | `{"kept": [Chunk], "removed": [...], "message", "results": [Result]}` |
| `POST /v1/answer` | `{"answer", "query"?, "context"?: [Chunk or string], "language"?, "partial"?}` | Result |

A `Chunk` is `{"text", "id"?, "doc_id"?, "chunk_id"?, "source"?, "title"?, "trust"?: "trusted" | "internal" | "untrusted", "acl"?: [principal], "score"?, "metadata"?}`.

A batch holds at most `server.max_batch` items (default 256); use a job for more. A job's callback
receives `{"event": "job.done", "job_id", "summary", "results"}`, signed like review webhooks.

`partial: true` on `/v1/answer` is for a streamed answer still being written. Only the
must-not-miss questions are asked and nothing is queued; check the complete answer at the end.

## Review

| Method and path | Body | Notes |
| --- | --- | --- |
| `GET /v1/reviews?status=pending&surface=&limit=&offset=` | | `{"items", "counts"}` |
| `GET /v1/reviews/{id}` | | the item, with content (unless purged) and violations |
| `POST /v1/reviews/{id}/decision` | `{"decision": "approve" \| "reject" \| "edit", "note"?, "content"?}` | `edit` needs `content`; a decided item returns `409` |

A decision becomes an override keyed by the content hash. Its scope is `document` (shared by ingest
and context), `query` or `answer`. It is posted to `review.webhook_url` as
`{"event": "review.decided", "review": {...}}` with the header
`X-Guardrail-Signature: sha256=<hex HMAC of the body>`.

## Audit

| Method and path | Notes |
| --- | --- |
| `GET /v1/audit?type=&surface=&decision=&ref=&limit=&before_seq=` | newest first; `type` also matches a prefix (`review` matches `review.decided`) |
| `GET /v1/audit/verify` | `{"ok", "count", "head"}` or `{"ok": false, "broken_at", "reason"}` |
| `GET /v1/audit/head` | `{"seq", "hash"}`: keep a copy outside the service |

Record types: `check`, `check.partial`, `document`, `review.decided`, `policy.changed`,
`shadow.compare`, `shadow.error`, `job.created`, `job.done`, `job.failed`.

## Policy

| Method and path | Body | Notes |
| --- | --- | --- |
| `GET /v1/policy?profile=` | | packs (on and off), categories, thresholds, rules, `locked` |
| `PATCH /v1/policy` | `{"packs"?: {id: bool}, "categories"?: {id: {"enabled"?, "sensitivity"?, "thresholds"?}}, "profile"?}` | `403` for a locked pack or category, `422` for an invalid change |
| `POST /v1/policy/reset?profile=` | | drops every runtime change |
| `GET /v1/config` | | the effective config, secrets masked |

## Platform integrations

| Path | For |
| --- | --- |
| `POST /v1/integrations/dify/moderation` | Dify's API-based moderation extension: points `ping`, `app.moderation.input`, `app.moderation.output` |
| `POST /v1/integrations/azure/skill` | an Azure AI Search custom WebApiSkill: `{"values": [{"recordId", "data": {"text"}}]}` becomes `{"values": [{"recordId", "data": {"decision", "text", "violations", "review_id", "guard_policy"}}]}` |

## Operations

`GET /healthz`, `GET /readyz` (policy and provider), `GET /metrics` (Prometheus), `GET /ui` (the
review console).
