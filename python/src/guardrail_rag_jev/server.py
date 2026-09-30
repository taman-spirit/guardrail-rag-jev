"""The HTTP service. ``guardrail-rag-jev serve --config guardrail.yaml``.

Roles, from the API key (``Authorization: Bearer <key>``):

* ``client``   the four checkpoints and ingest jobs
* ``reviewer`` everything a client can, plus the review queue and the audit log
* ``admin``    everything, plus policy changes and the effective config

With no key configured the service is open and says so in its log: for local development only.
A key bound to a tenant records its checks under that tenant and sees only that tenant's reviews.
"""

from __future__ import annotations

import hmac
import logging
from importlib import resources
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import ApiKey, Config
from .guard import Guard

log = logging.getLogger(__name__)
ROLES = {"client": 0, "reviewer": 1, "admin": 2}


# -- request bodies ---------------------------------------------------------------------------


class Chunk(BaseModel):
    text: str
    id: str | None = None
    doc_id: str | None = None
    chunk_id: str | None = None
    source: str | None = None
    title: str | None = None
    trust: Literal["trusted", "internal", "untrusted"] | None = None
    acl: list[str] | None = None
    score: float | None = None
    metadata: dict[str, Any] | None = None


class IngestRequest(BaseModel):
    documents: list[Chunk] = Field(..., description="Chunks to check before indexing")
    doc_id: str | None = Field(None, description="Set to roll every chunk up into one document decision")
    profile: str | None = None


class JobRequest(BaseModel):
    documents: list[Chunk]
    callback_url: str | None = None
    profile: str | None = None


class QueryRequest(BaseModel):
    query: str
    user_id: str | None = None
    session_id: str | None = None
    language: str | None = None
    metadata: dict[str, Any] | None = None
    profile: str | None = None


class ContextRequest(BaseModel):
    query: str | None = None
    chunks: list[Chunk]
    principals: list[str] | None = Field(None, description="Who is asking, for the ACL cross-check")
    language: str | None = None
    profile: str | None = None


class AnswerRequest(BaseModel):
    answer: str
    query: str | None = None
    context: list[Chunk | str] | None = None
    language: str | None = None
    partial: bool = False
    metadata: dict[str, Any] | None = None
    profile: str | None = None


class ReviewDecision(BaseModel):
    decision: Literal["approve", "reject", "edit"]
    note: str = ""
    content: str | None = Field(None, description="The corrected text, for an edit")


class PolicyChange(BaseModel):
    packs: dict[str, bool] | None = None
    categories: dict[str, dict[str, Any]] | None = None
    profile: str | None = None


# -- app --------------------------------------------------------------------------------------


def create_app(config: Config | None = None, *, guard: Guard | None = None) -> FastAPI:
    config = config or (guard.config if guard else Config.load())
    guard = guard or Guard(config)
    keys = list(config.server.api_keys)
    if not keys:
        log.warning("no server.api_keys configured: the service is open to anyone who can reach it")

    app = FastAPI(
        title="guardrail-rag-jev",
        version=__version__,
        description="Content guardrails for RAG: ingest, query, context and answer checks with a pluggable judging model.",
    )
    if config.server.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=config.server.cors_origins, allow_methods=["*"], allow_headers=["*"])

    def caller(authorization: str | None = Header(None), x_guardrail_tenant: str | None = Header(None),
               x_guardrail_profile: str | None = Header(None)) -> dict[str, Any]:
        if not keys:
            return {"role": "admin", "name": "anonymous", "tenant": x_guardrail_tenant, "profile": x_guardrail_profile}
        token = (authorization or "").removeprefix("Bearer ").strip()
        match: ApiKey | None = next((k for k in keys if token and hmac.compare_digest(k.key, token)), None)
        if match is None:
            raise HTTPException(401, "missing or unknown API key")
        return {
            "role": match.role,
            "name": match.name or match.role,
            # A bound key cannot act for another tenant or profile.
            "tenant": match.tenant or x_guardrail_tenant,
            "profile": match.profile or x_guardrail_profile,
            "bound_tenant": match.tenant,
        }

    def role(minimum: str):
        def check(who: dict[str, Any] = Depends(caller)) -> dict[str, Any]:
            if ROLES[who["role"]] < ROLES[minimum]:
                raise HTTPException(403, f"this needs the {minimum} role")
            return who
        return check

    def pick(who: dict[str, Any], requested: str | None) -> Guard:
        name = who.get("profile") if who.get("profile") else requested
        try:
            return guard.for_profile(name)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    def limit(items: list[Any]) -> None:
        if len(items) > config.server.max_batch:
            raise HTTPException(413, f"at most {config.server.max_batch} items per request; use /v1/ingest/jobs")

    # -- health ---------------------------------------------------------

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, Any]:
        return {"ok": True, "version": __version__}

    @app.get("/readyz", tags=["ops"])
    def readyz() -> dict[str, Any]:
        return {"ok": True, "policy": guard.policy.ref, "provider": config.provider}

    @app.get("/metrics", response_class=PlainTextResponse, tags=["ops"])
    def metrics() -> str:
        return guard.metrics.render()

    # -- checkpoints --------------------------------------------------------

    @app.post("/v1/ingest", tags=["checks"])
    def ingest(body: IngestRequest, who=Depends(role("client"))) -> dict[str, Any]:
        limit(body.documents)
        g = pick(who, body.profile)
        items = [c.model_dump(exclude_none=True) for c in body.documents]
        if body.doc_id:
            return g.check_document_chunks(body.doc_id, items, tenant=who["tenant"]).as_dict()
        return {"results": [r.as_dict() for r in g.check_documents(items, tenant=who["tenant"])]}

    @app.post("/v1/ingest/jobs", status_code=202, tags=["checks"])
    def ingest_job(body: JobRequest, who=Depends(role("client"))) -> dict[str, Any]:
        g = pick(who, body.profile)
        job_id = g.submit_job([c.model_dump(exclude_none=True) for c in body.documents],
                              callback_url=body.callback_url, tenant=who["tenant"])
        return {"job_id": job_id, "status": "queued", "total": len(body.documents)}

    @app.get("/v1/jobs/{job_id}", tags=["checks"])
    def job(job_id: str, results: bool = True, who=Depends(role("client"))) -> dict[str, Any]:
        found = guard.job(job_id, with_results=results)
        if found is None or (who.get("bound_tenant") and found.get("tenant") != who["bound_tenant"]):
            raise HTTPException(404, "no such job")
        return found

    @app.post("/v1/query", tags=["checks"])
    def query(body: QueryRequest, who=Depends(role("client"))) -> dict[str, Any]:
        g = pick(who, body.profile)
        return g.check_query(body.query, user_id=body.user_id, session_id=body.session_id, language=body.language,
                             metadata=body.metadata, tenant=who["tenant"]).as_dict()

    @app.post("/v1/context", tags=["checks"])
    def context(body: ContextRequest, who=Depends(role("client"))) -> dict[str, Any]:
        limit(body.chunks)
        g = pick(who, body.profile)
        return g.filter_context(body.query, [c.model_dump(exclude_none=True) for c in body.chunks],
                                principals=body.principals, language=body.language, tenant=who["tenant"]).as_dict()

    @app.post("/v1/answer", tags=["checks"])
    def answer(body: AnswerRequest, who=Depends(role("client"))) -> dict[str, Any]:
        g = pick(who, body.profile)
        ctx = [c if isinstance(c, str) else c.model_dump(exclude_none=True) for c in (body.context or [])]
        return g.check_answer(body.answer, query=body.query, context=ctx, language=body.language, partial=body.partial,
                              metadata=body.metadata, tenant=who["tenant"]).as_dict()

    # -- review -------------------------------------------------------------

    @app.get("/v1/reviews", tags=["review"])
    def reviews(status: str | None = "pending", surface: str | None = None, limit_: int = Query(50, alias="limit", le=500),
                offset: int = 0, who=Depends(role("reviewer"))) -> dict[str, Any]:
        tenant = who.get("bound_tenant") or who.get("tenant")
        items = guard.reviews.list(status=status, surface=surface, tenant=tenant, limit=limit_, offset=offset)
        return {"items": items, "counts": guard.reviews.counts(tenant)}

    @app.get("/v1/reviews/{review_id}", tags=["review"])
    def review(review_id: str, who=Depends(role("reviewer"))) -> dict[str, Any]:
        item = guard.reviews.get(review_id)
        if item is None or (who.get("bound_tenant") and item.get("tenant") != who["bound_tenant"]):
            raise HTTPException(404, "no such review")
        return item

    @app.post("/v1/reviews/{review_id}/decision", tags=["review"])
    def decide_review(review_id: str, body: ReviewDecision, who=Depends(role("reviewer"))) -> dict[str, Any]:
        item = guard.reviews.get(review_id)
        if item is None or (who.get("bound_tenant") and item.get("tenant") != who["bound_tenant"]):
            raise HTTPException(404, "no such review")
        try:
            return guard.decide_review(review_id, body.decision, reviewer=who["name"], note=body.note, content=body.content)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    # -- audit --------------------------------------------------------------

    @app.get("/v1/audit", tags=["audit"])
    def audit(type: str | None = None, surface: str | None = None, decision: str | None = None, ref: str | None = None,
              limit_: int = Query(100, alias="limit", le=1000), before_seq: int | None = None,
              who=Depends(role("reviewer"))) -> dict[str, Any]:
        records = guard.audit.query(kind=type, surface=surface, decision=decision, ref=ref, limit=limit_, before_seq=before_seq)
        if who.get("bound_tenant"):
            records = [r for r in records if r.get("tenant") == who["bound_tenant"]]
        return {"records": records}

    @app.get("/v1/audit/verify", tags=["audit"])
    def audit_verify(who=Depends(role("reviewer"))) -> dict[str, Any]:
        return guard.audit.verify()

    @app.get("/v1/audit/head", tags=["audit"])
    def audit_head(who=Depends(role("reviewer"))) -> dict[str, Any]:
        return guard.audit.head()

    # -- policy -------------------------------------------------------------

    @app.get("/v1/policy", tags=["policy"])
    def policy(profile: str | None = None, who=Depends(role("client"))) -> dict[str, Any]:
        g = pick(who, profile)
        return {**g.policy.summary(), "locked": g.config.policy.locked, "profile": g.profile}

    @app.patch("/v1/policy", tags=["policy"])
    def change_policy(body: PolicyChange, who=Depends(role("admin"))) -> dict[str, Any]:
        g = pick(who, body.profile)
        try:
            return g.update_policy(packs=body.packs, categories=body.categories, actor=who["name"])
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/v1/policy/reset", tags=["policy"])
    def reset_policy(profile: str | None = None, who=Depends(role("admin"))) -> dict[str, Any]:
        return pick(who, profile).reset_policy(actor=who["name"])

    @app.get("/v1/config", tags=["policy"])
    def effective_config(who=Depends(role("admin"))) -> dict[str, Any]:
        return guard.config.redacted()

    # -- platform integrations -----------------------------------------------

    @app.post("/v1/integrations/dify/moderation", tags=["integrations"])
    async def dify(request: Request, who=Depends(role("client"))) -> dict[str, Any]:
        """Dify's API-based moderation extension: point it at this URL with a client key."""
        body = await request.json()
        point = body.get("point")
        params = body.get("params") or {}
        if point == "ping":
            return {"result": "pong"}
        g = pick(who, None)
        if point == "app.moderation.input":
            text = str(params.get("query") or " ".join(str(v) for v in (params.get("inputs") or {}).values()))
            r = g.check_query(text, tenant=who["tenant"], metadata={"dify_app": params.get("app_id")})
            if r.decision == "redact":
                return {"flagged": True, "action": "overridden", "inputs": params.get("inputs") or {}, "query": r.content}
            if not r.usable:
                return {"flagged": True, "action": "direct_output", "preset_response": r.message or ""}
            return {"flagged": False, "action": "direct_output", "preset_response": ""}
        if point == "app.moderation.output":
            r = g.check_answer(str(params.get("text") or ""), tenant=who["tenant"], metadata={"dify_app": params.get("app_id")})
            if r.decision == "redact" or (r.usable and r.notices):
                return {"flagged": True, "action": "overridden", "text": r.text_for_user()}
            if not r.usable:
                return {"flagged": True, "action": "direct_output", "preset_response": r.message or ""}
            return {"flagged": False, "action": "direct_output", "preset_response": ""}
        raise HTTPException(400, f"unknown point {point!r}")

    @app.post("/v1/integrations/azure/skill", tags=["integrations"])
    async def azure_skill(request: Request, who=Depends(role("client"))) -> dict[str, Any]:
        """An Azure AI Search custom WebApiSkill. Map ``/document/content`` (or a chunk) to ``text``;
        the skill returns ``decision``, ``text`` (masked, or empty when removed), ``violations`` and
        ``review_id`` for the indexer to store and filter on."""
        body = await request.json()
        g = pick(who, None)
        records = body.get("values") or []
        items = [{"text": str((rec.get("data") or {}).get("text", "")), "chunk_id": rec.get("recordId"),
                  "doc_id": (rec.get("data") or {}).get("doc_id"), "source": (rec.get("data") or {}).get("source")}
                 for rec in records]
        results = g.check_documents(items, tenant=who["tenant"])
        out = []
        for rec, r in zip(records, results):
            out.append({
                "recordId": rec.get("recordId"),
                "data": {"decision": r.decision, "text": r.content or "", "violations": [f.category for f in r.violations],
                         "review_id": r.review_id, "guard_policy": r.verdict.policy_id},
                "errors": None,
                "warnings": [{"message": f"guardrail: {r.decision} ({r.reason})"}] if r.decision != "pass" else None,
            })
        return {"values": out}

    # -- review console ---------------------------------------------------------

    @app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
    def ui() -> str:
        return resources.files(__package__).joinpath("static/review.html").read_text("utf-8")

    return app


def app_from_env() -> FastAPI:
    """For ``uvicorn guardrail_rag_jev.server:app_from_env --factory``: config from $GUARDRAIL_CONFIG."""
    return create_app(Config.load())
