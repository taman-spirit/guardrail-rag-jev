"""The public entry point: one ``Guard``, four checkpoints, and the plumbing around them.

    guard = Guard.from_config("guardrail.yaml")

    guard.check_document(text, doc_id=..., chunk_id=...)       # ingest: before indexing
    guard.check_query(question)                                 # query: before answering
    guard.filter_context(question, chunks)                      # context: before the model sees them
    guard.check_answer(answer, query=question, context=chunks)  # answer: before the user sees it

Each returns a ``Result`` (``ContextResult`` for the context): a ``decision`` to act on, every
``violation`` found with its basis and location, and the text to use. Every check is written to
the audit log; held and removed items go to the review queue as the enforcement settings say.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .audit import AuditLog, MemoryAuditLog, content_hash, open_audit_log
from .cache import LRUCache, VerdictCache, cache_key
from .config import Config, SurfaceEnforcement
from .decide import decide, error_verdict, finding_for, merge_findings, now_ms
from .detectors import DEFAULT_DETECTORS, DetectorSet, Match, defang_urls, mask_excerpt, redact
from .i18n import Responder, detect_language
from .metrics import Metrics
from .policy import BUNDLED_PACKS, Policy
from .providers import Provider, ProviderError, ShadowProvider, build_provider
from .providers.base import Response
from .questions import HAZARD, LOCATE_PREFIX, _EVALUATING, available_parts, build_questions, build_state, locate_questions
from .review import ReviewStore
from .types import (
    ContextResult,
    Decision,
    DocumentResult,
    Finding,
    Location,
    Result,
    Surface,
    Verdict,
    rank,
    stronger,
    worst,
)

log = logging.getLogger(__name__)

_SURFACE_OF = {v: k for k, v in _EVALUATING.items()}
#: Contact details that an organisation publishes so people use them. When the model reads the data
#: subject as an organisation, these are not personal data; identity numbers always are.
ORG_CONTACT_DETECTORS = frozenset({"email", "vn_phone"})
RESIDENCY = ("offshore", "vn_hosted", "local")


@dataclass
class _Stack:
    """Everything one provider needs: the provider, the policy calibrated for it, and the helpers
    built from that policy."""

    name: str
    provider: Provider
    policy: Policy
    responder: Responder
    detectors: DetectorSet


class Guard:
    """Checks RAG content against a policy with a pluggable judging model.

    Args:
        config: the configuration; ``Config()`` gives the defaults (Jev, every bundled pack on).
        provider: use this provider for every surface instead of building one from the config.
            For tests and embedding.
        audit, reviews, cache, metrics: shared stores. Built from the config when omitted.
        profile: the profile this guard serves, recorded in audit and reviews.
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        provider: Provider | None = None,
        audit: AuditLog | None = None,
        reviews: ReviewStore | None = None,
        cache: VerdictCache | None = None,
        metrics: Metrics | None = None,
        profile: str = "default",
    ) -> None:
        self.config = config or Config()
        self.profile = profile
        self._override_provider = provider
        self.audit: AuditLog = audit if audit is not None else open_audit_log(
            self.config.audit.backend, self.config.resolve(self.config.audit.path) or "data/audit.jsonl",
            forward_to=self.config.audit.webhook_url,
        )
        self.reviews = reviews if reviews is not None else ReviewStore(
            self.config.resolve(self.config.review.path) or "data/review.db",
            webhook_url=self.config.review.webhook_url, webhook_secret=self.config.review.webhook_secret,
        )
        cache_cfg = self.config.cache
        self.cache: VerdictCache | None = cache if cache is not None else (
            LRUCache(int(cache_cfg.get("capacity", 8192)), float(cache_cfg.get("ttl", 900))) if cache_cfg.get("enabled", True) else None
        )
        self.metrics = metrics or Metrics()
        self._pool = ThreadPoolExecutor(max_workers=max(1, self.config.concurrency), thread_name_prefix="guard")
        self._locate_pool = ThreadPoolExecutor(max_workers=max(1, self.config.concurrency), thread_name_prefix="guard-locate")
        self._jobs = ThreadPoolExecutor(max_workers=2, thread_name_prefix="guard-jobs")
        self._lock = threading.RLock()
        self._profiles: dict[str, Guard] = {}
        self._state = self._load_state()
        self._stacks = self._build_stacks(self._state)

    # -- construction -------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path | None = None, **kwargs: Any) -> "Guard":
        return cls(Config.load(path), **kwargs)

    @classmethod
    def for_testing(cls, provider: Provider, config: Config | None = None, **kwargs: Any) -> "Guard":
        """A guard with in-memory audit and review stores and no state file."""
        config = config or Config()
        config.state_path = None
        return cls(config, provider=provider, audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"), **kwargs)

    def for_profile(self, name: str | None) -> "Guard":
        """The guard for a named profile; the stores are shared, the policy and settings are its own."""
        if not name or name == self.profile:
            return self
        with self._lock:
            if name not in self._profiles:
                self._profiles[name] = Guard(
                    self.config.for_profile(name), provider=self._override_provider, audit=self.audit,
                    reviews=self.reviews, cache=self.cache, metrics=self.metrics, profile=name,
                )
            return self._profiles[name]

    @property
    def policy(self) -> Policy:
        """The policy of the default provider."""
        return self._stacks[self.config.provider].policy

    def stack(self, surface: Surface) -> _Stack:
        return self._stacks[self.config.provider_for(surface)]

    # -- checkpoints ----------------------------------------------------

    def check_document(
        self,
        text: str,
        *,
        doc_id: str | None = None,
        chunk_id: str | None = None,
        source: str | None = None,
        title: str | None = None,
        trust: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        tenant: str | None = None,
    ) -> Result:
        """Ingest: check a chunk before it is indexed."""
        ref = _ref(doc_id=doc_id, chunk_id=chunk_id, source=source, trust=trust)
        document = {"title": title, "source": source, **dict(metadata or {})}
        return self._check("ingest", text, ref=ref, document=document, tenant=tenant)

    def check_documents(self, items: Sequence[Mapping[str, Any]], *, tenant: str | None = None) -> list[Result]:
        """Ingest a batch in parallel. Each item: ``text`` plus any of ``doc_id``, ``chunk_id``,
        ``source``, ``title``, ``trust``, ``metadata``."""
        futures = [
            self._pool.submit(
                self.check_document, str(item["text"]), doc_id=item.get("doc_id"), chunk_id=item.get("chunk_id") or item.get("id"),
                source=item.get("source"), title=item.get("title"), trust=item.get("trust"), metadata=item.get("metadata"),
                tenant=tenant,
            )
            for item in items
        ]
        return [f.result() for f in futures]

    def check_document_chunks(self, doc_id: str, chunks: Sequence[Mapping[str, Any]], *, tenant: str | None = None) -> DocumentResult:
        """Ingest a whole document and roll its chunks up into one decision.

        A chunk with a category listed in ``quarantine_document_on`` (injected instructions,
        malicious content, CSAE, weapons) holds the whole document: a poisoned document is rarely
        poisoned in only the chunk that was caught.
        """
        results = self.check_documents([{**dict(c), "doc_id": doc_id} for c in chunks], tenant=tenant)
        decision = worst([r.decision for r in results])
        reason = f"worst chunk decision: {decision}"
        hold_on = set(self.config.enforcement["ingest"].quarantine_document_on)
        hit = sorted({f.category for r in results for f in r.violations if f.category in hold_on and rank(f.action) >= rank("review")})
        if hit and self.config.enforcement["ingest"].mode == "enforce" and decision != "remove":
            decision, reason = "review", f"document held: a chunk carries {', '.join(hit)}"
        self.audit.record(
            "document", doc_id=doc_id, decision=decision, reason=reason, chunks=len(results), tenant=tenant or "",
            profile=self.profile, chunk_checks=[r.id for r in results],
        )
        return DocumentResult(doc_id, decision, tuple(results), reason)

    def check_query(
        self, query: str, *, user_id: str | None = None, session_id: str | None = None, language: str | None = None,
        metadata: Mapping[str, Any] | None = None, tenant: str | None = None,
    ) -> Result:
        """Query: check the user's question before it is answered."""
        ref = _ref(user_id=user_id, session_id=session_id)
        return self._check("query", query, ref=ref, language=language, metadata=metadata, tenant=tenant)

    def filter_context(
        self,
        query: str | None,
        chunks: Sequence[Mapping[str, Any] | str],
        *,
        principals: Sequence[str] | None = None,
        language: str | None = None,
        tenant: str | None = None,
    ) -> ContextResult:
        """Context: check retrieved passages in parallel and keep only the usable ones.

        Each chunk: ``text`` plus any of ``id``, ``doc_id``, ``source``, ``score``, ``acl`` (the
        principals allowed to read it), ``metadata``. Kept chunks come back with ``text`` replaced by
        the masked text where needed.
        """
        items = [{"text": c} if isinstance(c, str) else dict(c) for c in chunks]
        futures = [
            self._pool.submit(
                self._check, "context", str(item.get("text", "")), query=query, language=language, tenant=tenant,
                ref=_ref(chunk_id=item.get("id") or item.get("chunk_id"), doc_id=item.get("doc_id"), source=item.get("source")),
                document={"source": item.get("source"), "title": item.get("title")}, acl=item.get("acl"), principals=principals,
            )
            for item in items
        ]
        results = [f.result() for f in futures]
        kept, removed = [], []
        min_rel = self.config.enforcement["context"].min_relevance
        for item, r in zip(items, results):
            relevance = r.verdict.signals.get("relevance")
            if r.usable and min_rel is not None and isinstance(relevance, (int, float)) and relevance < min_rel:
                removed.append({**item, "decision": "remove", "reason": f"relevance {relevance:.2f} below {min_rel}", "check_id": r.id})
            elif r.usable:
                kept.append({**item, "text": r.content, "check_id": r.id})
            else:
                removed.append({
                    "id": item.get("id"), "doc_id": item.get("doc_id"), "source": item.get("source"),
                    "decision": r.decision, "violations": [f.category for f in r.violations], "check_id": r.id,
                    "review_id": r.review_id,
                })
        lang = language or detect_language(query, self.config.default_language)
        message = self.stack("context").responder.no_context(lang) if not kept else None
        return ContextResult(tuple(kept), tuple(removed), tuple(results), message)

    def check_answer(
        self,
        answer: str,
        *,
        query: str | None = None,
        context: Sequence[Mapping[str, Any] | str] | None = None,
        language: str | None = None,
        partial: bool = False,
        metadata: Mapping[str, Any] | None = None,
        tenant: str | None = None,
    ) -> Result:
        """Answer: check the generated answer before it is shown.

        ``context`` is the passages the answer was based on; it turns on the groundedness check.
        ``partial=True`` is for a streamed answer still being written: only the must-not-miss
        questions are asked, nothing is queued, and the complete answer gets the full check.
        """
        passages = [c if isinstance(c, str) else str(c.get("text", "")) for c in (context or ())]
        lang = language or detect_language(query or answer, self.config.default_language)
        return self._check("answer", answer, query=query, passages=passages, language=lang, metadata=metadata,
                           tenant=tenant, subset="sentinels" if partial else "full")

    # -- policy at runtime ------------------------------------------------

    def update_policy(
        self,
        *,
        packs: Mapping[str, bool] | None = None,
        categories: Mapping[str, Mapping[str, Any]] | None = None,
        actor: str = "unknown",
    ) -> dict[str, Any]:
        """Switch packs and categories on or off, or change a category's thresholds or sensitivity,
        without a restart. Locked packs and categories cannot be changed. The change is validated by
        building the new policy before it replaces the old one, persisted, and audited."""
        locked = set(self.config.policy.locked)
        for name, enabled in (packs or {}).items():
            if name in locked and not enabled:
                raise PermissionError(f"pack {name!r} is locked by the organisation policy")
        for cid in categories or {}:
            if cid in locked:
                raise PermissionError(f"category {cid!r} is locked by the organisation policy")
        with self._lock:
            before = self.policy.ref
            state = json.loads(json.dumps(self._state))
            state.setdefault("packs", {}).update({k: bool(v) for k, v in (packs or {}).items()})
            cats = state.setdefault("categories", {})
            for cid, patch in (categories or {}).items():
                cats[cid] = {**cats.get(cid, {}), **dict(patch)}
            stacks = self._build_stacks(state)  # raises on an invalid change; nothing is swapped
            state["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            state["updated_by"] = actor
            self._stacks, self._state = stacks, state
            self._save_state(state)
            after = self.policy.ref
        self.audit.record(
            "policy.changed", actor=actor, profile=self.profile, before=before, after=after,
            change={"packs": dict(packs or {}), "categories": dict(categories or {})},
        )
        return self.policy.summary()

    def reset_policy(self, *, actor: str = "unknown") -> dict[str, Any]:
        """Drop every runtime change and go back to the config file."""
        with self._lock:
            before = self.policy.ref
            self._stacks, self._state = self._build_stacks({}), {}
            self._save_state({})
        self.audit.record("policy.changed", actor=actor, profile=self.profile, before=before, after=self.policy.ref, change="reset")
        return self.policy.summary()

    # -- review -----------------------------------------------------------

    def decide_review(self, review_id: str, decision: str, *, reviewer: str, note: str = "", content: str | None = None) -> dict[str, Any]:
        item = self.reviews.decide(review_id, decision, reviewer=reviewer, note=note, content=content)
        self.audit.record(
            "review.decided", review_id=review_id, check_id=item.get("check_id"), surface=item.get("surface"),
            decision=item.get("status"), actor=reviewer, note=note, content_sha256=item.get("content_hash"),
            tenant=item.get("tenant") or "", profile=item.get("profile") or "",
        )
        return item

    # -- jobs -------------------------------------------------------------

    def submit_job(self, items: Sequence[Mapping[str, Any]], *, callback_url: str | None = None, tenant: str | None = None) -> str:
        """Check an ingest batch in the background. Poll ``job(id)`` or receive the callback."""
        job_id = self.reviews.job_create(total=len(items), callback_url=callback_url, tenant=tenant or "", profile=self.profile)
        self.audit.record("job.created", job_id=job_id, items=len(items), tenant=tenant or "", profile=self.profile)
        self._jobs.submit(self._run_job, job_id, [dict(i) for i in items], callback_url, tenant)
        return job_id

    def job(self, job_id: str, *, with_results: bool = True) -> dict[str, Any] | None:
        return self.reviews.job_get(job_id, with_results=with_results)

    def _run_job(self, job_id: str, items: list[dict[str, Any]], callback_url: str | None, tenant: str | None) -> None:
        self.reviews.job_update(job_id, status="running")
        try:
            results: list[dict[str, Any]] = []
            batch = max(1, self.config.concurrency * 4)
            for start in range(0, len(items), batch):
                for r in self.check_documents(items[start:start + batch], tenant=tenant):
                    results.append(_compact(r))
                self.reviews.job_update(job_id, done=len(results))
            summary: dict[str, int] = {}
            for r in results:
                summary[r["decision"]] = summary.get(r["decision"], 0) + 1
            self.reviews.job_update(job_id, status="done", summary=summary, results=results)
            self.audit.record("job.done", job_id=job_id, summary=summary, tenant=tenant or "", profile=self.profile)
            payload: dict[str, Any] = {"event": "job.done", "job_id": job_id, "summary": summary, "results": results}
        except Exception as exc:  # noqa: BLE001 - a job failure is reported, not raised into a thread
            log.exception("job %s failed", job_id)
            self.reviews.job_update(job_id, status="failed", error=str(exc))
            self.audit.record("job.failed", job_id=job_id, error=str(exc), tenant=tenant or "", profile=self.profile)
            payload = {"event": "job.failed", "job_id": job_id, "error": str(exc)}
        if callback_url:
            self.reviews.notify(payload, callback_url)

    # -- the check --------------------------------------------------------

    def _check(
        self,
        surface: Surface,
        text: str,
        *,
        query: str | None = None,
        passages: Sequence[str] | None = None,
        document: Mapping[str, Any] | None = None,
        ref: Mapping[str, Any] | None = None,
        language: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        tenant: str | None = None,
        acl: Sequence[str] | None = None,
        principals: Sequence[str] | None = None,
        subset: str = "full",
    ) -> Result:
        stack = self.stack(surface)
        policy = stack.policy
        enforcement = self.config.enforcement[surface]
        check_id = "chk_" + uuid.uuid4().hex[:20]
        tenant = tenant or ""
        ref = dict(ref or {})
        digest = content_hash(text)
        lang = language or detect_language(query if surface in ("context", "answer") and query else text, self.config.default_language)
        matches = stack.detectors.find(text)

        # 1. A reviewer's earlier decision on this exact text settles it.
        override = self.reviews.override(surface, digest, tenant) if subset == "full" else None
        if override is not None:
            return self._from_override(stack, surface, text, override, check_id, digest, lang, ref, tenant, matches)

        # 2. The deployment's own allow and deny patterns.
        verdict: Verdict | None = None
        pattern_findings: list[Finding] = []
        for pattern in stack.detectors.patterns_for(surface):
            if not pattern.regex.search(text):
                continue
            if pattern.kind == "allow":
                verdict = Verdict("allow", surface, route="deliver", policy_id=policy.ref, prefilter=pattern.name,
                                  applied_rules=(f"allow-pattern:{pattern.name}",))
                break
            f = finding_for(policy, str(pattern.category), action=pattern.action, source=f"pattern:{pattern.name}")
            if f is not None and policy.categories[f.category].applies(surface):
                pattern_findings.append(f)
                if pattern.settle:
                    verdict = merge_findings(policy, Verdict("allow", surface, policy_id=policy.ref, prefilter=pattern.name), [f])
                    break

        # 3. The model, through the cache.
        if verdict is None:
            verdict = self._judge(stack, surface, text, digest, query=query, passages=passages, document=document,
                                  metadata=metadata, subset=subset)
            if pattern_findings:
                verdict = merge_findings(policy, verdict, pattern_findings, note="deny-pattern")
            if verdict.signals.get("data_subject") == "organization":
                matches = [m for m in matches if m.detector not in ORG_CONTACT_DETECTORS]

        # 4. Deterministic evidence: detector spans and the ACL cross-check.
        verdict = merge_findings(policy, verdict, self._detector_findings(policy, surface, text, matches), note="detectors")
        if surface == "context" and acl and principals and not set(acl) & set(principals):
            f = finding_for(policy, "acl", action="block", source="acl", notes=("the caller's principals are not in the chunk's acl",))
            if f is not None:
                verdict = merge_findings(policy, verdict, [f], note="acl-mismatch")

        # 5. Untrusted sources get a closer look at ingest.
        if surface == "ingest" and ref.get("trust") == "untrusted" and verdict.action == "flag":
            verdict = replace(verdict, action="review", route="human_review" if verdict.route == "deliver" else verdict.route,
                              applied_rules=verdict.applied_rules + ("untrusted-source-review",))

        # 6. Where in the text each violation is.
        if enforcement.locate and subset == "full" and not verdict.degraded:
            verdict = self._locate(stack, surface, text, verdict, matches, document)

        # 7. Enforcement.
        return self._enforce(stack, surface, enforcement, text, verdict, check_id, digest, lang, ref, tenant, matches, subset)

    def _judge(self, stack: _Stack, surface: Surface, text: str, digest: str, *, query, passages, document, metadata, subset) -> Verdict:
        policy = stack.policy
        extra = ""
        if surface in ("context", "answer") and query:
            extra = content_hash(query)
        if surface == "answer" and passages:
            extra += content_hash("\0".join(passages))
        key = cache_key(policy.ref, stack.name, surface, digest, extra=extra, subset=subset)
        if self.cache is not None:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
            if surface == "context" and self.config.enforcement["context"].reuse_ingest and self.config.provider_for("ingest") == stack.name:
                ingest = self.cache.get(cache_key(policy.ref, stack.name, "ingest", digest))
                if ingest is not None:
                    return replace(ingest, surface="context", applied_rules=ingest.applied_rules + ("reused-ingest-verdict",))

        available = available_parts(query=query, passages=passages)
        if surface == "query":
            available.add("query")
        state = build_state(surface, text, query=query, passages=passages, document=document, metadata=metadata)
        started = now_ms()
        try:
            questions = build_questions(policy, surface, available=available, subset=subset)
            response: Response = stack.provider.decide(state, questions, timeout=self.config.timeout)
            verdict = decide(policy, surface, response.answers, model=response.model, usage=response.usage,
                             latency_ms=now_ms() - started)
        except (ProviderError, KeyError, ValueError, TypeError) as exc:
            log.warning("provider %s failed on %s: %s", stack.name, surface, exc)
            return error_verdict(policy, surface, exc, latency_ms=now_ms() - started)
        if self.cache is not None:
            self.cache.put(key, verdict)
        return verdict

    def _detector_findings(self, policy: Policy, surface: Surface, text: str, matches: list[Match]) -> list[Finding]:
        by_cat: dict[str, list[Match]] = {}
        for m in matches:
            by_cat.setdefault(m.category, []).append(m)
        stack = self.stack(surface)
        out = []
        for category, ms in by_cat.items():
            cat = policy.categories.get(category)
            if cat is None or not cat.applies(surface):
                continue
            action = "flag"
            for m in ms:
                action = stronger(action, stack.detectors.action_of(m.detector))
            locations = tuple(
                Location(m.start, m.end, mask_excerpt(text, max(0, m.start - 40), min(len(text), m.end + 40), matches),
                         kind=f"detector:{m.detector}")
                for m in ms
            )
            names = sorted({m.detector for m in ms})
            f = finding_for(policy, category, action=action, source="detector:" + ",".join(names),
                            notes=(f"{len(ms)} match(es): {', '.join(names)}",), locations=locations)
            if f is not None:
                out.append(f)
        return out

    def _locate(self, stack: _Stack, surface: Surface, text: str, verdict: Verdict, matches: list[Match], document) -> Verdict:
        """Find which segments of a longer passage carry each violation the model saw."""
        judged = [f for f in verdict.findings if rank(f.action) >= rank("flag") and not f.source.startswith(("detector:", "pattern:", "acl"))]
        cats = [stack.policy.categories[f.category] for f in judged if stack.policy.categories[f.category].judge]
        if not cats:
            return verdict
        segments = segment(text, min_chars=int(self.config.locate.get("min_chars", 30)),
                           max_chars=int(self.config.locate.get("max_chars", 1200)),
                           max_segments=int(self.config.locate.get("max_segments", 16)))
        if len(segments) <= 1:
            return verdict
        questions = locate_questions(cats)

        def ask(span: tuple[int, int]) -> Mapping[str, Any] | None:
            state = build_state(surface, text[span[0]:span[1]], document=document, segment=True)
            try:
                return stack.provider.decide(state, questions, timeout=self.config.timeout).answers
            except ProviderError as exc:
                log.warning("locating failed on a segment: %s", exc)
                return None

        answers = list(self._locate_pool.map(ask, segments))
        found: dict[str, list[Location]] = {}
        for (start, end), ans in zip(segments, answers):
            if not ans:
                continue
            for cat in cats:
                p = float((ans.get(LOCATE_PREFIX + cat.id) or {}).get("noul", 0.0))
                if p >= cat.threshold(surface).get("flag", 0.5):
                    found.setdefault(cat.id, []).append(
                        Location(start, end, mask_excerpt(text, start, end, matches), probability=p, kind="segment")
                    )
        findings = tuple(replace(f, locations=f.locations + tuple(found.get(f.category, ()))) for f in verdict.findings)
        return replace(verdict, findings=findings, applied_rules=verdict.applied_rules + ("located",))

    def _enforce(
        self, stack: _Stack, surface: Surface, e: SurfaceEnforcement, text: str, verdict: Verdict, check_id: str,
        digest: str, lang: str, ref: dict[str, Any], tenant: str, matches: list[Match], subset: str,
    ) -> Result:
        decision, reason, queue = _decision(surface, e, verdict, bool(matches), self.config.redaction.fallback)

        content: str | None = None
        redactions: tuple = ()
        if decision == "pass" and e.redact_always and matches:
            decision, reason = "redact", reason + "; detector matches masked (redact_always)"
        if decision in ("pass", "redact"):
            content = text
            if decision == "redact":
                content, redactions = redact(text, matches, template=self.config.redaction.template)
            if e.defang_links and any(f.category == "mal" and rank(f.action) >= rank("flag") for f in verdict.findings):
                content, n = defang_urls(content)
                if n:
                    reason += f"; {n} link(s) defanged"

        would: Decision | None = None
        if e.mode == "shadow" and decision != "pass":
            would, decision, content, redactions, queue = decision, "pass", text, (), False
            reason = f"shadow mode: would {would} ({reason})"

        message = None
        notices: tuple[str, ...] = ()
        if surface in ("query", "answer"):
            if decision in ("review", "remove"):
                message = stack.responder.withheld(verdict, lang).text
            elif surface == "answer" and subset == "full":
                notices = tuple(stack.responder.notices(verdict, lang, ai_label=e.ai_label))

        review_id = None
        if queue and subset == "full":
            stored = text if self.config.review.store_content == "full" else redact(text, matches)[0]
            review_id = self.reviews.enqueue(
                surface=surface, content=stored, content_hash=digest, decision=decision, reason=reason,
                violations=[f.as_dict(lang) for f in verdict.findings if rank(f.action) >= rank("flag")],
                verdict=verdict.as_dict(lang), ref=ref, language=lang, check_id=check_id, tenant=tenant, profile=self.profile,
            )

        metadata = {}
        if surface == "ingest":
            metadata = {"guard_decision": decision, "guard_policy": stack.policy.ref, "guard_checked_at": _now(),
                        "guard_categories": [f.category for f in verdict.findings if rank(f.action) >= rank("flag")]}

        result = Result(
            id=check_id, surface=surface, decision=decision, verdict=verdict, content=content, language=lang,
            redactions=redactions, review_id=review_id, message=message, notices=notices, ref=ref, reason=reason,
            would_decision=would, metadata=metadata, provider=stack.provider.name,
        )
        self._record(stack, result, text, digest, matches, tenant, subset)
        return result

    def _from_override(self, stack, surface, text, override, check_id, digest, lang, ref, tenant, matches) -> Result:
        decision: Decision = "remove" if override.decision == "rejected" else "pass"
        content = override.replacement if override.decision == "edited" else (text if decision == "pass" else None)
        verdict = Verdict("allow" if decision == "pass" else "block", surface,
                          route="deliver" if decision == "pass" else "safe_response",
                          policy_id=stack.policy.ref, applied_rules=(f"review-override:{override.review_id}",))
        message = stack.responder.withheld(verdict, lang).text if decision == "remove" and surface in ("query", "answer") else None
        result = Result(
            id=check_id, surface=surface, decision=decision, verdict=verdict, content=content, language=lang, message=message,
            ref=ref, override=override.decision, reason=f"settled by review {override.review_id}", provider="review",
            metadata={"guard_decision": decision, "guard_policy": stack.policy.ref, "guard_checked_at": _now()} if surface == "ingest" else {},
        )
        self._record(stack, result, text, digest, matches, tenant, "full")
        return result

    def _record(self, stack: _Stack, r: Result, text: str, digest: str, matches: list[Match], tenant: str, subset: str) -> None:
        v = r.verdict
        store = self.config.audit.store_content
        content = None
        if store == "full":
            content = text
        elif store == "redacted":
            content = redact(text, matches)[0]
        self.audit.record(
            "check.partial" if subset != "full" else "check",
            check_id=r.id, surface=r.surface, decision=r.decision, would_decision=r.would_decision, action=v.action,
            route=v.route, reason=r.reason, violations=[
                {"category": f.category, "action": f.action, "probability": round(f.probability, 4), "source": f.source,
                 "pack": f.pack, "refs": list(f.refs)}
                for f in r.violations
            ],
            applied_rules=list(v.applied_rules), policy=v.policy_id or stack.policy.ref, provider=r.provider, model=v.model,
            latency_ms=round(v.latency_ms, 1), degraded=v.degraded or None, error=v.error, cached=v.cached or None,
            override=r.override, review_id=r.review_id, content_sha256=digest if store != "none" else None, content=content,
            redactions=len(r.redactions) or None, language=r.language, ref=r.ref or None, tenant=tenant, profile=self.profile,
        )
        self.metrics.observe(surface=r.surface, decision=r.decision, provider=r.provider, latency_ms=v.latency_ms,
                             degraded=v.degraded, cached=v.cached, categories=[f.category for f in r.violations])

    # -- building -----------------------------------------------------------

    def _build_stacks(self, state: Mapping[str, Any]) -> dict[str, _Stack]:
        cfg = self.config
        names = {cfg.provider, *cfg.routing.values()}
        providers: dict[str, Provider] = {}
        if self._override_provider is not None:
            for name in names:
                providers[name] = self._override_provider
        else:
            self._check_residency(names | ({cfg.shadow.provider} if cfg.shadow.provider else set()))
            for name in names:
                providers[name] = build_provider(name, cfg.providers)
        stacks = {name: self._stack(name, provider, state) for name, provider in providers.items()}
        if cfg.shadow.provider and self._override_provider is None:
            shadow = self._stack(cfg.shadow.provider, build_provider(cfg.shadow.provider, cfg.providers), state)
            for s in stacks.values():
                s.provider = ShadowProvider(s.provider, shadow.provider, self._comparer(s, shadow), sample=cfg.shadow.sample)
        return stacks

    def _stack(self, name: str, provider: Provider, state: Mapping[str, Any]) -> _Stack:
        cfg = self.config
        packs = {**cfg.policy.packs, **dict(state.get("packs") or {})}
        enabled = [self._pack_source(p) for p, on in packs.items() if on]
        calibration = (cfg.providers.get(name) or {}).get("calibration")
        if calibration:
            enabled.append(self._pack_source(str(calibration)))
        available = [self._pack_source(p) for p in dict.fromkeys([*BUNDLED_PACKS, *packs])]
        categories = {**cfg.policy.categories}
        for cid, patch in (state.get("categories") or {}).items():
            categories[cid] = {**categories.get(cid, {}), **patch}
        policy = Policy.compose(
            self._pack_source(cfg.policy.base), enabled, categories=categories or None, rules=cfg.policy.rules or None,
            defaults=cfg.policy.defaults or None, available=available,
        )
        detector_names = [*DEFAULT_DETECTORS, *policy.detectors, *cfg.redaction.enable]
        detectors = DetectorSet.build(detector_names, disabled=cfg.redaction.disable, actions=cfg.redaction.actions,
                                      patterns=cfg.patterns)
        responder = Responder(policy, crisis_line=cfg.crisis_line, default_language=cfg.default_language)
        return _Stack(name, provider, policy, responder, detectors)

    def _pack_source(self, name: str) -> str:
        if "/" in name or name.endswith((".json", ".yaml", ".yml")):
            return self.config.resolve(name) or name
        return name

    def _check_residency(self, names: Iterable[str]) -> None:
        allowed = set(self.config.residency)
        for name in names:
            for member, spec in _expand(name, self.config.providers):
                where = residency_of(member, spec)
                if where not in allowed:
                    raise PermissionError(
                        f"provider {member!r} runs {where}, which residency.allow ({', '.join(sorted(allowed))}) does not "
                        "permit. Sending content there may be a cross-border transfer of personal data."
                    )

    def _comparer(self, primary: _Stack, shadow: _Stack):
        def compare(state, questions, main: Response, other: Response | None, error: Exception | None) -> None:
            if HAZARD not in questions or not isinstance(state, Mapping):
                return
            surface = _SURFACE_OF.get(str(state.get("evaluating")))
            if surface is None:
                return
            a = decide(primary.policy, surface, main.answers)
            text = str(state.get(state.get("evaluating"), ""))
            if other is None:
                self.audit.record("shadow.error", surface=surface, shadow=shadow.name, error=str(error), profile=self.profile)
                return
            b = decide(shadow.policy, surface, other.answers)
            if a.action != b.action or set(a.categories) != set(b.categories):
                self.metrics.disagreement(surface, shadow.name)
                self.audit.record(
                    "shadow.compare", surface=surface, primary=primary.name, shadow=shadow.name,
                    primary_action=a.action, shadow_action=b.action, primary_categories=list(a.categories),
                    shadow_categories=list(b.categories), content_sha256=content_hash(text), profile=self.profile,
                )
        return compare

    def _load_state(self) -> dict[str, Any]:
        path = self.config.resolve(self.config.state_path)
        if not path or not Path(path).exists():
            return {}
        try:
            data = json.loads(Path(path).read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("cannot read policy state %s: %s", path, exc)
            return {}
        return dict((data.get("profiles") or {}).get(self.profile) or {})

    def _save_state(self, state: Mapping[str, Any]) -> None:
        path = self.config.resolve(self.config.state_path)
        if not path:
            return
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data: dict[str, Any] = {}
        if p.exists():
            try:
                data = json.loads(p.read_text("utf-8"))
            except json.JSONDecodeError:
                data = {}
        data.setdefault("profiles", {})[self.profile] = dict(state)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(p)

    def close(self) -> None:
        for pool in (self._pool, self._locate_pool, self._jobs):
            pool.shutdown(wait=False, cancel_futures=True)


# -- helpers ---------------------------------------------------------------


def _decision(surface: Surface, e: SurfaceEnforcement, v: Verdict, has_spans: bool, fallback: str) -> tuple[Decision, str, bool]:
    """Verdict plus enforcement settings -> (decision, reason, queue for review)."""

    def review(why: str) -> tuple[Decision, str, bool]:
        if e.review == "hold":
            return "review", f"{why}: held for review", True
        if e.review == "remove":
            return "remove", f"{why}: removed" + (" and queued for review" if e.queue_reviews else ""), e.queue_reviews
        return "pass", f"{why}: used" + (" and queued for review" if e.queue_reviews else ""), e.queue_reviews

    top = ", ".join(f.category for f in v.findings if rank(f.action) >= rank("flag")) or "none"
    if v.degraded:
        if v.action == "allow":
            return "pass", "provider unavailable: fail open", False
        return review("provider unavailable: fail closed")
    route = v.route
    if route == "crisis_support" and surface in ("ingest", "context"):
        route = "safe_response" if v.action == "block" else "human_review"
    if route == "deliver":
        return "pass", f"action {v.action} ({top})", False
    if route == "guide":
        return "pass", f"action {v.action} ({top}): used with a notice", False
    if route == "redact":
        if has_spans:
            return "redact", f"action {v.action} ({top}): sensitive spans masked", False
        if fallback == "pass":
            return "pass", f"action {v.action} ({top}): masking asked, no span found", False
        if fallback == "remove":
            return "remove", f"action {v.action} ({top}): masking asked, no span found", e.queue_reviews
        return review(f"action {v.action} ({top}): masking asked, no span found")
    if route == "human_review":
        return review(f"action {v.action} ({top})")
    # safe_response, crisis_support
    return "remove", f"action {v.action} ({top})", e.queue_blocks


def segment(text: str, *, min_chars: int = 30, max_chars: int = 1200, max_segments: int = 16) -> list[tuple[int, int]]:
    """Split text into spans to locate violations in: one per paragraph, a paragraph longer than
    ``max_chars`` split at sentence ends, fragments under ``min_chars`` joined to their neighbour,
    and the closest neighbours joined until at most ``max_segments`` remain."""
    if not text.strip():
        return [(0, len(text))]
    cuts = [0, *[m.end() for m in re.finditer(r"\n\s*\n", text)], len(text)]
    spans: list[tuple[int, int]] = []
    for s, e in zip(cuts, cuts[1:]):
        if e <= s:
            continue
        if e - s <= max_chars:
            spans.append((s, e))
            continue
        start = s
        for m in re.finditer(r"(?<=[.!?。！？])\s+", text[s:e]):
            end = s + m.end()
            if end - start >= max_chars // 2:
                spans.append((start, end))
                start = end
        spans.append((start, e))
    merged: list[tuple[int, int]] = []
    for s, e in spans:
        if merged and (e - s < min_chars or merged[-1][1] - merged[-1][0] < min_chars):
            merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    while len(merged) > max_segments:
        i = min(range(len(merged) - 1), key=lambda k: merged[k + 1][1] - merged[k][0])
        merged[i:i + 2] = [(merged[i][0], merged[i + 1][1])]
    return merged


def residency_of(name: str, spec: Mapping[str, Any]) -> str:
    """Where a provider sends content: ``local``, ``vn_hosted`` or ``offshore``. Declared in the
    config; inferred conservatively when not."""
    declared = spec.get("residency")
    if declared:
        if declared not in RESIDENCY:
            raise ValueError(f"provider {name!r}: residency must be one of {RESIDENCY}")
        return str(declared)
    kind = spec.get("type", name)
    if kind == "offline":
        return "local"
    if kind == "llm-judge":
        host = urlparse(str(spec.get("base_url", "https://api.openai.com/v1"))).hostname or ""
        if host in ("localhost",) or "." not in host or host.endswith((".local", ".internal", ".svc", ".cluster.local")):
            return "local"
        try:
            if ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback:
                return "local"
        except ValueError:
            pass
    return "offshore"


def _expand(name: str, specs: Mapping[str, Mapping[str, Any]], seen: tuple[str, ...] = ()) -> list[tuple[str, Mapping[str, Any]]]:
    spec = specs.get(name) or {}
    if spec.get("type") == "fallback" and name not in seen:
        out: list[tuple[str, Mapping[str, Any]]] = []
        for member in spec.get("chain") or ():
            out += _expand(member, specs, (*seen, name))
        return out
    return [(name, spec)]


def _ref(**fields: Any) -> dict[str, Any]:
    return {k: v for k, v in fields.items() if v not in (None, "")}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _compact(r: Result) -> dict[str, Any]:
    """What an ingest job hands back per chunk: enough to index or skip it."""
    return {
        "check_id": r.id,
        "ref": dict(r.ref),
        "decision": r.decision,
        "content": r.content,
        "review_id": r.review_id,
        "violations": [{"category": f.category, "action": f.action, "name": f.display_name(r.language)} for f in r.violations],
        "metadata": dict(r.metadata),
    }
