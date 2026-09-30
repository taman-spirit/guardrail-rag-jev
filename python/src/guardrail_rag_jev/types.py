"""Typed results returned by the guardrail."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

#: The four points of a RAG pipeline the guardrail checks.
#:
#: ``ingest``  a document chunk about to be indexed
#: ``query``   a user question about to be answered
#: ``context`` a retrieved passage about to be put in the model's context
#: ``answer``  a generated answer about to be shown
Surface = Literal["ingest", "query", "context", "answer"]
SURFACES: tuple[Surface, ...] = ("ingest", "query", "context", "answer")

Action = Literal["allow", "flag", "review", "block"]
Route = Literal["deliver", "redact", "guide", "crisis_support", "human_review", "safe_response"]

#: What the pipeline should do with the content. This is the enforcement answer, derived from the
#: verdict and the deployment's enforcement settings:
#:
#: ``pass``    use it as it is (notices may be attached)
#: ``redact``  use the masked text in ``Result.content``
#: ``review``  hold it: it waits in the review queue and is not used until a person approves it
#: ``remove``  drop it: a chunk is not indexed or not given to the model, a query or answer is
#:             replaced by ``Result.message``
Decision = Literal["pass", "redact", "review", "remove"]

#: Routes that withhold the content and put something else in its place.
WITHHOLDING_ROUTES: frozenset[str] = frozenset({"safe_response", "crisis_support", "human_review"})

#: The enforcement ladder, least to most restrictive. How to handle content once decided is a
#: separate axis, carried by ``Verdict.route``.
LADDER: tuple[Action, ...] = ("allow", "flag", "review", "block")


def rank(action: str) -> int:
    """Position of an action on the ladder; unknown actions sort as ``allow``."""
    try:
        return LADDER.index(action)  # type: ignore[arg-type]
    except ValueError:
        return 0


def stronger(a: str, b: str) -> Action:
    return a if rank(a) >= rank(b) else b  # type: ignore[return-value]


def weaker(a: str, b: str) -> Action:
    return a if rank(a) <= rank(b) else b  # type: ignore[return-value]


def shift(action: str, steps: int) -> Action:
    """Move an action along the ladder, clamped at both ends."""
    return LADDER[max(0, min(len(LADDER) - 1, rank(action) + steps))]


@dataclass(frozen=True, slots=True)
class Location:
    """Where in the content a finding was seen: a detector match or a located segment."""

    start: int
    end: int
    #: A short excerpt, masked when it contains a detected span, for reviewers and logs.
    excerpt: str = ""
    probability: float | None = None
    kind: str = "segment"

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"start": self.start, "end": self.end, "kind": self.kind}
        if self.excerpt:
            out["excerpt"] = self.excerpt
        if self.probability is not None:
            out["probability"] = round(self.probability, 4)
        return out


@dataclass(frozen=True, slots=True)
class Finding:
    """One category that fired, with the evidence behind it."""

    category: str
    name: str
    probability: float
    confidence: float
    action: Action
    severity: float
    refs: tuple[str, ...] = ()
    #: "category" (hazard choice), "sentinel", "multilabel", "rule:<id>", "detector:<name>",
    #: "pattern:<name>" or "override".
    source: str = "category"
    notes: tuple[str, ...] = ()
    #: Raised by a yes/no question alone while the hazard choice gave its category next to nothing.
    uncorroborated: bool = False
    #: Uncorroborated and below its block band: never_below does not lift it.
    weak: bool = False
    #: The pack that defines the category ("standard-rag-v1", "vn-cybersecurity", ...).
    pack: str = ""
    #: Localised names, e.g. {"en": ..., "vi": ...}.
    names: Mapping[str, str] = field(default_factory=dict)
    locations: tuple[Location, ...] = ()

    def display_name(self, language: str = "en") -> str:
        return self.names.get(language) or self.names.get("en") or self.name

    def as_dict(self, language: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "category": self.category,
            "name": self.display_name(language or "en"),
            "names": dict(self.names),
            "pack": self.pack,
            "action": self.action,
            "probability": round(self.probability, 4),
            "confidence": round(self.confidence, 4),
            "severity": round(self.severity, 2),
            "refs": list(self.refs),
            "source": self.source,
            "notes": list(self.notes),
        }
        if self.locations:
            out["locations"] = [loc.as_dict() for loc in self.locations]
        return out


@dataclass(frozen=True, slots=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(self.input_tokens + other.input_tokens, self.output_tokens + other.output_tokens)

    def as_dict(self) -> dict[str, int]:
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens}


@dataclass(frozen=True, slots=True)
class Verdict:
    """The policy decision for one piece of content, before enforcement settings apply."""

    action: Action
    surface: Surface
    findings: tuple[Finding, ...] = ()
    signals: Mapping[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    severity: float = 0.0
    route: Route = "deliver"
    applied_rules: tuple[str, ...] = ()
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    latency_ms: float = 0.0
    degraded: bool = False
    error: str | None = None
    policy_id: str = ""
    cached: bool = False
    #: Set when a deterministic pattern decided without calling Jev.
    prefilter: str | None = None

    @property
    def allowed(self) -> bool:
        return rank(self.action) <= rank("flag")

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def deliverable(self) -> bool:
        return self.route not in WITHHOLDING_ROUTES

    @property
    def top(self) -> Finding | None:
        return self.findings[0] if self.findings else None

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(f.category for f in self.findings)

    def as_dict(self, language: str | None = None) -> dict[str, Any]:
        return {
            "action": self.action,
            "route": self.route,
            "surface": self.surface,
            "confidence": round(self.confidence, 4),
            "severity": round(self.severity, 2),
            "findings": [f.as_dict(language) for f in self.findings],
            "signals": dict(self.signals),
            "applied_rules": list(self.applied_rules),
            "policy_id": self.policy_id,
            "model": self.model,
            "usage": self.usage.as_dict(),
            "latency_ms": round(self.latency_ms, 1),
            "degraded": self.degraded,
            "cached": self.cached,
            "prefilter": self.prefilter,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class Redaction:
    """One masked span. The original text is never kept here."""

    detector: str
    category: str
    start: int
    end: int
    replacement: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "replacement": self.replacement,
        }


@dataclass(frozen=True, slots=True)
class Result:
    """What the pipeline should do with one piece of content, and why.

    ``decision`` is the answer to act on. ``violations`` lists every category that fired, so a
    passage with three problems reports all three, each with its legal or standard basis and,
    where known, where in the text it was seen.
    """

    id: str
    surface: Surface
    decision: Decision
    verdict: Verdict
    #: The text to use downstream: the original, the masked text, or None when held or removed.
    content: str | None
    language: str = "vi"
    redactions: tuple[Redaction, ...] = ()
    review_id: str | None = None
    #: For a query or an answer that is withheld: the prewritten reply, in ``language``.
    message: str | None = None
    #: Text to show with the content: a disclaimer, an AI label, a fixed affirmation.
    notices: tuple[str, ...] = ()
    #: The caller's identifiers for the content: doc_id, chunk_id, source, user_id, ...
    ref: Mapping[str, Any] = field(default_factory=dict)
    #: "approved", "rejected" or "edited" when a reviewer's earlier decision settled this content.
    override: str | None = None
    #: Why the enforcement settings mapped the verdict to this decision.
    reason: str = ""
    #: What enforcement would have decided, when the surface runs in shadow mode.
    would_decision: Decision | None = None
    #: Fields to write back to the vector store with the chunk, so retrieval can filter on them.
    metadata: Mapping[str, Any] = field(default_factory=dict)
    provider: str = ""

    @property
    def usable(self) -> bool:
        """True when the content (possibly masked) can be used."""
        return self.decision in ("pass", "redact")

    @property
    def violations(self) -> tuple[Finding, ...]:
        """Every finding at flag or above, strongest first."""
        return tuple(f for f in self.verdict.findings if rank(f.action) >= rank("flag"))

    def text_for_user(self) -> str:
        """For a query or an answer: what to show the user."""
        if not self.usable:
            return self.message or ""
        body = self.content or ""
        return "\n\n".join([body.rstrip(), *self.notices]) if self.notices else body

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "surface": self.surface,
            "decision": self.decision,
            "usable": self.usable,
            "content": self.content,
            "language": self.language,
            "message": self.message,
            "notices": list(self.notices),
            "violations": [f.as_dict(self.language) for f in self.violations],
            "redactions": [r.as_dict() for r in self.redactions],
            "review_id": self.review_id,
            "override": self.override,
            "reason": self.reason,
            "would_decision": self.would_decision,
            "metadata": dict(self.metadata),
            "provider": self.provider,
            "ref": dict(self.ref),
            "verdict": self.verdict.as_dict(self.language),
        }


@dataclass(frozen=True, slots=True)
class ContextResult:
    """The retrieved passages after filtering: what to give the model, and what was taken out."""

    kept: tuple[dict[str, Any], ...]
    removed: tuple[dict[str, Any], ...]
    results: tuple[Result, ...]
    #: Set when nothing usable is left, in the query's language.
    message: str | None = None

    @property
    def texts(self) -> list[str]:
        return [str(c.get("text", "")) for c in self.kept]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kept": list(self.kept),
            "removed": list(self.removed),
            "message": self.message,
            "results": [r.as_dict() for r in self.results],
        }


_ORDER = {"pass": 0, "redact": 1, "review": 2, "remove": 3}


def worst(decisions: "list[str]") -> Decision:
    """The most restrictive of several decisions."""
    return max(decisions, key=lambda d: _ORDER.get(d, 0), default="pass")  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class DocumentResult:
    """A whole document: its chunks' results rolled up into one decision."""

    doc_id: str
    decision: Decision
    results: tuple[Result, ...]
    reason: str = ""

    @property
    def violations(self) -> dict[str, list[str]]:
        """Category -> the chunk ids it was found in."""
        out: dict[str, list[str]] = {}
        for r in self.results:
            for f in r.violations:
                out.setdefault(f.category, []).append(str(r.ref.get("chunk_id", r.id)))
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "decision": self.decision,
            "reason": self.reason,
            "violations": self.violations,
            "chunks": [r.as_dict() for r in self.results],
        }


class GuardrailError(RuntimeError):
    """The guardrail could not reach a verdict."""
