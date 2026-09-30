"""The decision protocol every judging model is adapted to.

The guardrail never talks to a model directly. It sends a **question set** and reads back
**answers**, both in one canonical shape (the one Jev uses natively):

    questions = {
        "hazard": {"type": "choice", "instructions": "...", "criteria": {"none": "...", "prv": "..."}},
        "s_prv":  {"type": "noul",   "instructions": "..."},          # yes/no
        "actionability": {"type": "score", "instructions": "...", "criteria": ["...", "...", "..."]},
    }
    answers = {
        "hazard": {"type": "choice", "choice": "prv", "confidence": 0.91, "probabilities": {"none": 0.08, "prv": 0.91, ...}},
        "s_prv":  {"type": "noul", "noul": 0.87},
        "actionability": {"type": "score", "score": 1.2, "confidence": 0.8},
    }

A provider is anything that turns a state and a question set into answers. Models differ in what
they can do natively; :class:`Capabilities` declares it, and :class:`Normalizing` fills the gaps so
the decision engine always sees complete answers:

* no batching         -> one call per question, in parallel
* no yes/no questions -> asked as a two-label choice
* no score questions  -> asked as a choice over the scale, read back as the expected value
* no per-label probabilities -> the chosen label gets the confidence, the rest share the remainder

Thresholds in a policy are calibrated for a model. When the provider changes, load that provider's
calibration overlay (a policy patch) rather than reusing another model's numbers.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

from ..types import GuardrailError, Usage


class Answers(dict):
    """Answers keyed by question name, each a dict in the canonical shape."""


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What a model does natively. The normalizer adapts everything else."""

    #: Many named questions answered in one request.
    batch: bool = True
    #: Largest question set per request, when batching.
    max_questions: int = 256
    #: Per-label probabilities on a choice, not just the chosen label.
    label_probabilities: bool = True
    #: Native yes/no probability questions.
    yes_no: bool = True
    #: Native score questions over an ordinal scale.
    score: bool = True
    #: Largest number of labels on one choice question.
    max_labels: int = 64
    #: Image input in the state.
    images: bool = False
    #: A generative judge can return a reason; a decision model cannot.
    reasons: bool = False


@dataclass(frozen=True, slots=True)
class Response:
    answers: Answers
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    latency_ms: float = 0.0
    provider: str = ""


@runtime_checkable
class Provider(Protocol):
    """Anything that answers a question set about a state."""

    name: str
    capabilities: Capabilities

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response: ...


class ProviderError(GuardrailError):
    """The provider could not answer. The guardrail turns this into a degraded verdict."""


# -- normalizing ----------------------------------------------------------------------------


class Normalizing:
    """Wraps a provider so that it accepts any canonical question set.

    Questions the model cannot take natively are rewritten before the call and their answers
    converted back after it. Every answer the engine reads is therefore in canonical form, whatever
    the model returned.
    """

    def __init__(self, inner: Provider, *, max_workers: int = 16) -> None:
        self.inner = inner
        self.name = inner.name
        self.capabilities = inner.capabilities
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=f"provider-{inner.name}")

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        caps = self.inner.capabilities
        started = time.perf_counter()
        rewritten = {name: _rewrite(q, caps) for name, q in questions.items()}

        if caps.batch and len(rewritten) <= caps.max_questions:
            responses = [self.inner.decide(state, rewritten, timeout=timeout)]
        else:
            size = 1 if not caps.batch else caps.max_questions
            names = list(rewritten)
            groups = [names[i:i + size] for i in range(0, len(names), size)]
            futures = [
                self._pool.submit(self.inner.decide, state, {n: rewritten[n] for n in group}, timeout=timeout)
                for group in groups
            ]
            responses = [f.result() for f in futures]

        merged: dict[str, Any] = {}
        usage = Usage()
        model = ""
        for r in responses:
            merged.update(r.answers)
            usage = usage + r.usage
            model = model or r.model

        answers = Answers()
        for name, question in questions.items():
            raw = merged.get(name)
            if raw is None:
                raise ProviderError(f"{self.inner.name} returned no answer for question {name!r}")
            answers[name] = _restore(question, rewritten[name], raw, caps)
        return Response(answers, model, usage, (time.perf_counter() - started) * 1000.0, self.inner.name)


_YES_NO = {"yes": "The statement is true of the content.", "no": "The statement is not true of the content."}


def _rewrite(question: Mapping[str, Any], caps: Capabilities) -> dict[str, Any]:
    q = dict(question)
    kind = q.get("type")
    if kind == "noul" and not caps.yes_no:
        return {"type": "choice", "instructions": q["instructions"], "criteria": dict(_YES_NO), "_as": "noul"}
    if kind == "score" and not caps.score:
        criteria = q.get("criteria") or []
        labels = criteria if isinstance(criteria, Mapping) else {str(i): text for i, text in enumerate(criteria)}
        return {"type": "choice", "instructions": q["instructions"], "criteria": dict(labels), "_as": "score"}
    return q


def _restore(original: Mapping[str, Any], sent: Mapping[str, Any], raw: Mapping[str, Any], caps: Capabilities) -> dict[str, Any]:
    raw = dict(raw)
    if sent.get("type") == "choice":
        raw = _complete_choice(sent, raw)
    as_ = sent.get("_as")
    if as_ == "noul":
        return {"type": "noul", "noul": float(raw["probabilities"].get("yes", 0.0))}
    if as_ == "score":
        probs = raw["probabilities"]
        keys = list((sent.get("criteria") or {}).keys())
        # Positions on the scale, whatever the labels are called.
        expected = sum(i * float(probs.get(k, 0.0)) for i, k in enumerate(keys))
        return {"type": "score", "score": expected, "confidence": raw.get("confidence", 1.0), "probabilities": probs}
    raw.setdefault("type", original.get("type"))
    return raw


def _complete_choice(question: Mapping[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """Make sure a choice answer carries a probability for every label."""
    labels = list((question.get("criteria") or {}).keys())
    probs = {k: float(v) for k, v in (raw.get("probabilities") or {}).items() if k in labels}
    choice = raw.get("choice")
    confidence = float(raw.get("confidence", probs.get(choice, 1.0) if choice else 1.0))
    if not probs:
        if choice not in labels:
            raise ProviderError(f"choice {choice!r} is not one of the offered labels")
        rest = (1.0 - confidence) / max(1, len(labels) - 1)
        probs = {k: (confidence if k == choice else rest) for k in labels}
    else:
        for k in labels:
            probs.setdefault(k, 0.0)
    total = sum(probs.values()) or 1.0
    probs = {k: v / total for k, v in probs.items()}
    if choice not in probs:
        choice = max(probs, key=probs.__getitem__)
    return {"type": "choice", "choice": choice, "confidence": confidence, "probabilities": probs}
