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

import json
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
    #: Native choice questions. False for classifiers that only judge one criterion at a time
    #: (yes or no): a choice is then asked label by label.
    choice: bool = True
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

    Questions the model cannot take natively are rewritten into ones it can, identical rewritten
    questions are asked once, and the answers are converted back. Every answer the engine reads is
    therefore in canonical form, whatever the model returned.
    """

    def __init__(self, inner: Provider, *, max_workers: int = 16) -> None:
        self.inner = inner
        self.name = inner.name
        self.capabilities = inner.capabilities
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=f"provider-{inner.name}")

    def answerable(self, question_name: str) -> bool:
        """Whether the wrapped model can answer this question at all (a classifier with a fixed
        taxonomy cannot answer every category)."""
        check = getattr(self.inner, "answerable", None)
        return bool(check(question_name)) if callable(check) else True

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        caps = self.inner.capabilities
        started = time.perf_counter()
        atomic: dict[str, dict[str, Any]] = {}
        seen: dict[str, str] = {}
        plans = {name: _plan(name, q, caps, atomic, seen) for name, q in questions.items()}

        if caps.batch and len(atomic) <= caps.max_questions:
            responses = [self.inner.decide(state, atomic, timeout=timeout)]
        else:
            size = 1 if not caps.batch else caps.max_questions
            names = list(atomic)
            groups = [names[i:i + size] for i in range(0, len(names), size)]
            futures = [
                self._pool.submit(self.inner.decide, state, {n: atomic[n] for n in group}, timeout=timeout)
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

        missing = [n for n in atomic if merged.get(n) is None]
        if missing:
            raise ProviderError(f"{self.inner.name} returned no answer for {missing[:5]}")
        answers = Answers({name: _restore(questions[name], plan, atomic, merged) for name, plan in plans.items()})
        return Response(answers, model, usage, (time.perf_counter() - started) * 1000.0, self.inner.name)


_YES_NO = {"yes": "The statement is true of the content.", "no": "The statement is not true of the content."}


def _levels(question: Mapping[str, Any]) -> dict[str, str]:
    criteria = question.get("criteria") or []
    return dict(criteria) if isinstance(criteria, Mapping) else {str(i): str(text) for i, text in enumerate(criteria)}


def _add(atomic: dict[str, dict[str, Any]], seen: dict[str, str], name: str, question: dict[str, Any]) -> str:
    """Register a question to send; an identical one already registered is reused."""
    key = json.dumps(question, sort_keys=True, ensure_ascii=False)
    if key in seen:
        return seen[key]
    atomic[name] = question
    seen[key] = name
    return name


def _plan(name: str, q: Mapping[str, Any], caps: Capabilities, atomic, seen) -> tuple[str, Any]:
    kind = q.get("type")
    instructions = str(q.get("instructions", ""))
    if kind == "noul":
        if caps.yes_no:
            return "direct", _add(atomic, seen, name, dict(q))
        return "noul_from_choice", _add(atomic, seen, name, {"type": "choice", "instructions": instructions, "criteria": dict(_YES_NO)})
    if kind == "score" and caps.score:
        return "direct", _add(atomic, seen, name, dict(q))
    if kind == "choice" and caps.choice:
        return "direct", _add(atomic, seen, name, dict(q))
    labels = _levels(q)
    if kind == "score" and caps.choice:
        return "score_from_choice", (_add(atomic, seen, name, {"type": "choice", "instructions": instructions, "criteria": labels}), list(labels))
    if not caps.yes_no:
        raise ProviderError("a provider without choice questions must answer yes/no questions")
    # One yes/no question per label: "the content is <label description>".
    parts = {
        label: _add(atomic, seen, f"{name}::{label}", {"type": "noul", "instructions": f"{instructions} The content is: {text}"})
        for label, text in labels.items()
        if not (kind == "choice" and label == "none")
    }
    return ("score_from_noul" if kind == "score" else "choice_from_noul"), (parts, list(labels))


def _restore(original: Mapping[str, Any], plan: tuple[str, Any], atomic, merged) -> dict[str, Any]:
    how, ref = plan
    if how == "direct":
        raw = dict(merged[ref])
        if original.get("type") == "choice":
            raw = _complete_choice(original, raw)
        raw.setdefault("type", original.get("type"))
        return raw
    if how == "noul_from_choice":
        raw = _complete_choice(atomic[ref], dict(merged[ref]))
        return {"type": "noul", "noul": float(raw["probabilities"].get("yes", 0.0))}
    if how == "score_from_choice":
        sent, keys = ref
        raw = _complete_choice(atomic[sent], dict(merged[sent]))
        probs = raw["probabilities"]
        expected = sum(i * float(probs.get(k, 0.0)) for i, k in enumerate(keys))
        return {"type": "score", "score": expected, "confidence": raw.get("confidence", 1.0), "probabilities": probs}
    parts, keys = ref
    values = {label: _clamp(merged[n].get("noul", 0.0)) for label, n in parts.items()}
    if how == "choice_from_noul":
        # "none" is as likely as the strongest label is not.
        if "none" in keys:
            values["none"] = 1.0 - max(values.values(), default=0.0)
        total = sum(values.values()) or 1.0
        probs = {k: values.get(k, 0.0) / total for k in keys}
        choice = max(probs, key=probs.__getitem__)
        return {"type": "choice", "choice": choice, "confidence": probs[choice], "probabilities": probs}
    total = sum(values.values()) or 1.0
    probs = {k: values[k] / total for k in keys}
    expected = sum(i * probs[k] for i, k in enumerate(keys))
    return {"type": "score", "score": expected, "confidence": max(probs.values()), "probabilities": probs}


def _clamp(v: Any) -> float:
    try:
        return min(1.0, max(0.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


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
