from __future__ import annotations

from typing import Any, Mapping

import pytest

from guardrail_rag_jev import CallableProvider, Capabilities, Config, Guard, Policy
from guardrail_rag_jev.policy import BUNDLED_PACKS
from guardrail_rag_jev.questions import HAZARD, text_of

_SCORE_DEFAULTS = {"groundedness": 3.0, "relevance": 3.0, "answer_relevance": 3.0}
_CHOICE_DEFAULTS = {"intent": "benign", "genre": "other", "data_subject": "none"}


def scripted(
    table: Mapping[str, Mapping[str, float]] | None = None,
    *,
    signals: Mapping[str, Any] | None = None,
    confidence: float = 0.9,
    name: str = "scripted",
    capabilities: Capabilities | None = None,
) -> CallableProvider:
    """A provider that answers from a table: trigger substring -> {category: probability}.

    Like a real decision model, the single hazard choice concentrates on the strongest category and
    gives the others next to nothing, while each yes/no question answers for its own category.
    ``signals`` maps a signal name to its value, or to {trigger: value}.
    """
    table = dict(table or {})
    signals = dict(signals or {})

    def fn(state: Any, questions: dict[str, Any]) -> dict[str, Any]:
        text = text_of(state)
        probs: dict[str, float] = {}
        for trigger, cats in table.items():
            if trigger in text:
                for c, p in cats.items():
                    probs[c] = max(probs.get(c, 0.0), p)
        out: dict[str, Any] = {}
        for qname, q in questions.items():
            kind = q.get("type")
            if qname == HAZARD:
                labels = list(q["criteria"])
                present = {c: p for c, p in probs.items() if c in labels}
                dist = {label: 0.0 for label in labels}
                if present:
                    top = max(present, key=present.__getitem__)
                    dist[top] = present[top]
                    for c in present:
                        if c != top:
                            dist[c] = 0.01
                dist["none"] = max(0.0, 1.0 - sum(v for k, v in dist.items() if k != "none"))
                choice = max(dist, key=dist.__getitem__)
                out[qname] = {"type": "choice", "choice": choice, "confidence": confidence, "probabilities": dist}
            elif qname[:2] in ("s_", "m_", "l_"):
                out[qname] = {"type": "noul", "noul": probs.get(qname[2:], 0.01)}
            else:
                value = signals.get(qname)
                if isinstance(value, Mapping):
                    value = next((v for trig, v in value.items() if trig in text), None)
                if kind == "noul":
                    out[qname] = {"type": "noul", "noul": 0.02 if value is None else float(value)}
                elif kind == "score":
                    v = _SCORE_DEFAULTS.get(qname, 0.0) if value is None else float(value)
                    out[qname] = {"type": "score", "score": v, "confidence": confidence}
                else:
                    v = _CHOICE_DEFAULTS.get(qname, next(iter(q.get("criteria") or {"": ""}))) if value is None else value
                    out[qname] = {"type": "choice", "choice": v, "confidence": confidence, "probabilities": {v: confidence}}
        return out

    return CallableProvider(fn, name=name, capabilities=capabilities)


def make_guard(provider=None, *, config: Config | None = None, **overrides: Any) -> Guard:
    """A guard with in-memory stores. ``overrides`` go through ``Config.from_dict``."""
    cfg = config or Config.from_dict(overrides) if overrides else (config or Config())
    return Guard.for_testing(provider or scripted(), cfg)


@pytest.fixture(scope="session")
def policy() -> Policy:
    return Policy.compose(packs=BUNDLED_PACKS)


@pytest.fixture
def guard() -> Guard:
    return make_guard()
