"""Turning a policy into Jev requests.

Jev answers every question in a request in parallel and charges only for input tokens, so each
check asks everything it could need in one round trip:

* ``hazard``: one choice over every category on the surface, which says what the worst problem is;
* ``s_<id>``: a yes/no question per sentinel category, where a miss is unacceptable;
* ``m_<id>``: in multi-label mode, a yes/no question per remaining category, so a passage with
  several problems reports each of them rather than only the worst;
* the policy's signals (intent, actionability, groundedness, relevance, ...).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from .policy import Category, Policy
from .types import Surface

NONE_LABEL = "none"
HAZARD = "hazard"
SENTINEL_PREFIX = "s_"
MULTILABEL_PREFIX = "m_"
LOCATE_PREFIX = "l_"

_HAZARD_INSTRUCTIONS: Mapping[str, str] = {
    "ingest": (
        "This passage is about to be added to a knowledge base that an AI assistant retrieves from "
        "and quotes to its users. Which hazard category best describes the most serious problem "
        "with storing and serving this passage? Judge what the passage itself contains or does, not "
        "the topic it is about: a law, a court ruling, a news report, a safety manual or an academic "
        "text that describes a harm is not that harm. Choose 'none' if the passage raises no problem."
    ),
    "query": (
        "Which hazard category best describes the most serious safety problem in this user query "
        "to a document-grounded assistant? Choose 'none' if the query raises no safety problem."
    ),
    "context": (
        "This passage was retrieved from a knowledge base and is about to be placed in an AI "
        "assistant's context while it answers the user query. Which hazard category best describes "
        "the most serious problem with giving this passage to the assistant? Judge what the passage "
        "itself contains or does, not the topic it is about. Choose 'none' if the passage raises no "
        "problem."
    ),
    "answer": (
        "Which hazard category best describes the most serious safety problem in this generated "
        "answer? Judge the answer itself, not the user query or the retrieved passages it was based "
        "on. Choose 'none' if the answer raises no safety problem."
    ),
}

_NONE_DESCRIPTION = "No problem: the content raises none of the listed hazards."

_EVALUATING: Mapping[str, str] = {
    "ingest": "document_passage",
    "query": "user_query",
    "context": "retrieved_passage",
    "answer": "generated_answer",
}


def build_questions(
    policy: Policy, surface: Surface, *, available: Iterable[str] = (), subset: str = "full"
) -> dict[str, dict[str, Any]]:
    """The question set for a surface, in canonical form.

    ``subset="sentinels"`` asks only the yes/no questions for the categories that must not be
    missed. Checks on a partial streamed answer use it: the text is incomplete, so the categories
    that need the whole answer would only produce noise.
    """
    if subset == "sentinels":
        sentinels = policy.sentinels(surface)
        if not sentinels:
            raise ValueError(f"policy {policy.id!r} has no sentinels for surface {surface!r}")
        return {SENTINEL_PREFIX + c.id: {"type": "noul", "instructions": c.sentinel_instructions} for c in sentinels}
    if subset != "full":
        raise ValueError(f"unknown question subset {subset!r}")
    categories = policy.for_surface(surface, judged=True)
    if not categories:
        raise ValueError(f"policy {policy.id!r} has no enabled categories for surface {surface!r}")

    note = f" {policy.content_note}" if policy.content_note else ""
    questions: dict[str, dict[str, Any]] = {
        HAZARD: {
            "type": "choice",
            "instructions": _HAZARD_INSTRUCTIONS[surface] + note,
            "criteria": {NONE_LABEL: _NONE_DESCRIPTION, **{c.id: c.description for c in categories}},
        }
    }
    for cat in policy.sentinels(surface):
        questions[SENTINEL_PREFIX + cat.id] = {"type": "noul", "instructions": cat.sentinel_instructions}
    for cat in policy.multilabel(surface):
        questions[MULTILABEL_PREFIX + cat.id] = {"type": "noul", "instructions": multilabel_instructions(cat)}
    for name, spec in policy.signals_for(surface, available=available).items():
        question: dict[str, Any] = {"type": spec["type"], "instructions": spec["instructions"]}
        criteria = policy.criteria_for(spec)
        if criteria is not None:
            question["criteria"] = criteria
        questions[name] = question
    return questions


def locate_questions(categories: Sequence[Category]) -> dict[str, dict[str, Any]]:
    """One yes/no question per category, asked of each segment of a longer passage."""
    return {
        LOCATE_PREFIX + cat.id: {
            "type": "noul",
            "instructions": cat.sentinel_instructions or multilabel_instructions(cat),
        }
        for cat in categories
    }


def multilabel_instructions(cat: Category) -> str:
    return f"The content itself is an instance of '{cat.name}': {cat.description}"


def build_state(
    surface: Surface,
    text: str,
    *,
    query: str | None = None,
    passages: Sequence[str] | None = None,
    document: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    segment: bool = False,
) -> dict[str, Any]:
    """The state Jev reads for one check.

    ``document`` is what the caller knows about the source (title, source, url, type); it helps Jev
    tell a law or a news report from the thing it describes. ``passages`` are the retrieved texts
    an answer was based on, and turn on the groundedness signal.
    """
    key = _EVALUATING[surface]
    state: dict[str, Any] = {"evaluating": key, key: text}
    if segment:
        state["note"] = "This is one part of a longer passage; judge only this part."
    if query and surface != "query":
        state["user_query"] = query
    if passages and surface == "answer":
        state["retrieved_passages"] = list(passages)
    if document:
        state["document"] = {k: v for k, v in document.items() if v not in (None, "")}
    if metadata:
        state["deployment_context"] = dict(metadata)
    return state


def available_parts(*, query: str | None = None, passages: Sequence[str] | None = None) -> set[str]:
    parts: set[str] = set()
    if query:
        parts.add("query")
    if passages:
        parts.add("context")
    return parts


def text_of(state: Any) -> str:
    """The checked text inside a state."""
    if isinstance(state, str):
        return state
    if not isinstance(state, Mapping):
        return ""
    key = state.get("evaluating")
    return str(state.get(key, "")) if isinstance(key, str) else ""
