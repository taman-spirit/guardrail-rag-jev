"""Open safety classifiers, served behind an OpenAI-compatible API (vLLM, TGI, NIM, Ollama).

Classifiers do not answer arbitrary question sets. Each adapter declares exactly what it can do:

* ``YesNoClassifierProvider`` judges one criterion at a time and answers yes or no. Its
  probability comes from the log-probabilities of the "yes" and "no" tokens when the server
  returns them. Choice and score questions are asked label by label by the normaliser.
  Presets: ``granite-guardian`` (IBM Granite Guardian, bring-your-own criteria) and ``sea-guard``
  (AI Singapore SEA-Guard, trained on Southeast Asian languages including Vietnamese).
* ``LlamaGuardProvider`` classifies against Llama Guard's fixed taxonomy S1-S14. It answers only
  the yes/no questions of the categories that taxonomy covers. Route everything else to another
  provider with ``type: routed``.

The prompt formats follow the models' published cards; check them against the model version you
serve, and calibrate thresholds for it before letting it decide.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

from ..questions import LOCATE_PREFIX, MULTILABEL_PREFIX, SENTINEL_PREFIX, text_of
from ..types import Usage
from .base import Answers, Capabilities, ProviderError, Response


def _post(url: str, body: Mapping[str, Any], api_key: str, timeout: float, name: str) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"{name} returned {exc.code}: {exc.read()[:300]!r}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ProviderError(f"{name} unreachable: {exc}") from exc


def _content(state: Any) -> str:
    """The text a classifier judges, with the user query around an answer or a passage."""
    if not isinstance(state, Mapping):
        return str(state)
    text = text_of(state)
    query = state.get("user_query")
    return f"User query: {query}\n\nContent:\n{text}" if query else text


def yes_probability(choice: Mapping[str, Any], yes: str = "yes", no: str = "no") -> float:
    """P(yes) from the first generated token's log-probabilities, else from the text."""
    top = (((choice.get("logprobs") or {}).get("content") or [{}])[0] or {}).get("top_logprobs") or []
    p_yes = p_no = 0.0
    for entry in top:
        token = str(entry.get("token", "")).strip().lower().strip("<>").strip()
        p = math.exp(float(entry.get("logprob", -100)))
        if token.startswith(yes):
            p_yes += p
        elif token.startswith(no):
            p_no += p
    if p_yes + p_no > 0:
        return p_yes / (p_yes + p_no)
    text = str((choice.get("message") or {}).get("content", "")).lower()
    match = re.search(rf"\b({yes}|{no})\b", text)
    if not match:
        raise ProviderError(f"classifier answered neither {yes!r} nor {no!r}: {text[:80]!r}")
    return 1.0 if match.group(1) == yes else 0.0


PRESETS: Mapping[str, Mapping[str, Any]] = {
    # IBM Granite Guardian: the criterion goes into the chat template's guardian_config.
    "granite-guardian": {"mode": "guardian_config", "yes": "yes", "no": "no"},
    # SEA-Guard and other instruction-tuned classifiers: the criterion goes into the prompt.
    "sea-guard": {"mode": "prompt", "yes": "yes", "no": "no"},
    "generic": {"mode": "prompt", "yes": "yes", "no": "no"},
}

_PROMPT = (
    "You are a content safety classifier. Decide whether the content below meets the criterion. "
    "Judge its meaning in any language. Answer with one word: Yes or No.\n\n"
    "Criterion: {criterion}\n\n{content}"
)


class YesNoClassifierProvider:
    """One yes/no criterion per request; see the module docstring."""

    capabilities = Capabilities(batch=False, choice=False, yes_no=True, score=False, label_probabilities=False)

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str | None = None,
        preset: str = "generic",
        name: str = "classifier",
        timeout: float = 10.0,
        path: str = "/chat/completions",
    ) -> None:
        if preset not in PRESETS:
            raise ValueError(f"preset must be one of {sorted(PRESETS)}")
        self.name = name
        self.model = model
        self.url = base_url.rstrip("/") + path
        self.api_key = api_key if api_key is not None else os.environ.get("CLASSIFIER_API_KEY", "")
        self.preset = PRESETS[preset]
        self.timeout = timeout

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        (qname, q), = questions.items()
        if q.get("type") != "noul":
            raise ProviderError(f"{self.name} answers yes/no questions only; wrap it in Normalizing")
        body: dict[str, Any] = {"model": self.model, "temperature": 0, "max_tokens": 5, "logprobs": True, "top_logprobs": 5}
        if self.preset["mode"] == "guardian_config":
            body["messages"] = [{"role": "user", "content": _content(state)}]
            body["chat_template_kwargs"] = {"guardian_config": {"custom_criteria": q["instructions"]}}
        else:
            body["messages"] = [{"role": "user", "content": _PROMPT.format(criterion=q["instructions"], content=_content(state))}]
        started = time.perf_counter()
        payload = _post(self.url, body, self.api_key, timeout or self.timeout, self.name)
        try:
            choice = payload["choices"][0]
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"{self.name} returned no choice") from exc
        p = yes_probability(choice, self.preset["yes"], self.preset["no"])
        usage = payload.get("usage") or {}
        return Response(
            Answers({qname: {"type": "noul", "noul": p}}), str(payload.get("model", self.model)),
            Usage(int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)),
            (time.perf_counter() - started) * 1000.0, self.name,
        )


#: Llama Guard 3/4 hazard codes -> categories of standard-rag-v1.
LLAMA_GUARD_MAP: Mapping[str, str] = {
    "S1": "vcr", "S2": "ncr", "S3": "src", "S4": "cse", "S5": "dfm", "S6": "spc", "S7": "prv",
    "S8": "ipv", "S9": "iwp", "S10": "hte", "S11": "ssh", "S12": "sxc", "S13": "elc", "S14": "mal",
}


class LlamaGuardProvider:
    """Meta Llama Guard over the served model's own chat template.

    One request classifies the content; the answer covers the yes/no questions (``s_``, ``m_``,
    ``l_``) of every category in ``category_map``. Other questions are left unanswered, so this
    provider is meant to sit inside ``type: routed`` beside one that answers the rest.
    """

    capabilities = Capabilities(batch=True, choice=False, yes_no=True, score=False)

    def __init__(
        self,
        *,
        model: str = "meta-llama/Llama-Guard-4-12B",
        base_url: str,
        api_key: str | None = None,
        name: str = "llama-guard",
        timeout: float = 10.0,
        path: str = "/chat/completions",
        category_map: Mapping[str, str] | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self.url = base_url.rstrip("/") + path
        self.api_key = api_key if api_key is not None else os.environ.get("CLASSIFIER_API_KEY", "")
        self.timeout = timeout
        self.category_map = dict(category_map or LLAMA_GUARD_MAP)
        self.covers = frozenset(self.category_map.values())

    def answerable(self, question_name: str) -> bool:
        for prefix in (SENTINEL_PREFIX, MULTILABEL_PREFIX, LOCATE_PREFIX):
            if question_name.startswith(prefix):
                return question_name[len(prefix):] in self.covers
        return False

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        text = text_of(state)
        if isinstance(state, Mapping) and state.get("evaluating") == "generated_answer":
            messages = [{"role": "user", "content": str(state.get("user_query") or "")}, {"role": "assistant", "content": text}]
        else:
            messages = [{"role": "user", "content": text}]
        body = {"model": self.model, "messages": messages, "temperature": 0, "max_tokens": 20, "logprobs": True, "top_logprobs": 5}
        started = time.perf_counter()
        payload = _post(self.url, body, self.api_key, timeout or self.timeout, self.name)
        choice = (payload.get("choices") or [{}])[0]
        out = str((choice.get("message") or {}).get("content", "")).strip()
        try:
            p_unsafe = yes_probability(choice, "unsafe", "safe")
        except ProviderError:
            p_unsafe = 1.0 if out.lower().startswith("unsafe") else 0.0
        codes = set(re.findall(r"\bS\d{1,2}\b", out))
        flagged = {self.category_map[c] for c in codes if c in self.category_map}
        answers = Answers()
        for qname in questions:
            if not self.answerable(qname):
                continue
            cat = qname.split("_", 1)[1]
            answers[qname] = {"type": "noul", "noul": p_unsafe if cat in flagged else min(0.01, 1 - p_unsafe)}
        usage = payload.get("usage") or {}
        return Response(answers, str(payload.get("model", self.model)),
                        Usage(int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)),
                        (time.perf_counter() - started) * 1000.0, self.name)
