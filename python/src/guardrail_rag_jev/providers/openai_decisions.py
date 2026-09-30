"""OpenAI Decisions API (GPT-6 Luna). EXPERIMENTAL.

OpenAI announced a Decisions API at DevDay 2026: a question, a finite set of answers, and context
(text or images) in; the chosen answer and a confidence out, in a few hundred milliseconds. At the
time of writing it is in limited preview and the request schema, the confidence format and the
price are not published.

This adapter is therefore written against that announced shape, with every field name and the
endpoint configurable, so adopting the published schema is a config change. What it assumes:

* one question per request (no batching): the normalizer sends them in parallel;
* a choice among labels, with one confidence: yes/no and score questions are asked as choices,
  and the other labels share the remaining probability.

Those assumptions cost accuracy on the thresholds tuned for Jev. Run it in shadow mode against Jev
on real traffic, and calibrate before letting it decide.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

from ..types import Usage
from .base import Answers, Capabilities, ProviderError, Response

#: Request and response field names, overridable from the config once the schema is published.
DEFAULT_FIELDS: Mapping[str, str] = {
    "question": "question",
    "answers": "answers",
    "context": "context",
    "context_text": "text",
    "model": "model",
    "out_answer": "answer",
    "out_confidence": "confidence",
    "out_probabilities": "probabilities",
}


class OpenAIDecisionsProvider:
    name = "openai-decisions"

    def __init__(
        self,
        *,
        model: str = "gpt-6-luna",
        base_url: str = "https://api.openai.com/v1",
        path: str = "/decisions",
        api_key: str | None = None,
        timeout: float = 5.0,
        fields: Mapping[str, str] | None = None,
        label_descriptions: bool = True,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.model = model
        self.url = base_url.rstrip("/") + path
        self.api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
        if not self.api_key:
            raise ProviderError("No OpenAI API key. Set OPENAI_API_KEY or providers.<name>.api_key.")
        self.timeout = timeout
        self.fields = {**DEFAULT_FIELDS, **dict(fields or {})}
        #: Offer "label: description" as the answer text, since the API takes answers, not criteria.
        self.label_descriptions = label_descriptions
        self.headers = dict(headers or {})
        self.capabilities = Capabilities(batch=False, label_probabilities=False, yes_no=False, score=False, images=True)

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        if len(questions) != 1:
            raise ProviderError("openai-decisions takes one question per request; wrap it in Normalizing")
        (name, question), = questions.items()
        criteria: Mapping[str, str] = question.get("criteria") or {}
        options = [f"{label}: {text}" if self.label_descriptions else label for label, text in criteria.items()]
        f = self.fields
        body = {
            f["model"]: self.model,
            f["question"]: question["instructions"],
            f["answers"]: options,
            f["context"]: {f["context_text"]: json.dumps(state, ensure_ascii=False)},
        }
        request = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}", **self.headers},
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"openai-decisions returned {exc.code}: {exc.read()[:400]!r}") from exc
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"openai-decisions unreachable: {exc}") from exc

        chosen = str(payload.get(f["out_answer"], ""))
        label = _label_of(chosen, criteria)
        if label is None:
            raise ProviderError(f"openai-decisions answered {chosen!r}, which is not an offered label")
        answer: dict[str, Any] = {
            "type": "choice",
            "choice": label,
            "confidence": float(payload.get(f["out_confidence"], 1.0) or 0.0),
        }
        probs = payload.get(f["out_probabilities"])
        if isinstance(probs, Mapping):
            answer["probabilities"] = {
                lab: float(v) for key, v in probs.items() if (lab := _label_of(str(key), criteria)) is not None
            }
        usage = payload.get("usage") or {}
        return Response(
            Answers({name: answer}),
            str(payload.get("model", self.model)),
            Usage(int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)),
            (time.perf_counter() - started) * 1000.0,
            self.name,
        )


def _label_of(text: str, criteria: Mapping[str, str]) -> str | None:
    if text in criteria:
        return text
    head = text.split(":", 1)[0].strip()
    return head if head in criteria else None
