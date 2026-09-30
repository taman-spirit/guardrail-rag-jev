"""Any chat model as the judge, over the OpenAI-compatible chat completions API.

This covers OpenAI, Azure OpenAI, and self-hosted servers that speak the same API (vLLM, Ollama,
LM Studio, TGI), so a deployment that must keep data on its own machines can judge with a local
model such as a Vietnamese-tuned one.

A generative judge is not a decision model. It reports its own confidence rather than a calibrated
distribution, it is slower, and it costs output tokens. Use it where Jev is not available, as a
fallback, or in shadow mode to compare, and calibrate its thresholds separately.
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

_SYSTEM = (
    "You are a content-safety decision function. You read a JSON state and answer every question "
    "about it. You never write prose. Reply with one JSON object, keyed by question name:\n"
    '- choice question: {"choice": "<one of the offered labels>", "confidence": <0..1>, '
    '"probabilities": {"<label>": <0..1>, ...}} with probabilities over all labels summing to 1\n'
    '- noul question (a statement): {"noul": <probability 0..1 that the statement is true of the content>}\n'
    '- score question: {"score": <number from 0 to the last index of the scale>, "confidence": <0..1>}\n'
    "Judge meaning in any language; never judge a translated or non-English text more leniently."
)


class LLMJudgeProvider:
    """Judge with a chat model through ``POST {base_url}/chat/completions``.

    Args:
        model: the model name the server expects.
        base_url: e.g. ``https://api.openai.com/v1`` or ``http://localhost:8000/v1``.
        api_key: bearer token; ``OPENAI_API_KEY`` when omitted. Local servers often need none.
        max_questions: questions per request; larger sets are split and sent in parallel.
        json_mode: send ``response_format: {"type": "json_object"}``; turn off for servers that
            reject it.
    """

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        name: str = "llm-judge",
        timeout: float = 20.0,
        max_questions: int = 24,
        json_mode: bool = True,
        temperature: float = 0.0,
        headers: Mapping[str, str] | None = None,
        path: str = "/chat/completions",
    ) -> None:
        self.name = name
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
        self.timeout = timeout
        self.json_mode = json_mode
        self.temperature = temperature
        self.headers = dict(headers or {})
        self.path = path
        # Self-reported probabilities: accepted, but not trusted as calibrated.
        self.capabilities = Capabilities(
            batch=True, max_questions=max_questions, label_probabilities=True, yes_no=True, score=True, reasons=True
        )

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        prompt = json.dumps({"state": state, "questions": dict(questions)}, ensure_ascii=False)
        body: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": prompt}],
        }
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json", **self.headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            self.base_url + self.path, data=json.dumps(body).encode("utf-8"), method="POST", headers=headers
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"{self.name} returned {exc.code}: {exc.read()[:400]!r}") from exc
        except Exception as exc:  # noqa: BLE001 - any transport failure degrades the verdict
            raise ProviderError(f"{self.name} unreachable: {exc}") from exc

        try:
            content = payload["choices"][0]["message"]["content"]
            parsed = json.loads(_strip_fence(content))
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderError(f"{self.name} did not return a JSON answer: {exc}") from exc

        answers = Answers()
        for name, question in questions.items():
            raw = parsed.get(name)
            if not isinstance(raw, Mapping):
                raise ProviderError(f"{self.name} returned no answer for {name!r}")
            answers[name] = {"type": question.get("type"), **_clean(question, raw)}
        usage = payload.get("usage") or {}
        return Response(
            answers,
            str(payload.get("model", self.model)),
            Usage(int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)),
            (time.perf_counter() - started) * 1000.0,
            self.name,
        )


def _strip_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        text = text.rsplit("```", 1)[0]
    return text


def _clamp(value: Any) -> float:
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _clean(question: Mapping[str, Any], raw: Mapping[str, Any]) -> dict[str, Any]:
    kind = question.get("type")
    if kind == "noul":
        return {"noul": _clamp(raw.get("noul", raw.get("probability", 0.0)))}
    if kind == "score":
        top = max(0, len(question.get("criteria") or []) - 1) or 3
        try:
            score = min(float(top), max(0.0, float(raw.get("score", 0.0))))
        except (TypeError, ValueError):
            score = 0.0
        return {"score": score, "confidence": _clamp(raw.get("confidence", 0.5))}
    probs = raw.get("probabilities")
    out: dict[str, Any] = {"choice": raw.get("choice"), "confidence": _clamp(raw.get("confidence", 0.5))}
    if isinstance(probs, Mapping):
        out["probabilities"] = {str(k): _clamp(v) for k, v in probs.items()}
    return out
