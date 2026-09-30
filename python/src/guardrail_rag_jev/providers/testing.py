"""Providers for tests, offline work and calibration."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .base import Answers, Capabilities, Provider, Response


class RecordedProvider:
    """Replays the same answers for every request."""

    name = "recorded"

    def __init__(self, answers: Mapping[str, Mapping[str, Any]], *, capabilities: Capabilities | None = None) -> None:
        self.answers = Answers(dict(answers))
        self.capabilities = capabilities or Capabilities()
        self.calls: list[tuple[Any, dict[str, Any]]] = []

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        self.calls.append((state, dict(questions)))
        return Response(Answers({k: v for k, v in self.answers.items() if k in questions}), "recorded", provider=self.name)


class CallableProvider:
    """Answers with a function of the state and the questions."""

    def __init__(
        self,
        fn: Callable[[Any, dict[str, Any]], Mapping[str, Any]],
        *,
        name: str = "callable",
        capabilities: Capabilities | None = None,
    ) -> None:
        self.fn = fn
        self.name = name
        self.capabilities = capabilities or Capabilities()
        self.calls: list[tuple[Any, dict[str, Any]]] = []

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        self.calls.append((state, dict(questions)))
        return Response(Answers(self.fn(state, dict(questions))), self.name, provider=self.name)


class RecordingProvider:
    """Wraps a provider and keeps every exchange, so a calibration run can be replayed offline."""

    def __init__(self, inner: Provider, sink: list[dict[str, Any]] | None = None) -> None:
        self.inner = inner
        self.name = inner.name
        self.capabilities = inner.capabilities
        self.records: list[dict[str, Any]] = sink if sink is not None else []

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        response = self.inner.decide(state, questions, timeout=timeout)
        self.records.append({"state": state, "answers": dict(response.answers), "model": response.model, "provider": response.provider})
        return response
