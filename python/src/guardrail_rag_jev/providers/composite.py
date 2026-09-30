"""Combining providers: fall back when one fails, or run a second one in the shadow.

``FallbackProvider``: try each provider in order; the first answer wins. A Jev outage then degrades
to a local judge instead of to fail-open or fail-closed.

``ShadowProvider``: the primary decides; the shadow answers the same questions in the background
and both answers go to a callback. This is how a switch of model (Jev to OpenAI Decisions, or to a
self-hosted judge) is evaluated on real traffic before it decides anything.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Mapping, Sequence

from ..types import Usage
from .base import Answers, Capabilities, Provider, ProviderError, Response

log = logging.getLogger(__name__)


class FallbackProvider:
    def __init__(self, providers: Sequence[Provider], *, name: str | None = None) -> None:
        if not providers:
            raise ValueError("FallbackProvider needs at least one provider")
        self.providers = list(providers)
        self.name = name or ">".join(p.name for p in self.providers)
        # The chain is normalised per member, so it presents the richest interface.
        self.capabilities = Capabilities()

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        errors: list[str] = []
        for provider in self.providers:
            try:
                return provider.decide(state, questions, timeout=timeout)
            except ProviderError as exc:
                errors.append(f"{provider.name}: {exc}")
                log.warning("provider %s failed, trying the next: %s", provider.name, exc)
        raise ProviderError("every provider failed: " + "; ".join(errors))


Comparison = Callable[[Any, Mapping[str, Any], Response, "Response | None", "Exception | None"], None]


class ShadowProvider:
    def __init__(self, primary: Provider, shadow: Provider, on_compare: Comparison, *, sample: float = 1.0) -> None:
        self.primary = primary
        self.shadow = shadow
        self.on_compare = on_compare
        self.sample = sample
        self.name = primary.name
        self.capabilities = primary.capabilities
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="provider-shadow")
        self._counter = 0

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        response = self.primary.decide(state, questions, timeout=timeout)
        self._counter += 1
        if self.sample >= 1.0 or (self._counter * self.sample) % 1.0 < self.sample:
            self._pool.submit(self._run_shadow, state, dict(questions), response, timeout)
        return response

    def _run_shadow(self, state: Any, questions: Mapping[str, Any], primary: Response, timeout: float | None) -> None:
        try:
            shadow = self.shadow.decide(state, questions, timeout=timeout)
            self.on_compare(state, questions, primary, shadow, None)
        except Exception as exc:  # noqa: BLE001 - the shadow never affects the primary path
            try:
                self.on_compare(state, questions, primary, None, exc)
            except Exception:  # noqa: BLE001
                log.exception("shadow comparison callback failed")


class RoutedProvider:
    """Sends each question to the provider that should answer it.

    ``routes`` is a list of (glob patterns, provider): a question goes to the first route whose
    pattern matches its name and whose provider can answer it; everything else goes to ``default``.
    The parts are asked in parallel and merged into one response. Typical use: the categories a
    classifier covers go to it, the policy's signals and the rest to a general judge.
    """

    def __init__(self, routes: Sequence[tuple[Sequence[str], Provider]], default: Provider, *, name: str = "routed") -> None:
        self.routes = [(list(patterns), provider) for patterns, provider in routes]
        self.default = default
        self.name = name
        self.capabilities = Capabilities()
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="provider-routed")

    def _target(self, question_name: str) -> Provider:
        for patterns, provider in self.routes:
            if any(fnmatch.fnmatchcase(question_name, p) for p in patterns):
                check = getattr(provider, "answerable", None)
                if not callable(check) or check(question_name):
                    return provider
        return self.default

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        started = time.perf_counter()
        groups: dict[int, tuple[Provider, dict[str, Any]]] = {}
        for qname, q in questions.items():
            provider = self._target(qname)
            groups.setdefault(id(provider), (provider, {}))[1][qname] = q
        futures = [self._pool.submit(p.decide, state, qs, timeout=timeout) for p, qs in groups.values()]
        answers = Answers()
        usage = Usage()
        models = []
        for f in futures:
            r = f.result()
            answers.update(r.answers)
            usage = usage + r.usage
            models.append(r.model)
        return Response(answers, "+".join(m for m in models if m), usage, (time.perf_counter() - started) * 1000.0, self.name)
