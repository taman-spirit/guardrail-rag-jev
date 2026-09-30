"""OpenTelemetry tracing, when it is installed and switched on.

    telemetry: {otel: true}

Each check is a ``guardrail.check`` span, with the model call as a ``guardrail.judge`` child, so a
guardrail's latency shows up inside the application's own trace. Attributes: ``guardrail.surface``,
``guardrail.decision``, ``guardrail.action``, ``guardrail.categories``, ``guardrail.policy``,
``guardrail.provider``, ``guardrail.cached``, ``guardrail.degraded``, ``guardrail.review_id``, and
``gen_ai.request.model`` / ``gen_ai.usage.input_tokens`` from the GenAI semantic conventions.
Content is never put on a span. Configure the exporter the usual way (``OTEL_EXPORTER_OTLP_*``) in
the application or with ``opentelemetry-instrument``.
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterator

try:  # pragma: no cover - exercised when opentelemetry is installed
    from opentelemetry import trace as _trace
except ImportError:  # pragma: no cover
    _trace = None


class _NoSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_attributes(self, attributes: dict[str, Any]) -> None:
        pass

    def record_exception(self, exc: BaseException) -> None:
        pass


class Telemetry:
    def __init__(self, enabled: bool = False, *, tracer_provider: Any = None) -> None:
        self.enabled = bool(enabled and _trace is not None)
        self._tracer = None
        if self.enabled:
            self._tracer = (tracer_provider or _trace.get_tracer_provider()).get_tracer("guardrail-rag-jev")

    @contextlib.contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[Any]:
        if self._tracer is None:
            yield _NoSpan()
            return
        with self._tracer.start_as_current_span(name) as span:
            span.set_attributes({k: v for k, v in attributes.items() if v is not None})
            yield span


def clean(attributes: dict[str, Any]) -> dict[str, Any]:
    """OpenTelemetry takes str, bool, int, float and lists of them; drop None."""
    out: dict[str, Any] = {}
    for k, v in attributes.items():
        if v is None:
            continue
        out[k] = list(v) if isinstance(v, (tuple, set)) else v
    return out
