"""TypeSafe Jev, the default provider.

Jev is a decision model: it answers named questions (choice, yes/no, score) about a state with
calibrated probabilities, all questions in one request, 70-500 ms. The canonical protocol of this
package is Jev's own wire shape, so this adapter is a thin HTTP client.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

from ..types import Usage
from .base import Answers, Capabilities, ProviderError, Response

DEFAULT_BASE_URL = "https://api.typesafe.ai"
DEFAULT_MODEL = "jev-latest"
ENDPOINT = "/v1/systemone"
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 529})


class JevProvider:
    """Zero-dependency client for ``POST /v1/systemone``.

    Configured from arguments, then ``JEV_API_KEY``, ``JEV_BASE_URL`` and ``JEV_MODEL``.
    """

    name = "jev"
    capabilities = Capabilities(batch=True, label_probabilities=True, yes_no=True, score=True)

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        backoff_initial: float = 0.5,
        backoff_max: float = 5.0,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.api_key = (api_key or os.environ.get("JEV_API_KEY", "")).strip()
        if not self.api_key:
            raise ProviderError("No Jev API key. Set JEV_API_KEY, or jev.api_key in the config.")
        self.base_url = (base_url or os.environ.get("JEV_BASE_URL") or DEFAULT_BASE_URL).strip().rstrip("/")
        self.model = model or os.environ.get("JEV_MODEL") or DEFAULT_MODEL
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_initial = backoff_initial
        self.backoff_max = backoff_max
        self.headers = dict(headers or {})

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        body = json.dumps({"model": self.model, "state": state, "questions": dict(questions)}).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + ENDPOINT,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "guardrail-rag-jev/0.1 (+python)",
                **self.headers,
            },
        )
        started = time.perf_counter()
        delay = self.backoff_initial
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                usage = payload.get("usage") or {}
                return Response(
                    Answers(dict(payload.get("answers") or {})),
                    str(payload.get("model", self.model)),
                    Usage(int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)),
                    (time.perf_counter() - started) * 1000.0,
                    self.name,
                )
            except urllib.error.HTTPError as exc:
                last = ProviderError(f"Jev API returned {exc.code}: {exc.read()[:400]!r}")
                if exc.code not in RETRY_STATUSES or attempt == self.max_retries:
                    raise last from exc
                retry_after = exc.headers.get("retry-after") if exc.headers else None
                delay = min(float(retry_after), self.backoff_max) if _is_number(retry_after) else delay
            except (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError, json.JSONDecodeError) as exc:
                last = ProviderError(f"Jev API unreachable: {exc}")
                if attempt == self.max_retries:
                    raise last from exc
            time.sleep(delay * (1 - random.random() * 0.25))
            delay = min(delay * 2, self.backoff_max)
        raise last or ProviderError("Jev API call failed")  # pragma: no cover


def _is_number(value: Any) -> bool:
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True
