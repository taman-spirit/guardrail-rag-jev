"""Judging models behind one protocol. See ``base`` for the protocol and how gaps are filled.

Built-in provider types, chosen by ``type`` in the config:

========================  ==========================================================================
``jev``                   TypeSafe Jev (default): batched, calibrated probabilities, 70-500 ms
``openai-decisions``      OpenAI Decisions API on GPT-6 Luna. Experimental: schema not yet published
``llm-judge``             any OpenAI-compatible chat model: OpenAI, Azure, vLLM, Ollama, local models
``offline``               keyword heuristic for demos and tests. Never for real content
``fallback``              a chain of other providers, the first that answers wins
``plugin``                your own class, ``class: "package.module:ClassName"``
========================  ==========================================================================
"""

from __future__ import annotations

import importlib
from typing import Any, Mapping

from .base import Answers, Capabilities, Normalizing, Provider, ProviderError, Response
from .composite import FallbackProvider, ShadowProvider
from .jev import JevProvider
from .llm_judge import LLMJudgeProvider
from .offline import OfflineProvider
from .openai_decisions import OpenAIDecisionsProvider
from .testing import CallableProvider, RecordedProvider, RecordingProvider

PROVIDER_TYPES = ("jev", "openai-decisions", "llm-judge", "offline", "fallback", "plugin")


def build_provider(name: str, specs: Mapping[str, Mapping[str, Any]]) -> Provider:
    """Build the provider called ``name`` from the config's ``providers`` section, normalised."""
    return _build(name, specs, seen=())


def _build(name: str, specs: Mapping[str, Mapping[str, Any]], *, seen: tuple[str, ...]) -> Provider:
    if name in seen:
        raise ValueError(f"provider {name!r} refers to itself through {' -> '.join(seen)}")
    if name not in specs:
        raise ValueError(f"no provider named {name!r}; configured: {', '.join(sorted(specs)) or 'none'}")
    spec = dict(specs[name])
    kind = spec.pop("type", name)
    for meta in ("calibration", "description", "residency"):
        spec.pop(meta, None)
    if kind == "jev":
        provider: Provider = JevProvider(**_keep(spec, "api_key", "base_url", "model", "timeout", "max_retries",
                                                 "backoff_initial", "backoff_max", "headers"))
    elif kind == "openai-decisions":
        provider = OpenAIDecisionsProvider(**_keep(spec, "model", "base_url", "path", "api_key", "timeout", "fields",
                                                   "label_descriptions", "headers"))
    elif kind == "llm-judge":
        provider = LLMJudgeProvider(name=name, **_keep(spec, "model", "base_url", "api_key", "timeout", "max_questions",
                                                        "json_mode", "temperature", "headers", "path"))
    elif kind == "offline":
        provider = OfflineProvider()
    elif kind == "fallback":
        chain = [_build(n, specs, seen=(*seen, name)) for n in spec.get("chain") or ()]
        return FallbackProvider(chain, name=name)
    elif kind == "plugin":
        target = str(spec.pop("class", ""))
        module, _, attr = target.partition(":")
        if not module or not attr:
            raise ValueError(f"provider {name!r}: plugin needs class: 'package.module:ClassName'")
        provider = getattr(importlib.import_module(module), attr)(**spec.get("options", {}))
    else:
        raise ValueError(f"provider {name!r} has unknown type {kind!r}; known: {', '.join(PROVIDER_TYPES)}")
    return Normalizing(provider)


def _keep(spec: Mapping[str, Any], *names: str) -> dict[str, Any]:
    unknown = set(spec) - set(names)
    if unknown:
        raise ValueError(f"unknown provider settings {sorted(unknown)}; allowed: {', '.join(names)}")
    return {k: v for k, v in spec.items() if v is not None}


__all__ = [
    "Answers",
    "CallableProvider",
    "Capabilities",
    "FallbackProvider",
    "JevProvider",
    "LLMJudgeProvider",
    "Normalizing",
    "OfflineProvider",
    "OpenAIDecisionsProvider",
    "PROVIDER_TYPES",
    "Provider",
    "ProviderError",
    "RecordedProvider",
    "RecordingProvider",
    "Response",
    "ShadowProvider",
    "build_provider",
]
