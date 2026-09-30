"""Verdict cache, so identical content does not pay for a second round trip.

RAG repeats itself: the same chunks come back for many queries, and a re-index sends the same text
again. A verdict is a function of the policy, the provider, the surface and the content, so the key
carries all four. Publishing a new policy changes its fingerprint and every old entry stops matching
without anyone having to flush.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import replace
from typing import Any, Mapping, Protocol, runtime_checkable

from .types import Verdict


def cache_key(policy_ref: str, provider: str, surface: str, content_hash: str, *, extra: str = "", subset: str = "full") -> str:
    material = "\0".join((policy_ref, provider, surface, subset, content_hash, extra))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@runtime_checkable
class VerdictCache(Protocol):
    """Anything that can remember a verdict. Implement this over Redis to share across workers."""

    def get(self, key: str) -> Verdict | None: ...

    def put(self, key: str, verdict: Verdict) -> None: ...


class LRUCache:
    """In-process LRU with a TTL, safe across threads. Degraded verdicts are never stored: they say
    nothing about the content, and caching one would turn a brief outage into a lasting answer."""

    def __init__(self, capacity: int = 8192, ttl: float = 900.0) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.capacity = capacity
        self.ttl = ttl
        self._entries: OrderedDict[str, tuple[float, Verdict]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Verdict | None:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or (self.ttl and now - entry[0] > self.ttl):
                if entry is not None:
                    del self._entries[key]
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
            return replace(entry[1], cached=True, latency_ms=0.0)

    def put(self, key: str, verdict: Verdict) -> None:
        if verdict.degraded:
            return
        with self._lock:
            self._entries[key] = (time.monotonic(), verdict)
            self._entries.move_to_end(key)
            while len(self._entries) > self.capacity:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    @property
    def stats(self) -> Mapping[str, Any]:
        total = self.hits + self.misses
        return {"size": len(self._entries), "capacity": self.capacity, "hits": self.hits, "misses": self.misses,
                "hit_rate": round(self.hits / total, 4) if total else 0.0}
