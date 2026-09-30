"""Counters and latency histograms in the Prometheus text format, with no dependency.

Exposed by the service at ``GET /metrics``. The degraded counter matters most: a week at 5 %
degraded means the guardrail was really running 95 % of the time.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Iterable

_BUCKETS = (25, 50, 100, 150, 250, 400, 600, 1000, 2000, 5000)


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.checks: dict[tuple[str, str, str], int] = defaultdict(int)
        self.violations: dict[tuple[str, str], int] = defaultdict(int)
        self.degraded: dict[tuple[str, str], int] = defaultdict(int)
        self.cache_hits: dict[str, int] = defaultdict(int)
        self.latency: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0] * (len(_BUCKETS) + 1))
        self.latency_sum: dict[tuple[str, str], float] = defaultdict(float)
        self.shadow_disagreements: dict[tuple[str, str], int] = defaultdict(int)

    def observe(self, *, surface: str, decision: str, provider: str, latency_ms: float, degraded: bool,
                cached: bool, categories: Iterable[str]) -> None:
        with self._lock:
            self.checks[(surface, decision, provider)] += 1
            for c in categories:
                self.violations[(surface, c)] += 1
            if degraded:
                self.degraded[(surface, provider)] += 1
            if cached:
                self.cache_hits[surface] += 1
            else:
                buckets = self.latency[(surface, provider)]
                for i, bound in enumerate(_BUCKETS):
                    if latency_ms <= bound:
                        buckets[i] += 1
                        break
                else:
                    buckets[-1] += 1
                self.latency_sum[(surface, provider)] += latency_ms

    def disagreement(self, surface: str, shadow: str) -> None:
        with self._lock:
            self.shadow_disagreements[(surface, shadow)] += 1

    def render(self) -> str:
        lines: list[str] = []

        def block(name: str, kind: str, help_: str) -> None:
            lines.append(f"# HELP {name} {help_}")
            lines.append(f"# TYPE {name} {kind}")

        with self._lock:
            block("guardrail_checks_total", "counter", "Checks by surface, decision and provider.")
            for (s, d, p), n in sorted(self.checks.items()):
                lines.append(f'guardrail_checks_total{{surface="{s}",decision="{d}",provider="{p}"}} {n}')
            block("guardrail_violations_total", "counter", "Violations at flag or above, by category.")
            for (s, c), n in sorted(self.violations.items()):
                lines.append(f'guardrail_violations_total{{surface="{s}",category="{c}"}} {n}')
            block("guardrail_degraded_total", "counter", "Checks where the provider could not be reached.")
            for (s, p), n in sorted(self.degraded.items()):
                lines.append(f'guardrail_degraded_total{{surface="{s}",provider="{p}"}} {n}')
            block("guardrail_cache_hits_total", "counter", "Checks answered from the verdict cache.")
            for s, n in sorted(self.cache_hits.items()):
                lines.append(f'guardrail_cache_hits_total{{surface="{s}"}} {n}')
            block("guardrail_shadow_disagreements_total", "counter", "Checks where the shadow provider decided differently.")
            for (s, p), n in sorted(self.shadow_disagreements.items()):
                lines.append(f'guardrail_shadow_disagreements_total{{surface="{s}",shadow="{p}"}} {n}')
            block("guardrail_check_latency_ms", "histogram", "Provider latency per check, milliseconds.")
            for (s, p), buckets in sorted(self.latency.items()):
                running = 0
                for bound, n in zip(_BUCKETS, buckets):
                    running += n
                    lines.append(f'guardrail_check_latency_ms_bucket{{surface="{s}",provider="{p}",le="{bound}"}} {running}')
                running += buckets[-1]
                lines.append(f'guardrail_check_latency_ms_bucket{{surface="{s}",provider="{p}",le="+Inf"}} {running}')
                lines.append(f'guardrail_check_latency_ms_sum{{surface="{s}",provider="{p}"}} {self.latency_sum[(s, p)]:.1f}')
                lines.append(f'guardrail_check_latency_ms_count{{surface="{s}",provider="{p}"}} {running}')
        return "\n".join(lines) + "\n"
