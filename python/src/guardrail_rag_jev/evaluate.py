"""Measuring the guardrail on labelled cases, and calibrating thresholds for a model.

    guardrail-rag-jev eval --dataset datasets/vi-rag-v1.jsonl --record runs/jev.jsonl
    guardrail-rag-jev calibrate --dataset datasets/vi-rag-v1.jsonl --replay runs/jev.jsonl --out calibration/jev.json

A case is one line of JSON: ``surface``, ``text``, optional ``query`` and ``context``, and
``expect``: whether the content should stay usable, and which categories should be reported.

``eval`` runs every case and reports decision accuracy, the share of harmless content held (false
holds), the share of violations caught, and precision and recall per category. ``--record`` keeps
every raw model answer, so later runs replay them with no network: calibration is then a question
of arithmetic, not of API budget.

``calibrate`` replays a recording under scaled thresholds, category by category, and writes the
factors that catch the most while keeping false holds under a ceiling, as a policy overlay to load
with ``providers.<name>.calibration``. Thresholds belong to a model: calibrate each provider on its
own recording. A few dozen cases give a direction, not a measurement; grow the set with real,
reviewed traffic, and near misses above all.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .config import Config
from .providers.base import Answers, Capabilities, ProviderError, Response
from .types import rank

FACTORS: tuple[float, ...] = (0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.25, 1.4, 1.6)


def load_cases(path: str | Path) -> list[dict[str, Any]]:
    cases = []
    for n, line in enumerate(Path(path).read_text("utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        case = json.loads(line)
        if case.get("surface") not in ("ingest", "query", "context", "answer") or "expect" not in case:
            raise ValueError(f"{path}:{n}: a case needs surface and expect")
        cases.append(case)
    return cases


def _key(state: Any) -> str:
    return json.dumps(state, sort_keys=True, ensure_ascii=False)


class ReplayProvider:
    """Answers from a recording made with ``eval --record``: no network, the same answers every time."""

    name = "replay"
    capabilities = Capabilities()

    def __init__(self, records: Iterable[Mapping[str, Any]]) -> None:
        self.answers: dict[str, dict[str, Any]] = {}
        for rec in records:
            self.answers.setdefault(_key(rec["state"]), {}).update(rec["answers"])

    @classmethod
    def load(cls, path: str | Path) -> "ReplayProvider":
        return cls(json.loads(line) for line in Path(path).read_text("utf-8").splitlines() if line.strip())

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        known = self.answers.get(_key(state))
        if known is None:
            raise ProviderError("this state is not in the recording; record again after changing cases or questions")
        missing = [q for q in questions if q not in known]
        if missing:
            raise ProviderError(f"the recording has no answer for {missing[:3]}; record again")
        return Response(Answers({q: known[q] for q in questions}), "replay", provider=self.name)


def run_case(guard: Any, case: Mapping[str, Any]) -> dict[str, Any]:
    surface = case["surface"]
    if surface == "ingest":
        r = guard.check_document(case["text"], doc_id=case.get("id"))
    elif surface == "query":
        r = guard.check_query(case["text"])
    elif surface == "context":
        r = guard.filter_context(case.get("query"), [{"id": case.get("id"), "text": case["text"]}]).results[0]
    else:
        r = guard.check_answer(case["text"], query=case.get("query"), context=case.get("context"))
    expected = case["expect"]
    got = sorted({f.category for f in r.violations if rank(f.action) >= rank("flag")})
    want = sorted(expected.get("categories") or ())
    return {
        "id": case.get("id"), "surface": surface, "decision": r.decision, "degraded": r.verdict.degraded,
        "usable_expected": bool(expected["usable"]), "usable": r.usable,
        "categories_expected": want, "categories": got,
        "ok": r.usable == bool(expected["usable"]) and set(want) <= set(got),
    }


def summarise(outcomes: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    harmless = [o for o in outcomes if o["usable_expected"]]
    harmful = [o for o in outcomes if not o["usable_expected"]]
    cats = sorted({c for o in outcomes for c in (*o["categories_expected"], *o["categories"])})
    per: dict[str, dict[str, Any]] = {}
    for c in cats:
        tp = sum(c in o["categories_expected"] and c in o["categories"] for o in outcomes)
        fp = sum(c not in o["categories_expected"] and c in o["categories"] for o in outcomes)
        fn = sum(c in o["categories_expected"] and c not in o["categories"] for o in outcomes)
        per[c] = {"tp": tp, "fp": fp, "fn": fn,
                  "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                  "recall": round(tp / (tp + fn), 3) if tp + fn else None}
    return {
        "cases": len(outcomes),
        "decision_accuracy": round(sum(o["usable"] == o["usable_expected"] for o in outcomes) / len(outcomes), 3) if outcomes else None,
        "exact": round(sum(o["ok"] for o in outcomes) / len(outcomes), 3) if outcomes else None,
        "false_hold_rate": round(sum(not o["usable"] for o in harmless) / len(harmless), 3) if harmless else None,
        "catch_rate": round(sum(not o["usable"] for o in harmful) / len(harmful), 3) if harmful else None,
        "degraded": sum(o["degraded"] for o in outcomes),
        "categories": per,
        "failures": [o for o in outcomes if not o["ok"]],
    }


def evaluate(guard: Any, cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return summarise([run_case(guard, c) for c in cases])


def eval_config(config: Config) -> Config:
    """The config for an evaluation run: no cache and no stored state, so every case is decided anew."""
    cfg = copy.deepcopy(config)
    cfg.cache = {"enabled": False}
    cfg.state_path = None
    return cfg


def calibrate(
    config: Config,
    replay: ReplayProvider,
    cases: Sequence[Mapping[str, Any]],
    *,
    max_false_hold: float = 0.05,
    factors: Sequence[float] = FACTORS,
    name: str = "calibration",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Scale each category's thresholds by the factor that does best on the recording.

    Returns the overlay (a policy patch), the report before, and the report after. A factor is
    kept only when it does not raise false holds above ``max_false_hold`` (or above the baseline,
    when the baseline is already over it). Between equally good factors the one closest to 1 wins.
    """
    from .guard import Guard

    base_cfg = eval_config(config)
    probe = Guard.for_testing(replay, copy.deepcopy(base_cfg))
    policy = probe.policy

    def run(chosen: Mapping[str, float]) -> dict[str, Any]:
        cfg = copy.deepcopy(base_cfg)
        cfg.policy.categories = {**cfg.policy.categories, **{c: {"thresholds": _scaled(policy.categories[c].thresholds, f)}
                                                             for c, f in chosen.items() if f != 1.0}}
        return evaluate(Guard.for_testing(replay, cfg), cases)

    before = run({})
    ceiling = max(max_false_hold, before["false_hold_rate"] or 0.0)
    relevant = sorted({c for c in (*before["categories"],) if c in policy.categories and policy.categories[c].judge})
    chosen: dict[str, float] = {}
    best = before
    for c in relevant:
        scored = []
        for f in factors:
            report = run({**chosen, c: f})
            if (report["false_hold_rate"] or 0.0) > ceiling:
                continue
            per = report["categories"].get(c) or {}
            f1 = _f1(per)
            scored.append(((report["decision_accuracy"] or 0.0) + 0.5 * f1, -abs(f - 1.0), f, report))
        if scored:
            _, _, f, report = max(scored, key=lambda s: (s[0], s[1]))
            if f != 1.0:
                chosen[c] = f
                best = report
    overlay = {
        "id": name,
        "version": "1.0.0",
        "summary": f"Thresholds calibrated on {len(cases)} cases; factors {dict(sorted(chosen.items()))}.",
        "categories": {c: {"thresholds": _scaled(policy.categories[c].thresholds, f)} for c, f in sorted(chosen.items())},
    }
    return overlay, before, best


def _scaled(thresholds: Mapping[str, Mapping[str, float]], factor: float) -> dict[str, dict[str, float]]:
    return {s: {b: round(min(0.99, v * factor), 4) for b, v in bands.items()} for s, bands in thresholds.items()}


def _f1(per: Mapping[str, Any]) -> float:
    tp, fp, fn = per.get("tp", 0), per.get("fp", 0), per.get("fn", 0)
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0


def format_report(report: Mapping[str, Any]) -> str:
    lines = [
        f"cases {report['cases']}  decision accuracy {report['decision_accuracy']}  exact {report['exact']}",
        f"false holds {report['false_hold_rate']}  violations caught {report['catch_rate']}  degraded {report['degraded']}",
        "",
        f"{'category':10} {'tp':>3} {'fp':>3} {'fn':>3} {'precision':>9} {'recall':>6}",
    ]
    for c, m in report["categories"].items():
        lines.append(f"{c:10} {m['tp']:>3} {m['fp']:>3} {m['fn']:>3} {str(m['precision']):>9} {str(m['recall']):>6}")
    if report["failures"]:
        lines += ["", "mismatches:"]
        for o in report["failures"]:
            lines.append(f"  {o['id']:8} {o['surface']:7} expected usable={o['usable_expected']} {o['categories_expected']}"
                         f"  got {o['decision']} {o['categories']}")
    return "\n".join(lines)
