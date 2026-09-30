"""The decision engine: Jev answers in, a verdict out.

This module makes no network calls and holds no state, so the whole policy can be tested against
recorded answers without an API key.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any, Iterable, Mapping

from .policy import Category, Policy, SentinelCorroboration
from .questions import HAZARD, MULTILABEL_PREFIX, NONE_LABEL, SENTINEL_PREFIX
from .types import Action, Finding, Route, Surface, Usage, Verdict, rank, shift, stronger, weaker

#: Handling modes a category may ask for when it fires below the block line.
_CATEGORY_ROUTES = frozenset({"redact", "guide", "crisis_support"})


def decide(
    policy: Policy,
    surface: Surface,
    answers: Mapping[str, Mapping[str, Any]],
    *,
    model: str = "",
    usage: Usage | None = None,
    latency_ms: float = 0.0,
) -> Verdict:
    """Turn one set of Jev answers into a verdict."""
    signals = _read_signals(policy, answers)
    probabilities, confidences, sources = _hazard_probabilities(policy, surface, answers)
    corroboration = policy.sentinel_corroboration()
    choice = (answers.get(HAZARD) or {}).get("probabilities") or {}
    trust = policy.multilabel_trust()

    findings: list[Finding] = []
    for cat in policy.for_surface(surface):
        p = probabilities.get(cat.id, 0.0)
        source = sources.get(cat.id, "category")
        backed = _num(choice.get(cat.id)) >= (corroboration.min_choice if corroboration else 0.0)
        if source == "multilabel":
            # A multi-label answer stands on its own once it is confident enough: a second problem
            # in the same passage rarely gets much of the single hazard choice.
            uncorroborated = corroboration is not None and not backed and p < trust
        else:
            uncorroborated = corroboration is not None and source == "sentinel" and not backed
        finding = _finding(
            cat,
            surface,
            p,
            confidences.get(cat.id, 1.0),
            source=source,
            uncorroborated=uncorroborated,
            never_weak=corroboration is not None and cat.id in corroboration.weak_except,
        )
        if finding is not None:
            findings.append(finding)

    findings, floors, applied = _apply_rules(policy, surface, findings, signals, probabilities)
    if corroboration is not None:
        if surface == "answer":
            findings = _cap_uncorroborated_on_refusal(findings, signals, corroboration)
        if corroboration.redact_instead_of_block_below > 0:
            findings = [_redact_instead_of_block(policy, f, corroboration) for f in findings]
        if corroboration.weak_at_most_flag:
            findings = [
                replace(f, action="flag", notes=f.notes + (f"uncorroborated below its block band: {f.action} -> flag",))
                if f.weak and rank(f.action) > rank("flag")
                else f
                for f in findings
            ]

    action: Action = "allow"
    for finding in findings:
        action = stronger(action, finding.action)
    for floor in floors:
        action = stronger(action, floor)

    confidence = _overall_confidence(answers, findings, confidences)
    # A rule can vouch for the content strongly enough that low confidence is not a reason to hold
    # it, such as a pack's "this only mentions a place" rule. Floors still apply.
    gate_off = any(
        (rule.get("then") or {}).get("skip_confidence_gate") and rule.get("id") in applied for rule in policy.rules
    )
    if not gate_off:
        action, escalated = _confidence_gate(
            policy, action, confidence, findings, probabilities, surface, choice, signals,
            corroboration.min_choice if corroboration is not None else 0.0,
        )
        if escalated:
            applied.append("confidence-gate")

    findings.sort(key=lambda f: (-rank(f.action), -f.probability))
    route = _route(policy, findings, action)
    if route not in ("safe_response", "crisis_support", "human_review") and action == "review" and any(
        (rule.get("then") or {}).get("hold") and rule.get("id") in applied for rule in policy.rules
    ):
        route = "human_review"

    return Verdict(
        action=action,
        surface=surface,
        findings=tuple(findings),
        signals=signals,
        confidence=confidence,
        severity=_severity(signals, findings),
        route=route,
        applied_rules=tuple(applied),
        model=model,
        usage=usage or Usage(),
        latency_ms=latency_ms,
        policy_id=policy.ref,
    )


def error_verdict(policy: Policy, surface: Surface, error: Exception, *, latency_ms: float = 0.0) -> Verdict:
    """The verdict to use when Jev could not be reached. Fail-closed surfaces hold the content."""
    action: Action = policy.error_action() if policy.fail_closed(surface) else "allow"  # type: ignore[assignment]
    route: Route = "safe_response" if action == "block" else "human_review" if action == "review" else "deliver"
    return Verdict(
        action=action,
        surface=surface,
        route=route,
        confidence=0.0,
        degraded=True,
        error=f"{type(error).__name__}: {error}",
        latency_ms=latency_ms,
        policy_id=policy.ref,
    )


def merge_findings(policy: Policy, verdict: Verdict, extra: Iterable[Finding], *, note: str | None = None) -> Verdict:
    """Add findings from outside Jev (detectors, patterns, located segments) and recompute the action
    and the route. Per category the stronger finding wins; locations are combined."""
    extra = list(extra)
    if not extra:
        return verdict
    by_cat = {f.category: f for f in verdict.findings}
    for f in extra:
        have = by_cat.get(f.category)
        if have is None:
            by_cat[f.category] = f
            continue
        winner = f if rank(f.action) > rank(have.action) else have
        other = have if winner is f else f
        by_cat[f.category] = replace(
            winner,
            probability=max(winner.probability, other.probability),
            locations=_merge_locations(winner.locations, other.locations),
            notes=tuple(dict.fromkeys(winner.notes + other.notes)),
        )
    findings = sorted(by_cat.values(), key=lambda f: (-rank(f.action), -f.probability))
    action = verdict.action
    for f in findings:
        action = stronger(action, f.action)
    route = _route(policy, findings, action)
    if verdict.route == "human_review" and route not in ("safe_response", "crisis_support"):
        route = "human_review"
    return replace(
        verdict,
        findings=tuple(findings),
        action=action,
        route=route,
        severity=max([verdict.severity, *(f.severity for f in extra)]),
        applied_rules=verdict.applied_rules + ((note,) if note else ()),
    )


def finding_for(
    policy: Policy,
    category_id: str,
    *,
    action: Action,
    source: str,
    probability: float = 1.0,
    notes: tuple[str, ...] = (),
    locations: tuple = (),
) -> Finding | None:
    """A finding for a category, or None when the category is missing or switched off."""
    cat = policy.categories.get(category_id)
    if cat is None or not cat.enabled:
        return None
    return Finding(
        category=cat.id,
        name=cat.name,
        probability=probability,
        confidence=1.0,
        action=action,
        severity=float(cat.base_severity),
        refs=cat.refs,
        source=source,
        notes=notes,
        pack=cat.pack,
        names=dict(cat.names),
        locations=tuple(locations),
    )


# -- internals --------------------------------------------------------


def _merge_locations(a: tuple, b: tuple) -> tuple:
    seen = {(x.start, x.end, x.kind) for x in a}
    return tuple(a) + tuple(x for x in b if (x.start, x.end, x.kind) not in seen)


def _read_signals(policy: Policy, answers: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    signals: dict[str, Any] = {}
    for name in policy.signals:
        answer = answers.get(name)
        if not answer:
            continue
        kind = answer.get("type")
        if kind == "noul":
            signals[name] = float(answer.get("noul", 0.0))
        elif kind == "score":
            signals[name] = float(answer.get("score", 0.0))
        elif kind == "choice":
            signals[name] = answer.get("choice")
    return signals


def _hazard_probabilities(
    policy: Policy, surface: Surface, answers: Mapping[str, Mapping[str, Any]]
) -> tuple[dict[str, float], dict[str, float], dict[str, str]]:
    """Per-category probability: the strongest of the hazard choice and the yes/no questions."""
    probabilities: dict[str, float] = {}
    confidences: dict[str, float] = {}
    sources: dict[str, str] = {}

    hazard = answers.get(HAZARD) or {}
    hazard_confidence = float(hazard.get("confidence", 1.0))
    for label, value in (hazard.get("probabilities") or {}).items():
        if label == NONE_LABEL:
            continue
        probabilities[label] = float(value)
        confidences[label] = hazard_confidence
        sources[label] = "category"

    yes_no = [(SENTINEL_PREFIX, "sentinel", c) for c in policy.sentinels(surface)]
    yes_no += [(MULTILABEL_PREFIX, "multilabel", c) for c in policy.multilabel(surface)]
    for prefix, source, cat in yes_no:
        answer = answers.get(prefix + cat.id)
        if not answer:
            continue
        value = float(answer.get("noul", 0.0))
        current = probabilities.get(cat.id, 0.0)
        # A sentinel takes over on a tie, so its corroboration rules apply; a multi-label answer only
        # when it says more than the choice did.
        if value > current or (source == "sentinel" and value == current):
            probabilities[cat.id] = value
            sources[cat.id] = source
            # A noul reports belief, not uncertainty; the request-level confidence stands in.
            confidences[cat.id] = hazard_confidence
    return probabilities, confidences, sources


def _finding(
    cat: Category,
    surface: Surface,
    probability: float,
    confidence: float,
    *,
    source: str = "category",
    uncorroborated: bool = False,
    never_weak: bool = False,
) -> Finding | None:
    bands = cat.threshold(surface)
    if not bands:
        return None
    if probability >= bands["block"]:
        action: Action = "block"
    elif probability >= bands["review"]:
        action = "review"
    elif probability >= bands["flag"]:
        action = "flag"
    else:
        return None

    notes: list[str] = []
    if cat.route in _CATEGORY_ROUTES:
        notes.append(f"handled by {cat.route}")
    weak = uncorroborated and probability < bands["block"] and not never_weak
    if cat.never_below and weak:
        notes.append(f"uncorroborated: never below {cat.never_below} not applied")
    elif cat.never_below:
        action = stronger(action, cat.never_below)
        notes.append(f"never below {cat.never_below}")

    return Finding(
        category=cat.id,
        name=cat.name,
        probability=probability,
        confidence=confidence,
        action=action,
        severity=float(cat.base_severity),
        refs=cat.refs,
        source=source,
        notes=tuple(notes),
        uncorroborated=uncorroborated,
        weak=weak,
        pack=cat.pack,
        names=dict(cat.names),
    )


def _num(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _cap_uncorroborated_on_refusal(
    findings: list[Finding], signals: Mapping[str, Any], c: SentinelCorroboration
) -> list[Finding]:
    """An answer that declines names the hazard without carrying it."""
    refusal = signals.get("refusal")
    if not isinstance(refusal, float) or refusal < c.refusal:
        return findings
    out = []
    for f in findings:
        if (
            f.uncorroborated
            and f.probability < c.refusal_max_sentinel
            and f.category not in c.refusal_except
            and rank(f.action) > rank("flag")
        ):
            f = replace(f, action="flag", notes=f.notes + (f"refusal with an uncorroborated signal: {f.action} -> flag",))
        out.append(f)
    return out


def _redact_instead_of_block(policy: Policy, f: Finding, c: SentinelCorroboration) -> Finding:
    """Personal data is handled by masking it; blocking on a yes/no answer alone is the wrong remedy."""
    if (
        f.uncorroborated
        and f.action == "block"
        and f.probability < c.redact_instead_of_block_below
        and policy.categories[f.category].route == "redact"
    ):
        return replace(f, action="review", notes=f.notes + ("uncorroborated on a masked category: block -> review",))
    return f


def _matches(op: str, value: Any, target: Any) -> bool:
    if op in ("==", "!="):
        equal = str(value) == str(target)
        return equal if op == "==" else not equal
    try:
        left, right = float(value), float(target)
    except (TypeError, ValueError):
        return False
    return {">=": left >= right, "<=": left <= right, ">": left > right, "<": left < right}.get(op, False)


def _apply_rules(
    policy: Policy,
    surface: Surface,
    findings: list[Finding],
    signals: Mapping[str, Any],
    probabilities: Mapping[str, float],
) -> tuple[list[Finding], list[str], list[str]]:
    floors: list[str] = []
    applied: list[str] = []

    for rule in policy.rules:
        when = rule.get("when") or {}
        signal = when.get("signal")
        if signal not in signals:
            continue
        if when.get("surfaces") and surface not in when["surfaces"]:
            continue
        if not _matches(str(when.get("op", "==")), signals[signal], when.get("value")):
            continue

        then = rule.get("then") or {}
        rule_id = str(rule.get("id", "rule"))
        applied.append(rule_id)
        exempt = set(rule.get("except_categories") or ())

        added = then.get("add_finding")
        if added and added in policy.categories and added not in {f.category for f in findings}:
            cat = policy.categories[added]
            if cat.applies(surface):
                findings.append(
                    Finding(
                        category=cat.id,
                        name=cat.name,
                        probability=probabilities.get(cat.id, 0.0),
                        confidence=1.0,
                        # The finding carries the rule's floor, so the violation list shows the
                        # same severity as the decision it caused.
                        action=stronger("flag", str(then.get("floor_action", "flag"))),
                        severity=float(cat.base_severity),
                        refs=cat.refs,
                        source=f"rule:{rule_id}",
                        notes=(f"raised by {rule_id}",),
                        pack=cat.pack,
                        names=dict(cat.names),
                    )
                )

        steps = int(then.get("upgrade", 0)) - int(then.get("downgrade", 0))
        cap = then.get("cap_action")
        if steps or cap:
            findings = [_adjust(f, steps, cap, rule_id, policy) if f.category not in exempt else f for f in findings]

        if floor := then.get("floor_action"):
            floors.append(str(floor))

    return findings, floors, applied


def _adjust(finding: Finding, steps: int, cap: str | None, rule_id: str, policy: Policy) -> Finding:
    action: Action = shift(finding.action, steps) if steps else finding.action
    if steps < 0:
        # A softening rule lowers the response, it does not erase the record.
        action = stronger(action, "flag")
    if cap:
        action = weaker(action, cap)
    never_below = policy.categories[finding.category].never_below
    if never_below and not finding.weak:
        action = stronger(action, never_below)
    if action == finding.action:
        return finding
    return replace(finding, action=action, notes=finding.notes + (f"{rule_id}: {finding.action} -> {action}",))


def _overall_confidence(
    answers: Mapping[str, Mapping[str, Any]], findings: list[Finding], confidences: Mapping[str, float]
) -> float:
    if findings:
        return min(confidences.get(f.category, 1.0) for f in findings)
    hazard = answers.get(HAZARD) or {}
    return float(hazard.get("confidence", 1.0))


def _confidence_gate(
    policy: Policy,
    action: Action,
    confidence: float,
    findings: list[Finding],
    probabilities: Mapping[str, float],
    surface: Surface,
    choice: Mapping[str, Any] | None = None,
    signals: Mapping[str, Any] | None = None,
    min_choice: float = 0.0,
) -> tuple[Action, bool]:
    """A low-confidence answer is not evidence of safety, so it escalates toward review."""
    if confidence >= policy.min_confidence() or policy.on_low_confidence() != "escalate":
        return action, False
    opts = policy.confidence_gate()
    intent = (signals or {}).get("intent")
    if isinstance(intent, str) and intent in opts.skip_when_intent and confidence >= opts.skip_min_confidence:
        return action, False
    if opts.needs_corroboration:
        findings = [f for f in findings if not f.uncorroborated]
        probabilities = {cid: p for cid, p in probabilities.items() if _num((choice or {}).get(cid)) >= min_choice}
    near_miss = any(
        probability >= (policy.categories[cid].threshold(surface).get("flag", 1.0) * 0.5)
        for cid, probability in probabilities.items()
        if cid in policy.categories and policy.categories[cid].applies(surface)
    )
    if not findings and not near_miss:
        return action, False
    if rank(action) >= rank("review"):
        return action, False
    return "review", True


def _route(policy: Policy, findings: list[Finding], action: Action) -> Route:
    """How to handle the content, given the decision and the hazard."""
    hazard_route = next(
        (
            policy.categories[f.category].route
            for f in findings
            if f.category in policy.categories
            and _route_counts(f)
            and policy.categories[f.category].route in _CATEGORY_ROUTES
            and (policy.categories[f.category].route != "crisis_support" or _leads(f, findings))
        ),
        None,
    )
    if hazard_route == "crisis_support" and action != "allow":
        return "crisis_support"
    if action == "block":
        return "safe_response"
    if action == "allow":
        return "deliver"
    if hazard_route in ("redact", "guide"):
        return hazard_route  # type: ignore[return-value]
    return "human_review" if action == "review" else "deliver"


def _route_counts(f: Finding) -> bool:
    return rank(f.action) >= rank("flag") and not (f.uncorroborated and f.action == "flag")


def _leads(f: Finding, findings: list[Finding]) -> bool:
    return not any(
        g.category != f.category
        and _route_counts(g)
        and (rank(g.action) > rank(f.action) or (g.action == f.action and g.probability > f.probability))
        for g in findings
    )


def _severity(signals: Mapping[str, Any], findings: list[Finding]) -> float:
    reported = signals.get("severity")
    if isinstance(reported, (int, float)):
        return float(reported)
    return max((f.severity for f in findings), default=0.0)


def now_ms() -> float:
    return time.perf_counter() * 1000.0
