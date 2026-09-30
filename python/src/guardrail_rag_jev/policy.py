"""Loading, composing and querying a policy.

A policy is one base pack (the shared taxonomy, ``standard-rag-v1``) with any number of packs
layered on top of it (``vn-cybersecurity``, ``vn-ai``, ``vn-personal-data``, or your own). Packs are
merged at load time, so switching one off at runtime is a recompose, not a fork: whatever a pack
added or changed disappears with it, and the base is untouched.

Merge rules, the same for packs and for the category or rule overrides in a config file:

* ``categories``, ``signals`` and ``rules`` merge by key (rules by ``id``). A patch replaces each
  key it names whole, so a patch that sets ``thresholds`` replaces every surface's bands.
* A key ending in ``+`` appends to a list instead of replacing it, without duplicates. This is how
  two packs can each add categories to the same rule's ``except_categories``.
* ``defaults`` and ``responses`` merge deeply.
* ``"$all_but:a,b"`` in ``except_categories`` expands, after every pack is merged, to every category
  except ``a`` and ``b``: how a rule is made to apply to only a few categories.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .types import SURFACES, Surface

BASE = "standard-rag-v1"
BUNDLED_PACKS: tuple[str, ...] = ("vn-cybersecurity", "vn-ai", "vn-personal-data")
MACRO = "$all_but:"


@dataclass(frozen=True, slots=True)
class Category:
    id: str
    name: str
    description: str
    refs: tuple[str, ...]
    surfaces: frozenset[str]
    weight: float
    base_severity: int
    sentinel: bool
    sentinel_instructions: str | None
    thresholds: Mapping[str, Mapping[str, float]]
    route: str | None
    never_below: str | None
    enabled: bool
    pack: str = BASE
    names: Mapping[str, str] = field(default_factory=dict)
    #: False for categories decided only by deterministic checks (ACL): never asked of a model.
    judge: bool = True

    def threshold(self, surface: str) -> Mapping[str, float]:
        """Bands for a surface, falling back to ``default``."""
        return self.thresholds.get(surface) or self.thresholds.get("default") or {}

    def applies(self, surface: str) -> bool:
        return self.enabled and surface in self.surfaces

    def display_name(self, language: str = "en") -> str:
        return self.names.get(language) or self.names.get("en") or self.name


@dataclass(frozen=True, slots=True)
class SentinelCorroboration:
    """How a yes/no answer must be backed by the hazard choice before it can drive the strongest
    actions on its own. See ``defaults.sentinel_corroboration``."""

    min_choice: float
    refusal: float
    refusal_max_sentinel: float
    refusal_except: frozenset[str]
    weak_at_most_flag: bool
    redact_instead_of_block_below: float
    weak_except: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ConfidenceGateOptions:
    needs_corroboration: bool
    skip_when_intent: frozenset[str]
    skip_min_confidence: float


@dataclass(frozen=True, slots=True)
class PackInfo:
    """What a loaded pack is, for listings and the audit log."""

    id: str
    version: str
    name: str
    names: Mapping[str, str]
    law: Mapping[str, str]
    summary: str
    categories: tuple[str, ...]
    enabled: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "name": self.name,
            "names": dict(self.names),
            "law": dict(self.law),
            "summary": self.summary,
            "categories": list(self.categories),
            "enabled": self.enabled,
        }


class Policy:
    """A composed policy: the base pack with its packs merged in.

    The descriptions in it are also the text sent to Jev as question criteria, so editing a pack
    changes both what the model is asked and how the answer is judged.
    """

    def __init__(self, data: Mapping[str, Any], *, packs: Sequence[PackInfo] = ()) -> None:
        self.data = dict(data)
        self.id: str = str(data.get("id", "custom"))
        self.version: str = str(data.get("version", "0"))
        self.name: str = str(data.get("name", self.id))
        self.content_note: str = str(data.get("content_note", ""))
        self.defaults: Mapping[str, Any] = dict(data.get("defaults") or {})
        self.signals: Mapping[str, Any] = dict(data.get("signals") or {})
        self.rules: tuple[Mapping[str, Any], ...] = tuple(
            r for r in (data.get("rules") or ()) if r.get("enabled", True)
        )
        self.responses: Mapping[str, Any] = dict(data.get("responses") or {})
        self.detectors: tuple[str, ...] = tuple(data.get("detectors") or ())
        self.scales: dict[str, Any] = {k: v for k, v in data.items() if k.endswith("_scale")}
        self.categories: dict[str, Category] = {
            cid: _category(cid, raw) for cid, raw in (data.get("categories") or {}).items()
        }
        self.packs: tuple[PackInfo, ...] = tuple(packs)
        canonical = json.dumps(self.data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self.fingerprint: str = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
        _validate(self)

    # -- construction -------------------------------------------------

    @classmethod
    def bundled(cls, name: str = BASE) -> "Policy":
        """Load a base pack shipped inside the package, with no packs on top."""
        return cls(load_document(name))

    @classmethod
    def compose(
        cls,
        base: str | Path | Mapping[str, Any] = BASE,
        packs: Iterable[str | Path | Mapping[str, Any]] = (),
        *,
        categories: Mapping[str, Mapping[str, Any]] | None = None,
        rules: Mapping[str, Mapping[str, Any]] | None = None,
        defaults: Mapping[str, Any] | None = None,
        available: Iterable[str | Path | Mapping[str, Any]] = (),
    ) -> "Policy":
        """Merge ``packs`` onto ``base``, then apply the category, rule and defaults overrides.

        ``available`` lists packs that are known but switched off, so listings can show them.
        """
        data = copy.deepcopy(load_document(base))
        data.setdefault("detectors", [])
        infos: list[PackInfo] = []
        for source in packs:
            patch = load_document(source)
            data = merge(data, patch, pack_id=str(patch.get("id", "pack")))
            infos.append(_pack_info(patch, enabled=True))
        enabled_ids = {p.id for p in infos}
        for source in available:
            patch = load_document(source)
            if str(patch.get("id")) not in enabled_ids:
                infos.append(_pack_info(patch, enabled=False))

        overrides: dict[str, Any] = {}
        if categories:
            unknown = set(categories) - set(data.get("categories") or {})
            if unknown:
                raise ValueError(
                    f"category overrides name unknown categories {sorted(unknown)}; "
                    "a category from a pack that is switched off cannot be overridden"
                )
            overrides["categories"] = {
                k: _with_sensitivity(data["categories"][k], dict(v)) for k, v in categories.items()
            }
        if rules:
            known = {r["id"] for r in data.get("rules") or ()}
            unknown = set(rules) - known
            if unknown:
                raise ValueError(f"rule overrides name unknown rules {sorted(unknown)}")
            overrides["rules"] = [{"id": rid, **dict(v)} for rid, v in rules.items()]
        if defaults:
            overrides["defaults"] = dict(defaults)
        if overrides:
            data = merge(data, overrides, pack_id=None)

        data = expand_macros(data)
        data["packs"] = [p.id for p in infos if p.enabled]
        return cls(data, packs=infos)

    # -- queries ------------------------------------------------------

    @property
    def ref(self) -> str:
        """Identifies exactly this composition: base, version, packs and a content fingerprint."""
        packs = "+".join(p.id for p in self.packs if p.enabled)
        return f"{self.id}@{self.version}{'+' + packs if packs else ''}#{self.fingerprint}"

    def for_surface(self, surface: Surface, *, judged: bool = False) -> list[Category]:
        """Enabled categories that apply to a surface, most serious first. ``judged`` keeps only the
        ones a model is asked about."""
        cats = [c for c in self.categories.values() if c.applies(surface) and (c.judge or not judged)]
        cats.sort(key=lambda c: (-c.weight, -c.base_severity, c.id))
        return cats

    def sentinels(self, surface: Surface) -> list[Category]:
        """Categories with a dedicated yes/no question on this surface."""
        return [c for c in self.for_surface(surface, judged=True) if c.sentinel and c.sentinel_instructions]

    def multilabel(self, surface: Surface) -> list[Category]:
        """Categories that get a yes/no question in multi-label mode, beyond the sentinels.

        A choice question picks one label, so a passage with several problems reports mainly the
        worst. In multi-label mode every category gets its own independent question, so each
        problem in the passage is reported on its own.
        """
        spec = self.defaults.get("multilabel") or {}
        if surface not in (spec.get("surfaces") or ()):
            return []
        return [c for c in self.for_surface(surface, judged=True) if not (c.sentinel and c.sentinel_instructions)]

    def multilabel_trust(self) -> float:
        """A multi-label answer at or above this is corroborated without the hazard choice."""
        return float((self.defaults.get("multilabel") or {}).get("trust", 0.6))

    def signals_for(self, surface: Surface, *, available: Iterable[str] = ()) -> dict[str, Any]:
        """Signals asked on a surface. A signal with ``requires`` (``query``, ``context``) is asked
        only when the state carries that part: relevance needs a query, groundedness needs the
        retrieved passages."""
        have = set(available)
        out: dict[str, Any] = {}
        for name, spec in self.signals.items():
            if surface not in (spec.get("surfaces") or []):
                continue
            needs = set(spec.get("requires") or ())
            if spec.get("requires_context"):
                needs.add("context")
            if not needs <= have:
                continue
            out[name] = spec
        return out

    def criteria_for(self, spec: Mapping[str, Any]) -> Any:
        if "criteria" in spec:
            return spec["criteria"]
        ref = spec.get("criteria_ref")
        return self.scales.get(str(ref)) if ref else None

    def min_confidence(self) -> float:
        return float(self.defaults.get("min_confidence", 0.65))

    def on_low_confidence(self) -> str:
        return str(self.defaults.get("on_low_confidence", "escalate"))

    def fail_closed(self, surface: Surface | None = None) -> bool:
        """Whether an unreachable Jev holds content on this surface."""
        setting = self.defaults.get("on_error", "fail_closed")
        if isinstance(setting, Mapping):
            setting = setting.get(surface or "", "fail_closed")
        return str(setting) == "fail_closed"

    def error_action(self) -> str:
        return str(self.defaults.get("error_action", "review"))

    def sentinel_corroboration(self) -> SentinelCorroboration | None:
        raw = self.defaults.get("sentinel_corroboration")
        if not isinstance(raw, Mapping):
            return None
        return SentinelCorroboration(
            min_choice=float(raw.get("min_choice", 0.02)),
            refusal=float(raw.get("refusal", 0.8)),
            refusal_max_sentinel=float(raw.get("refusal_max_sentinel", 0.5)),
            refusal_except=frozenset(raw.get("refusal_except") or ()),
            weak_at_most_flag=bool(raw.get("weak_at_most_flag", False)),
            redact_instead_of_block_below=float(raw.get("redact_instead_of_block_below", 0) or 0),
            weak_except=frozenset(raw.get("weak_except") or ()),
        )

    def confidence_gate(self) -> ConfidenceGateOptions:
        raw = self.defaults.get("confidence_gate")
        raw = raw if isinstance(raw, Mapping) else {}
        return ConfidenceGateOptions(
            needs_corroboration=bool(raw.get("needs_corroboration", False)),
            skip_when_intent=frozenset(raw.get("skip_when_intent") or ()),
            skip_min_confidence=float(raw.get("skip_min_confidence", 0.5)),
        )

    def summary(self) -> dict[str, Any]:
        """The effective policy, for the API and the CLI."""
        return {
            "id": self.id,
            "version": self.version,
            "ref": self.ref,
            "fingerprint": self.fingerprint,
            "packs": [p.as_dict() for p in self.packs],
            "detectors": list(self.detectors),
            "categories": {
                c.id: {
                    "name": c.name,
                    "names": dict(c.names),
                    "pack": c.pack,
                    "enabled": c.enabled,
                    "surfaces": sorted(c.surfaces, key=SURFACES.index),
                    "sentinel": c.sentinel,
                    "route": c.route,
                    "thresholds": {k: dict(v) for k, v in c.thresholds.items()},
                    "refs": list(c.refs),
                }
                for c in self.categories.values()
            },
            "rules": [
                {"id": r.get("id"), "when": r.get("when"), "then": r.get("then"), "why": r.get("why", "")}
                for r in self.rules
            ],
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Policy {self.ref}: {len(self.categories)} categories>"


# -- documents and merging ------------------------------------------------


def load_document(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    """A pack as a dict: a bundled name (``standard-rag-v1``, ``vn-ai``), a JSON or YAML path, or a
    dict."""
    if isinstance(source, Mapping):
        return copy.deepcopy(dict(source))
    text = str(source)
    if not any(sep in text for sep in ("/", "\\")) and not text.endswith((".json", ".yaml", ".yml")):
        return _bundled(text)
    path = Path(text)
    raw = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        import yaml  # type: ignore[import-untyped]

        return dict(yaml.safe_load(raw))
    return dict(json.loads(raw))


def _bundled(name: str) -> dict[str, Any]:
    root = resources.files(__package__).joinpath("policies")
    for candidate in (root.joinpath(f"{name}.json"), root.joinpath("packs", f"{name}.json")):
        if candidate.is_file():
            return dict(json.loads(candidate.read_text("utf-8")))
    raise ValueError(f"no bundled policy pack named {name!r}; bundled packs: {', '.join(bundled_names())}")


def bundled_names() -> list[str]:
    root = resources.files(__package__).joinpath("policies")
    names = [p.name[:-5] for p in root.iterdir() if p.name.endswith(".json")]
    names += [p.name[:-5] for p in root.joinpath("packs").iterdir() if p.name.endswith(".json")]
    return sorted(names)


def merge(base: Mapping[str, Any], patch: Mapping[str, Any], *, pack_id: str | None) -> dict[str, Any]:
    """Layer ``patch`` onto ``base``. See the module docstring for the rules."""
    data = copy.deepcopy(dict(base))

    for block in ("categories", "signals"):
        merged = dict(data.get(block) or {})
        for key, value in (patch.get(block) or {}).items():
            if key in merged:
                merged[key] = _patch_item(merged[key], value)
            else:
                item = _patch_item({}, value)
                if block == "categories" and pack_id:
                    item.setdefault("pack", pack_id)
                merged[key] = item
        data[block] = merged

    by_id = {rule["id"]: dict(rule) for rule in data.get("rules") or ()}
    order = list(by_id)
    for rule in patch.get("rules") or ():
        if rule["id"] in by_id:
            by_id[rule["id"]] = _patch_item(by_id[rule["id"]], rule)
        else:
            by_id[rule["id"]] = _patch_item({}, rule)
            order.append(rule["id"])
    data["rules"] = [by_id[rid] for rid in order]

    for block in ("defaults", "responses"):
        if isinstance(patch.get(block), Mapping):
            data[block] = _deep(data.get(block) or {}, patch[block])

    if patch.get("detectors"):
        data["detectors"] = _union(data.get("detectors") or [], patch["detectors"])

    return data


def expand_macros(data: dict[str, Any]) -> dict[str, Any]:
    everything = list(data.get("categories") or {})
    for rule in data.get("rules") or ():
        if "except_categories" not in rule:
            continue
        expanded: list[str] = []
        for item in rule.get("except_categories") or ():
            if isinstance(item, str) and item.startswith(MACRO):
                keep = set(item[len(MACRO):].split(","))
                unknown = keep - set(everything)
                if unknown:
                    raise ValueError(f"rule {rule['id']!r}: {MACRO} names unknown {sorted(unknown)}")
                expanded.extend(c for c in everything if c not in keep)
            else:
                expanded.append(item)
        rule["except_categories"] = list(dict.fromkeys(expanded))
    return data


def _patch_item(target: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(target))
    for key, value in patch.items():
        if key.endswith("+"):
            name = key[:-1]
            out[name] = _union(out.get(name) or [], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _deep(target: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(target))
    for key, value in patch.items():
        if key.endswith("+"):
            name = key[:-1]
            out[name] = _union(out.get(name) or [], value)
        elif isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _union(a: Iterable[Any], b: Iterable[Any]) -> list[Any]:
    return list(dict.fromkeys([*a, *b]))


#: Multipliers on every band. Lower bands fire sooner.
SENSITIVITY: Mapping[str, float] = {"strict": 0.7, "balanced": 1.0, "lenient": 1.3}


def _with_sensitivity(category: Mapping[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Turn ``sensitivity: strict | balanced | lenient`` into scaled thresholds.

    Explicit ``thresholds`` in the same override win: the level is a shortcut, not a second knob.
    """
    level = override.pop("sensitivity", None)
    if level is None or "thresholds" in override:
        return override
    if level not in SENSITIVITY:
        raise ValueError(f"sensitivity must be one of {sorted(SENSITIVITY)}, not {level!r}")
    factor = SENSITIVITY[level]
    override["thresholds"] = {
        surface: {band: round(min(0.99, float(value) * factor), 4) for band, value in bands.items()}
        for surface, bands in (category.get("thresholds") or {}).items()
    }
    return override


def _pack_info(patch: Mapping[str, Any], *, enabled: bool) -> PackInfo:
    return PackInfo(
        id=str(patch.get("id", "pack")),
        version=str(patch.get("version", "0")),
        name=str(patch.get("name", patch.get("id", "pack"))),
        names=dict(patch.get("names") or {}),
        law=dict(patch.get("law") or {}),
        summary=str(patch.get("summary", "")),
        categories=tuple((patch.get("categories") or {}).keys()),
        enabled=enabled,
    )


def _category(cid: str, raw: Mapping[str, Any]) -> Category:
    names = dict(raw.get("names") or {})
    names.setdefault("en", str(raw.get("name", cid)))
    return Category(
        id=cid,
        name=str(raw.get("name", cid)),
        description=str(raw.get("description", "")),
        refs=tuple(raw.get("refs") or ()),
        surfaces=frozenset(raw.get("surfaces") or SURFACES),
        weight=float(raw.get("weight", 0.5)),
        base_severity=int(raw.get("base_severity", 2)),
        sentinel=bool(raw.get("sentinel", False)),
        sentinel_instructions=raw.get("sentinel_instructions"),
        thresholds={k: {kk: float(vv) for kk, vv in v.items()} for k, v in (raw.get("thresholds") or {}).items()},
        route=raw.get("route"),
        never_below=raw.get("never_below"),
        enabled=bool(raw.get("enabled", True)),
        pack=str(raw.get("pack", BASE)),
        names=names,
        judge=bool(raw.get("judge", True)),
    )


def _validate(policy: Policy) -> None:
    if not policy.categories:
        raise ValueError("policy has no categories")
    for cid, cat in policy.categories.items():
        if not cat.description and cat.judge:
            raise ValueError(f"category {cid!r} has no description")
        if not cat.thresholds.get("default"):
            raise ValueError(f"category {cid!r} has no default thresholds")
        bad = set(cat.surfaces) - set(SURFACES)
        if bad:
            raise ValueError(f"category {cid!r} names unknown surfaces {sorted(bad)}")
        for surface, bands in cat.thresholds.items():
            missing = {"block", "review", "flag"} - set(bands)
            if missing:
                raise ValueError(f"category {cid!r} thresholds[{surface}] missing {sorted(missing)}")
            if not bands["block"] >= bands["review"] >= bands["flag"]:
                raise ValueError(f"category {cid!r} thresholds[{surface}] are not ordered block >= review >= flag")
        if cat.route not in (None, "redact", "guide", "crisis_support"):
            raise ValueError(f"category {cid!r} has unknown route {cat.route!r}")
    for name, spec in policy.signals.items():
        bad = set(spec.get("surfaces") or ()) - set(SURFACES)
        if bad:
            raise ValueError(f"signal {name!r} names unknown surfaces {sorted(bad)}; surfaces are {SURFACES}")
    for rule in policy.rules:
        when = rule.get("when") or {}
        signal = when.get("signal")
        if signal and signal not in policy.signals:
            raise ValueError(f"rule {rule.get('id')!r} refers to unknown signal {signal!r}")
        added = (rule.get("then") or {}).get("add_finding")
        if added and added not in policy.categories:
            raise ValueError(f"rule {rule.get('id')!r} adds unknown category {added!r}")
