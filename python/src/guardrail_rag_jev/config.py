"""The configuration file: one YAML or JSON document for the library, the service and the CLI.

Values may reference the environment as ``${NAME}`` or ``${NAME:-default}``, so secrets stay out of
the file. See ``config/guardrail.example.yaml`` for every setting with its default.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .policy import BASE, BUNDLED_PACKS
from .types import SURFACES

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

REVIEW_MODES = ("hold", "remove", "pass")
MODES = ("enforce", "shadow")
STORE_CONTENT = ("none", "hash", "redacted", "full")


@dataclass
class SurfaceEnforcement:
    """What a verdict turns into on one surface.

    ``mode``: ``enforce`` acts on decisions; ``shadow`` records what it would have done and passes
    everything, for a trial period before switching on.
    ``review``: what a review verdict does here. ``hold`` keeps it out until a person approves it
    (ingest, answer); ``remove`` drops it now and still queues it (context, where nobody can wait);
    ``pass`` uses it and queues it for audit (realtime chat).
    """

    mode: str = "enforce"
    review: str = "hold"
    queue_reviews: bool = True
    queue_blocks: bool = False
    #: Find which segments of a flagged passage carry each violation.
    locate: bool = False
    #: Mask detector matches even when nothing else fired (data minimisation before indexing).
    redact_always: bool = False
    #: Context only: drop passages scored below this relevance (0-3), None to keep all.
    min_relevance: float | None = None
    #: Answer only: append the AI transparency label when a pack provides one.
    ai_label: bool = False
    #: Make links unclickable when malicious content is found.
    defang_links: bool = True
    #: Ingest only: a chunk with any of these holds its whole document for review.
    quarantine_document_on: list[str] = field(default_factory=list)
    #: Context only: reuse the verdict a chunk got at ingest when policy and provider are unchanged.
    reuse_ingest: bool = True

    def validate(self, surface: str) -> None:
        if self.mode not in MODES:
            raise ValueError(f"enforcement.{surface}.mode must be one of {MODES}")
        if self.review not in REVIEW_MODES:
            raise ValueError(f"enforcement.{surface}.review must be one of {REVIEW_MODES}")


def _default_enforcement() -> dict[str, SurfaceEnforcement]:
    return {
        "ingest": SurfaceEnforcement(review="hold", queue_blocks=True, locate=True, redact_always=True,
                                     quarantine_document_on=["ipi", "mal", "cse", "iwp"]),
        "query": SurfaceEnforcement(review="hold"),
        # A chunk blocked at retrieval means the index holds content it should not: queue it so
        # someone purges it. The queue keeps one pending item per text.
        "context": SurfaceEnforcement(review="remove", queue_blocks=True),
        "answer": SurfaceEnforcement(review="hold", ai_label=True),
    }


@dataclass
class PolicyConfig:
    base: str = BASE
    #: Pack name (bundled) or path -> enabled.
    packs: dict[str, bool] = field(default_factory=lambda: {p: True for p in BUNDLED_PACKS})
    categories: dict[str, dict[str, Any]] = field(default_factory=dict)
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    defaults: dict[str, Any] = field(default_factory=dict)
    #: Packs and categories that the runtime API may not switch off: the organisation's floor.
    locked: list[str] = field(default_factory=list)


@dataclass
class RedactionConfig:
    enable: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    actions: dict[str, str] = field(default_factory=dict)
    template: str = "{label}"
    #: When a verdict asks for masking but no detector found a span to mask.
    fallback: str = "review"


@dataclass
class AuditConfig:
    backend: str = "jsonl"
    path: str = "data/audit.jsonl"
    #: How much of the checked text an audit record keeps. Never ``full`` for personal data unless
    #: the log itself is protected like the data.
    store_content: str = "redacted"
    #: Also send every record to this URL (a SIEM collector), best effort.
    webhook_url: str | None = None


@dataclass
class ReviewConfig:
    path: str = "data/review.db"
    #: Reviewers need the text to decide; ``redacted`` keeps personal data out of the queue.
    store_content: str = "full"
    webhook_url: str | None = None
    webhook_secret: str | None = None
    #: Days a decided item keeps its content before it is purged; 0 keeps it.
    retention_days: int = 90


@dataclass
class ApiKey:
    key: str
    role: str = "client"
    name: str = ""
    #: Bind the key to one tenant: its checks are recorded under it and it sees only its reviews.
    tenant: str | None = None
    #: Bind the key to one profile.
    profile: str | None = None


@dataclass
class ServerConfig:
    api_keys: list[ApiKey] = field(default_factory=list)
    cors_origins: list[str] = field(default_factory=list)
    max_batch: int = 256


@dataclass
class ShadowConfig:
    provider: str | None = None
    sample: float = 1.0


@dataclass
class Config:
    provider: str = "jev"
    providers: dict[str, dict[str, Any]] = field(default_factory=lambda: {"jev": {"type": "jev"}})
    #: Surface -> provider name, for surfaces that should not use the default one.
    routing: dict[str, str] = field(default_factory=dict)
    shadow: ShadowConfig = field(default_factory=ShadowConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    enforcement: dict[str, SurfaceEnforcement] = field(default_factory=_default_enforcement)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    patterns: list[dict[str, Any]] = field(default_factory=list)
    locate: dict[str, Any] = field(default_factory=lambda: {"max_segments": 16, "min_chars": 30, "max_chars": 1200})
    default_language: str = "vi"
    crisis_line: str | None = None
    cache: dict[str, Any] = field(default_factory=lambda: {"enabled": True, "capacity": 8192, "ttl": 900})
    concurrency: int = 8
    timeout: float | None = None
    audit: AuditConfig = field(default_factory=AuditConfig)
    review: ReviewConfig = field(default_factory=ReviewConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    #: Where runtime policy changes (pack and category toggles) are kept across restarts.
    state_path: str | None = "data/policy-state.json"
    #: Which data-residency classes a provider may have: offshore, vn_hosted, local.
    residency: list[str] = field(default_factory=lambda: ["offshore", "vn_hosted", "local"])
    #: Named partial configs layered over this one, chosen per request (tenant or app).
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: The file this config came from; relative paths resolve against its directory.
    source: str | None = None
    #: The document this config was built from, for profiles.
    raw: dict[str, Any] = field(default_factory=dict)

    # -- loading -----------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Load from ``path``, else ``$GUARDRAIL_CONFIG``, else the defaults."""
        path = path or os.environ.get("GUARDRAIL_CONFIG")
        if not path:
            return cls()
        p = Path(path)
        raw = p.read_text("utf-8")
        if p.suffix in (".yaml", ".yml"):
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(raw) or {}
        else:
            data = json.loads(raw)
        cfg = cls.from_dict(data)
        cfg.source = str(p.resolve())
        return cfg

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Config":
        data = expand_env(dict(data))
        known = {
            "provider", "providers", "routing", "shadow", "policy", "enforcement", "redaction", "patterns",
            "locate", "default_language", "crisis_line", "cache", "concurrency", "timeout", "audit", "review",
            "server", "state_path", "jev", "residency", "profiles",
        }
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown config keys {sorted(unknown)}")
        cfg = cls()
        # "jev:" at the top level is a shortcut for providers.jev.
        providers = {k: dict(v) for k, v in (data.get("providers") or {}).items()}
        if "jev" in data:
            providers["jev"] = {"type": "jev", **providers.get("jev", {}), **dict(data["jev"] or {})}
        if providers:
            cfg.providers = {**cfg.providers, **providers}
        for name, spec in cfg.providers.items():
            spec.setdefault("type", name)
        cfg.provider = str(data.get("provider", cfg.provider))
        cfg.routing = {str(k): str(v) for k, v in (data.get("routing") or {}).items()}
        if data.get("shadow"):
            cfg.shadow = ShadowConfig(**dict(data["shadow"]))
        if data.get("policy"):
            p = dict(data["policy"])
            packs = p.get("packs") or {}
            if isinstance(packs, list):
                packs = {name: True for name in packs}
            # Listed packs override the defaults; a bundled pack not listed stays on.
            packs = {**cfg.policy.packs, **packs}
            cfg.policy = PolicyConfig(
                base=str(p.get("base", BASE)),
                packs={str(k): bool(v) for k, v in packs.items()},
                categories={k: dict(v) for k, v in (p.get("categories") or {}).items()},
                rules={k: dict(v) for k, v in (p.get("rules") or {}).items()},
                defaults=dict(p.get("defaults") or {}),
                locked=list(p.get("locked") or ()),
            )
        enforcement = _default_enforcement()
        for surface, raw in (data.get("enforcement") or {}).items():
            if surface == "mode":
                for e in enforcement.values():
                    e.mode = str(raw)
                continue
            if surface not in SURFACES:
                raise ValueError(f"enforcement.{surface}: unknown surface; surfaces are {SURFACES}")
            unknown = set(dict(raw)) - set(enforcement[surface].__dict__)
            if unknown:
                raise ValueError(f"enforcement.{surface}: unknown settings {sorted(unknown)}")
            enforcement[surface] = SurfaceEnforcement(**{**enforcement[surface].__dict__, **dict(raw)})
        cfg.enforcement = enforcement
        if data.get("redaction"):
            r = dict(data["redaction"])
            det = dict(r.pop("detectors", {}) or {})
            cfg.redaction = RedactionConfig(
                enable=list(det.get("enable") or ()),
                disable=list(det.get("disable") or ()),
                actions=dict(det.get("actions") or {}),
                **r,
            )
        cfg.patterns = list(data.get("patterns") or ())
        if data.get("locate"):
            cfg.locate = {**cfg.locate, **dict(data["locate"])}
        cfg.default_language = str(data.get("default_language", cfg.default_language))
        cfg.crisis_line = data.get("crisis_line", cfg.crisis_line)
        if data.get("cache") is not None:
            cfg.cache = {**cfg.cache, **dict(data["cache"])}
        cfg.concurrency = int(data.get("concurrency", cfg.concurrency))
        cfg.timeout = data.get("timeout", cfg.timeout)
        if data.get("audit"):
            cfg.audit = AuditConfig(**dict(data["audit"]))
        if data.get("review"):
            cfg.review = ReviewConfig(**dict(data["review"]))
        if data.get("server"):
            s = dict(data["server"])
            keys = [ApiKey(**k) if isinstance(k, Mapping) else ApiKey(key=str(k)) for k in s.pop("api_keys", []) or ()]
            cfg.server = ServerConfig(api_keys=[k for k in keys if k.key], **s)
        if "state_path" in data:
            cfg.state_path = data["state_path"]
        if data.get("residency"):
            res = data["residency"]
            cfg.residency = list(res.get("allow") if isinstance(res, Mapping) else res)
        cfg.profiles = {str(k): dict(v or {}) for k, v in (data.get("profiles") or {}).items()}
        cfg.raw = {k: v for k, v in data.items() if k != "profiles"}
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.provider not in self.providers:
            raise ValueError(f"provider {self.provider!r} is not configured under providers")
        for surface, name in self.routing.items():
            if surface not in SURFACES:
                raise ValueError(f"routing.{surface}: unknown surface")
            if name not in self.providers:
                raise ValueError(f"routing.{surface}: provider {name!r} is not configured")
        if self.shadow.provider and self.shadow.provider not in self.providers:
            raise ValueError(f"shadow.provider {self.shadow.provider!r} is not configured")
        for surface, e in self.enforcement.items():
            e.validate(surface)
        if self.audit.store_content not in STORE_CONTENT:
            raise ValueError(f"audit.store_content must be one of {STORE_CONTENT}")
        if self.review.store_content not in ("full", "redacted"):
            raise ValueError("review.store_content must be full or redacted")
        if self.redaction.fallback not in ("review", "remove", "pass"):
            raise ValueError("redaction.fallback must be review, remove or pass")
        for key in self.server.api_keys:
            if key.role not in ("client", "reviewer", "admin"):
                raise ValueError(f"server.api_keys: role must be client, reviewer or admin, not {key.role!r}")

    def for_profile(self, name: str) -> "Config":
        """This config with the named profile layered over it."""
        if name not in self.profiles:
            raise KeyError(f"no profile named {name!r}; profiles: {', '.join(sorted(self.profiles)) or 'none'}")
        child = Config.from_dict(deep_merge(self.raw, self.profiles[name]))
        child.source = self.source
        return child

    def resolve(self, path: str | None) -> str | None:
        """A path from the config, relative to the config file's directory."""
        if not path:
            return path
        p = Path(path)
        if p.is_absolute() or not self.source:
            return str(p)
        return str(Path(self.source).parent / p)

    def provider_for(self, surface: str) -> str:
        return self.routing.get(surface, self.provider)

    def redacted(self) -> dict[str, Any]:
        """The config with secrets masked, for the API and the logs."""
        providers = {
            name: {k: ("***" if "key" in k or "secret" in k else v) for k, v in spec.items()}
            for name, spec in self.providers.items()
        }
        return {
            "provider": self.provider,
            "providers": providers,
            "routing": dict(self.routing),
            "shadow": self.shadow.__dict__,
            "policy": self.policy.__dict__,
            "enforcement": {s: e.__dict__ for s, e in self.enforcement.items()},
            "redaction": self.redaction.__dict__,
            "audit": {**self.audit.__dict__},
            "review": {**self.review.__dict__, "webhook_secret": "***" if self.review.webhook_secret else None},
            "default_language": self.default_language,
        }


def deep_merge(base: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def expand_env(value: Any) -> Any:
    """Replace ``${NAME}`` and ``${NAME:-default}`` in every string."""
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else ""), value)
    if isinstance(value, Mapping):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value
