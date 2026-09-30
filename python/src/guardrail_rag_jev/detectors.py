"""Deterministic detectors: exact spans that a probability cannot give.

Jev reads meaning; it does not locate characters, count digits or check a Luhn sum. Masking needs
exact spans, so personal identifiers and secrets are found here, by pattern and validator, in
microseconds and without a network call. The two work together: Jev says *that* a passage carries
personal data, a detector says *where*, and the pipeline masks it.

Deny and allow patterns are the deployment's own exact rules: a deny pattern adds a finding (and can
settle the check without calling Jev), an allow pattern settles known-safe content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Sequence

from .types import Action, Redaction, Surface


@dataclass(frozen=True, slots=True)
class Match:
    detector: str
    category: str
    start: int
    end: int
    label: str


@dataclass(frozen=True, slots=True)
class Detector:
    """One kind of identifier or secret."""

    name: str
    category: str
    regex: re.Pattern[str]
    label: str
    #: Which regex group is the sensitive part; 0 is the whole match. A keyword in front of an
    #: account number is context, not data, and stays readable.
    group: int = 0
    validator: Callable[[str], bool] | None = None
    action: Action = "review"
    description: str = ""

    def find(self, text: str) -> list[Match]:
        out: list[Match] = []
        for m in self.regex.finditer(text):
            start, end = m.span(self.group)
            if start < 0:
                continue
            value = text[start:end]
            if self.validator is not None and not self.validator(value):
                continue
            out.append(Match(self.name, self.category, start, end, self.label))
        return out


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn(value: str) -> bool:
    digits = _digits(value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _cccd(value: str) -> bool:
    # The first three digits are the province code of the place of birth registration (001-096).
    return 1 <= int(value[:3]) <= 96


def _d(name: str, category: str, pattern: str, label: str, **kw) -> Detector:
    flags = kw.pop("flags", 0)
    return Detector(name, category, re.compile(pattern, flags), label, **kw)


_I = re.IGNORECASE

#: Every detector the package knows. A deployment switches them on by name, from the policy (packs
#: list the ones they need) and from the config.
REGISTRY: Mapping[str, Detector] = {
    d.name: d
    for d in (
        _d("email", "prv", r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}", "[EMAIL]",
           description="Email address"),
        _d("payment_card", "prv", r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", "[CARD]", validator=luhn,
           description="Payment card number (Luhn-checked)"),
        _d("vn_cccd", "prv", r"(?<!\d)0\d{11}(?!\d)", "[CCCD]", validator=_cccd,
           description="Vietnamese citizen ID (CCCD), 12 digits"),
        _d("vn_phone", "prv", r"(?<![\d+])(?:\+84|84|0)[ .-]?(?:3|5|7|8|9)\d(?:[ .-]?\d){7}(?!\d)", "[PHONE]",
           description="Vietnamese mobile number"),
        _d("vn_bank_account", "prv",
           r"(?:STK|số tài khoản|so tai khoan|tài khoản ngân hàng|account (?:no\.?|number))\s*[:#]?\s*(\d(?:[ .-]?\d){5,18})",
           "[BANK_ACCOUNT]", group=1, flags=_I, description="Bank account number after an account keyword"),
        _d("vn_passport", "prv", r"(?:hộ chiếu|passport)(?:\s*(?:số|no\.?|number))?\s*[:#]?\s*([A-Z]\d{7,8})(?!\d)",
           "[PASSPORT]", group=1, flags=_I, description="Passport number after a passport keyword"),
        _d("vn_social_insurance", "prv", r"(?:BHXH|bảo hiểm xã hội)\D{0,24}?(\d{10})(?!\d)", "[BHXH]", group=1,
           flags=_I, description="Vietnamese social insurance number after a BHXH keyword"),
        _d("vn_license_plate", "prv", r"(?<![\w-])\d{2}[A-Z]{1,2}\d?[ -]?\d{3}\.?\d{2}(?![\w])", "[PLATE]",
           description="Vietnamese vehicle licence plate"),
        _d("api_key", "sid", r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|apikey_[a-f0-9]{30,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b",
           "[SECRET]", description="API key or access token in a known format"),
        _d("private_key", "sid", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
           "[PRIVATE_KEY]", description="PEM private key block"),
        _d("jwt", "sid", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[TOKEN]",
           description="JSON Web Token"),
        _d("password", "sid", r"(?:password|passwd|pwd|mật khẩu|mat khau)\s*[:=]\s*([^\s,;\"']{4,})", "[PASSWORD]",
           group=1, flags=_I, description="Password written after a password keyword"),
        _d("hidden_unicode", "ipi", r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]{3,}|[\U000e0000-\U000e007f]+", "",
           action="review", description="Invisible or tag characters that can hide instructions from human readers"),
        _d("connection_string", "sid", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@]+:([^\s@]+)@",
           "[SECRET]", group=1, flags=_I, description="Password inside a database connection string"),
    )
}

#: Always on unless the config switches them off.
DEFAULT_DETECTORS: tuple[str, ...] = ("email", "payment_card", "api_key", "private_key", "jwt", "password", "connection_string", "hidden_unicode")

_URL = re.compile(r"\bhttps?://[^\s<>\")\]]+", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Pattern:
    """A deployment's own exact rule.

    ``kind="deny"`` adds a finding for ``category`` at ``action``; with ``settle`` it decides without
    calling Jev. ``kind="allow"`` settles the check as allowed: for boilerplate known to be safe.
    """

    name: str
    regex: re.Pattern[str]
    kind: str = "deny"
    category: str | None = None
    action: Action = "block"
    surfaces: frozenset[str] = frozenset({"ingest", "query", "context", "answer"})
    settle: bool = False

    @classmethod
    def from_config(cls, raw: Mapping[str, object]) -> "Pattern":
        flags = 0 if raw.get("case_sensitive") else re.IGNORECASE
        kind = str(raw.get("kind", "deny"))
        if kind not in ("deny", "allow"):
            raise ValueError(f"pattern {raw.get('name')!r}: kind must be deny or allow")
        if kind == "deny" and not raw.get("category"):
            raise ValueError(f"deny pattern {raw.get('name')!r} needs a category")
        return cls(
            name=str(raw["name"]),
            regex=re.compile(str(raw["regex"]), flags),
            kind=kind,
            category=str(raw["category"]) if raw.get("category") else None,
            action=str(raw.get("action", "block")),  # type: ignore[arg-type]
            surfaces=frozenset(raw.get("surfaces") or ("ingest", "query", "context", "answer")),  # type: ignore[arg-type]
            settle=bool(raw.get("settle", False)),
        )


@dataclass
class DetectorSet:
    """The detectors and patterns in force for one policy and config."""

    detectors: list[Detector] = field(default_factory=list)
    patterns: list[Pattern] = field(default_factory=list)

    @classmethod
    def build(
        cls,
        names: Iterable[str],
        *,
        disabled: Iterable[str] = (),
        actions: Mapping[str, str] | None = None,
        patterns: Sequence[Mapping[str, object]] = (),
    ) -> "DetectorSet":
        off = set(disabled)
        chosen: list[Detector] = []
        for name in dict.fromkeys(names):
            if name in off:
                continue
            if name not in REGISTRY:
                raise ValueError(f"unknown detector {name!r}; known: {', '.join(sorted(REGISTRY))}")
            det = REGISTRY[name]
            if actions and name in actions:
                det = Detector(det.name, det.category, det.regex, det.label, det.group, det.validator,
                               actions[name], det.description)  # type: ignore[arg-type]
            chosen.append(det)
        return cls(chosen, [Pattern.from_config(p) for p in patterns])

    def find(self, text: str) -> list[Match]:
        """Non-overlapping matches, earliest first, the longer one winning an overlap."""
        found = [m for d in self.detectors for m in d.find(text)]
        found.sort(key=lambda m: (m.start, -(m.end - m.start)))
        out: list[Match] = []
        last_end = -1
        for m in found:
            if m.start >= last_end:
                out.append(m)
                last_end = m.end
        return out

    def action_of(self, detector: str) -> Action:
        for d in self.detectors:
            if d.name == detector:
                return d.action
        return "review"

    def patterns_for(self, surface: Surface) -> list[Pattern]:
        return [p for p in self.patterns if surface in p.surfaces]


def redact(text: str, matches: Sequence[Match], *, template: str = "{label}") -> tuple[str, tuple[Redaction, ...]]:
    """Replace every match. Offsets in the result refer to the original text."""
    if not matches:
        return text, ()
    parts: list[str] = []
    redactions: list[Redaction] = []
    cursor = 0
    for m in sorted(matches, key=lambda m: m.start):
        if m.start < cursor:
            continue
        replacement = template.format(label=m.label, detector=m.detector, category=m.category)
        parts.append(text[cursor:m.start])
        parts.append(replacement)
        redactions.append(Redaction(m.detector, m.category, m.start, m.end, replacement))
        cursor = m.end
    parts.append(text[cursor:])
    return "".join(parts), tuple(redactions)


def defang_urls(text: str) -> tuple[str, int]:
    """Make links unclickable (``hxxps://example[.]com``) so a planted phishing link cannot be
    followed from an answer or a snippet. Returns the text and the number of links changed."""
    count = 0

    def _one(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        url = m.group(0)
        url = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
        head, sep, rest = url.partition("://")
        host, slash, path = rest.partition("/")
        return f"{head}{sep}{host.replace('.', '[.]')}{slash}{path}"

    return _URL.sub(_one, text), count


def mask_excerpt(text: str, start: int, end: int, matches: Sequence[Match], *, width: int = 160) -> str:
    """A short excerpt around ``start:end`` with every detected span inside it masked, so the
    excerpt can go to logs and reviewers without carrying the data it points at."""
    lo, hi = max(0, start), min(len(text), end)
    if hi - lo > width:
        hi = lo + width
    inside = [m for m in matches if m.start >= lo and m.end <= hi]
    shifted = [Match(m.detector, m.category, m.start - lo, m.end - lo, m.label) for m in inside]
    excerpt, _ = redact(text[lo:hi], shifted)
    excerpt = " ".join(excerpt.split())
    return excerpt + ("…" if end - start > width else "")
