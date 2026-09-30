"""Languages: telling which one the user writes in, and answering in it.

The judging model reads meaning in any language, so detection here never changes a verdict. It only
picks the language of the prewritten replies and notices, which live in the policy's ``responses``
section so that legal wording is exact and never written by a model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .policy import Policy
from .types import Verdict, rank

_KANA = re.compile(r"[぀-ヿ]")
_HANGUL = re.compile(r"[가-힯]")
_CJK = re.compile(r"[㐀-鿿]")
_THAI = re.compile(r"[฀-๿]")
# Letters Vietnamese uses and French, Spanish or Portuguese do not.
_VIETNAMESE = re.compile(r"[ăđơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịĩọỏốồổỗộớờởỡợụủũứừửữựỳỵỷỹ]", re.IGNORECASE)
# Common Vietnamese words, for text whose only accents are ones French shares ("xin chào").
_VIETNAMESE_WORDS = re.compile(
    r"\b(?:và|của|là|không|có|những|được|cho|với|này|xin|chào|tôi|bạn|mình|gì|nào|ở|thì|cũng|như|khi|rồi|nhé|ạ)\b",
    re.IGNORECASE,
)
_FRENCH = re.compile(r"[çœ]|\b(?:le|la|les|des|est|une|pour|avec|dans|vous|nous|qui|que|pas)\b", re.IGNORECASE)
_LATIN = re.compile(r"[A-Za-z]")

LANGUAGES: tuple[str, ...] = ("vi", "en", "zh", "ja", "ko", "th", "fr")


def detect_language(text: str | None, default: str = "vi") -> str:
    """A cheap guess, good enough to pick the language of a reply."""
    if not text:
        return default
    if _KANA.search(text):
        return "ja"
    if _HANGUL.search(text):
        return "ko"
    if _CJK.search(text):
        return "zh"
    if _THAI.search(text):
        return "th"
    if _VIETNAMESE.search(text) or _VIETNAMESE_WORDS.search(text):
        return "vi"
    if len(_FRENCH.findall(text)) >= 2:
        return "fr"
    if _LATIN.search(text):
        return "en"
    return default


@dataclass(frozen=True, slots=True)
class Reply:
    """A chosen prewritten reply and the group it came from, for logs and audits."""

    group: str
    text: str


class Responder:
    """Selects prewritten replies and notices from the policy's ``responses`` section.

    Packs add and override response groups, so switching off a law pack also removes its wording.
    """

    def __init__(self, policy: Policy, *, crisis_line: str | None = None, default_language: str | None = None) -> None:
        spec = policy.responses
        self.spec = spec
        self.languages: tuple[str, ...] = tuple(spec.get("languages") or ("vi", "en"))
        self.default_language = default_language or str(spec.get("default_language") or self.languages[0])
        self.crisis_line = crisis_line or str(spec.get("crisis_line_default") or "")
        groups: Mapping[str, Mapping[str, Any]] = spec.get("groups") or {}
        self._groups = sorted(groups.items(), key=lambda kv: (float(kv[1].get("priority", 500)), kv[0]))

    def group_for(self, verdict: Verdict) -> str:
        """The response group that answers the strongest finding."""
        counted = [f for f in verdict.findings if rank(f.action) >= rank("review")] or list(verdict.findings)
        top = max((rank(f.action) for f in counted), default=0)
        leading = {f.category for f in counted if rank(f.action) == top}
        for name, group in self._groups:
            if set(group.get("categories") or ()) & leading:
                return name
        return "general"

    def withheld(self, verdict: Verdict, language: str | None = None) -> Reply:
        """The reply that replaces a query or an answer that is not used."""
        if verdict.degraded:
            return Reply("unavailable", self.text(self.spec.get("unavailable") or {}, language))
        if verdict.route == "crisis_support":
            return Reply("self_harm", self.group_text("self_harm", language))
        if verdict.route == "human_review":
            return Reply("review", self.text(self.spec.get("review") or {}, language))
        group = self.group_for(verdict)
        text = self.group_text(group, language)
        if any(f.category == "ssh" and f.action == "block" and not f.weak for f in verdict.findings):
            # Self-harm at its block band beside a stronger finding: the reply names what stopped
            # the content, and the line is there in case the person is also at risk.
            footer = self.text(self.spec.get("crisis_footer") or {}, language)
            text = f"{text}\n\n{footer}" if footer else text
        return Reply(group, text)

    def notices(self, verdict: Verdict, language: str | None = None, *, ai_label: bool = False) -> list[str]:
        """Text shown with a used answer: guidance for steered categories, pack affirmations and the
        AI transparency label."""
        out: list[str] = []
        guidance: Mapping[str, Any] = self.spec.get("guidance") or {}
        for f in verdict.findings:
            if f.category in guidance and rank(f.action) >= rank("flag") and not f.weak:
                text = self.text(guidance[f.category], language)
                if text and text not in out:
                    out.append(text)
        for affirmation in (self.spec.get("affirmations") or {}).values():
            if self._affirms(affirmation, verdict):
                out.append(self.text(affirmation.get("text") or {}, language))
        label = (self.spec.get("transparency") or {}).get("label")
        if ai_label and label:
            out.append(self.text(label, language))
        return [t for t in out if t]

    def no_context(self, language: str | None = None) -> str:
        return self.text(self.spec.get("no_context") or {}, language)

    def group_text(self, group: str, language: str | None) -> str:
        groups = dict(self._groups)
        spec = groups.get(group) or groups.get("general") or {}
        return self.text(spec.get("text") or {}, language)

    def text(self, texts: Mapping[str, str], language: str | None) -> str:
        for lang in (language, self.default_language, "en", *self.languages):
            if lang and texts.get(lang):
                return texts[lang].replace("{crisis_line}", self.crisis_line)
        return ""

    def _affirms(self, affirmation: Mapping[str, Any], verdict: Verdict) -> bool:
        if set(affirmation.get("not_after_rules") or ()) & set(verdict.applied_rules):
            return False
        cats = set(affirmation.get("categories") or ())
        if any(f.category in cats and rank(f.action) >= rank("flag") for f in verdict.findings):
            return True
        signal = affirmation.get("trigger_signal")
        value = verdict.signals.get(signal) if signal else None
        return isinstance(value, (int, float)) and value >= float(affirmation.get("trigger_value", 0.6))
