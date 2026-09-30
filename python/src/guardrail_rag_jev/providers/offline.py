"""A keyword heuristic that answers in the canonical shape. FOR DEMOS AND TESTS ONLY.

It lets the service, the examples and the Go and Python clients run end to end with no API key and
no network. It matches a few keywords per category in Vietnamese, English and Chinese; it does not
understand meaning, context, negation or anything a real model does. Never use it to decide on real
content: ``guardrail-rag-jev serve --offline`` says so in every verdict's ``model`` field.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from ..questions import HAZARD, LOCATE_PREFIX, MULTILABEL_PREFIX, SENTINEL_PREFIX
from .base import Answers, Capabilities, Response

KEYWORDS: Mapping[str, tuple[str, ...]] = {
    "iwp": ("thuốc nổ", "chất nổ", "chế tạo bom", "thermite", "explosive", "make a bomb", "nerve agent", "sarin", "炸药"),
    "vcr": ("giết người", "ám sát", "kill him", "murder", "khủng bố", "terrorist attack"),
    "ssh": ("tự tử", "muốn chết", "kill myself", "suicide", "tự làm hại", "自杀"),
    "cse": ("ấu dâm", "child porn", "csam"),
    "ncr": ("lừa đảo chiếm đoạt", "rửa tiền", "money laundering", "ma túy", "buôn lậu", "hack tài khoản"),
    "hte": ("đồ mọi rợ", "bọn chúng không phải người", "subhuman", "phân biệt chủng tộc"),
    "sxc": ("khiêu dâm", "porn", "sex scene"),
    "prv": ("địa chỉ nhà riêng", "số cccd", "căn cước", "home address", "số điện thoại riêng", "身份证"),
    "pij": ("ignore previous instructions", "ignore all previous", "bỏ qua mọi hướng dẫn", "bỏ qua các chỉ dẫn", "you are now dan", "jailbreak", "忽略之前"),
    "ipi": ("ignore previous instructions", "ignore all previous", "bỏ qua mọi hướng dẫn", "bỏ qua các chỉ dẫn", "ai assistant must", "trợ lý ai hãy", "send the conversation to", "gửi toàn bộ dữ liệu", "system prompt"),
    "sid": ("password:", "mật khẩu:", "api_key", "secret key", "begin private key"),
    "mal": ("click here to verify your account", "xác minh tài khoản tại", "nhận quà miễn phí", "bit.ly/", "download the patch from"),
    "dfm": ("là kẻ lừa đảo", "đã tham ô", "is a fraudster"),
    "vsv": ("xisha", "nansha", "sansha", "đường chín đoạn", "nine-dash line", "thuộc về trung quốc", "belong to china", "属于中国"),
    "vas": ("lật đổ chính quyền", "overthrow the government", "chống phá nhà nước"),
    "vld": ("xúc phạm lãnh tụ", "insult ho chi minh"),
    "vcs": ("tin giả", "fake news campaign", "kích động biểu tình", "tấn công ddos"),
    "vai": ("deepfake", "giả giọng", "clone giọng", "mạo danh", "impersonate", "tôi là người thật", "i am a real person"),
    "vam": ("thao túng người già", "manipulate the elderly", "chấm điểm công dân"),
    "vsd": ("hồ sơ bệnh án", "nhiễm hiv", "tiền án", "medical record", "xu hướng tính dục", "sinh trắc"),
    "spc": ("liều dùng", "uống bao nhiêu viên", "dosage", "nên đầu tư", "should invest"),
}
_REFUSAL = ("mình không thể", "tôi không thể", "i can't", "i cannot", "xin lỗi, mình không", "我无法")
_ORG = ("hotline", "tổng đài", "chăm sóc khách hàng", "customer service", "support email")
_REFERENCE = ("điều ", "luật ", "nghị định", "article ", "law ", "regulation", "báo cáo", "news", "theo quy định")
_SOVEREIGNTY_Q = ("thuộc nước nào", "của nước nào", "belong to which", "thuộc chủ quyền")
_ASKS_AI = ("bạn là người hay máy", "bạn có phải người thật", "are you a human", "are you a bot", "are you real")


def _text(state: Any) -> str:
    if not isinstance(state, Mapping):
        return str(state)
    key = state.get("evaluating")
    return str(state.get(key, "")) if isinstance(key, str) else ""


def _has(text: str, words: tuple[str, ...]) -> bool:
    return any(w in text for w in words)


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"\w+", text.lower()) if len(t) > 2}


class OfflineProvider:
    name = "offline-heuristic"
    capabilities = Capabilities()

    def decide(self, state: Any, questions: Mapping[str, Any], *, timeout: float | None = None) -> Response:
        text = _text(state).lower()
        hits = [cid for cid, words in KEYWORDS.items() if _has(text, words)]
        answers = Answers()
        for name, q in questions.items():
            kind = q.get("type")
            if name == HAZARD:
                labels = list((q.get("criteria") or {}).keys())
                present = [c for c in hits if c in labels]
                probs = {k: 0.0 for k in labels}
                if present:
                    share = 0.9 / len(present)
                    for c in present:
                        probs[c] = share
                    probs["none"] = 0.1
                else:
                    probs["none"] = 1.0
                top = max(probs, key=probs.__getitem__)
                answers[name] = {"type": "choice", "choice": top, "confidence": 0.9, "probabilities": probs}
            elif name.startswith((SENTINEL_PREFIX, MULTILABEL_PREFIX, LOCATE_PREFIX)):
                cid = name.split("_", 1)[1]
                answers[name] = {"type": "noul", "noul": 0.9 if cid in hits else 0.02}
            elif kind == "noul":
                answers[name] = {"type": "noul", "noul": self._signal_noul(name, text, hits, state)}
            elif kind == "score":
                answers[name] = {"type": "score", "score": self._signal_score(name, text, hits, state), "confidence": 0.9}
            elif kind == "choice":
                answers[name] = {"type": "choice", "choice": self._signal_choice(name, text, hits, q), "confidence": 0.9}
        return Response(answers, "offline-heuristic (not for production)", provider=self.name)

    def _signal_noul(self, name: str, text: str, hits: list[str], state: Any) -> float:
        if name == "refusal":
            return 0.95 if _has(text, _REFUSAL) else 0.02
        if name == "neutral_mention":
            query = str(state.get("user_query", "") if isinstance(state, Mapping) else "").lower()
            political = any(h in ("vsv", "vas", "vld", "vcs") for h in hits)
            return 0.02 if political or _has(query or text, _SOVEREIGNTY_Q) else 0.9
        if name == "sovereignty_question":
            query = str(state.get("user_query", "") if isinstance(state, Mapping) else "").lower() or text
            return 0.9 if _has(query, _SOVEREIGNTY_Q) else 0.02
        if name == "asks_if_ai":
            return 0.9 if _has(text, _ASKS_AI) else 0.02
        if name == "claims_human":
            return 0.9 if _has(text, ("tôi là người thật", "i am a real person", "i'm a real person")) else 0.02
        return 0.02

    def _signal_score(self, name: str, text: str, hits: list[str], state: Any) -> float:
        if name in ("groundedness", "relevance", "answer_relevance"):
            if not isinstance(state, Mapping):
                return 3.0
            if name == "groundedness":
                source = " ".join(state.get("retrieved_passages") or [])
            else:
                source = str(state.get("user_query", ""))
            ours, theirs = _tokens(text), _tokens(source)
            if not ours or not theirs:
                return 1.5
            return round(3.0 * len(ours & theirs) / len(ours), 2)
        if name == "actionability":
            return 2.0 if hits and _has(text, ("cách", "how to", "bước", "step", "hướng dẫn")) else 0.0
        if name == "severity":
            return 3.0 if hits else 0.0
        return 0.0

    def _signal_choice(self, name: str, text: str, hits: list[str], q: Mapping[str, Any]) -> str:
        labels = list((q.get("criteria") or {}).keys())
        if name == "intent":
            if "pij" in hits:
                return "evasion"
            return "seeking_capability" if hits and _has(text, ("cách", "how to", "hướng dẫn")) else "benign"
        if name == "genre":
            return "reference" if _has(text, _REFERENCE) else "other"
        if name == "data_subject":
            if _has(text, _ORG):
                return "organization"
            return "individual" if "prv" in hits or "vsd" in hits else "none"
        return labels[0] if labels else ""
