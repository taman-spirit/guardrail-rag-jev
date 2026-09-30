"""Guarding a streamed answer: release text only after it is checked, retract when the whole says otherwise.

    stream = guard.answer_stream(query=question, context=passages)
    for token in llm.stream(...):
        for event in stream.feed(token):
            handle(event)
    for event in stream.finish():
        handle(event)

Events:

``release``  checked text the client may show now (masked where needed)
``stop``     a chunk failed its check: show ``text`` (the prewritten reply) and stop the model
``retract``  the complete answer failed the full check after parts were shown: replace everything
             shown with ``text``
``notice``   a notice to show after the answer (disclaimer, AI label, affirmation)
``done``     the full check's result is in ``result``

Chunks are cut at sentence ends once ``chunk_chars`` have accumulated, and each is checked together
with the last ``overlap_chars`` already released, so a harmful sentence split across two chunks is
still read whole. Mid-stream checks ask only the must-not-miss questions; the complete answer gets
the full question set at the end, which is what can retract.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from .types import Result

if TYPE_CHECKING:  # pragma: no cover
    from .guard import Guard

_SENTENCE_END = re.compile(r"[.!?。！？\n](?=\s|$)")


@dataclass(frozen=True, slots=True)
class StreamEvent:
    type: str
    text: str = ""
    result: Result | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "text": self.text}
        if self.result is not None:
            out["result"] = self.result.as_dict()
        return out


class AnswerStream:
    def __init__(
        self,
        guard: "Guard",
        *,
        query: str | None = None,
        context: Sequence[Mapping[str, Any] | str] | None = None,
        language: str | None = None,
        tenant: str | None = None,
        chunk_chars: int = 200,
        overlap_chars: int = 120,
    ) -> None:
        self.guard = guard
        self.query = query
        self.context = list(context or ())
        self.language = language
        self.tenant = tenant
        self.chunk_chars = chunk_chars
        self.overlap_chars = overlap_chars
        self.buffer = ""
        self.original = ""       # everything the model produced
        self.released = ""       # everything the client was allowed to show
        self.stopped = False
        self.finished = False
        self._lock = threading.Lock()

    def feed(self, text: str) -> list[StreamEvent]:
        with self._lock:
            if self.stopped or self.finished:
                return []
            self.original += text
            self.buffer += text
            events: list[StreamEvent] = []
            while len(self.buffer) >= self.chunk_chars:
                cut = _last_sentence_end(self.buffer, self.chunk_chars)
                if cut is None:
                    break
                chunk, self.buffer = self.buffer[:cut], self.buffer[cut:]
                events += self._check_chunk(chunk)
                if self.stopped:
                    break
            return events

    def finish(self) -> list[StreamEvent]:
        with self._lock:
            if self.finished:
                return []
            self.finished = True
            events: list[StreamEvent] = []
            if self.buffer and not self.stopped:
                events += self._check_chunk(self.buffer)
                self.buffer = ""
            if self.stopped:
                return events
            result = self.guard.check_answer(self.original, query=self.query, context=self.context,
                                             language=self.language, tenant=self.tenant)
            if not result.usable:
                events.append(StreamEvent("retract", result.message or "", result))
            else:
                if result.decision == "redact" and result.content != self.released:
                    # The full check masked something the chunk checks let through: replace it all.
                    events.append(StreamEvent("retract", result.content or "", result))
                events += [StreamEvent("notice", n) for n in result.notices]
            events.append(StreamEvent("done", "", result))
            return events

    def _check_chunk(self, chunk: str) -> list[StreamEvent]:
        overlap = self.released[-self.overlap_chars:] if self.overlap_chars else ""
        window = overlap + chunk
        r = self.guard.check_answer(window, query=self.query, language=self.language, tenant=self.tenant, partial=True)
        if not r.usable:
            self.stopped = True
            return [StreamEvent("stop", r.message or "", r)]
        text = chunk
        if r.decision == "redact" and r.content is not None and r.content.startswith(_masked_prefix(r, overlap)):
            text = r.content[len(_masked_prefix(r, overlap)):]
        self.released += text
        return [StreamEvent("release", text)]


def _last_sentence_end(text: str, at_least: int) -> int | None:
    """The end of the last sentence in ``text`` that ends at or after ``at_least`` characters,
    else of the last sentence at all; None when there is no sentence end yet."""
    ends = [m.end() for m in _SENTENCE_END.finditer(text)]
    if not ends:
        return None
    after = [e for e in ends if e >= at_least]
    return after[0] if after else ends[-1]


def _masked_prefix(r: Result, overlap: str) -> str:
    """The overlap as it appears in the masked window (masks shift offsets)."""
    if not overlap:
        return ""
    cut = sum(1 for red in r.redactions if red.end <= len(overlap))
    shift = sum(len(red.replacement) - (red.end - red.start) for red in list(r.redactions)[:cut])
    return (r.content or "")[: len(overlap) + shift]
