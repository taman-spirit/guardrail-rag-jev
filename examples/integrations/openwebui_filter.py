"""
title: guardrail-rag-jev
description: Checks the user query, the retrieved passages and the answer with the guardrail service.
requirements: requests
version: 0.1.0

An Open WebUI Filter Function (Admin Panel -> Functions -> + -> paste this file).

inlet:  the latest user message goes through /v1/query; a withheld query is replaced by an
        instruction to reply with the prewritten message. Retrieved passages that Open WebUI has put
        into the body (``files`` / ``sources``) go through /v1/context where present.
outlet: the assistant's last message goes through /v1/answer and is replaced by what to show.
"""

from __future__ import annotations

from typing import Optional

import requests
from pydantic import BaseModel, Field


class Filter:
    class Valves(BaseModel):
        guardrail_url: str = Field(default="http://guardrail:8080", description="The guardrail service")
        api_key: str = Field(default="", description="A client key")
        tenant: str = Field(default="open-webui")
        timeout: float = Field(default=5.0)

    def __init__(self) -> None:
        self.valves = self.Valves()

    def _post(self, path: str, body: dict) -> dict:
        headers = {"X-Guardrail-Tenant": self.valves.tenant}
        if self.valves.api_key:
            headers["Authorization"] = f"Bearer {self.valves.api_key}"
        resp = requests.post(self.valves.guardrail_url.rstrip("/") + path, json=body, headers=headers, timeout=self.valves.timeout)
        resp.raise_for_status()
        return resp.json()

    def inlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        messages = body.get("messages") or []
        last = next((m for m in reversed(messages) if m.get("role") == "user"), None)
        if not last or not isinstance(last.get("content"), str):
            return body
        result = self._post("/v1/query", {"query": last["content"], "user_id": (__user__ or {}).get("id")})
        if result["decision"] == "redact":
            last["content"] = result["content"]
        elif not result["usable"]:
            # The model is asked to repeat the prewritten reply instead of answering.
            last["content"] = "Reply with exactly this text and nothing else:\n\n" + (result.get("message") or "")
        return body

    def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        messages = body.get("messages") or []
        question = next((m.get("content") for m in reversed(messages) if m.get("role") == "user"), None)
        answer = next((m for m in reversed(messages) if m.get("role") == "assistant"), None)
        if not answer or not isinstance(answer.get("content"), str):
            return body
        passages = [s.get("document", [""])[0] if isinstance(s.get("document"), list) else str(s.get("document", ""))
                    for s in body.get("sources") or []]
        result = self._post("/v1/answer", {"answer": answer["content"], "query": question if isinstance(question, str) else None,
                                           "context": [p for p in passages if p]})
        if result["usable"]:
            answer["content"] = "\n\n".join([result["content"] or "", *result.get("notices", [])])
        else:
            answer["content"] = result.get("message") or ""
        return body
