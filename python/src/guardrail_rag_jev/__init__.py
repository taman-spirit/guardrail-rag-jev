"""guardrail-rag-jev: content guardrails for RAG systems.

Four checkpoints (ingest, query, context, answer), one policy with toggleable Viet Nam law packs,
a pluggable judging model (TypeSafe Jev by default), a review queue and a tamper-evident audit log.

    from guardrail_rag_jev import Guard

    guard = Guard.from_config("guardrail.yaml")
    result = guard.check_document(text, doc_id="handbook.pdf", chunk_id="p3-2")
    if result.usable:
        index(result.content, metadata=result.metadata)
"""

from .audit import JsonlAuditLog, MemoryAuditLog, SqliteAuditLog, content_hash, open_audit_log
from .cache import LRUCache
from .config import Config, SurfaceEnforcement
from .detectors import REGISTRY as DETECTORS, DetectorSet, defang_urls, redact
from .guard import Guard, residency_of, segment
from .i18n import Responder, detect_language
from .policy import BASE, BUNDLED_PACKS, Policy, bundled_names
from .providers import (
    CallableProvider,
    Capabilities,
    FallbackProvider,
    JevProvider,
    LLMJudgeProvider,
    Normalizing,
    OfflineProvider,
    OpenAIDecisionsProvider,
    Provider,
    ProviderError,
    RecordedProvider,
    RecordingProvider,
    ShadowProvider,
    build_provider,
)
from .review import ReviewStore, verify_signature
from .types import (
    ContextResult,
    Decision,
    DocumentResult,
    Finding,
    GuardrailError,
    Location,
    Redaction,
    Result,
    Surface,
    SURFACES,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "BASE", "BUNDLED_PACKS", "CallableProvider", "Capabilities", "Config", "ContextResult", "DETECTORS", "Decision",
    "DetectorSet", "DocumentResult", "FallbackProvider", "Finding", "Guard", "GuardrailError", "JevProvider",
    "JsonlAuditLog", "LLMJudgeProvider", "LRUCache", "Location", "MemoryAuditLog", "Normalizing", "OfflineProvider",
    "OpenAIDecisionsProvider", "Policy", "Provider", "ProviderError", "RecordedProvider", "RecordingProvider",
    "Redaction", "Responder", "Result", "ReviewStore", "SURFACES", "ShadowProvider", "SqliteAuditLog", "Surface",
    "SurfaceEnforcement", "Verdict", "build_provider", "bundled_names", "content_hash", "defang_urls",
    "detect_language", "open_audit_log", "redact", "residency_of", "segment", "verify_signature", "__version__",
]
