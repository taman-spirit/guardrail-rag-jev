"""Command line.

    guardrail-rag-jev serve  --config guardrail.yaml [--host 0.0.0.0 --port 8080] [--offline]
    guardrail-rag-jev check  --surface query --text "..." [--dry-run] [--offline]
    guardrail-rag-jev scan   ./docs  [--glob "*.md"] [--offline]
    guardrail-rag-jev audit  verify
    guardrail-rag-jev policy show

``check`` exits with the decision, so a script can branch on it: 0 pass, 1 redact, 2 review,
3 remove, 4 degraded (the provider was unreachable, so nothing was actually checked).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .config import Config
from .guard import Guard, segment
from .providers.base import Capabilities
from .questions import available_parts, build_questions, build_state

EXIT = {"pass": 0, "redact": 1, "review": 2, "remove": 3}


def _config(args: argparse.Namespace) -> Config:
    cfg = Config.load(args.config)
    if getattr(args, "offline", False):
        cfg.providers["offline"] = {"type": "offline"}
        cfg.provider = "offline"
        cfg.routing = {}
        cfg.shadow.provider = None
    return cfg


def _print(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .server import create_app

    cfg = _config(args)
    if args.offline:
        print("OFFLINE MODE: keyword heuristic, not a real model. Demos and tests only.", file=sys.stderr)
    uvicorn.run(create_app(cfg), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    text = args.text if args.text is not None else Path(args.file).read_text("utf-8")
    cfg = _config(args)
    if args.dry_run:
        cfg.state_path = None
        guard = Guard(cfg, provider=_NoCall())
        stack = guard.stack(args.surface)
        passages = args.context or None
        avail = available_parts(query=args.query, passages=passages) | ({"query"} if args.surface == "query" else set())
        _print({
            "provider": stack.name,
            "policy": stack.policy.ref,
            "state": build_state(args.surface, text, query=args.query, passages=passages),
            "questions": build_questions(stack.policy, args.surface, available=avail),
        })
        return 0
    guard = Guard(cfg)
    if args.surface == "ingest":
        r = guard.check_document(text, doc_id=args.file)
    elif args.surface == "query":
        r = guard.check_query(text)
    elif args.surface == "context":
        ctx = guard.filter_context(args.query, [text])
        r = ctx.results[0]
    else:
        r = guard.check_answer(text, query=args.query, context=args.context)
    _print(r.as_dict())
    return 4 if r.verdict.degraded else EXIT[r.decision]


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = _config(args)
    guard = Guard(cfg)
    root = Path(args.path)
    files = [root] if root.is_file() else sorted(p for p in root.rglob(args.glob) if p.is_file())
    summary: dict[str, int] = {}
    worst = 0
    for path in files:
        text = path.read_text("utf-8", errors="replace")
        chunks = [{"text": text[s:e], "chunk_id": f"{path.name}#{i}"} for i, (s, e) in
                  enumerate(segment(text, min_chars=args.chunk_chars, max_segments=10_000))]
        doc = guard.check_document_chunks(str(path), chunks)
        summary[doc.decision] = summary.get(doc.decision, 0) + 1
        worst = max(worst, EXIT[doc.decision])
        cats = ", ".join(f"{c}×{len(ids)}" for c, ids in doc.violations.items()) or "-"
        print(f"{doc.decision:7} {path}  [{cats}]")
    print(json.dumps({"files": len(files), "decisions": summary}, ensure_ascii=False))
    return worst


def cmd_worker(args: argparse.Namespace) -> int:
    import signal
    import threading

    from .jobs import RedisJobs, run_worker

    guard = Guard(_config(args))
    if not isinstance(guard.jobs, RedisJobs):
        print("worker needs jobs.backend: redis in the config; with the local backend the service runs jobs itself",
              file=sys.stderr)
        return 2
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    done = run_worker(guard, guard.jobs, stop=stop, once=args.once)
    print(json.dumps({"jobs_processed": done}))
    return 0


def _eval_guard(args: argparse.Namespace, cfg: Config):
    from .audit import MemoryAuditLog
    from .evaluate import ReplayProvider, eval_config
    from .providers import RecordingProvider, build_provider
    from .review import ReviewStore

    cfg = eval_config(cfg)
    if args.replay:
        provider: Any = ReplayProvider.load(args.replay)
    else:
        provider = build_provider(cfg.provider, cfg.providers)
    sink: list[dict[str, Any]] = []
    if getattr(args, "record", None):
        provider = RecordingProvider(provider, sink)
    return Guard(cfg, provider=provider, audit=MemoryAuditLog(), reviews=ReviewStore(":memory:")), sink


def cmd_eval(args: argparse.Namespace) -> int:
    from .evaluate import evaluate, format_report, load_cases

    cases = load_cases(args.dataset)
    guard, sink = _eval_guard(args, _config(args))
    report = evaluate(guard, cases)
    if args.record:
        Path(args.record).parent.mkdir(parents=True, exist_ok=True)
        Path(args.record).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in sink), "utf-8")
    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), "utf-8")
    print(format_report(report))
    return 0


def cmd_calibrate(args: argparse.Namespace) -> int:
    from .evaluate import ReplayProvider, calibrate, format_report, load_cases

    cases = load_cases(args.dataset)
    overlay, before, after = calibrate(_config(args), ReplayProvider.load(args.replay), cases,
                                       max_false_hold=args.max_false_hold, name=args.name)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(overlay, ensure_ascii=False, indent=2) + "\n", "utf-8")
    print("== before\n" + format_report(before) + "\n\n== after\n" + format_report(after))
    print(f"\nwrote {args.out}: load it with providers.<name>.calibration")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)
    from .audit import open_audit_log

    log = open_audit_log(cfg.audit.backend, cfg.resolve(cfg.audit.path) or "data/audit.jsonl")
    if args.action == "verify":
        result = log.verify()
        _print(result)
        return 0 if result["ok"] else 1
    _print(log.head())
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    cfg = _config(args)
    guard = Guard(cfg, provider=_NoCall())
    _print(guard.policy.summary())
    return 0


class _NoCall:
    """Stands in for a provider when nothing is sent."""

    name = "none"
    capabilities = Capabilities()

    def decide(self, state, questions, *, timeout=None):  # pragma: no cover - never called
        raise RuntimeError("no provider call expected")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail-rag-jev", description="Content guardrails for RAG systems.")
    parser.add_argument("--config", "-c", help="config file (default: $GUARDRAIL_CONFIG)")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("serve", help="run the HTTP service")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--offline", action="store_true", help="keyword heuristic instead of a model: demos only")
    s.set_defaults(func=cmd_serve)

    c = sub.add_parser("check", help="check one text")
    c.add_argument("--surface", choices=["ingest", "query", "context", "answer"], default="query")
    src = c.add_mutually_exclusive_group(required=True)
    src.add_argument("--text")
    src.add_argument("--file")
    c.add_argument("--query", help="the user query, for context and answer checks")
    c.add_argument("--context", action="append", help="a retrieved passage, for answer checks (repeatable)")
    c.add_argument("--dry-run", action="store_true", help="print the request that would be sent; needs no key")
    c.add_argument("--offline", action="store_true")
    c.set_defaults(func=cmd_check)

    sc = sub.add_parser("scan", help="check every file under a directory as if ingesting it")
    sc.add_argument("path")
    sc.add_argument("--glob", default="*.md")
    sc.add_argument("--chunk-chars", type=int, default=1200)
    sc.add_argument("--offline", action="store_true")
    sc.set_defaults(func=cmd_scan)

    w = sub.add_parser("worker", help="process ingest jobs from Redis (jobs.backend: redis)")
    w.add_argument("--once", action="store_true", help="exit when the queue is empty")
    w.add_argument("--offline", action="store_true")
    w.set_defaults(func=cmd_worker)

    e = sub.add_parser("eval", help="measure the guardrail on labelled cases")
    e.add_argument("--dataset", required=True)
    e.add_argument("--record", help="keep every raw model answer in this JSONL file, for replay and calibration")
    e.add_argument("--replay", help="answer from a recording instead of calling the model")
    e.add_argument("--out", help="write the full report as JSON")
    e.add_argument("--offline", action="store_true")
    e.set_defaults(func=cmd_eval)

    cal = sub.add_parser("calibrate", help="fit per-category threshold factors on a recording")
    cal.add_argument("--dataset", required=True)
    cal.add_argument("--replay", required=True, help="a recording made with eval --record")
    cal.add_argument("--out", required=True, help="the calibration overlay to write")
    cal.add_argument("--name", default="calibration")
    cal.add_argument("--max-false-hold", type=float, default=0.05)
    cal.add_argument("--offline", action="store_true")
    cal.set_defaults(func=cmd_calibrate)

    a = sub.add_parser("audit", help="verify the audit chain or print its head")
    a.add_argument("action", choices=["verify", "head"])
    a.set_defaults(func=cmd_audit)

    p = sub.add_parser("policy", help="print the effective policy")
    p.add_argument("action", choices=["show"])
    p.add_argument("--offline", action="store_true")
    p.set_defaults(func=cmd_policy)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
