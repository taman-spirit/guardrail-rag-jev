"""Evaluation on labelled cases, recording and replay, and threshold calibration."""

import json
from pathlib import Path

from guardrail_rag_jev import Config, Guard, RecordingProvider
from guardrail_rag_jev.evaluate import ReplayProvider, calibrate, eval_config, evaluate, load_cases
from guardrail_rag_jev.audit import MemoryAuditLog
from guardrail_rag_jev.review import ReviewStore

from conftest import scripted

ROOT = Path(__file__).resolve().parents[2]


def cases():
    harmful = [{"id": f"h{i}", "surface": "ingest", "text": f"PROPAGANDA-WEAK {i}", "expect": {"usable": False, "categories": ["vas"]}} for i in range(4)]
    harmless = [{"id": f"b{i}", "surface": "ingest", "text": f"NEWS {i}", "expect": {"usable": True, "categories": []}} for i in range(6)]
    return harmful + harmless


# The model is sure enough to notice, not to cross the shipped review band (0.30): a threshold question.
TABLE = {"PROPAGANDA-WEAK": {"vas": 0.26}, "NEWS": {"vas": 0.08}}


def record(tmp_path):
    sink = []
    guard = Guard(eval_config(Config()), provider=RecordingProvider(scripted(TABLE), sink), audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"))
    before = evaluate(guard, cases())
    path = tmp_path / "rec.jsonl"
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in sink))
    return before, path


def test_evaluate_reports_accuracy_false_holds_and_per_category(tmp_path):
    before, _ = record(tmp_path)
    assert before["catch_rate"] == 0.0 and before["false_hold_rate"] == 0.0
    assert before["categories"]["vas"] == {"tp": 4, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0}  # seen at flag
    assert {f["id"] for f in before["failures"]} == {"h0", "h1", "h2", "h3"}


def test_replay_answers_without_the_model_and_calibration_lowers_the_right_band(tmp_path):
    before, path = record(tmp_path)
    replay = ReplayProvider.load(path)
    again = evaluate(Guard.for_testing(replay, eval_config(Config())), cases())
    assert again["decision_accuracy"] == before["decision_accuracy"]
    overlay, base, after = calibrate(Config(), replay, cases(), max_false_hold=0.0)
    assert after["catch_rate"] == 1.0 and after["false_hold_rate"] == 0.0
    assert list(overlay["categories"]) == ["vas"]
    assert overlay["categories"]["vas"]["thresholds"]["default"]["review"] <= 0.26
    # the overlay loads as a provider calibration
    cfg = Config.from_dict({"providers": {"jev": {"type": "jev", "calibration": str(tmp_path / "cal.json")}}, "state_path": None})
    (tmp_path / "cal.json").write_text(json.dumps(overlay))
    calibrated = Guard(cfg, provider=scripted(TABLE), audit=MemoryAuditLog(), reviews=ReviewStore(":memory:"))
    assert calibrated.check_document("PROPAGANDA-WEAK x").decision == "review"
    assert calibrated.check_document("NEWS x").decision == "pass"


def test_the_shipped_dataset_is_well_formed():
    data = load_cases(ROOT / "datasets" / "vi-rag-v1.jsonl")
    assert len(data) >= 40 and len({c["id"] for c in data}) == len(data)
    from guardrail_rag_jev import Policy
    from guardrail_rag_jev.policy import BUNDLED_PACKS

    known = set(Policy.compose(packs=BUNDLED_PACKS).categories)
    assert all(set(c["expect"]["categories"]) <= known for c in data)
    assert {c["surface"] for c in data} == {"ingest", "query", "context", "answer"}
    assert sum(len(c["expect"]["categories"]) > 1 for c in data) >= 1  # at least one multi-violation case


def test_eval_cli_offline_records_and_replays(tmp_path, monkeypatch, capsys):
    from guardrail_rag_jev.cli import main

    monkeypatch.chdir(tmp_path)
    ds = str(ROOT / "datasets" / "vi-rag-v1.jsonl")
    assert main(["eval", "--offline", "--dataset", ds, "--record", "rec.jsonl", "--out", "r1.json"]) == 0
    assert main(["eval", "--dataset", ds, "--replay", "rec.jsonl", "--out", "r2.json"]) == 0
    r1, r2 = (json.loads((tmp_path / f).read_text()) for f in ("r1.json", "r2.json"))
    assert r1["decision_accuracy"] == r2["decision_accuracy"] and r1["cases"] == 48
    assert main(["calibrate", "--dataset", ds, "--replay", "rec.jsonl", "--out", "cal.json"]) == 0
    assert json.loads((tmp_path / "cal.json").read_text())["id"] == "calibration"
