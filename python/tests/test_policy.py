import json
from pathlib import Path

import pytest

from guardrail_rag_jev import Policy
from guardrail_rag_jev.policy import BUNDLED_PACKS, bundled_names

ROOT = Path(__file__).resolve().parents[2]


def test_bundled_policies_match_the_repository_copies():
    """The package ships a copy of policies/; scripts/sync-policies.sh keeps them identical."""
    pkg = ROOT / "python" / "src" / "guardrail_rag_jev" / "policies"
    for src in [ROOT / "policies" / "standard-rag-v1.json", *sorted((ROOT / "policies" / "packs").glob("*.json"))]:
        copy = pkg / src.relative_to(ROOT / "policies")
        assert copy.read_text("utf-8") == src.read_text("utf-8"), f"{copy} is stale: run scripts/sync-policies.sh"


def test_every_bundled_pack_is_listed():
    assert set(BUNDLED_PACKS) | {"standard-rag-v1"} == set(bundled_names())


def test_base_alone_has_no_vietnam_categories():
    p = Policy.compose()
    assert not {"vsv", "vas", "vld", "vcs", "vai", "vam", "vsd"} & set(p.categories)
    assert p.ref.startswith("standard-rag-v1@")


def test_packs_add_their_categories_and_can_be_switched_off(policy):
    assert {"vsv", "vas", "vld", "vcs", "vai", "vam", "vsd"} <= set(policy.categories)
    without_ai = Policy.compose(packs=["vn-cybersecurity", "vn-personal-data"])
    assert "vai" not in without_ai.categories and "vsv" in without_ai.categories
    assert without_ai.fingerprint != policy.fingerprint


def test_list_patches_from_several_packs_accumulate(policy):
    rule = next(r for r in policy.rules if r["id"] == "low-actionability-softens")
    # the base's own exceptions, the cybersecurity pack's and the personal data pack's
    assert {"cse", "ipi", "vsv", "vas", "vld", "vcs", "vsd"} <= set(rule["except_categories"])
    sc = policy.sentinel_corroboration()
    assert {"ssh", "vsv", "vld"} <= sc.weak_except
    assert {"sid", "prv", "vsv", "vsd"} <= sc.refusal_except


def test_all_but_macro_expands_after_every_pack_is_merged(policy):
    rule = next(r for r in policy.rules if r["id"] == "neutral-mention-is-not-a-violation")
    assert "vsv" not in rule["except_categories"] and "iwp" in rule["except_categories"]
    assert "vsd" in rule["except_categories"]  # from a pack merged after this rule's pack


def test_personal_data_pack_patches_the_base_category(policy):
    prv = policy.categories["prv"]
    assert "hotline" in prv.description
    assert any("91/2025" in r for r in prv.refs) and "AILuminate prv" in prv.refs
    assert Policy.compose().categories["prv"].description != prv.description


def test_category_overrides_disable_and_rescale():
    p = Policy.compose(packs=BUNDLED_PACKS, categories={"spc": {"enabled": False}, "hte": {"sensitivity": "strict"}})
    assert not p.categories["spc"].enabled and "spc" not in [c.id for c in p.for_surface("answer")]
    base = Policy.compose(packs=BUNDLED_PACKS).categories["hte"].threshold("query")
    assert p.categories["hte"].threshold("query")["block"] == pytest.approx(base["block"] * 0.7)


def test_unknown_overrides_are_refused():
    with pytest.raises(ValueError, match="unknown categories"):
        Policy.compose(categories={"vsv": {"enabled": False}})  # its pack is off
    with pytest.raises(ValueError, match="sensitivity"):
        Policy.compose(categories={"hte": {"sensitivity": "extreme"}})
    with pytest.raises(ValueError, match="unknown rules"):
        Policy.compose(rules={"nope": {"enabled": False}})


def test_rules_can_be_switched_off():
    p = Policy.compose(rules={"reference-material-softens": {"enabled": False}})
    assert "reference-material-softens" not in [r["id"] for r in p.rules]


def test_non_judged_categories_are_never_asked(policy):
    from guardrail_rag_jev.questions import build_questions

    qs = build_questions(policy, "context", available={"query"})
    assert "acl" not in qs["hazard"]["criteria"] and "m_acl" not in qs
    assert "acl" in [c.id for c in policy.for_surface("context")]


def test_multilabel_asks_every_category_on_document_surfaces(policy):
    from guardrail_rag_jev.questions import build_questions

    ingest = build_questions(policy, "ingest")
    judged = {c.id for c in policy.for_surface("ingest", judged=True)}
    asked = {k[2:] for k in ingest if k[:2] in ("s_", "m_")}
    assert asked == judged
    query = build_questions(policy, "query", available={"query"})
    assert not any(k.startswith("m_") for k in query)  # multi-label is off for queries by default


def test_signals_that_need_a_query_or_passages_are_only_asked_with_them(policy):
    from guardrail_rag_jev.questions import build_questions

    assert "groundedness" not in build_questions(policy, "answer")
    assert "groundedness" in build_questions(policy, "answer", available={"context", "query"})
    assert "relevance" in build_questions(policy, "context", available={"query"})
    assert "relevance" not in build_questions(policy, "context")


def test_packs_declare_their_legal_basis():
    for name in BUNDLED_PACKS:
        data = json.loads((ROOT / "policies" / "packs" / f"{name}.json").read_text("utf-8"))
        assert data["law"]["vi"] and data["law"]["en"] and data["disclaimer"]
