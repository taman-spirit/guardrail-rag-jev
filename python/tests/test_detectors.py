import pytest

from guardrail_rag_jev import DetectorSet, defang_urls, redact
from guardrail_rag_jev.detectors import DEFAULT_DETECTORS, REGISTRY, luhn

VN = ["vn_cccd", "vn_phone", "vn_bank_account", "vn_passport", "vn_social_insurance", "vn_license_plate"]
ALL = DetectorSet.build([*DEFAULT_DETECTORS, *VN])


def kinds(text):
    return [m.detector for m in ALL.find(text)]


@pytest.mark.parametrize("text,expected", [
    ("CCCD: 001203004567", ["vn_cccd"]),
    ("mã 099203004567", []),                      # province code 099 does not exist
    ("gọi 0912345678", ["vn_phone"]),
    ("gọi +84 912 345 678", ["vn_phone"]),
    ("gọi 0912.345.678", ["vn_phone"]),
    ("tổng đài 1900 1234", []),                   # a business hotline is not a personal number
    ("STK: 0123 4567 8901", ["vn_bank_account"]),
    ("Hộ chiếu số C1234567", ["vn_passport"]),
    ("mã số BHXH 0123456789", ["vn_social_insurance"]),
    ("xe biển 30A-123.45", ["vn_license_plate"]),
    ("thẻ 4111 1111 1111 1111", ["payment_card"]),
    ("thẻ 4111 1111 1111 1112", []),              # fails the Luhn check
    ("mail lan.nguyen@example.com.vn", ["email"]),
    ("key sk-proj-abcdefghijklmnopqrstuvwxyz123456", ["api_key"]),
    ("AKIAABCDEFGHIJKLMNOP", ["api_key"]),
    ("password: hunter2!", ["password"]),
    ("mật khẩu = Abc@12345", ["password"]),
    ("postgres://app:s3cr3t@db:5432/x", ["connection_string"]),
    ("ok​​​hidden", ["hidden_unicode"]),
    ("tag\U000e0069\U000e0067\U000e006e", ["hidden_unicode"]),
])
def test_detectors(text, expected):
    assert kinds(text) == expected


def test_only_the_sensitive_group_is_masked_and_offsets_refer_to_the_original():
    text = "STK: 0123456789 tại VCB, password: hunter2"
    masked, reds = redact(text, ALL.find(text))
    assert masked == "STK: [BANK_ACCOUNT] tại VCB, password: [PASSWORD]"
    assert text[reds[0].start:reds[0].end] == "0123456789"


def test_hidden_characters_are_removed_not_labelled():
    text = "Hướng dẫn​​​⁣ sử dụng"
    masked, _ = redact(text, ALL.find(text))
    assert masked == "Hướng dẫn sử dụng"


def test_defang():
    out, n = defang_urls("Xác minh tại https://evil.example.com/login?x=1 ngay")
    assert n == 1 and out == "Xác minh tại hxxps://evil[.]example[.]com/login?x=1 ngay"


def test_config_can_disable_and_retune_detectors():
    ds = DetectorSet.build(["email", "vn_phone"], disabled=["email"], actions={"vn_phone": "flag"})
    assert [d.name for d in ds.detectors] == ["vn_phone"] and ds.action_of("vn_phone") == "flag"
    with pytest.raises(ValueError, match="unknown detector"):
        DetectorSet.build(["nope"])


def test_patterns_need_a_category_to_deny():
    with pytest.raises(ValueError, match="needs a category"):
        DetectorSet.build([], patterns=[{"name": "x", "regex": "x"}])


def test_luhn():
    assert luhn("4111111111111111") and not luhn("4111111111111112") and not luhn("123")


def test_every_detector_names_a_known_category_and_label():
    for d in REGISTRY.values():
        assert d.category in {"prv", "sid", "ipi"} and d.description
