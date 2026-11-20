import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "host"))
import pytest
from secforge.minimize import ddmin


def make_oracle(required):
    def oracle(rules):
        return required.issubset(set(rules))
    return oracle


def test_finds_required_rules_only():
    rules = [f"r{i}" for i in range(20)]
    required = {"r3", "r11", "r17"}
    assert set(ddmin(rules, make_oracle(required))) == required


def test_deterministic():
    rules = [f"r{i}" for i in range(30)]
    required = {"r0", "r29"}
    assert ddmin(rules, make_oracle(required)) == ddmin(rules, make_oracle(required))


def test_single_required():
    assert ddmin(list("abcdefgh"), make_oracle({"e"})) == ["e"]


def test_everything_required():
    rules = list("abcd")
    assert ddmin(rules, make_oracle(set(rules))) == rules


def test_rejects_failing_baseline():
    with pytest.raises(ValueError):
        ddmin(["a", "b"], lambda r: False)
