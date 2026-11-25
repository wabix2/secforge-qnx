import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "host"))
from secforge.probe import evaluate


def test_legit_command_passes():
    r = evaluate("uname", True, "QNX", 0, "QNX noname 8.0.0")
    assert r["passed"]


def test_legit_command_fails_on_nonzero_exit():
    assert not evaluate("uname", True, "QNX", 1, "QNX noname")["passed"]


def test_attack_denied_passes():
    r = evaluate("on", False, "not permitted", 1, "on: Operation not permitted (sleep)")
    assert r["passed"]


def test_attack_that_succeeds_fails():
    assert not evaluate("on", False, "not permitted", 0, "")["passed"]


def test_denied_for_wrong_reason_fails():
    # nonzero exit but no permission error text: not evidence of the policy
    assert not evaluate("on", False, "not permitted", 1, "No such file or directory")["passed"]
