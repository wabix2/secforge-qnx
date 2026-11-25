import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "host"))
import pytest
from secforge.policy import Policy
from secforge.automin import select_candidates, minimize_policy
from secforge.runner import build_command, sha256

SAMPLE = """\
type console_t;
allow console_t self:ability {
    spawn
    fork
    mac_policy
    channel_connect:devb_t,random_t
};
allow sshd_t self:ability {
    nonroot
    chroot:0
};
"""


def labels_in(text):
    return {a.label() for a in Policy(text).atoms}


def test_select_candidates_and_missing_label():
    p = Policy(SAMPLE)
    idx = select_candidates(p, ["console_t mac_policy", "sshd_t chroot:0"])
    assert [p.atoms[i].label() for i in idx] == ["console_t mac_policy", "sshd_t chroot:0"]
    with pytest.raises(ValueError):
        select_candidates(p, ["console_t nonexistent"])


def test_minimize_removes_only_unneeded_candidates():
    p = Policy(SAMPLE)
    cands = select_candidates(p, ["console_t mac_policy", "console_t spawn", "sshd_t chroot:0"])
    needed = {"sshd_t chroot:0", "console_t channel_connect:devb_t"}   # chroot is a candidate
    calls = []

    def passes(text):
        calls.append(text)
        return needed.issubset(labels_in(text))

    keep = minimize_policy(p, cands, passes)
    assert [p.atoms[i].label() for i in keep] == ["sshd_t chroot:0"]
    assert len(calls) < 2 ** len(cands)


def test_fixed_atoms_are_never_removed():
    p = Policy(SAMPLE)
    cands = select_candidates(p, ["console_t mac_policy"])
    seen = []
    minimize_policy(p, cands, lambda t: seen.append(labels_in(t)) or True)
    assert all("sshd_t nonroot" in s and "console_t fork" in s for s in seen)


def test_build_command_shape():
    cmd = build_command(r"C:\work\policies\trial-001.txt")
    assert cmd.startswith('call "C:\\qnxvm\\env.bat" && mkqnximage')
    assert "--policy=C:/work/policies/trial-001.txt" in cmd
    assert "--secpol=secure" in cmd and cmd.endswith("--build")
    assert "--clean" in cmd and "--noprompt" in cmd


def test_sha256_is_stable():
    assert sha256("a") == sha256("a") != sha256("b")
