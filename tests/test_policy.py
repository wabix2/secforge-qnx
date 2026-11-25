import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "host"))
from secforge.policy import Policy
from secforge.minimize import ddmin

SAMPLE = """\
# header comment
type console_t;
type user_root_t;
allow user_root_t self:ability {
    nonroot
    setuid:0
    fork
    channel_connect:devb_t,devc_pty_t,io_sock_t
    network/jailroot
};
allow_attach devb_t {
    mount:/
    /dev/hd0
};
allow console_t self:ability {
    spawn
    fork
    xprocess_query:20-22,24-25
    channel_connect:devb_t,random_t
    mac_policy
};
# mount_point ... /dev/console;
"""


def labels(p):
    return [a.label() for a in p.atoms]


def test_atom_count_and_splitting():
    p = Policy(SAMPLE)
    # user_root_t: nonroot, setuid:0, fork, 3 channel_connect, network/jailroot = 7
    # console_t: spawn, fork, xprocess_query (1 atom), 2 channel_connect, mac_policy = 6
    assert len(p.atoms) == 13
    assert "console_t mac_policy" in labels(p)
    assert "user_root_t channel_connect:io_sock_t" in labels(p)
    assert "console_t xprocess_query:20-22,24-25" in labels(p)


def test_full_render_keeps_all_permissions():
    p = Policy(SAMPLE)
    again = Policy(p.render())
    assert sorted(labels(again)) == sorted(labels(p))


def test_text_outside_blocks_is_preserved():
    p = Policy(SAMPLE)
    out = p.render(keep=[])
    for line in ["# header comment", "type console_t;", "allow_attach devb_t {",
                 "    mount:/", "# mount_point ... /dev/console;"]:
        assert line in out
    assert "self:ability" not in out          # all blocks dropped


def test_remove_mac_policy_only():
    p = Policy(SAMPLE)
    keep = [a.index for a in p.atoms if a.label() != "console_t mac_policy"]
    out = Policy(p.render(keep))
    assert "console_t mac_policy" not in labels(out)
    assert len(out.atoms) == 12
    assert "mac_policy" not in p.render(keep)


def test_channel_connect_rejoined_after_removal():
    p = Policy(SAMPLE)
    keep = [a.index for a in p.atoms if a.label() != "user_root_t channel_connect:devc_pty_t"]
    out = p.render(keep)
    assert "channel_connect:devb_t,io_sock_t" in out


def test_ddmin_on_atoms_finds_required():
    p = Policy(SAMPLE)
    required = {a.index for a in p.atoms
                if a.label() in ("user_root_t fork", "console_t channel_connect:devb_t")}
    result = ddmin(p.unique_indexes, lambda idx: required.issubset(set(idx)))
    assert set(result) == required


DUP = """\
allow user_root_t self:ability {
    fork
    channel_connect:devb_t
};
allow user_root_t self:ability {
    fork
    channel_connect:devb_t,random_t
};
"""


def test_duplicates_are_one_unit():
    p = Policy(DUP)
    assert len(p.atoms) == 5
    assert len(p.unique_indexes) == 3          # fork, devb_t, random_t
    keep = [i for i in p.unique_indexes if p.atoms[i].label() != "user_root_t fork"]
    out = p.render(keep)
    assert "fork" not in out                   # both copies removed together
    assert "random_t" in out
