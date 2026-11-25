"""One trial = write a policy, build a QNX image with it, boot it, run the checks.

Not yet tested against a real build: build_command() and the result handling are
unit-tested, the mkqnximage call itself is the thing to verify on the first run.
"""
import hashlib
import os
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import Optional

from secforge import probe

ENV_BAT = r"C:\qnxvm\env.bat"                      # sets up the QNX tools and QEMU on PATH
SSH_PUB = "C:/Users/Admin/.ssh/id_ed25519.pub"     # forward slashes: mkqnximage drops backslashes


@dataclass
class TrialResult:
    passed: bool
    stage: str                      # build | setup | boot | ssh | checks
    policy_sha256: str
    build_seconds: float = 0.0
    boot_seconds: Optional[float] = None
    ssh_seconds: Optional[float] = None
    total_seconds: float = 0.0
    detail: str = ""

    def to_dict(self):
        return asdict(self)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_command(policy_file: str, env_bat: str = ENV_BAT, ssh_pub: str = SSH_PUB,
                  clean: bool = True, force: bool = False) -> str:
    pol = policy_file.replace("\\", "/")
    parts = ["mkqnximage", "--type=qemu", "--cpu=2", "--ram=1G", "--secpol=secure",
             f"--policy={pol}", f"--ssh-ident={ssh_pub}", "--noprompt"]
    if clean:
        parts.append("--clean")
    if force:
        parts.append("--force")
    parts.append("--build")
    return f'call "{env_bat}" && ' + " ".join(parts)


def run_trial(policy_text: str, workdir: str, name: str, clean: bool = True) -> TrialResult:
    """Policies are written to <workdir>/policies, images built in <workdir>/img."""
    t_start = time.time()
    digest = sha256(policy_text)
    pol_dir = os.path.join(workdir, "policies")
    img_dir = os.path.join(workdir, "img")
    os.makedirs(pol_dir, exist_ok=True)
    os.makedirs(img_dir, exist_ok=True)
    policy_file = os.path.abspath(os.path.join(pol_dir, f"{name}.txt"))
    with open(policy_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(policy_text)

    t0 = time.time()
    try:
        r = subprocess.run(build_command(policy_file, clean=clean), shell=True, cwd=img_dir,
                           capture_output=True, text=True, timeout=900)
        build_out = (r.stdout or "") + (r.stderr or "")
        built = r.returncode == 0 and os.path.exists(os.path.join(img_dir, "output", "ifs.bin"))
    except subprocess.TimeoutExpired:
        build_out, built = "mkqnximage timed out", False
    build_s = round(time.time() - t0, 1)
    if not built:
        return TrialResult(False, "build", digest, build_s,
                           total_seconds=round(time.time() - t_start, 1), detail=build_out[-800:])

    res = probe.probe_image(img_dir)
    failed = [c["name"] for c in res.get("checks", []) if not c["passed"]]
    detail = res.get("error", "") or ("failed checks: " + ", ".join(failed) if failed else "")
    if "Compiling policy" not in build_out:
        detail = (detail + " ").lstrip() + "[warning: build log has no 'Compiling policy' line, policy may be stale]"
    return TrialResult(bool(res.get("all_passed")), res.get("stage", "checks"), digest, build_s,
                       res.get("boot_seconds"), res.get("ssh_seconds"),
                       round(time.time() - t_start, 1), detail)
