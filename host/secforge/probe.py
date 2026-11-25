"""Boot one built QNX image headless in QEMU, run checks over SSH, report timings.

Usage (Windows prompt, nothing else may be listening on port 2222):
    set PYTHONPATH=host
    python -m secforge.probe C:\\qnxvm-min1

NOT yet tested against a real image. Its purpose is to measure boot time and to
show whether QEMU can run in the background with its serial output in a file.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from typing import Dict, List

SSH_PORT = 2222
DEFAULT_QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
DEFAULT_KEY = os.path.expanduser(os.path.join("~", ".ssh", "id_ed25519"))

# name, command, should_succeed, text that must appear in the output
LEGIT = [
    ("uname", "uname -a", True, "QNX"),
    ("fs_write_read", "echo secforge-probe > /data/sf_probe.txt && cat /data/sf_probe.txt", True, "secforge-probe"),
    ("ls_root", "ls /", True, "data"),
]
ATTACKS = [
    ("on_type_change", "on -T random_t sleep 1", False, "not permitted"),
    ("secpolpush", "/proc/boot/secpolpush", False, "not permitted"),
]


def evaluate(name: str, should_succeed: bool, needle: str, rc: int, output: str) -> Dict:
    """Pure check logic: did this command behave as the policy should make it?"""
    ok_rc = (rc == 0) == should_succeed
    ok_text = needle.lower() in output.lower()
    return {"name": name, "passed": ok_rc and ok_text, "rc": rc,
            "expected_success": should_succeed, "output": output.strip()[:300]}


def port_in_use(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ssh_cmd(key: str, command: str) -> List[str]:
    return ["ssh", "-p", str(SSH_PORT), "-i", key,
            "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-c", "aes128-ctr", "-m", "hmac-sha2-256", "root@127.0.0.1", command]


def run_ssh(key: str, command: str, timeout: int = 30):
    try:
        r = subprocess.run(ssh_cmd(key, command), capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m secforge.probe <image_dir>")
        return 2
    image_dir = os.path.abspath(argv[1])
    qemu = DEFAULT_QEMU if os.path.exists(DEFAULT_QEMU) else shutil.which("qemu-system-x86_64")
    if not qemu:
        print("qemu-system-x86_64 not found")
        return 2
    if port_in_use(SSH_PORT):
        print(f"port {SSH_PORT} is already in use: stop the running VM first")
        return 2
    out = os.path.join(image_dir, "output")
    serial = os.path.join(out, "serial.log")
    if os.path.exists(serial):
        os.remove(serial)
    cmd = [qemu, "-smp", "2", "-cpu", "max", "-m", "1G",
           "-drive", "file=output/disk-qemu.vmdk,if=ide,id=drv0",
           "-kernel", "output/ifs.bin", "-display", "none",
           "-serial", "file:output/serial.log", "-monitor", "none",
           "-object", "rng-builtin,id=rng0", "-device", "virtio-rng-pci,rng=rng0",
           "-netdev", f"user,id=net0,hostfwd=tcp::{SSH_PORT}-:22",
           "-device", "virtio-net-pci,netdev=net0"]
    result: Dict = {"image": image_dir}
    t0 = time.time()
    err = open(os.path.join(out, "qemu-stderr.log"), "w")
    proc = subprocess.Popen(cmd, cwd=image_dir, stdout=subprocess.DEVNULL, stderr=err,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        # 1. wait for the QNX banner in the serial log
        while time.time() - t0 < 240:
            if proc.poll() is not None:
                print("QEMU exited early; see output/qemu-stderr.log")
                return 1
            if os.path.exists(serial) and "Startup complete" in open(serial, errors="replace").read():
                break
            time.sleep(1)
        else:
            print("timeout waiting for Startup complete")
            return 1
        result["boot_seconds"] = round(time.time() - t0, 1)
        # 2. wait until SSH answers
        while time.time() - t0 < 360:
            rc, _ = run_ssh(DEFAULT_KEY, "true", timeout=10)
            if rc == 0:
                break
            time.sleep(2)
        else:
            print("timeout waiting for SSH")
            return 1
        result["ssh_seconds"] = round(time.time() - t0, 1)
        # 3. run the checks
        checks = []
        for name, command, should_succeed, needle in LEGIT + ATTACKS:
            rc, text = run_ssh(DEFAULT_KEY, command)
            checks.append(evaluate(name, should_succeed, needle, rc, text))
        result["checks"] = checks
        result["all_passed"] = all(c["passed"] for c in checks)
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        err.close()
    print(json.dumps(result, indent=2))
    return 0 if result.get("all_passed") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
