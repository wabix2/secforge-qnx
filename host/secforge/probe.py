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
BOOT_TIMEOUT = 120
SSH_TIMEOUT = 150

# name, command, should_succeed, text that must appear in the output
LEGIT = [
    ("uname", "uname -a", True, "QNX"),
    ("fs_write_read", "echo secforge-probe > /data/sf_probe.txt && cat /data/sf_probe.txt", True, "secforge-probe"),
    ("ls_root", "ls /", True, "data"),
    # needs the process-query permission: the SSH shell must be able to see other services
    ("pidin_sees_services", "pidin ar", True, "sshd"),
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
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
            "-c", "aes128-ctr", "-m", "hmac-sha2-256", "root@127.0.0.1", command]


def run_ssh(key: str, command: str, timeout: int = 30):
    try:
        r = subprocess.run(ssh_cmd(key, command), capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def probe_image(image_dir: str, key: str = DEFAULT_KEY) -> Dict:
    """Boot the image headless, run LEGIT + ATTACKS over SSH, return a result dict.

    On failure the dict has "error" and "stage" ("setup", "boot", "ssh"); it never
    raises for boot or SSH problems, so a caller can treat them as a failed trial."""
    image_dir = os.path.abspath(image_dir)
    qemu = DEFAULT_QEMU if os.path.exists(DEFAULT_QEMU) else shutil.which("qemu-system-x86_64")
    result: Dict = {"image": image_dir, "all_passed": False}
    if not qemu:
        return {**result, "stage": "setup", "error": "qemu-system-x86_64 not found"}
    if port_in_use(SSH_PORT):
        return {**result, "stage": "setup",
                "error": f"port {SSH_PORT} in use: stop the running VM first"}
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
    t0 = time.time()
    err = open(os.path.join(out, "qemu-stderr.log"), "w")
    proc = subprocess.Popen(cmd, cwd=image_dir, stdout=subprocess.DEVNULL, stderr=err,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        while True:
            if time.time() - t0 > BOOT_TIMEOUT:
                return {**result, "stage": "boot", "error": "timeout waiting for Startup complete"}
            if proc.poll() is not None:
                return {**result, "stage": "boot", "error": "QEMU exited early"}
            if os.path.exists(serial) and "Startup complete" in open(serial, errors="replace").read():
                break
            time.sleep(1)
        result["boot_seconds"] = round(time.time() - t0, 1)
        while True:
            if time.time() - t0 > SSH_TIMEOUT:
                return {**result, "stage": "ssh", "error": "timeout waiting for SSH"}
            rc, _ = run_ssh(key, "true", timeout=10)
            if rc == 0:
                break
            time.sleep(2)
        result["ssh_seconds"] = round(time.time() - t0, 1)
        checks = []
        for name, command, should_succeed, needle in LEGIT + ATTACKS:
            rc, text = run_ssh(key, command)
            checks.append(evaluate(name, should_succeed, needle, rc, text))
        result["checks"] = checks
        result["all_passed"] = all(c["passed"] for c in checks)
        result["stage"] = "checks"
        return result
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(10)
        err.close()


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m secforge.probe <image_dir>")
        return 2
    result = probe_image(argv[1])
    print(json.dumps(result, indent=2))
    return 0 if result.get("all_passed") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
