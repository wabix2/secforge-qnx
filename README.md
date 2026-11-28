# SecForge-QNX - Harden and Prove

Test-guided least-privilege minimizer for QNX OS 8.0 security policies.

QNX's `secpolgenerate` writes a policy from what a system did while it ran, and
the QNX docs say to review it by hand for permissions a process does not need.
SecForge automates that review: it removes a permission, rebuilds the image,
boots it in QEMU, runs functional checks and attack checks, and keeps the
removal only if everything still passes. The search uses delta debugging (ddmin).

Hackathon: QNX Global Hackathon 2026. Category: Developer Tooling & Host Tools.
Target: QNX SDP 8.0 (QNX Everywhere), QEMU x86_64, Windows host.

## Status
- Works on a real QNX 8.0 image: builds, boots, checks and minimizes automatically.
- Run 1 (28 suspect permissions): 17 removed, 11 required, 59 trials in 7,735 s
  (see `evidence/run1/`). The full generated policy lists 230 permission entries.
- Run 1 had a gap: the serial console was never exercised, so `console_t spawn`
  and `fork` were removed without a check noticing. A console check has been
  added and run 2 (stronger checks) is in progress. Numbers here will be updated.

## What a trial checks
Legitimate: `uname -a`, write and read a file in /data, `ls /`, `pidin ar` sees
sshd, a command typed at the serial console starts a new process.
Attacks that must be denied with "Operation not permitted": `on -T random_t sleep 1`
(change security type) and `secpolpush` (change the enforced policy).
A trial also fails if the policy does not compile, the image does not boot, or
SSH never answers.

## Honest limits
A removal means "unneeded for the tested workload", not "proven unnecessary".
The candidate list (`candidates.txt`) is a shortlist chosen by reading the
policy; each candidate is tested, not assumed. Some kept permissions are required
only because QNX's compiler refuses a type that could switch to another type
holding abilities it lacks (settypeid). See `docs/log.md` for known gaps.

## Requirements (Windows)
- QNX SDP 8.0 from QNX Everywhere (qcc, mkqnximage, secpolcompile)
- QEMU 11 for Windows, Python 3.13, an SSH key (~/.ssh/id_ed25519)
- A helper `C:\qnxvm\env.bat` that runs `qnxsdp-env.bat`, adds QEMU to PATH and
  sets MKFS_PATH (paths are constants in `host/secforge/runner.py` and `probe.py`)
- Port 2222 (SSH) and 5555 (serial) free; run only one VM at a time

## Usage
```
set PYTHONPATH=host
python -m pytest tests
python -m secforge.cli atoms evidence\policies\policy-merged.txt
python -m secforge.trial --policy evidence\policies\policy-merged.txt --workdir C:\qnxwork\t1
python -m secforge.automin --policy evidence\policies\policy-merged.txt --candidates candidates.txt --workdir C:\qnxwork\run2
```
Results are saved after every trial, so an interrupted run resumes when repeated.

## Repository layout
- `host/secforge/policy.py` - parses a policy into removable permissions, renders it back
- `host/secforge/minimize.py` - ddmin core (QNX-independent, unit-tested)
- `host/secforge/runner.py` - one trial: build image with mkqnximage, boot, check
- `host/secforge/probe.py` - headless QEMU boot, SSH and serial-console checks
- `host/secforge/automin.py`, `trial.py`, `cli.py` - command line tools
- `candidates.txt` - permissions to test
- `evidence/policies/` - baseline, generated update and merged policy
- `evidence/run1/` - run 1 result.json, trial log, minimized policy
- `docs/log.md` - engineering log; `docs/evidence-run1.txt`, `docs/evidence-run2.txt`

## License
Apache-2.0 (see LICENSE).
