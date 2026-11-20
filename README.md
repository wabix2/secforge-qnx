# SecForge-QNX — Harden and Prove

Host tool that takes a `secpolgenerate`-produced security policy for a QNX OS 8.0
image, removes every rule the workload does not need (delta debugging), and proves
a planted "attacker" process is blocked under the minimized policy.

Status: day 0 scaffold. Nothing here has been run on QNX yet.

Target: QNX SDP 8.0 (QNX Everywhere), QEMU x86_64, qcc toolchain.
Category: Developer Tooling & Host Tools.

## Layout
- `host/secforge/minimize.py` — ddmin core, QNX-independent, unit-tested
- `tests/` — run with `python -m pytest tests`
- `target/` — tiny C demo workload + attacker (to be written after day-2 tests)
- `scripts/` — build/boot/run helpers (to be written)
- `docs/day1-checklist.md` — what to prove first

## License
Add an open-source license file (e.g. Apache-2.0) at the repo root before the first push.
