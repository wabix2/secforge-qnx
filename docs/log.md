# Engineering log - SecForge-QNX

Sources for the dates: file timestamps, Git history and session notes.
A line ending in [confirm date] has a date I could not verify: check it with
`dir /ad /t:c C:\` (folder creation dates) or `git log --date=short --format="%ad %h %s"`,
fix the date if needed, then delete the marker.

## 2026-11-14
- Chose the project: SecForge-QNX ("Harden and Prove") for the QNX Global Hackathon 2026, category Developer Tooling & Host Tools.
- Wrote the QNX-independent ddmin minimizer (host/secforge/minimize.py) with unit tests.

## 2026-11-15
- Installed QNX SDP 8.0 with QNX Software Center (folder C:\Users\Admin\qnx800, 8.0.6 packages, env script qnxsdp-env.bat).

## 2026-11-17
- Installed QEMU 11.1.0 for Windows. [confirm date]
- Built a QNX 8.0 x86_64 image with mkqnximage and booted it in QEMU on Windows 10 (uname, pidin worked). [confirm date]
- Windows workarounds:
  - mkqnximage's generated QEMU command fails on Windows (rng-random): run QEMU myself with -object rng-builtin,id=rng0.
  - Networking: -netdev user,id=net0,hostfwd=tcp::2222-:22 and -device virtio-net-pci,netdev=net0.
  - SSH to the VM needs -c aes128-ctr -m hmac-sha2-256, otherwise "Corrupted MAC".
  - mkqnximage --ssh-ident needs forward slashes (C:/Users/...), backslashes are dropped.
- Built an open-mode image (--secpol=open). Boot log shows "Starting policy generator"; secpolgenerate runs with -t 100 -S -c -s options from /proc/boot/secpolgen_start.sh.
- Retrieved the generated policy over SSH with `ssh ... cat /dev/secpolgenerate/policy` (73 lines). Baseline policy: 487 lines. Do not use scp for this: the QNX docs say scp copies only the stat() size and secpolgenerate has no meaningful file size.
- secpolcompile accepted baseline + generated update (merged) with no errors. A compile with -p dc9c713a was rejected ("invalid policy id"); not needed, so not investigated.
- Built a secure-mode image (--secpol=secure --policy=policy-merged.txt).
- Parked, not needed for the core loop: secpolmonitor trace-logger errors, secpolpush use, dumper_t access to /dev/slog2.

## 2026-11-18 to 2026-11-20 (exact days to confirm)
- Secure image booted; SSH worked; no secpolgenerate process, /dev/secpolgenerate absent, secpol -v: 4 blobs OK. [confirm date]
- Enforcement evidence (docs/evidence-run1.txt): `on -T random_t sleep 1` and `secpolpush` are denied in the secure image and allowed in the open image (serial console). Legitimate commands work. [confirm date]
- First manual minimization (docs/evidence-run2.txt): removed `mac_policy` from the generated console_t rule; rebuild took 70 s; image booted; console `secpolpush` changed from "File exists" to "Operation not permitted". [confirm date]
- Build lessons:
  - Stop QEMU before rebuilding, or "output/disk-qemu: Device or resource busy".
  - If output/ifs.bin fails to write, delete the stale file and rebuild.
  - Set MKFS_PATH to the target/qnx/x86_64 folders so mkifs finds multiboot.boot.
  - find.exe on this PC is not the Windows one: use PowerShell (Get-Content f).Count.
  - QNX commands go in the SSH or QEMU window (prompt "#"), Windows commands in a Windows prompt.

## 2026-11-20
- Created the public GitHub repo wabix2/secforge-qnx and pushed the first commit; added the Apache-2.0 LICENSE and evidence-run2.txt.

## 2026-11-21
- Wrote the policy parser (host/secforge/policy.py: splits `allow <type> self:ability {...}` blocks into removable permissions, deduplicates repeats), the atoms CLI and the headless probe (host/secforge/probe.py).

## 2026-11-25
- Registered for the hackathon on Devpost.
- Ran the probe on the reduced image: boot 46.9 s, SSH after 57.4 s, 5 of 5 checks passed.
- Single trials with the runner: full policy 86 s, policy without mac_policy 53 s (rebuild in the same folder picked up the new policy).
- Added the trial runner, minimizer driver (automin) and the 28-permission candidates list; pushed.
- Run 1 of the automated minimizer (workdir C:\qnxwork\run1): 59 trials in 7,735 s. 17 of 28 candidates removed, 11 required. 9 trials passed, 12 were rejected at build time by the QNX policy compiler, 38 booted but SSH never answered (about 180 s each). Saved to evidence/run1/.
- The final run-1 policy was an actual passing trial, and each of the 11 single removals failed afterwards.

## 2026-11-28
- Power cut during evidence copying; files re-copied and checked, nothing lost.
- Found a gap in run 1: console_t spawn and fork were removed, but no check used the serial console, so nothing noticed. Added a console check (types /proc/boot/echo SFCON$((20+22)) at the serial console and expects SFCON42) and shortened the boot and SSH timeouts to 60 s and 75 s.
- Verified the new check passes on the full policy (trial total 112 s).
- Started run 2 with the stronger checks (workdir C:\qnxwork\run2). In progress.

## Status
| Item | State |
|---|---|
| QNX 8.0 images build and boot (open and secure) in QEMU on Windows | Done |
| Policy parser, ddmin minimizer, trial runner, headless probe | Done, 22 tests pass |
| Run 1 (SSH-only checks) | Done: 17 of 28 suspects removable; console gap found |
| Run 2 (adds serial console check) | In progress |
| Minimized policy re-verified several times | Not yet |
| HTML before/after report | Not started |
| README final numbers | After run 2 |
| Demo video, Devpost text | Not started (freeze Dec 10, submit by Dec 14) |

## Known limits
- A removal means "unneeded for the tested workload" (boot, SSH login, file write and read, ls, pidin, serial console command, two denied attacks), not "proven unnecessary".
- qconn_t debug permissions were removed in run 1: remote debugging through qconn is not tested.
- The candidate list is a shortlist chosen by reading the policy, not the whole policy.
