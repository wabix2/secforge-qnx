# Engineering log

## 2026-11-17
- QNX SDP 8.0 installed at C:\Users\Admin\qnx800 (8.0.6 packages)
- QEMU 11.1.0 for Windows installed
- Built a QNX 8.0 x86_64 image with mkqnximage and booted it (uname, pidin OK)
- Windows fixes: QEMU rng-builtin instead of rng-random; virtio-net with hostfwd 2222->22; SSH needs -c aes128-ctr -m hmac-sha2-256 (otherwise "Corrupted MAC")
- SSH to root@127.0.0.1:2222 works 
Open-mode (--secpol=open) image built and booted; secpolgenerate running; security types visible via pidin -f an_
- Open-mode QNX image built and booted successfully.
- secpolgenerate confirmed running.
- Security types inspected using pidin -f an_.
- Generated policy retrieved through SSH from /dev/secpolgenerate/policy.
- Captured baseline policy: 487 lines.
- Secure-mode compilation and enforcement not yet tested.
- Secure-mode QNX 8.0 image built successfully.
- Secure image booted successfully with original generated policy.
- Startup complete; networking and SSH started.
- SSH login verified under secure mode.
- pidin -f an_ confirmed process security types.
- /proc/boot/secpol.bin confirmed present (6,560 bytes).
- Actual unauthorized-access denial not yet demonstrated.
  


  # QNX Security Policy Development Log

## Tuesday, November 17, 2026

**Project:** QNX 8.0 Security Policy Generation, Compilation and Enforcement  
**Platform:** Windows + QNX SDP 8.0 + QEMU  
**Architecture:** x86_64  
**Development stage:** Open-mode policy generation → policy compilation → secure-mode image build

---

## 1. Objectives for the day

The primary objective was to advance the QNX security-policy development workflow from policy generation to secure-mode image construction.

The planned five-test workflow was:

1. Build and boot an open-mode QNX image.
2. Retrieve the generated security policy from the running VM.
3. Compile and validate the policy.
4. Build and boot a secure-mode QNX image.
5. Verify that legitimate operations succeed while unauthorized operations are denied.

The main focus for Tuesday was completing the policy retrieval and compilation stages and producing a separate secure-mode image.

---

## 2. Environment and working directories

### Development environment

| Component | Configuration |
|---|---|
| Host OS | Windows |
| QNX version | QNX SDP 8.0 |
| Architecture | x86_64 |
| Virtualization | QEMU |
| CPUs | 2 |
| RAM | 1 GB |
| SSH forwarding | Host 2222 → Guest 22 |

### Important paths

QNX installation:

`C:\Users\Admin\qnx800`

Original open-mode workspace:

`C:\qnxvm-secpol-secpolgen`

Policy files:

`C:\qnxvm-secpol`

New secure-mode workspace:

`C:\qnxvm-secure`

SSH private key:

`C:\Users\Admin\.ssh\id_ed25519`

SSH public key:

`C:\Users\Admin\.ssh\id_ed25519.pub`

---

## 3. Verified the generated policy retrieval

**Time:** Approximately 15:30–15:32 UTC

The open-mode QNX VM was still running, and the policy generator was active.

The generator process had previously been identified as:

```sh
secpolgenerate -vl -t 100 -S /data/var/secpol/secpol.bin -c /data/var/secpol/config -s /data/var/secpol/saved-state
```

We had already exercised normal system operations, including:

```sh
uname -a
pidin ar
ls /
```

These commands completed successfully.

### Retrieved the generated policy over SSH

The Windows command used was:

```cmd
ssh -p 2222 -i C:\Users\Admin\.ssh\id_ed25519 -o StrictHostKeyChecking=no -c aes128-ctr -m hmac-sha2-256 root@127.0.0.1 "cat /dev/secpolgenerate/policy" > C:\qnxvm-secpol\policy-run2.txt
```

The retrieval was successful.

We initially attempted to count lines using:

```cmd
find /c /v "" < C:\qnxvm-secpol\policy-run2.txt
```

This failed because Windows resolved a Unix-like `find` executable instead of the Windows utility.

Error:

```text
find: '/c': No such file or directory
find: '/v': No such file or directory
find: '': No such file or directory
```

We used PowerShell instead:

```cmd
powershell -NoProfile -Command "$p='C:\qnxvm-secpol\policy-run2.txt'; if(Test-Path $p){'Bytes: '+(Get-Item $p).Length; 'Lines: '+(Get-Content $p).Count; Get-Content $p -TotalCount 40}else{'FILE NOT FOUND'}"
```

Result:

```text
Bytes: 2287
Lines: 73
```

The file was successfully retrieved and contained actual generated policy updates.

### Important discovery

The generated file began with:

```text
# This represents policy updates for policy id dc9c713a.
# It contains the rules representing the result of actions
# that would have failed with the existing policy.
```

This established that `policy-run2.txt` was an update policy, not a complete standalone policy.

---

## 4. Inspected the complete generated policy

**Time:** Approximately 15:36–15:37 UTC

Command:

```cmd
type C:\qnxvm-secpol\policy-run2.txt
```

The generated file contained:

### Additional ability definitions

```text
ability iofunc/chown allow { root };
ability iofunc/read allow { root };
ability iofunc/exec allow { };
ability iofunc/read=77;
ability iofunc/dup=78 allow { root };
ability iofunc/exec=79;
ability vfs/mount-blk=80 allow { root };
ability vfs/pregrow=81 allow { root };
ability vfs/relearn=82 allow { root };
ability vfs/stats-clear=83 allow { root };
ability vfs/fs-control=84 allow { root };
ability network/privport=85 allow { root };
ability network/rawsocket=86 allow { root };
ability network/reuseport=87 allow { root };
ability network/ipsec=88 allow { root };
ability network/admin=89 allow { root };
ability network/jailroot=90 allow { root nonroot };
```

### Additional rules

The generated file included rules for:

- `console_t`
- `devc_t`
- `devc_t__run`

For example:

```text
allow console_t self:ability {
    spawn
    fork
    able_create
    xprocess_query:20-22,24-25,29-30,33-34,37-38,43-44,47-48
    channel_connect:devb_t,random_t
    mac_policy
};
```

It also contained mount-point information for resources such as:

- `/dev/console`
- `/dev/random`
- `/dev/socket`
- `/dev/tun`
- `/dev/tap`
- `/dev/io-sock/`
- `/dev/bpf`

These entries were inspected but not independently validated as necessary or safe.

---

## 5. Inspected the original baseline policy

**Time:** Approximately 15:37–15:38 UTC

Command:

```cmd
powershell -NoProfile -Command "$p='C:\qnxvm-secpol\policy-open-baseline.txt'; 'Bytes: '+(Get-Item $p).Length; 'Lines: '+(Get-Content $p).Count; Get-Content $p -TotalCount 100"
```

Result:

```text
Bytes: 10098
Lines: 487
```

The baseline contained:

- Original policy type definitions.
- Default rules.
- Console permissions.
- Device permissions.
- Filesystem permissions.
- Networking permissions.
- Process and service permissions.
- Mount-point rules.

Examples of defined types:

```text
type console_t;
type default;
type devb_t;
type devb_t__run;
type devc_pty_t;
type devc_pty_t__run;
type devc_t;
type devc_t__run;
type dhcpcd_t;
type dumper_t;
type fsevmgr_t;
type io_sock_t;
type pci_server_t;
type qconn_t;
type random_t;
type slogger_t;
type sshd_t;
type user_root_t;
```

This confirmed that we had the original policy source required for the next compilation stage.

---

## 6. Investigated mkqnximage security options

**Time:** Approximately 15:33–15:36 UTC

We inspected the supported security options.

Command:

```cmd
mkqnximage --help=secpol
```

Output:

```text
Builtin options:
--secpol=[no|develop|open|secure]

If no, don't use security polices. May also be 'secure' to use a policy in secure mode,
'develop' to use in normal developer mode or 'open' to be unrestricted by default.

The default is no.
```

This confirmed that QNX supports four modes:

- `no`
- `develop`
- `open`
- `secure`

We then checked the policy option:

```cmd
mkqnximage --help=policy
```

Output:

```text
Builtin options:
--policy=[none|<path>]

The path to the security policy file to compile and include at /proc/boot/secpol.bin or none
to not include a security policy.

This does not by itself cause the policy to be used, the use
of policies is controlled by the --secpol option.
```

Important conclusion:

`--policy` specifies the policy source file, while `--secpol=secure` controls enforcement mode.

---

## 7. Compiled the baseline and generated policy

**Time:** Approximately 15:39–15:44 UTC

We inspected the compiler usage.

Command:

```cmd
secpolcompile --help
```

The command did not support GNU-style `--help`.

Output:

```text
secpolcompile: unknown option -- -
secpolcompile: unknown option -- h
secpolcompile: unknown option -- l
secpolcompile: option requires an argument -- p

usage: secpolcompile [-em] [-p policy-id] [-o output-file] file ...

-e Output as a secpolgenerate event file instead of a binary policy
-m Create a mutable policy allowing subsequent versions to be pushed to procnto during development
-o Path for output file
-p Policy id (see docs)
```

### First compilation attempt

We attempted:

```cmd
secpolcompile C:\qnxvm-secpol\policy-open-baseline.txt C:\qnxvm-secpol\policy-run2.txt
```

The compiler returned to the command prompt without reporting an error.

### Second attempt: explicit policy ID

Command:

```cmd
secpolcompile -p dc9c713a -o C:\qnxvm-secpol\policy-merged.bin C:\qnxvm-secpol\policy-open-baseline.txt C:\qnxvm-secpol\policy-run2.txt
```

Result:

```text
invalid policy id: dc9c713a
```

The compiler rejected the supplied ID. We did not establish why the generated header ID was not accepted by this option.

We therefore stopped using that ID.

### Third attempt: compiler default policy ID

Command:

```cmd
secpolcompile -o C:\qnxvm-secpol\policy-merged.bin C:\qnxvm-secpol\policy-open-baseline.txt C:\qnxvm-secpol\policy-run2.txt
```

The compiler returned without reporting errors.

We checked the output:

```cmd
powershell -NoProfile -Command "$p='C:\qnxvm-secpol\policy-merged.bin'; if(Test-Path $p){Get-Item $p | Select-Object FullName,Length,LastWriteTime}else{'OUTPUT FILE NOT FOUND'}"
```

Result:

```text
C:\qnxvm-secpol\policy-merged.bin

Length: 7136
```

The compiled output existed.

### Created a combined policy source

Command:

```cmd
copy /b C:\qnxvm-secpol\policy-open-baseline.txt+C:\qnxvm-secpol\policy-run2.txt C:\qnxvm-secpol\policy-merged.txt
```

Result:

```text
1 file(s) copied.
```

Then compiled the combined source:

```cmd
secpolcompile -o C:\qnxvm-secpol\policy-merged-check.bin C:\qnxvm-secpol\policy-merged.txt
```

The compiler returned without reporting errors.

**Important qualification:** The compiler accepted the combined source. This did not independently establish that the resulting policy was semantically correct, secure, or appropriate for every workload.

---

## 8. Stopped the open-mode VM

**Time:** Approximately 15:45 UTC

We stopped the running QEMU VM using:

```text
Ctrl+A
X
```

The VM terminated successfully.

This was done to avoid file locks and preserve a clean build environment.

The original open-mode workspace was left intact.

---

## 9. Created a separate secure-mode workspace

**Time:** Approximately 15:46 UTC

Created:

```cmd
mkdir C:\qnxvm-secure
```

Entered the directory:

```cmd
cd /d C:\qnxvm-secure
```

This isolated the secure-mode image from the original working open-mode image.

### Initialized QNX environment

The environment initialization output included:

```cmd
set QNX_CONFIGURATION=C:\Users\Admin/.qnx
set MAKEFLAGS=-IC:/Users/Admin/qnx800/target/qnx/usr/include
set PYTHONDONTWRITEBYTECODE=1
set TMPDIR=C:\Users\Admin\AppData\Local\Temp
```

The PATH was configured to include QNX host tools.

We also configured:

```cmd
set "MKFS_PATH=C:\Users\Admin\qnx800\target\qnx\x86_64;C:\Users\Admin\qnx800\target\qnx\x86_64\boot\sys;C:\Users\Admin\qnx800\target\qnx"
```

This reused the configuration that fixed the earlier missing boot-file problem.

---

## 10. Built the secure-mode QNX image

**Time:** Approximately 15:49 UTC

First build:

```cmd
mkqnximage --secpol=secure --policy=C:/qnxvm-secpol/policy-merged.txt --build
```

The build completed successfully.

Output included:

```text
Compiling policy
Generating output/build/mount_fs.sh
Generating output/build/expandfs.sh
Generating output/build/post_startup.sh
Generating output/build/start_net.sh
Generating output/build/startup.sh
Generating output/build/passwd
Generating output/build/group
Generating output/build/shadow
Generating output/build/ifs.build
Generating output/build/system.build
Generating output/build/data.build
Generating output/build/qemu_options
Building disk
Generating system partition . . .
Generating data partition . . .
Generating ifs . . .
Building boot partition . . .
Building disk . . .

Target type: qemu
Architecture: x86_64
Security: secure
```

### SSH identity warning

The first build warned:

```text
To allow root ssh, you need an ssh identity file.
```

This meant we needed to configure the public SSH key for the secure image.

### Second build: SSH identity configured

Command:

```cmd
mkqnximage --secpol=secure --policy=C:/qnxvm-secpol/policy-merged.txt --ssh-ident=C:/Users/Admin/.ssh/id_ed25519.pub --build
```

The second build completed successfully.

The SSH warning disappeared.

Output again confirmed:

```text
Target type: qemu
Architecture: x86_64
Security: secure
```

This was the major achievement of the day.

---

## 11. Verified secure image artifacts

**Time:** Approximately 15:51 UTC

Command:

```cmd
dir output
```

Results:

| File | Size |
|---|---:|
| `disk-qemu` | 157,270,528 bytes |
| `disk-qemu.vmdk` | 169 bytes |
| `ifs.bin` | 11,023,160 bytes |
| `procnto-smp-instr.sym` | 12,419,152 bytes |
| `diskimage.out` | 0 bytes |

Other generated directories:

```text
output/build
output/inc
output/option_files
```

The secure image artifacts were present in the isolated workspace.

---

## 12. Final status at the end of Tuesday

### Five-test gate

| Test | Status | Evidence |
|---|---|---|
| 1. Open-mode image builds and boots | PASS | QNX booted and reached startup complete |
| 2. Generated policy retrieved | PASS | 2,287-byte, 73-line policy file retrieved over SSH |
| 3. Policy compiles | PASS* | Compiler returned without errors for combined source |
| 4. Secure-mode image builds and boots | BUILD PASS | Secure image built; boot still untested |
| 5. Legitimate operations succeed and unauthorized operations are denied | NOT STARTED | Requires secure VM runtime tests |

*Compilation success does not establish runtime correctness or security effectiveness.*

### What was completed

- Open-mode QNX environment established.
- Policy generator identified and confirmed running.
- Generated policy retrieved from the VM.
- Original baseline policy inspected.
- Generated policy updates inspected.
- `mkqnximage` security options inspected.
- `secpolcompile` syntax inspected.
- Combined policy source created.
- Compiler accepted the combined policy source.
- Separate secure workspace created.
- Secure-mode image successfully built.
- SSH public-key configuration added to the secure build.
- Secure image artifacts verified.

### Problems that occurred

1. Windows `find` resolved to the wrong executable.
2. `secpolcompile -p dc9c713a` rejected the supplied policy ID.
3. The first secure image build warned about missing SSH identity.
4. Earlier work had encountered stale IFS files, missing boot-file lookup paths, and QEMU disk locks; those had already been resolved.
5. Earlier `secpolmonitor` and `secpolpush` investigations were parked.

### Important unresolved technical concerns

- The generated policy is an update/delta, not an independent complete policy.
- The policy's permissions have not undergone a complete security review.
- We have not established that every generated rule is necessary.
- The secure image has not yet been booted.
- We have not yet verified that QNX actually enforces the intended policy at runtime.

---

## 13. Exact stopping point

The last completed command was:

```cmd
dir output
```

The next command planned was:

```cmd
type output\build\qemu_options
```

Working directory:

```text
C:\qnxvm-secure
```

The purpose is to inspect the QEMU configuration generated by `mkqnximage` before launching the secure VM.

### Next objectives

**Wednesday / next working session:**

1. Inspect `output\build\qemu_options`.
2. Launch QEMU using the secure workspace's `output` artifacts.
3. Verify that the secure VM reaches startup complete.
4. Verify SSH connectivity.
5. Confirm security-policy enforcement is active.
6. Test legitimate operations.
7. Perform a controlled unauthorized-access test.
8. Capture evidence of the allowed and denied operations.

Do not overwrite the original open-mode image.

---

## 14. Overall conclusion

Tuesday was a major development milestone.

We moved from running an open-mode QNX environment and observing generated policy updates to successfully compiling a combined policy source and building a separate secure-mode QNX image.

The secure image exists, but the actual enforcement demonstration remains unfinished.

The next priority is to boot that image and complete the final two tests. Avoid returning to parked investigations unless they directly prevent those tests from succeeding.


# Engineering log

## 2026-11-17 (adjust dates to the real ones)
- Installed QNX SDP 8.0 on Windows 10 using QNX Software Center; env script: C:\Users\Admin\qnx800\qnxsdp-env.bat
- Installed QEMU 11.1.0 for Windows
- mkqnximage built a QNX 8.0 x86_64 image; it booted (uname, pidin ran)
- Windows workarounds found:
  - mkqnximage's generated QEMU command fails on Windows (rng-random). Fix: run QEMU myself with -object rng-builtin,id=rng0
  - Networking: add -netdev user,id=net0,hostfwd=tcp::2222-:22 and -device virtio-net-pci,netdev=net0
  - SSH to the VM fails with "Corrupted MAC" unless: ssh -c aes128-ctr -m hmac-sha2-256
  - mkqnximage --ssh-ident needs forward slashes (C:/Users/...), backslashes are dropped
- Built an open-mode image (--secpol=open): boot log shows "Starting policy generator"; secpolgenerate runs with -t 100 -S -c -s options from /proc/boot/secpolgen_start.sh
- Retrieved the generated policy over SSH: ssh ... cat /dev/secpolgenerate/policy > policy-run2.txt (73 lines).
  Do NOT use scp for this: QNX docs say scp copies only the stat() size and secpolgenerate has no meaningful file size.

## 2026-11-18
- secpolcompile accepted baseline (487 lines) + generated updates (73 lines) with no errors
- Built a secure-mode image (--secpol=secure --policy=policy-merged.txt); booted; SSH works
- In the secure image: no secpolgenerate process, /dev/secpolgenerate absent, secpol -v: 4 blobs OK
- Probes (see docs/evidence-run1.txt): on -T random_t sleep 1 and secpolpush are denied in the secure image and allowed in the open image (serial console)
- Build lessons:
  - Stop QEMU before rebuilding, or "output/disk-qemu: Device or resource busy"
  - If output/ifs.bin fails to write, delete the stale output/ifs.bin and rebuild
  - Set MKFS_PATH to the target/qnx/x86_64 folders so mkifs finds multiboot.boot
  - find.exe on this PC resolves to a non-Windows find; use PowerShell: (Get-Content f).Count
  - Typing Windows commands into the QEMU window runs them inside QNX (wrong window); QNX prompt is "#"
- Parked (not needed for the core loop): secpolmonitor trace-logger errors, secpolpush use, dumper_t access to /dev/slog2

## Status of the 5-test gate
1. Open-mode image builds and boots: PASS
2. Generated policy retrieved: PASS (73 lines)
3. Policy compiles: PASS (secpolcompile, no errors)
4. Secure image boots, SSH works: PASS
5. Legit workload works, unauthorized operation denied: PASS (console open vs secure contrast; SSH denial in secure only)

## Next
- Manual minimization experiment: remove mac_policy from console_t, rebuild, boot, check secpolpush at the console
- Measure build time and boot time (not yet measured)
- Write the workload and the host-side pass/fail check, then plug into the ddmin minimizer