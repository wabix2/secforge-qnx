# Day 1-2 checklist (record every result with a timestamp in docs/log.md)

Rule: copy commands from the official QNX docs, never from memory or from an AI.

## Today
- [ ] Create public GitHub repo `secforge-qnx`, add LICENSE, push this scaffold
- [ ] Join the hackathon on Devpost (registration, not just a draft)
- [ ] Read https://qnx.devpost.com/rules sections on new vs existing projects
- [ ] Create a QNX Everywhere account, download SDP 8.0
      https://qnx.software/en/developers/get-started/qnx-everywhere
- [ ] Decide host: Ubuntu VM or WSL2. Follow the SDP 8.0 Quick Start Guide
- [ ] Boot a QEMU image and run hello world built with qcc

## Day 2 (kill tests)
- [ ] Build an image with the mkqnximage security-policy options
      (System Security Guide: "Using mkqnximage to Display Security Features")
- [ ] Run secpolgenerate, retrieve /dev/secpolgenerate/policy with sftp or ssh cat
- [ ] secpolcompile on the host accepts your free license (it does a license check)
- [ ] Edit one rule, recompile, rebuild image, reboot, observe a real denial
- [ ] Time the full edit->compile->boot->test loop

## Kill criteria
- secpolcompile license check fails, or loop takes > ~5 min with no way to speed up
  -> switch to the MsgForge plan (same environment work is reused)
