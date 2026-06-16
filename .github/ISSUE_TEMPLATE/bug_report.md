---
name: Bug report
about: wepwolf produced a wrong, missing, or corrupt result
title: "[bug] "
labels: bug
---

## What happened

<!-- Exact command you ran and what you expected vs what happened. -->

```
$ wepwolf ...
```

## Expected behaviour

<!-- One paragraph: what should have happened? -->

## Minimal reproducing capture

<!-- Attach a redacted pcap < 1 MiB if possible. Real ESSIDs / MACs must be
scrubbed unless the capture is lab-owned. If you cannot share the capture,
describe what it contains: # of APs / STAs, # of WEP data frames, # of unique
IVs, capture tool. -->

## Environment

- wepwolf version: `wepwolf --version`
- OS + arch:
- Rust toolchain: `rustc --version`
- Install method: source / release binary / package manager

## Comparison with other tools (optional)

<!-- If aircrack-ng (or another WEP cracker) recovers a key from the same
capture that wepwolf does not, note its version and how many IVs it needed.
That helps separate "not enough IVs captured" from a real bug. -->
