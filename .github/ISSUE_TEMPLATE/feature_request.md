---
name: Feature request
about: Propose new functionality
title: "[feat] "
labels: enhancement
---

## Problem

<!-- What is missing? One paragraph. -->

## Proposed solution

<!-- How should wepwolf behave? Note where it fits: capture parsing, IV /
keystream collection, the key-recovery attack, or output. -->

## Scope check

- [ ] This stays within "offline capture analysis" (no live capture, no frame injection).
- [ ] This is in scope: WEP (40-bit / 104-bit) key recovery from pcap/pcapng captures.
      Out of scope: WPA/WPA2/WPA3, live capture, and frame injection.
- [ ] No new crate dependency *or* the dependency is justified per CONTRIBUTING.md
      (the runtime dependency budget is deliberately small).

## Alternatives considered

<!-- What else did you look at? Why is this the right shape? -->
