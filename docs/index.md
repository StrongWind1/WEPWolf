# WEPWolf

Offline, passive WEP key recovery from 802.11 captures -- a faster, parity-or-better alternative to aircrack-ng.

WEPWolf reads a pcap, pcapng, or gzip-compressed capture, pulls the WEP-encrypted frames out of the 802.11 traffic, and recovers the WEP key from them. It needs no wordlist and no external cracker: WEP's "RC4 keyed by a 24-bit IV" construction leaks key bytes statistically, so enough captured initialisation vectors (IVs) recover the key directly. Every key it reports has been confirmed by RC4-decrypting real frames and checking their CRC-32 ICV -- there is no heuristic acceptance.

**[Read the Guide](guide/index.md)** · **[Install](getting-started/installation.md)** · **[CLI Reference](reference/cli.md)** · **[vs aircrack-ng](comparison.md)**

## Why WEPWolf

- **Passive and offline.** It operates only on capture files you already have on disk. It never captures traffic, injects frames, deauthenticates clients, or touches a radio.
- **Fewer packets than aircrack-ng.** It ships the full Sepehrdad "Smashing WEP" RC4-bias database (FSE 2013) that aircrack-ng does not, so it can recover a key from a marginal capture where the Klein-only PTW that aircrack uses still cannot.
- **One tool, one file.** It ingests an entire directory of captures in parallel, merges a network's frames across every file deterministically, and can carve the exact WEP frame set it cracks from into a single re-crackable pcap.
- **One acceptance path.** A key is accepted only after RC4-decrypting at least two retained frames and matching the transmitted CRC-32 ICV -- the same standard aircrack-ng applies, so a reported key is correct, not merely "likely".
- **Real key sizes only.** WEP-40, WEP-104, and WEP-232 (5 / 13 / 29 secret octets). The 16-octet "152-bit" vendor extension is rejected.
- **Fast and lean.** A work-stealing sweep cracks every network in parallel, the CRC-32 ICV folds on PCLMULQDQ, and the 40-bit brute (when you ask for it) runs a SIMD-batched known-plaintext prefilter.

## Quick start

```sh
git clone https://github.com/StrongWind1/WEPWolf
cd WEPWolf
make release                 # -> target/release/wepwolf

wepwolf capture.cap          # scan, enumerate BSSIDs, and crack the WEP networks
```

```text
$ wepwolf wep_64_ptw.cap
KEYS RECOVERED
BSSID              ESSID             BITS  ID  VIA              IVS    TIME  KEY
00:12:bf:12:32:29  Appart              40   0  ptw            30566   0.03s  1f:1f:1f:1f:1f

WEP BSSIDs (most IVs first):
BSSID                   IVS  VIA         ESSID
00:12:bf:12:32:29     30566  ptw         Appart
(1 WEP, 0 WPA, 0 open, 0 unknown BSSIDs observed; --json for all)
=== WEPWolf ====================================================
-- ingest ------------------------------------------------------
captures read ............................................: 1
packets total ............................................: 65282
...
```

That crack runs in a fraction of a second. See the [installation guide](getting-started/installation.md) to build it, then the [guide](guide/index.md) for the full workflow.

## How it works

WEPWolf runs a streaming pipeline: it ingests the capture files in parallel, classifies every BSSID as WEP / WPA / open, harvests the WEP key material (IVs paired with the keystream recovered from known plaintext), runs every applicable attack against each WEP network, and confirms each candidate key through the single CRC-32 acceptance path before reporting it. The [guide](guide/index.md) walks through each stage; [How it works](guide/how-it-works.md) explains the cryptography.

## Scope and ethics

WEPWolf is for authorized security research, penetration testing with permission, and education. It operates on captures you already possess; running it on traffic you do not own or lack written authorization to analyze is illegal in most jurisdictions. See the [FAQ](faq.md) for the project's scope and the deliberate decision to stay passive.

## License

[Apache License 2.0](https://github.com/StrongWind1/WEPWolf/blob/main/LICENSE)
