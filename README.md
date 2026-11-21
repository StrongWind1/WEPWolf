<h1 align="center">WEPWolf</h1>

<p align="center"><strong>Recover WEP keys from 802.11 traffic captured in a pcap. Offline, passive, no radio.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/WEPWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/WEPWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/wepwolf"><img src="https://img.shields.io/crates/v/wepwolf.svg" alt="crates.io"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/WEPWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/WEPWolf/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind.dev/WEPWolf/#quick-start">Quick start</a> &bull;
  <a href="https://strongwind.dev/WEPWolf/reference/cli/">CLI reference</a> &bull;
  <a href="https://strongwind.dev/WEPWolf/comparison/">vs aircrack-ng</a> &bull;
  <a href="https://strongwind.dev/WEPWolf/">Documentation</a>
</p>

---

WEPWolf reads pcap, pcapng, and gzip captures, pulls out the WEP-encrypted 802.11 frames, and recovers the key with no wordlist and no external cracker: WEP's RC4-with-a-24-bit-IV construction leaks key bytes statistically, so enough captured initialisation vectors (IVs) give up the key directly. It runs the same attack family as aircrack-ng, adds an RC4-bias attack aircrack-ng does not ship, and on a real capture recovers the key in a fraction of the time. It works offline on capture files you already have and never captures traffic, injects frames, or touches a radio.

## Example

```console
$ wepwolf wep_64_ptw.cap
KEYS RECOVERED
BSSID              ESSID               BITS  ID  VIA              IVS     TIME  KEY
00:12:bf:12:32:29  Appart                40   0  ptw            30566    0.02s  1f:1f:1f:1f:1f

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

That crack runs in a fraction of a second.

## Features

- **Verified keys only**: every candidate key is RC4-decrypted against real frames and must match the CRC-32 ICV of two of them before it is reported; there is no heuristic acceptance.
- **Whole directories**: point it at a directory and every capture is parsed in parallel, each network's frames are merged across files, and the networks are cracked in parallel.
- **Key reuse**: a key found on one network is tried against co-located access points that share it, and `--potfile` carries keys forward across runs.
- **Every network gets a try**: a built-in list of common and default keys runs on every network however few IVs it has; a network too thin for the statistical attacks is reported with its shortfall.
- **Per key slot**: each WEP key slot (Key ID 0-3) is cracked separately, so a multi-key access point yields a key per slot.
- **Real key sizes**: WEP-40, WEP-104, and WEP-232 (5, 13, or 29 secret octets).
- **Scriptable**: tagged TSV (`--plain`) or NDJSON (`--json`), keys only with `--quiet`, and exit code 0 only when a key is recovered.
- **Frame carving**: `--carve` writes every WEP frame it parsed, from every input, into one raw 802.11 pcap that both WEPWolf and aircrack-ng read.

## Installation

### From crates.io

```sh
cargo install wepwolf
```

### Prebuilt binaries

Download the binary for your platform from the [latest release](https://github.com/StrongWind1/WEPWolf/releases/latest) and put it on your `PATH`. The [installation guide](https://strongwind.dev/WEPWolf/getting-started/installation/) lists the assets and how to verify them.

### From source

```sh
git clone https://github.com/StrongWind1/WEPWolf
cd WEPWolf
make release      # optimised native build -> target/release/wepwolf
```

Requires a stable Rust toolchain (pinned in `rust-toolchain.toml`).

## Quick start

```sh
# Scan one capture and crack its WEP networks
wepwolf capture.cap

# Recurse a directory of captures (parsed in parallel, merged per BSSID)
wepwolf /captures/

# Try a wordlist of keys and passphrases as well as the statistical attacks
wepwolf -w rockyou.txt capture.cap

# Carry recovered keys forward across runs
wepwolf --potfile keys.pot /captures/

# Machine-readable output for a pipeline
wepwolf --json /captures/ > keys.ndjson

# Collapse many capture files into one re-crackable pcap
wepwolf --carve wep-frames.pcap /captures/
```

Every option, the exit codes, and the output formats are in the [CLI reference](https://strongwind.dev/WEPWolf/reference/cli/).

## Attacks

| Attack | Recovers from | Needs IVs |
| --- | --- | --- |
| **PTW** (Tews-Weinmann-Pyshkin / Klein) | ordinary captured traffic; the headline attack | yes |
| **KoreK** (17 correlations) | weak IVs (fewer than FMS needs) | yes |
| **FMS** (Fluhrer-Mantin-Shamir) | weak IVs | yes |
| **RC4-bias** (Sepehrdad "Smashing WEP" database) | many RC4 biases voted together; recovers from fewer packets than PTW, and aircrack-ng does not ship it | yes |
| Shared-Key-auth keystream | the WEP-encrypted SKA frame 3, fed to the attacks above | yes |
| **Dictionary** | a built-in list of common and default keys, tried on every network, plus your `--wordlist` (each entry raw and hex-decoded) | no |
| **Keygen** (`--wordlist`) | passphrases via Neesus-Datacom (40-bit) and MD5 (104-bit) | no |
| **Brute force** (`--brute`) | exhaustive WEP-40 (last resort: about six hours for the whole keyspace on an 8-core CPU) | no |

The attacks that need IVs start once a network has 1,000 distinct IVs for WEP-40 (5,000 for WEP-104, 15,000 for WEP-232), because below that they cannot [converge](https://strongwind.dev/WEPWolf/guide/how-it-works/#the-convergence-floor). The rest, plus key reuse and the potfile, run on every network. Known plaintext, voting, and key verification are explained in [How it works](https://strongwind.dev/WEPWolf/guide/how-it-works/).

## How WEPWolf compares to aircrack-ng

aircrack-ng is the reference WEP cracker and WEPWolf's ground truth: every key WEPWolf reports is differentially validated to match it. WEPWolf re-implements the same attack family (PTW, KoreK, FMS), the same known-plaintext trick (`known_clear`), the same search knobs (`-f` / `-x` / `-c`), the same unique-IV voting, and the same two-frame CRC-32 acceptance standard. Where they differ:

| Behaviour | aircrack-ng | WEPWolf |
| --- | --- | --- |
| Sepehrdad "Smashing WEP" RC4-bias database | not shipped | full database; recovers a WEP-104 key from fewer packets |
| Several capture files | read serially | parsed in parallel, a network's frames merged across every file, deterministically |
| Multi-key access points (Key ID 0-3) | one vote table per BSSID | each key slot cracked separately |
| Known plaintext | content-based guess | also reads the cleartext destination MAC to mine IPv6 Neighbor Discovery and EAPOL headers |
| Fragments and snap-length-truncated frames | mined as whole frames | kept out of the votes and out of key verification |
| Common and default keys | no built-in list | tried on every network, however few IVs it has |
| Frame carving | no equivalent | `--carve` writes the exact WEP frame set into one re-crackable pcap |
| Active attacks (injection, replay, deauthentication) | in the aircrack-ng suite | none: passive and offline only |

The full breakdown, including the caveats, is in the [documentation](https://strongwind.dev/WEPWolf/comparison/).

## Development

Conventional commit messages (`feat:`, `fix:`, `docs:`); run `make check` before every commit. Every change maps to an `FR-*` requirement and lands a test. Release history is in [CHANGELOG.md](CHANGELOG.md).

## Credits

[aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) is the reference WEP cracker and the differential oracle every result is checked against. The RC4-bias attack implements the Sepehrdad-Vaudenay-Vuagnoux "Smashing WEP in a Passive Attack" database (FSE 2013). The capture front-end (container parsing, link-header recovery, and 802.11 frame parsing) is ported from the sibling [WPAWolf](https://github.com/StrongWind1/WPAWolf).

## Related tools

- [**WPAWolf**](https://github.com/StrongWind1/WPAWolf): WPA / WPA2 / WPA3 PSK handshake and PMKID extractor for hashcat mode 22000
- [**WiFi_Cracking**](https://github.com/StrongWind1/WiFi_Cracking): IEEE 802.11 security reference: WPA/WPA2/WPA3 PSK, EAP, and WEP, from protocol internals to cracking

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

WEPWolf is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
