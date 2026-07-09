<h1 align="center">WEPWolf</h1>

<p align="center">
  <strong>Recover WEP keys from 802.11 traffic captured in a pcap. Offline, passive, no radio.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/WEPWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/WEPWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind1.github.io/WEPWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="#attacks">Attacks</a> &bull;
  <a href="#example">Example</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#cli-reference">CLI reference</a> &bull;
  <a href="#how-wepwolf-compares-to-aircrack-ng">vs aircrack-ng</a> &bull;
  <a href="https://strongwind1.github.io/WEPWolf/">Docs</a>
</p>

---

WEPWolf reads a pcap, pcapng, or gzip-compressed capture, pulls the WEP-encrypted frames out of the 802.11 traffic, and recovers the WEP key from them. Unlike WPA cracking it needs no wordlist and no external cracker: WEP's RC4-with-a-24-bit-IV construction leaks key bytes statistically, so enough captured initialisation vectors (IVs) recover the key directly. The closest existing tool is aircrack-ng, and WEPWolf targets the same attack family -- and on a real capture it recovers the key in a fraction of the time.

It is **passive and offline**: it operates on capture files you already have on disk, never captures traffic, injects frames, or touches a radio.

---

## Attacks

| Attack | Recovers from | Status |
|---|---|---|
| **PTW** (Tews-Weinmann-Pyshkin / Klein) | ordinary captured traffic; the headline attack | yes |
| **KoreK** (17 correlations) | weak IVs (fewer than FMS needs) | yes |
| **FMS** (Fluhrer-Mantin-Shamir) | weak IVs | yes |
| **Dictionary** (`--wordlist`) | a wordlist of candidate keys (raw or hex) | yes |
| **Keygen** (`--wordlist`) | passphrases via Neesus-Datacom (40-bit) and MD5 (104-bit) | yes |
| **RC4-bias** (Sepehrdad "Smashing WEP" database) | many RC4 biases voted together; recovers from fewer packets than PTW, and aircrack-ng does not ship it | yes |
| **Brute force** (`--brute`) | exhaustive WEP-40 (last resort, slow) | yes |
| Shared-Key-auth keystream | the WEP-encrypted SKA frame 3, fed to the attacks above | yes |

Every candidate key is confirmed by RC4-decrypting real frames and checking the CRC-32 ICV before it is reported -- there is no heuristic acceptance.

---

## Example

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

That crack runs in a fraction of a second. The same keys, summary, and stats are available as tagged TSV (`--plain`) or typed NDJSON (`--json`). Point WEPWolf at a directory to scan many captures at once; networks are cracked in parallel and a key found on one is reused against co-located access points that share it.

---

## Installation

### From crates.io

```sh
cargo install wepwolf
```

### Prebuilt binaries

Download the binary for your platform from the [latest release](https://github.com/StrongWind1/WEPWolf/releases/latest) and put it on your `PATH`.

### From source

Requires a stable Rust toolchain (`rust-toolchain.toml` pins the version).

```sh
git clone https://github.com/StrongWind1/WEPWolf
cd WEPWolf
make release          # optimised native build -> target/release/wepwolf
```

---

## CLI reference

```text
wepwolf [OPTIONS] <PATH>...

Arguments:
  <PATH>...  Capture files or directories to scan

Options:
  -h, --help     Print help (see more with '--help')
  -V, --version  Print version

Targeting & attacks:
  -w, --wordlist <FILE>  Wordlist for the dictionary and keygen attacks (one candidate per line)
  -n, --keylen <BITS>    Only try one key strength in bits: 40, 104, or 232 (default: all three)
  -b, --bssid <MAC>      Restrict the run to a single BSSID (e.g. 00:11:22:33:44:55)
      --brute            Brute-force WEP-40 keys no other attack recovered (slow: scalar 2^40)

Search tuning:
  -f, --fudge <FACTOR>  KoreK/bias fudge factor: keep octets voting >= top/FACTOR (aircrack -f)
  -x, --bruteforce <N>  Exhaustively sweep the last N key octets (aircrack -x; default 2, max 4)
  -c, --alnum           Restrict candidate key octets to printable ASCII (aircrack -c)

Performance:
  -j, --threads <N>                     Worker threads for the parallel sweep and ingest (default: all cores)
      --per-bssid-time-max <SECS>       Max seconds any one network may spend in recovery and brute force (default 300)
      --total-brute-time-max <SECS>     Max total seconds for the whole 40-bit brute-force phase (default 0: unlimited)
      --total-recovery-time-max <SECS>  Max total seconds for the whole recovery phase (default 0: unlimited)

Output:
      --plain           Tab-separated records, tagged key / wep / stat (machine-readable)
      --json            NDJSON: one typed object per line (key / bssid / stats)
  -q, --quiet           Print only the recovered keys (drop the summary and stats)
      --potfile <FILE>  Read and append recovered keys, hashcat-style (bssid:key_hex)
      --carve <FILE>    Carve every parsed WEP frame and each WEP beacon into one standalone pcap

Diagnostics:
  -d, --debug       Emit timestamped diagnostics to stderr
  -l, --log <FILE>  Write categorized diagnostic lines to FILE
```

Exit code is `0` iff at least one key was recovered, `1` if none, `2` on a fatal I/O error.

`--carve` collects the WEP frames wepwolf's parser recovers -- across every input file, with its tiered link-header recovery applied -- into one self-contained pcap. Because the frames are written post-strip as raw 802.11 with zeroed timestamps, the output normalises mixed radiotap/Prism/AVS inputs to a single link type that both wepwolf and aircrack-ng read, and many capture files collapse into one capture you can re-crack or hand to another tool.

The full option reference, output formats, and tuning guide are in the [documentation](https://strongwind1.github.io/WEPWolf/).

---

## How WEP recovery works

WEP encrypts each frame with `RC4(IV || key)`, where the 24-bit IV is sent in the clear. The first octets of an 802.11 data frame are a known LLC/SNAP header, so XORing the ciphertext with that known plaintext recovers the start of the keystream for each IV. Seven octets of SNAP keystream are enough to drive PTW for a 40-bit key; for a 104-bit key PTW needs fifteen, so WEPWolf reconstructs more known plaintext from the predictable start of the encapsulated packet -- the fixed ARP header, the IPv4 header whose total-length field is read straight from the captured frame size, or -- identified from the cleartext 802.11 destination MAC -- the IPv6 Neighbor Discovery and EAPOL headers (mirroring, and extending, aircrack-ng's `known_clear`). PTW then correlates those keystream octets across many packets to vote for the key bytes, fixing the strong leading octets and sweeping the weakest trailing octet exhaustively (aircrack's `-x`); FMS exploits IVs whose RC4 key schedule leaks individual key octets. Beyond PTW and FMS, WEPWolf votes the full Sepehrdad "Smashing WEP" RC4-bias database (FSE 2013), which aircrack-ng does not ship, to recover a key from fewer packets, and it cracks each WEP key slot (Key ID 0-3) separately, so a multi-key access point yields a key per slot. Reliability scales with the number of *distinct* IVs -- WEP reuses its 24-bit IV heavily, and WEPWolf, like aircrack-ng, votes each distinct IV once -- so PTW typically wants on the order of tens of thousands of unique WEP frames.

---

## How WEPWolf compares to aircrack-ng

aircrack-ng is the reference WEP cracker and WEPWolf's ground truth -- every key WEPWolf reports is differentially validated to match it. WEPWolf re-implements the same attack family (PTW, KoreK, FMS), the same known-plaintext trick (`known_clear`), the same search knobs (`-f` / `-x` / `-c`), the same unique-IV voting, and the same two-frame CRC-32 acceptance standard. On top of that it:

- ships the full Sepehrdad "Smashing WEP" RC4-bias database that aircrack-ng does not, recovering a WEP-104 key from fewer packets;
- ingests an entire directory of captures in parallel and merges a network's frames across every file, deterministically;
- cracks each WEP key slot (Key ID 0-3) separately, recovering keys a single pooled vote table misses;
- reads the cleartext destination MAC to mine IPv6 Neighbor Discovery and EAPOL known-plaintext the IPv4-shaped guess would miss;
- carves the exact WEP frame set it cracks from into one re-crackable pcap.

It is deliberately **passive and offline only** -- the active tools (packet injection, replay, deauthentication) are the aircrack-ng suite's job. The full breakdown is in the [documentation](https://strongwind1.github.io/WEPWolf/comparison/).

---

## Contributing

Conventional commit messages (`feat:`, `fix:`, `docs:`); run `make check` before every commit. Every change maps to an `FR-*` requirement and lands a test.

---

## Credits

[aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) is the reference WEP cracker and the differential oracle every result is checked against. The capture front-end -- container parsing, link-header recovery, and fragment reassembly -- is ported from the sibling [WPAWolf](https://github.com/StrongWind1/WPAWolf).

---

## Related tools

Other projects in this collection:

- [WPAWolf](https://github.com/StrongWind1/WPAWolf) - WPA/WPA2/WPA3-FT-PSK handshake extraction from captures
- [WiFi_Cracking](https://github.com/StrongWind1/WiFi_Cracking) - IEEE 802.11 security reference and attack guide
- [NFSWolf](https://github.com/StrongWind1/NFSWolf) - native NFS security toolkit
- [CredWolf](https://github.com/StrongWind1/CredWolf) - Active Directory credential validation
- [KerbWolf](https://github.com/StrongWind1/KerbWolf) - Kerberos roasting and hash extraction toolkit
- [NTDSWolf](https://github.com/StrongWind1/NTDSWolf) - offline NTDS.dit parser and credential extractor

---

## Disclaimer

WEPWolf operates on capture files you already have on disk. It does not capture traffic, inject frames, or touch a radio. It is intended for authorized security research only; running it on captures you do not own or lack written authorization to analyze is illegal in most jurisdictions. The authors are not responsible for any misuse or damage caused by this tool.

---

## License

[Apache License 2.0](LICENSE)
