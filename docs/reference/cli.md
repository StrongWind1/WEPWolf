# CLI Reference

```
wepwolf [OPTIONS] <PATH>...
```

WEPWolf takes one or more capture files or directories, scans them, and recovers the WEP keys. Directories are recursed and every capture inside is discovered automatically.

## Arguments

| Argument | Description |
|---|---|
| `<PATH>...` | One or more capture files or directories. pcap, pcapng, and gzip-compressed captures are read; directories are recursed and captures auto-discovered. **Required.** |

## Options

### Targeting & attacks

| Option | Description |
|---|---|
| `-w`, `--wordlist FILE` | Wordlist for the dictionary and keygen attacks. Each line is tried as a raw key, a hex key, and a passphrase through the weak-key generators. |
| `-n`, `--keylen BITS` | Only try one key strength: `40`, `104`, or `232`. Default: all three (the statistical attacks recover the length implicitly). |
| `-b`, `--bssid MAC` | Restrict the run to a single BSSID, e.g. `00:11:22:33:44:55`. |
| `--brute` | Enable the exhaustive 2⁴⁰ brute force for WEP-40 keys no other attack recovered. Slow; off by default. |

### Search tuning (mirrors aircrack-ng)

| Option | Description |
|---|---|
| `-f`, `--fudge FACTOR` | KoreK/bias fudge: keep candidate octets whose vote is at least `top / FACTOR`. Higher = wider, slower search. Default: 5 for WEP-40, 2 for longer keys (aircrack-ng `-f`). |
| `-x`, `--bruteforce N` | Exhaustively sweep the last `N` key octets (1-4). Default: 2 (aircrack-ng `-x`). |
| `-c`, `--alnum` | Restrict candidate octets to printable ASCII, for expected passphrase keys (aircrack-ng `-c`). |

### Performance

| Option | Description |
|---|---|
| `-j`, `--threads N` | Worker threads for the parallel BSSID sweep and ingest. Default: all cores. |
| `--per-bssid-time-max SECS` | Max seconds any one network may spend in recovery and brute force, scaled down by unique-IV count for a thin capture. Default: 300; `0` = unlimited. |
| `--total-brute-time-max SECS` | Max total seconds for the whole 40-bit brute-force phase across all networks. Default: 0 (unlimited). |
| `--total-recovery-time-max SECS` | Max total seconds for the whole recovery phase across all networks; once spent, networks not yet started are skipped. Default: 0 (unlimited). |

### Output

| Option | Description |
|---|---|
| `--plain` | Tab-separated records, each tagged in column 1: `key` (the full per-key record), `wep` (one row per WEP BSSID), `stat` (one counter). `grep '^key'` or `cut` isolates a section. |
| `--json` | NDJSON: one typed object per line — `{"type":"key"}` per key, `{"type":"bssid"}` per WEP BSSID, then one `{"type":"stats"}` with the full breakdown. |
| `-q`, `--quiet` | Print only the recovered keys: drop the WEP-BSSID summary and the stats from every surface. |
| `--potfile FILE` | Read and append recovered keys hashcat-style (`bssid:key_hex`); an existing potfile seeds the run. |
| `--carve FILE` | Write every parsed WEP frame plus each WEP network's beacon to a standalone pcap (raw 802.11, zeroed timestamps). |

### Diagnostics

| Option | Description |
|---|---|
| `-d`, `--debug` | Timestamped diagnostics to stderr, including per-network "why uncracked" detail. |
| `-l`, `--log FILE` | Write categorized diagnostic lines (read/link/parse errors) to a file. |
| `-h`, `--help` | Print help and exit. |
| `-V`, `--version` | Print version and exit. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | At least one key was recovered. |
| `1` | No key was recovered. |
| `2` | A fatal I/O error (e.g. no readable capture at the given paths). |

This makes WEPWolf easy to script: `wepwolf capture.cap && echo cracked`.

## Examples

```sh
# Scan one capture and crack its WEP networks
wepwolf capture.cap

# Recurse a directory of captures (parsed in parallel, merged per BSSID)
wepwolf /captures/

# Several files at once
wepwolf session-1.pcapng session-2.pcap.gz dump.cap

# Target a single network
wepwolf --bssid 00:11:22:33:44:55 capture.cap

# Try a wordlist of keys / passphrases as well as the statistical attacks
wepwolf -w rockyou.txt capture.cap

# Only WEP-104, restrict to ASCII keys, give each network two minutes
wepwolf --keylen 104 -c --per-bssid-time-max 120 capture.cap

# Enable the last-resort 40-bit brute force with a 10-minute per-network cap
wepwolf --brute --per-bssid-time-max 600 capture.cap

# Machine-readable output for a pipeline
wepwolf --json /captures/ > keys.ndjson

# Carry recovered keys forward across runs
wepwolf --potfile keys.pot /captures/

# Collapse many capture files into one re-crackable pcap
wepwolf --carve wep-frames.pcap /captures/

# Diagnose why a capture did not crack
wepwolf --debug capture.cap
```

## See also

- [Tuning & performance](../guide/tuning.md) -- when and why to reach for each flag.
- [Output & diagnostics](../guide/output.md) -- reading the result.
