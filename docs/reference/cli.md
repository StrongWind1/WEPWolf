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
| `-w`, `--wordlist FILE` | Wordlist for the dictionary and keygen attacks, one candidate per line. Each line is tried as a raw key, a hex key, and a passphrase through the weak-key generators. A built-in list of common and default keys is tried on every network even without this flag; the wordlist extends it and enables the keygen. |
| `-n`, `--keylen BITS` | Only try one key strength: `40`, `104`, or `232`. Default: all three (the statistical attacks recover the length implicitly). |
| `-b`, `--bssid MAC` | Restrict the run to a single BSSID, e.g. `00:11:22:33:44:55`. |
| `--brute` | Enable the exhaustive 2⁴⁰ brute force for WEP-40 keys no other attack recovered. Off by default. Each network is bounded by `--per-bssid-time-max`, whose 300 s default covers only about 1.3% of the keyspace at ~50M keys/s; pass `--per-bssid-time-max 0` for a full sweep (about six hours on an 8-core CPU). |

The statistical attacks (PTW, KoreK, FMS, the bias database, and the Shared-Key bootstrap) run on a network once it holds 1,000 distinct IVs for WEP-40, 5,000 for WEP-104, or 15,000 for WEP-232; below that they cannot converge and are not started. The dictionary, the keygen, key reuse, the potfile, and the brute force have no such floor.

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
| `--per-bssid-time-max SECS` | Max seconds any one network may spend in recovery, and again in the brute force. In recovery a network earns a share of it in proportion to its distinct IVs (all of it at 20,000 and up). Default: 300; `0` = unlimited. |
| `--total-brute-time-max SECS` | Max total seconds for the whole 40-bit brute-force phase across all networks. Default: 0 (unlimited). |
| `--total-recovery-time-max SECS` | Max total seconds for the whole recovery phase across all networks; once spent, networks not yet started are skipped. Default: 0 (unlimited). |

### Output

| Option | Description |
|---|---|
| `--plain` | Tab-separated records, each tagged in column 1: `key` (the full per-key record), `wep` (one row per WEP BSSID), `stat` (one counter). `grep '^key'` or `cut` isolates a section. |
| `--json` | NDJSON: one typed object per line — `{"type":"key"}` per key, `{"type":"bssid"}` per WEP BSSID, then one `{"type":"stats"}` with the full breakdown. |
| `-q`, `--quiet` | Print only the recovered keys: drop the WEP-BSSID summary and the stats from every surface. |
| `--potfile FILE` | Read and append recovered keys hashcat-style (`bssid:key_hex`); an existing potfile seeds the run. |
| `--carve FILE` | Write every parsed WEP frame plus each WEP network's beacon to a standalone pcap (raw 802.11, zeroed timestamps; a frame the source cut short keeps its original length). |

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

# Only WEP-104, restrict to ASCII keys, give each network up to twenty minutes
wepwolf --keylen 104 -c --per-bssid-time-max 1200 capture.cap

# Last resort: brute-force one network's whole 40-bit keyspace (hours)
wepwolf --brute --per-bssid-time-max 0 --bssid 00:11:22:33:44:55 capture.cap

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
