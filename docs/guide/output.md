# Output & diagnostics

Every run produces the same three sections in the same order — the recovered keys, then a summary of the WEP BSSIDs (most IVs first), then a stats breakdown. WEPWolf renders them on one of three surfaces that all carry the same information and differ only in shape: the default human table, `--plain` (tagged tab-separated records), and `--json` (typed NDJSON). `--quiet` reduces any surface to the keys section alone. This page explains each surface and what every field means.

## The default table

With no output flag, WEPWolf prints the three sections as aligned columns.

```text
KEYS RECOVERED
BSSID              ESSID             BITS  ID  VIA              IVS    TIME  KEY
aa:bb:cc:dd:ee:ff  OfficeNet          104   0  bias           48213   0.21s  4e:65:74:77:6f:72:6b:31:32:33:34:35:36  Network123456
00:11:22:33:44:55  HomeWiFi            40   0  ptw            30630   0.03s  61:62:63:64:65  abcde

WEP BSSIDs (most IVs first):
BSSID                   IVS  VIA         ESSID
aa:bb:cc:dd:ee:ff     48213  bias        OfficeNet
00:11:22:33:44:55     30630  ptw         HomeWiFi
de:ad:be:ef:00:01        12  -           ThinNet
  ... and 5 more WEP BSSIDs with fewer IVs
(8 WEP, 142 WPA, 11 open, 2 unknown BSSIDs observed; --json for all)
```

The **keys** block is one row per recovered key (one per WEP key slot for a multi-key access point): the BSSID, the ESSID, the key strength in bits (40 / 104 / 232), the key-ID slot, the attack that found it, the unique-IV count of that network, the time from the start of the attack phase to when the key verified, and the key in hex — with its ASCII form appended when every octet is printable. The ESSID column is truncated for alignment; the full value is in `--plain` / `--json`.

The **summary** lists WEP networks most-IVs-first (the ones most likely to crack), each with the attack that cracked it (`VIA`, or `-` when uncracked), and closes with a one-line census of everything else — it does not dump every observed network. ESSIDs are sanitised so binary bytes cannot mangle your terminal.

## The accounting banner

The third section is the stats banner. It accounts for every packet and every BSSID (nothing is silently dropped), grouped into `ingest` / `networks` / `run`. The zero rows (drop causes, unfired attacks) stay hidden so a clean run reads short, and it closes with a `wepwolf <version> (<git>)` footer.

```text
=== WEPWolf ====================================================
-- ingest ------------------------------------------------------
captures read ............................................: 12
packets total ............................................: 4231908
  data ...................................................: 1186402
  management .............................................: 372145
  control ................................................: 2673361
  extension ..............................................: 0
  dropped ................................................: 0
-- networks ----------------------------------------------------
BSSIDs seen ..............................................: 163
  WEP ....................................................: 8
    WEP data / auth frames ...............................: 78843 / 0
    cracked ..............................................: 2
      via PTW ............................................: 1
      via RC4-bias .......................................: 1
    uncracked ............................................: 6
      capture too thin ...................................: 6
  WPA ....................................................: 142
  open ...................................................: 11
  unknown ................................................: 2
-- run ---------------------------------------------------------
wallclock ................................................: 1.8s
  sweep / grind ..........................................: 1.8s / 0.0s
peak RSS .................................................: 41 MiB
================================================================
wepwolf 0.1.0 (a1b2c3d)
```

Field by field:

| Field | Meaning |
|---|---|
| **ingest / networks / run** | the three sections: capture parsing, BSSID classification and cracks, then run metrics |
| **captures read** | capture files successfully opened |
| **packets total** | every packet read; the five classes below always print and sum to it |
| **data / management / control / extension** | packets by 802.11 frame type |
| **dropped** | packets the parser could not use; expands into its causes (no link type, link strip failed, malformed MAC header, truncated body, each summing to the total) when nonzero |
| **BSSIDs seen** | distinct access points, split into WEP / WPA / open / unknown |
| **WEP data / auth frames** | WEP-encrypted data frames and Shared-Key auth frames |
| **cracked** | WEP networks whose key was recovered, one `via <attack>` row per attack that found a key (`reuse` = a key found on another network; `potfile` = a seeded known key) |
| **uncracked** | WEP networks left unrecovered: *capture too thin* (below the distinct-IV floor) or *key infeasible* (104/232-bit with material but no key) |
| **wallclock** | total run time |
| **sweep / grind** | time in the parallel cheap-attack sweep and in the serial 40-bit brute |
| **peak RSS** | the high-water resident memory for the run |

`--quiet` drops the summary and this banner, printing only the recovered keys.

## Machine-readable output

Both machine surfaces carry the same three sections as the table. Each line (or object) is self-describing, so you can `grep` / `cut` / `jq` whichever section you need.

=== "`--plain`"

    Tab-separated, one record per line, tagged in column 1:

    - `key` — the full per-key record: bssid, essid, key hex, key ASCII (empty when non-printable), key bits, key id, attack, unique IVs, seconds.
    - `wep` — one summary row per WEP BSSID: bssid, essid, unique IVs, the attack that cracked it (`-` if none).
    - `stat` — one `name<TAB>value` per counter (the full banner breakdown; durations in seconds, RSS in bytes).

    ```text
    key	00:12:bf:12:32:29	Appart	1f:1f:1f:1f:1f		40	0	ptw	30566	0.027
    wep	00:12:bf:12:32:29	Appart	30566	ptw
    stat	captures_read	1
    stat	packets_total	65282
    stat	cracked	1
    stat	wallclock_s	0.037
    stat	peak_rss_bytes	8159232
    ```

    Isolate a section with the tag: `wepwolf --plain caps/ | grep '^key' | cut -f2,4` lists each BSSID and its key.

=== "`--json`"

    NDJSON: one typed object per line. A `{"type":"key"}` object per recovered key, a `{"type":"bssid"}` object per WEP BSSID, then one `{"type":"stats"}` object with the full breakdown nested by section. Stream-friendly — parse it line by line.

    ```json
    {"type":"key","bssid":"00:12:bf:12:32:29","essid":"Appart","key_hex":"1f:1f:1f:1f:1f","key_ascii":null,"key_bits":40,"key_id":0,"attack":"ptw","ivs":30566,"seconds":0.026}
    {"type":"bssid","bssid":"00:12:bf:12:32:29","essid":"Appart","ivs":30566,"cracked":true,"via":"ptw"}
    {"type":"stats","captures":1,"packets":{"total":65282,"data":30630,"mgmt":2845,"control":31807,"extension":0,"dropped":0},"bssids":{"total":1,"wep":1,"wpa":0,"open":0,"unknown":0},"wep":{"data_frames":30630,"auth_frames":0,"cracked":1,"uncracked_thin":0,"uncracked_infeasible":0},"keys_by":{"ptw":1,"korek":0,"fms":0,"bias":0,"dict":0,"keygen":0,"ska":0,"brute":0,"reuse":0,"potfile":0},"timing":{"wallclock_s":0.036,"sweep_s":0.026,"grind_s":0.000},"peak_rss_bytes":8253440}
    ```

    `key_ascii` is `null` when the key is not printable ASCII; `via` is `null` for an uncracked BSSID. Pull the keys with `wepwolf --json caps/ | jq -r 'select(.type=="key") | [.bssid, .key_hex] | @tsv'`.

Live progress is drawn on a terminal with the default output only, on stderr: an ingest spinner, a sweep bar showing BSSIDs done, elapsed, ETA, and the network currently being attacked (with each recovered key streamed above it as it verifies), and a brute keyspace bar naming the network being ground with percent, keys/sec, ETA, and the active SIMD tier. `--plain`, `--json`, `--quiet`, and `--debug` suppress them so those streams stay clean.

## Potfile

`--potfile FILE` works like hashcat's pot: recovered keys are appended as `bssid:key_hex`, and an existing potfile seeds the run, so a network already in the pot is reported (attributed to `potfile`) without being re-attacked. Run it across a growing set of captures and each run starts from what the last one learned.

## Carving the WEP frames

`--carve FILE` writes every parsed WEP frame -- the WEP-encrypted data and Shared-Key auth frames -- plus each WEP network's beacon/probe into one standalone pcap (raw 802.11, with zeroed timestamps). Because WEPWolf's own parser selects and writes the frames after its tiered link-header recovery, the output is exactly the WEP set it cracks from, normalised to a single link type from mixed radiotap/Prism/AVS inputs. A multi-file capture set collapses into one self-contained capture that both WEPWolf and aircrack-ng can re-crack -- handy for differential checks or for handing a clean artifact to another tool. The carver streams within bounded memory.

## Diagnostics

- **`--debug`** prints timestamped, context-tagged lines to stderr: per-file ingest, per-BSSID material (IV / ARP / SKA counts), and -- for each uncracked WEP network -- *why* it did not crack: the distinct-IV count versus the raw frame count, which key lengths cleared the feasibility floor, how far a thin capture falls short, and the likely cause when material was sufficient (multiple key slots in use, sparse known plaintext, or below the practical packet count). This turns "nothing cracked" into something you can act on.
- **`--log FILE`** writes categorized `[category] key=value` lines (read errors, unknown link types, malformed frames, link-strip failures) to a file for post-run analysis, with correct per-file attribution even though ingest runs in parallel.

## Next

- [Tuning & performance](tuning.md) -- when a network is uncracked, what to try.
- [CLI Reference](../reference/cli.md) -- every flag.
