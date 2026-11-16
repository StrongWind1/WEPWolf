# Tuning & performance

WEPWolf cracks a typical capture with no flags at all. The knobs here help on **hard or marginal** captures, large corpora, and the rare case where you want to trade time for reach. Every flag is also in the [CLI reference](../reference/cli.md).

## When nothing cracks

The overwhelmingly common reason is too little material. WEP recovery is statistical and scales with **distinct** IVs (not raw frames -- a replayed capture is frame-rich but IV-poor). Run with `--debug` and read the per-network line:

```text
attack aa:bb:cc:dd:ee:ff: uncracked -- thin (812 unique IVs from 41003 frames; WEP-40 floor is 1000, ~188 more needed)
```

That tells you exactly what is missing. There are two numbers per key length: the floor below which the statistical attacks are not run at all, and the count at which they start to succeed.

| Key length | Statistical attacks start at | Practical distinct-IV count |
|---|---|---|
| WEP-40 | 1,000 | ten to twenty thousand |
| WEP-104 | 5,000 | several tens of thousands |
| WEP-232 | 15,000 | more still |

Being over the floor does not mean a crack is likely -- it means one is possible. For WEP-40 in the best case, 5,000 distinct IVs cracked 6% of random keys, 8,000 cracked 44%, and 20,000 cracked 97% (the [measurement](how-it-works.md#the-convergence-floor)).

If a network is below the floor there is nothing to tune -- the dictionary, key reuse, and the potfile have already been tried, and for anything more you need more capture (or, for WEP-40, `--brute`). If it is *above* the floor and still uncracked, the diagnostics name the likely cause (multiple key slots, sparse known plaintext, or a packet count near the edge), and the flags below may tip it -- though for a capture that is simply short on IVs, more capture is the only real fix.

## Search depth: `--fudge` and `-x`

The KoreK and bias attacks keep every candidate octet whose vote is within a factor of the top vote; that factor is the **fudge**. Lowering the bar keeps more candidates (a wider, slower search that can recover a more ambiguous key):

```sh
wepwolf --fudge 8 capture.cap     # keep candidates voting >= top/8 (default: 5 for WEP-40, 2 for longer)
```

`-x / --bruteforce N` exhaustively sweeps the last **N** key octets (1-4, default 2). The trailing octets are the hardest for the statistical vote, so a deeper tail sweep can land a key the vote alone misses, at the cost of `256^N` work:

```sh
wepwolf -x 3 capture.cap          # sweep the last three octets exhaustively
```

Both mirror aircrack-ng's `-f` and `-x`. WEPWolf also runs an adaptive margin-ranked search automatically when the fast paths fail, so you often do not need these -- reach for them on a stubborn capture.

## Restricting the keyspace: `-c` and `--keylen`

If you expect an ASCII-passphrase key, `-c / --alnum` restricts candidate octets to printable ASCII, shrinking and speeding the search (aircrack-ng's `-c`).

`--keylen BITS` restricts the hypotheses to a single key size (`40`, `104`, or `232`). By default WEPWolf tries all three; the statistical attacks recover the length implicitly, so this is only a speed optimisation when you already know the size.

```sh
wepwolf --keylen 104 -c capture.cap
```

## Parallelism: `--threads`

The BSSID sweep and the multi-file ingest run on a work-stealing pool sized to all cores by default. `-j / --threads N` caps it -- useful to leave headroom on a shared machine:

```sh
wepwolf -j 4 /captures/
```

## Time budget: `--per-bssid-time-max`

Each network gets a wall-clock ceiling for its recovery attacks and for its brute force (default **300 seconds**; `0` = unlimited), so one hard network cannot starve a large run. A network earns a share of the ceiling in proportion to its distinct IVs -- the full 300 seconds at 20,000 and up, a quarter of it at 5,000 -- and for the deep search the share is split evenly between the attacks, so a slow one cannot starve the next.

Be realistic about what more time buys. A capture that is short on IVs is short on information, and time does not replace it: at 5,000 distinct IVs, quadrupling the ceiling from 300 to 1,200 seconds left the WEP-40 success rate where it was, at 6%. Where a higher ceiling has paid off is WEP-104 from ordinary IP traffic on a capture that already has tens of thousands of IVs, whose deep search over the octets real traffic leaves unknown can run for minutes:

```sh
wepwolf --per-bssid-time-max 1200 capture.cap   # up to twenty minutes per network
wepwolf --per-bssid-time-max 60 /captures/      # move faster through a large corpus
```

Two opt-in flags cap the *whole* phases across all networks: `--total-recovery-time-max` and `--total-brute-time-max` (default `0` = unlimited) -- once a total is spent, networks not yet started are skipped.

## The 40-bit brute: `--brute`

For a WEP-40 key with no statistical signal (for example a random key in a capture too thin for PTW), `--brute` enables an exhaustive 2⁴⁰ search. It applies only to WEP-40 (2¹⁰⁴ is infeasible) and runs one network at a time on the full machine, with a batched known-plaintext prefilter that rejects almost every candidate on four keystream octets. The live bar shows percent, keys-per-second, ETA, and the detected SIMD tier.

Budget it deliberately. Measured on an 8-core, 16-thread CPU it clears about 50 million keys per second, so:

| Budget | Keyspace covered |
|---|---|
| `--per-bssid-time-max 300` (the default) | ~1.3% |
| `--per-bssid-time-max 3600` | ~16% |
| `--per-bssid-time-max 0` | all of it, in about 6 hours |

A time-limited run searches a fixed set of contiguous slices of the keyspace, one per worker thread. It is not a sample of likely keys, so the chance it holds yours is just the fraction covered. If you want the key, give it the whole space:

```sh
wepwolf --brute --per-bssid-time-max 0 --bssid 00:11:22:33:44:55 capture.cap
```

`cargo bench` prints the keys-per-second figure, and the full-sweep time it implies, for your own machine.

## Performance notes

- **Parallel multi-file ingest.** A directory of captures is parsed concurrently; across many files this is a large wall-clock win over reading them one by one. The files are ingested in bounded batches that fold into the result and are freed before the next batch, and the merge is order-fixed -- so the result is identical regardless of thread scheduling, and peak memory does not grow with the number of files.
- **Fast where it counts.** Nearly all the cracking time is key verification -- every wrong candidate has to be proven wrong against the retained frames -- so that is where the work went. A candidate's frames are decrypted side by side on interleaved RC4 lanes, each frame's CRC-32 ICV is folded as it decrypts (on PCLMULQDQ where the CPU has it), and the check stops as soon as the outcome is settled. The 40-bit brute runs a batched known-plaintext prefilter on the same lanes. RC4 is inherently sequential within one stream, so the win is across independent streams, not within one; the lane kernel is portable code, and every fast path is validated byte-exact against a plain scalar reference.
- **Thin networks cost nothing.** A network below the distinct-IV floor is tried against the dictionary, reused keys, and the potfile, and that is all -- no time is spent on statistical searches that cannot converge. On a corpus that is mostly thin networks, that was most of the attack phase.
- **Bounded memory.** Packets are streamed; a multi-gigabyte file is never loaded whole. Peak memory is proportional to the WEP material harvested from the inputs (the IV/keystream samples and a few retained frames per network), not to the input file sizes.
- **Throughput.** On the aircrack-ng `wep_64_ptw.cap` reference capture (65,282 packets) the whole run takes a few hundredths of a second. A 70-million-packet input spread over 1,800 files, holding about 1,600 WEP networks, ingests in 1.3 seconds and finishes its attack phase in under a second on sixteen threads.

## Next

- [CLI Reference](../reference/cli.md) -- the full option list.
- [WEPWolf vs aircrack-ng](../comparison.md) -- how the defaults compare.
