# Tuning & performance

WEPWolf cracks a typical capture with no flags at all. The knobs here help on **hard or marginal** captures, large corpora, and the rare case where you want to trade time for reach. Every flag is also in the [CLI reference](../reference/cli.md).

## When nothing cracks

The overwhelmingly common reason is too little material. WEP recovery is statistical and scales with **distinct** IVs (not raw frames -- a replayed capture is frame-rich but IV-poor). Run with `--debug` and read the per-network line:

```text
attack aa:bb:cc:dd:ee:ff: uncracked -- thin (812 unique IVs from 41003 frames; WEP-40 floor is 1000, ~188 more needed)
```

That tells you exactly what is missing. The rough floors:

| Key length | Practical distinct-IV count |
|---|---|
| WEP-40 | a few thousand |
| WEP-104 | tens of thousands |
| WEP-232 | more still |

If a network is below the floor there is nothing to tune -- you need more capture. If it is *above* the floor and still uncracked, the diagnostics name the likely cause (multiple key slots, sparse known plaintext, or a packet count near the edge), and the flags below may tip it.

## Search depth: `--fudge` and `-x`

The KoreK and bias attacks keep every candidate octet whose vote is within a factor of the top vote; that factor is the **fudge**. Lowering the bar keeps more candidates (a wider, slower search that can recover a more ambiguous key):

```sh
wepwolf --fudge 8 capture.cap     # keep candidates voting >= top/8 (default: 5 for WEP-40, 2 for longer)
```

`-x / --bruteforce N` exhaustively sweeps the last **N** key octets (1-4, default 1). The trailing octet is the hardest for the statistical vote, so a deeper tail sweep can land a key the vote alone misses, at the cost of `256^N` work:

```sh
wepwolf -x 2 capture.cap          # sweep the last two octets exhaustively
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

## Time budget: `--time-budget`

Each network gets a wall-clock budget for its statistical sweep (default **30 seconds**) so one hard network cannot starve a large run. Raise it to give the deeper search more room, or lower it to move faster through many files:

```sh
wepwolf --time-budget 120 capture.cap    # up to two minutes per network
```

The same budget also bounds the optional 40-bit brute grind per network.

## The 40-bit brute: `--brute`

For a WEP-40 key with no statistical signal (for example a random key in a capture too thin for PTW), `--brute` enables an exhaustive 2⁴⁰ search. It is off by default because it is slow. It applies only to WEP-40 (2¹⁰⁴ is infeasible) and runs one network at a time on the full machine, bounded by `--time-budget`, with a SIMD-batched prefilter that rejects almost every candidate cheaply. The live bar shows percent, keys-per-second, ETA, and the active SIMD tier.

```sh
wepwolf --brute --time-budget 600 capture.cap
```

## Performance notes

- **Parallel multi-file ingest.** A directory of captures is parsed concurrently; across many files this is a large wall-clock win over reading them one by one. The files are ingested in bounded batches that fold into the result and are freed before the next batch, and the merge is order-fixed -- so the result is identical regardless of thread scheduling, and peak memory does not grow with the number of files.
- **SIMD where it counts.** The CRC-32 ICV fold (run for every verify) uses PCLMULQDQ via an audited kernel; the 40-bit brute uses a lane-interleaved batched-RC4 prefilter. Both fall back to a byte-exact scalar path on non-`x86_64` targets and are validated equal to that path. RC4's key schedule is inherently sequential per stream, so the SIMD win is across keys, not within one.
- **Bounded memory.** Packets are streamed; a multi-gigabyte file is never loaded whole. Peak memory is proportional to the WEP material harvested from the inputs (the IV/keystream samples and a few retained frames per network), not to the input file sizes.
- **Throughput.** On the aircrack-ng `wep_64_ptw.cap` reference capture WEPWolf recovers the key in about a fifth of a second; a large multi-file input of tens of millions of packets ingests in a few seconds.

## Next

- [CLI Reference](../reference/cli.md) -- the full option list.
- [WEPWolf vs aircrack-ng](../comparison.md) -- how the defaults compare.
