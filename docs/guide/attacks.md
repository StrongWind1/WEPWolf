# The attacks

WEPWolf runs a suite of attacks against each WEP network, cheapest first, and stops at the first key the [verifier](how-it-works.md#the-one-acceptance-path) accepts. You do not choose an attack -- the tool tries every one that has enough material -- but understanding them explains what a given capture can yield. Most need no configuration; a few take optional flags (see [Tuning](tuning.md) and the [CLI reference](../reference/cli.md)).

## At a glance

| Attack | Recovers a key from | Needs a wordlist? | Notes |
|---|---|---|---|
| **PTW** | ordinary captured traffic (ARP/IP) | no | the headline attack; any key length |
| **RC4-bias database** | ordinary traffic, *fewer packets* | no | the Sepehrdad "Smashing WEP" database aircrack-ng does not ship |
| **KoreK** | weak IVs (17 correlations) | no | needs only the IV + first two keystream octets |
| **FMS** | weak IVs | no | the classic Fluhrer-Mantin-Shamir attack |
| **Dictionary** | a list of candidate keys | yes (`-w`) | each word tried raw and hex-decoded |
| **Keygen** | passphrases | yes (`-w`) | Neesus-Datacom (40-bit) and MD5 (104-bit) generators |
| **Shared-Key auth** | a captured SKA handshake | no | recovered keystream feeds the statistical attacks |
| **Brute force** | exhaustive WEP-40 | no | last resort, gated behind `--brute` |

Every candidate, whichever attack found it, is confirmed by RC4-decrypting real frames and matching the CRC-32 ICV before it is reported.

## PTW

PTW (Pyshkin-Tews-Weinmann, building on Klein's correlation) is the modern WEP attack and WEPWolf's workhorse. It correlates the keystream octets recovered from known plaintext across many packets to vote for each key octet's cumulative sum, then resolves the votes into the key. It works on **ordinary traffic** -- you do not need weak IVs -- which is why it dominates FMS and KoreK in practice.

WEPWolf strengthens PTW beyond aircrack-ng's implementation: it casts a second per-packet vote (the Maitra-Paul estimate) alongside Klein's, and when the easy paths fail it runs an adaptive, margin-ranked search that allocates depth to the least-confident key positions under a bounded budget -- enough to recover the real-IP-traffic case (where the IPv4 Identification field leaves two noisy interior octets) that a fixed top-k search misses. PTW pins the strong leading octets and sweeps the weakest trailing octet exhaustively, mirroring aircrack's last-keybyte brute (`-x`).

## RC4-bias database (the "Smashing WEP" attack)

This is the single biggest reason WEPWolf can beat aircrack-ng on packet count. It is the complete Table 1 from Sepehrdad-Vaudenay-Vuagnoux (FSE 2013): the Klein-Improved and Maitra-Paul biases, the full KoreK A\_\* correlation family, the four negative biases, and SVV\_10 -- each voting for the same cumulative key sum in the key-independent frame, weighted by its published bias strength, resolved by the shared PTW search. Voting many biases together extracts more signal per packet than the Klein-only PTW aircrack-ng uses, so it recovers a WEP-104 key from a marginal capture (around 30k packets in testing) where Klein-only PTW does not. **aircrack-ng does not ship this attack.**

## KoreK and FMS

These are the classic weak-IV attacks. **FMS** (Fluhrer-Mantin-Shamir, 2001) exploits IVs of the form `(3 + b, 0xFF, X)` whose RC4 key schedule leaks the `b`-th key octet. **KoreK** (2004) generalises this into 17 statistical correlations that fire on the first two keystream octets and need no special IV pattern. WEPWolf ports aircrack-ng's correlation weights and its adaptive ratio-fudge search. On a clean modern capture PTW and the bias database usually win first; KoreK and FMS remain valuable on captures rich in weak IVs.

## Dictionary and keygen

When you pass `-w / --wordlist FILE`, two extra attacks run:

- **Dictionary** tries each line as a key directly -- once as raw octets (when the line is exactly 5, 13, or 29 bytes) and once hex-decoded (colons ignored), so both `password` and `1f:1f:1f:1f:1f` styles work.
- **Keygen** treats each line as a **passphrase** and runs the weak key generators consumer gear used: the Neesus-Datacom 40-bit generator (a 32-bit LCG that collapses the WEP-40 space to ~2²¹) and the MD5-based 104-bit generator.

These are cheap and run early in the order, so a known or guessable passphrase is found before the statistical attacks spin up.

## Shared-Key authentication keystream

If the capture contains a WEP Shared-Key authentication exchange, WEPWolf pairs the cleartext challenge from frame 2 with the WEP-encrypted frame 3 to recover a long run of keystream for one IV "for free", and feeds it to the statistical attacks as one more high-quality sample. This can bootstrap a crack on a capture that is otherwise short on usable known plaintext.

## Brute force

As a last resort, `--brute` enables an exhaustive search of the entire **WEP-40** key space (2⁴⁰). It is off by default because it is slow, and it applies only to WEP-40 -- 2¹⁰⁴ is infeasible, so longer keys are recovered statistically or by keygen/dictionary, never brute-forced. WEPWolf's brute is not naive: it runs a SIMD-batched known-plaintext prefilter that rejects almost every candidate on its first few keystream octets, so the full decrypt-and-verify runs only for the rare survivor. The 40-bit grind runs one network at a time on the whole machine, bounded by `--per-bssid-time-max` (and by `--total-brute-time-max` over the whole phase), with microsecond cancellation once a key is found.

## How the attacks are scheduled

- **Cheapest first.** Each network is run through the attacks in cost order; the first verified key wins (FR-ATK-1).
- **Feasibility gate.** A statistical attack is skipped when the capture has too few distinct IVs for that key length, so a hopeless network is reported "too thin" instead of spun on. The floors are roughly 1k / 5k / 15k distinct IVs for WEP-40 / 104 / 232.
- **Two-pass per network.** A quick pass runs only the cheap argmax/top-k search of every attack across every key length; a full pass then adds the expensive backtracking. This stops a wrong key-length's heavy search from eating the whole time budget before the true length's cheap crack runs.
- **Parallel sweep, serial grind.** The cheap attacks run BSSID-parallel; the 40-bit brute runs one network at a time on the full pool, so two brute jobs never compete.
- **Per key slot.** A multi-key access point is attacked per Key ID, recovering a key per slot.
- **Key reuse.** A key recovered on one network is tried against co-located networks too thin to crack on their own, so a shared organisational key unlocks them all.

## Next

- [Tuning & performance](tuning.md) -- the search knobs (`--fudge`, `-x`, `-c`), feasibility, and SIMD.
- [Output & diagnostics](output.md) -- reading the result and the attack attribution.
