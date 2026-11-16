# The attacks

WEPWolf runs a suite of attacks against each WEP network and stops at the first key the [verifier](how-it-works.md#the-one-acceptance-path) accepts. You do not choose an attack -- the tool tries every one that has enough material -- but understanding them explains what a given capture can yield. Most need no configuration; a few take optional flags (see [Tuning](tuning.md) and the [CLI reference](../reference/cli.md)).

## At a glance

| Attack | Recovers a key from | Needs IVs? | Notes |
|---|---|---|---|
| **PTW** | ordinary captured traffic (ARP/IP) | yes | the headline attack; any key length |
| **RC4-bias database** | ordinary traffic, *fewer packets* | yes | the Sepehrdad "Smashing WEP" database aircrack-ng does not ship |
| **KoreK** | weak IVs (17 correlations) | yes | needs only the IV + first two keystream octets |
| **FMS** | weak IVs | yes | the classic Fluhrer-Mantin-Shamir attack |
| **Shared-Key auth** | a captured SKA handshake | yes | recovered keystream joins the pool the statistical attacks vote on |
| **Dictionary** | a list of candidate keys | no | a built-in list of common keys on every network; `-w` adds your own |
| **Keygen** | passphrases (`-w`) | no | Neesus-Datacom (40-bit) and MD5 (104-bit) generators |
| **Key reuse / potfile** | a key already recovered elsewhere | no | tried against every network still uncracked |
| **Brute force** | exhaustive WEP-40 | no | last resort, gated behind `--brute` |

Every candidate, whichever attack found it, is confirmed by RC4-decrypting real frames and matching the CRC-32 ICV before it is reported.

The "needs IVs" column is the dividing line for a thin capture. The attacks that need IVs run only once the capture holds enough distinct ones to [converge](how-it-works.md#the-convergence-floor) -- 1,000 for WEP-40, 5,000 for WEP-104, 15,000 for WEP-232. The rest are tried on every network, so a default or reused key is found however little traffic was captured.

## PTW

PTW (Pyshkin-Tews-Weinmann, building on Klein's correlation) is the modern WEP attack and WEPWolf's workhorse. It correlates the keystream octets recovered from known plaintext across many packets to vote for each key octet's cumulative sum, then resolves the votes into the key. It works on **ordinary traffic** -- you do not need weak IVs -- which is why it dominates FMS and KoreK in practice.

WEPWolf strengthens PTW beyond aircrack-ng's implementation: it casts a second per-packet vote (the Maitra-Paul estimate) alongside Klein's, and when the easy paths fail it runs an adaptive, margin-ranked search that allocates depth to the least-confident key positions under a bounded budget -- enough to recover the real-IP-traffic case (where the IPv4 Identification field leaves two noisy interior octets) that a fixed top-k search misses. PTW pins the strong leading octets and sweeps the weakest trailing octets exhaustively (two by default), mirroring aircrack's last-keybyte brute (`-x`).

## RC4-bias database (the "Smashing WEP" attack)

This is the single biggest reason WEPWolf can beat aircrack-ng on packet count. It is the complete Table 1 from Sepehrdad-Vaudenay-Vuagnoux (FSE 2013): the Klein-Improved and Maitra-Paul biases, the full KoreK A\_\* correlation family, the four negative biases, and SVV\_10 -- each voting for the same cumulative key sum in the key-independent frame, weighted by its published bias strength, resolved by the shared PTW search. Voting many biases together extracts more signal per packet than the Klein-only PTW aircrack-ng uses, so it recovers a WEP-104 key from a marginal capture (around 30k packets in testing) where Klein-only PTW does not. **aircrack-ng does not ship this attack.**

## KoreK and FMS

These are the classic weak-IV attacks. **FMS** (Fluhrer-Mantin-Shamir, 2001) exploits IVs of the form `(3 + b, 0xFF, X)` whose RC4 key schedule leaks the `b`-th key octet. **KoreK** (2004) generalises this into 17 statistical correlations that fire on the first two keystream octets and need no special IV pattern. WEPWolf ports aircrack-ng's correlation weights and its adaptive ratio-fudge search. On a clean modern capture PTW and the bias database usually win first; KoreK and FMS remain valuable on captures rich in weak IVs.

## Dictionary and keygen

**Dictionary** runs on every network, with or without a wordlist. WEPWolf ships a short built-in list of the keys that recur across real captures -- the hex `1234567890` and the ASCII `12345` lead it -- plus a few obvious weak patterns, so a network left on a default key cracks at once even from a handful of frames. Each entry is tried as a key directly, once as raw octets (when it is exactly 5, 13, or 29 bytes) and once hex-decoded (colons ignored), so both `password` and `1f:1f:1f:1f:1f` styles work.

Pass `-w / --wordlist FILE` to add your own candidates to that list and to enable the second attack:

- **Keygen** treats each line as a **passphrase** and runs the weak key generators consumer gear used: the Neesus-Datacom 40-bit generator (a 32-bit LCG that collapses the WEP-40 space to ~2²¹) and the MD5-based 104-bit generator.

Neither needs IVs, so both apply to a capture far too thin for statistics. Each candidate costs one verification, and the whole list is tried once per network and key length.

## Shared-Key authentication keystream

If the capture contains a WEP Shared-Key authentication exchange, WEPWolf pairs the cleartext challenge from frame 2 with the WEP-encrypted frame 3 to recover a long run of keystream for one IV "for free", and adds it to the pool the statistical attacks vote on as one more high-quality sample. A network cracked from a pool that includes a handshake is credited to `ska`. The handshake is one sample among the thousands a vote needs, so it helps a capture that already holds enough IVs; it cannot crack a thin one by itself.

## Key reuse and the potfile

Once the networks have been attacked, every key recovered is tried against every network still uncracked. Co-located access points of one organisation usually share a key, so cracking the busy one unlocks the quiet ones, which report `reuse`. A `--potfile` does the same across runs: keys recovered earlier are tried first, and a network they fit reports `potfile` without being attacked at all.

## Brute force

As a last resort, `--brute` enables an exhaustive search of the **WEP-40** key space (2⁴⁰). It applies only to WEP-40 -- 2¹⁰⁴ is infeasible, so longer keys are recovered statistically or by keygen/dictionary, never brute-forced -- and it runs after everything else, on networks still uncracked, one network at a time on the whole machine.

It is not naive: a batched known-plaintext prefilter runs eight RC4 key schedules in step and rejects almost every candidate on its first four keystream octets, so the full decrypt-and-verify runs only for the rare survivor. That clears about 7 million keys per second per core -- roughly 50 million per second on an 8-core, 16-thread CPU.

It is still slow in absolute terms, and the defaults are conservative, so know what you are asking for:

| | At ~50M keys/s |
|---|---|
| The whole 2⁴⁰ keyspace | about 6 hours (3 on average, if the key is in a random place) |
| The default 300 s per network | the first ~1.3% of the keyspace |

The per-network cap is `--per-bssid-time-max`, and it bounds the brute force as well as the statistical attacks. For a full sweep pass `--per-bssid-time-max 0` (and consider `--bssid` to aim it at one network); `--total-brute-time-max` caps the phase as a whole. A found key cancels the search within microseconds. `cargo bench` prints the keys-per-second figure for your machine.

## How the attacks are scheduled

- **One verified key wins.** Each network is run through the attacks in a fixed order -- the statistical attacks, then the keygen and the dictionary -- and the first key the verifier accepts ends the search.
- **Convergence floor.** A statistical attack runs for a key length only when the capture holds that length's floor of distinct IVs (1,000 / 5,000 / 15,000 for WEP-40 / 104 / 232). Below it the search cannot converge, so it is not started; a network that then has no dictionary, reuse, or potfile hit is reported "too thin".
- **Two passes per network.** A quick pass runs only the cheap argmax/top-k search of every attack across every key length; a full pass then adds the expensive backtracking. This stops a wrong key-length's heavy search from eating the whole time budget before the true length's cheap crack runs. Attacks whose work is the same in both passes -- dictionary, keygen, FMS -- run once.
- **Parallel recovery, serial brute force.** The recovery attacks run BSSID-parallel; the 40-bit brute runs one network at a time on the full pool, so two brute jobs never compete.
- **Per key slot.** A multi-key access point is attacked per Key ID, recovering a key per slot.
- **Key reuse.** A key recovered on one network is tried against the networks still uncracked, in parallel, so a shared organisational key unlocks them all.

## Next

- [Tuning & performance](tuning.md) -- the search knobs (`--fudge`, `-x`, `-c`), feasibility, and SIMD.
- [Output & diagnostics](output.md) -- reading the result and the attack attribution.
