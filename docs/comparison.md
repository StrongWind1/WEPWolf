# WEPWolf vs aircrack-ng

aircrack-ng is the reference WEP cracker, and WEPWolf treats it as ground truth: every key WEPWolf recovers is differentially validated to match aircrack-ng's, and the performance bar is parity-or-better. WEPWolf targets the same attack family -- PTW, KoreK, FMS -- and then pulls ahead in the places below. This page is honest about both the wins and the deliberate trade-offs.

## Where they are at parity

WEPWolf re-implements aircrack-ng's WEP core faithfully:

- **The same attacks** -- PTW (Klein/σ voting), the 17 KoreK correlations, and FMS.
- **The same known-plaintext trick** -- the LLC/SNAP and ARP/IPv4 headers, with the IPv4 total-length read from the captured frame size (aircrack's `known_clear`).
- **The same search knobs** -- the adaptive ratio-fudge (`-f` / `--fudge`), last-keybyte brute force (`-x`), and printable-ASCII keyspace (`-c`).
- **The same IV accounting** -- each distinct IV voted once (aircrack's unique-IV table).
- **The same acceptance standard** -- a key is confirmed by RC4-decrypting frames and matching the CRC-32 ICV, requiring two agreements (~2⁻⁶⁴ false-accept).

On the captures it has been validated against, every WEP key aircrack-ng recovers, WEPWolf recovers, to the byte.

## Where WEPWolf pulls ahead

### Fewer packets: the Sepehrdad bias database

WEPWolf ships the complete Sepehrdad-Vaudenay-Vuagnoux "Smashing WEP" RC4-bias database (FSE 2013) -- Klein-Improved, Maitra-Paul, the full KoreK A\_\* family, the negative biases, and SVV\_10 -- voting together in one table. **aircrack-ng does not ship this.** Extracting more signal per packet, it recovers a WEP-104 key from a marginal capture (around 30k packets in testing) where the Klein-only PTW aircrack uses still cannot. Fewer packets to crack is the single biggest way to genuinely beat aircrack-ng, not just match it.

WEPWolf also strengthens PTW itself: a second per-packet Maitra-Paul vote alongside Klein's, with optimal `a_opt` bias weighting, and an adaptive margin-ranked search that recovers the real-IP-traffic case (the unpredictable IPv4 Identification field) a fixed top-k search misses.

### More known plaintext from the cleartext destination

The 802.11 destination MAC stays in the clear even when the payload is encrypted, and group MACs map deterministically to an L3 protocol. WEPWolf reads it to pick the right known plaintext per frame -- which is more information than aircrack-ng's content-based guess. The standout is **IPv6 Neighbor Discovery**: its header is checksum-free and contiguous, so WEPWolf mines a clean 16-octet keystream from frames the IPv4-shaped guess turns into noise.

### Fragments and truncated captures

WEP encrypts every fragment of a fragmented packet separately, and only the first one starts with the known LLC/SNAP header; a capture taken with a snap length holds only the front of each long frame, with the ICV cut off. aircrack-ng's cracker reads neither the fragment number nor the capture's original length, so it mines every such frame as if it were a whole one. WEPWolf takes known plaintext only from first fragments and length-derived plaintext only from whole packets, which keeps noise out of the votes, and it never keeps a cut-short frame as one of the few it verifies a key against -- a set of those would reject the correct key.

### Per-key-slot cracking

A WEP access point can run up to four keys at once (Key ID 0-3). aircrack-ng keys its vote table by BSSID alone, so a busy slot drowns the others and at most one key is reported. WEPWolf tags every sample with its Key ID and attacks each slot independently, recovering a key per slot.

### One tool, many files

- **Parallel multi-file ingest.** WEPWolf parses an entire directory of captures concurrently and merges a network's frames across every file; aircrack-ng reads its inputs serially. Across many files this is a large wall-clock win, and the merge is order-fixed so the result is deterministic.
- **Cross-file BSSID merge.** A network whose IVs are spread across many capture files is cracked from the union -- something a single-file run cannot reproduce.
- **Frame carving (`--carve`).** WEPWolf can collapse a multi-file, mixed-link-layer capture set into one self-contained pcap of exactly the WEP frames it cracks from -- re-crackable by either tool. aircrack-ng has no equivalent.
- **A hashcat-style potfile (`--potfile`)** carries recovered keys forward across runs.

### Faster and clearer

- **Lane-interleaved verification.** Checking a candidate key is where a WEP cracker spends its time. WEPWolf decrypts a candidate's retained frames side by side on interleaved RC4 lanes and stops the moment the outcome is settled.
- **Batched brute.** When you ask for the 40-bit brute, the same lanes run a known-plaintext prefilter that rejects almost every candidate on its first keystream octets -- about 7 million keys per second per core, ~5× a per-key full verify -- and the prefilter is anchored only on a frame whose plaintext is certain.
- **PCLMULQDQ ICV.** The CRC-32 the verifier runs for every candidate folds on PCLMULQDQ.
- **A default-key check on every network.** A built-in list of common and default keys, reused keys, and the potfile are tried on every WEP network, however little traffic it has.
- **A measured convergence floor.** The statistical attacks run only where the capture holds enough distinct IVs to converge (a replayed capture is frame-rich but IV-poor), so no time goes to searches that cannot succeed, and WEPWolf reports *why* each uncracked network failed -- distinct IVs vs raw frames, the shortfall, and the likely cause. aircrack-ng leaves you to infer it.

## A deliberate difference: passive and offline only

This is the most important distinction, and it is a **scope choice, not a deficiency to apologise for**. The aircrack-ng *suite* includes active tools -- packet injection, ARP replay, deauthentication, fake authentication, chopchop, fragmentation, Caffe-Latte -- that generate or manipulate traffic to farm IVs faster. WEPWolf does none of that, by design:

- It only ever reads capture files you already have. It never captures traffic, injects frames, deauthenticates clients, or touches a radio.
- That makes it safe to run anywhere (no radio, no interaction, no collateral effect) and trivial to reason about legally and operationally: give it a pcap, get keys.

If your workflow needs to *generate* IVs on a live network, that is the aircrack-ng suite's job (`aireplay-ng`, `airodump-ng`). WEPWolf is the offline cracker you point at the resulting capture -- and on that capture, it does more with the packets than aircrack-ng does.

## Honest caveats

Truthful comparison cuts both ways:

- **The IPv4 application protocols are recognition, not extra reach.** WEPWolf identifies mDNS / SSDP / IGMP / DHCP from the destination MAC, but their distinguishing bytes sit past the IPv4 header's ID/checksum/source gaps, which the WEP cumulative-sum key chain cannot bridge. So they improve classification precision, not contiguous keystream. IPv6 Neighbor Discovery is the exception that adds real reach.
- **No GPU brute.** The brute backend is CPU-only; there is no GPU backend yet (the seam exists for one). A full 2⁴⁰ sweep is about six hours on an 8-core CPU, and for a signal-less random WEP-40 key a GPU would be far faster.
- **No `.ivs` input.** WEPWolf reads full captures (pcap, pcapng, gzip); it does not read aircrack-ng's compact `.ivs` / `.ivs2` files.
- **The validation set is favourable.** WEPWolf's parity is proven on the real captures it has been tested against, but a checked-in real passive-IP WEP-104 vector is still missing from the public test set.

## In one sentence

On an offline capture, WEPWolf matches aircrack-ng's attacks and acceptance standard, then beats it on packet count (the bias database), on multi-file corpora (parallel deterministic ingest plus carving), on multi-key access points (per-slot cracking), on awkward captures (fragments and truncated frames handled for what they are), and on clarity (it tells you why a capture did not crack) -- while deliberately staying passive and offline.
