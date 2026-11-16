# How it works

This page explains the cryptography WEPWolf exploits and the moving parts behind the attacks. You do not need any of it to run the tool, but it explains *why* a capture does or does not crack.

## WEP in one paragraph

WEP encrypts each frame with the RC4 stream cipher, keyed by a 24-bit Initialisation Vector (IV) prepended to the shared secret key: the RC4 seed is `IV(3 octets) || secret(5, 13, or 29 octets)`. The IV is sent in the clear at the start of every encrypted frame; the ciphertext is the plaintext XORed with the RC4 keystream, followed by a 4-octet CRC-32 Integrity Check Value (the ICV), also encrypted. Decryption is the same XOR. This design has two fatal weaknesses: the IV space is tiny (2²⁴, so IVs repeat), and RC4's key schedule leaks information about the secret through the first keystream octets. Everything below follows from those two facts. (Per IEEE 802.11-2007 §8.2.1.)

## Keystream from known plaintext

To attack the key statistically, WEPWolf needs the **keystream** for each IV -- but the keystream is `ciphertext XOR plaintext`, and the plaintext is encrypted. The trick is that the start of an 802.11 data frame is *predictable*. Every LLC/SNAP-encapsulated frame begins with the fixed header `AA AA 03 00 00 00`, so XORing the first ciphertext octets with that known plaintext recovers the first keystream octets for free.

How many octets you can recover sets how long a key you can attack. PTW needs `key_length + 2` keystream octets, so:

- **7 octets** (the bare SNAP header) is enough for **WEP-40**.
- **15+ octets** are needed for **WEP-104**, which the SNAP header alone does not reach.

So WEPWolf reconstructs *more* known plaintext from the predictable headers of the encapsulated protocol:

| Protocol | How it is identified | Known plaintext |
|---|---|---|
| LLC/SNAP | the first fragment of every packet | `AA AA 03 00 00 00` (+ the `0x08` EtherType high byte) |
| ARP | the fixed WEP-ARP MSDU length (36 or 54) | SNAP + the fixed ARP header (16 octets) |
| IPv4 | length, or a confirmed IPv4 destination MAC | SNAP + the IPv4 header start, total-length read from the frame size |
| IPv6 Neighbor Discovery | a `33:33:..` multicast destination MAC | SNAP + EtherType `86DD` + the IPv6 fixed-header start (16 octets) |
| EAPOL | the 802.1X PAE group destination MAC | SNAP + EtherType `888E` |

The IPv4 total-length field is the only variable part of the header, and WEPWolf reads it straight from the captured frame size -- exactly aircrack-ng's `known_clear` trick.

### The destination MAC is a free protocol hint

The 802.11 **Destination Address stays in the clear** even when the payload is encrypted, and multicast/broadcast group MACs map deterministically to an L3 protocol (RFC 1112 §6.4 for IPv4, RFC 2464 §7 for IPv6, IEEE 802.1X for EAPOL). WEPWolf reads that cleartext address to pick the right known plaintext per frame -- which is *more* information than aircrack-ng's content-based guess, and the reason IPv6 Neighbor Discovery frames (which the IPv4-shaped guess mis-keys from the EtherType on) become usable instead of noise. IPv6 has no header checksum and ND mandates a hop limit of 255, so its fixed header is unusually predictable.

!!! note "An honest reach limit"
    The deeper a protocol's *application* payload sits, the less of it is contiguously known. The WEP key forms a cumulative-sum chain (see below), so only known plaintext that is **contiguous from the first octet** extends the recoverable key length. For IPv4 the header's ID, checksum, and source-address fields are gaps the chain cannot bridge, so recognising mDNS / SSDP / IGMP / DHCP buys classification precision (routing each frame to the correct known plaintext) rather than extra key bytes. IPv6 Neighbor Discovery is the standout because its header is contiguous and checksum-free. IPv4 unicast ICMP carries no cleartext signal and is not mined; ICMPv6 is covered by the Neighbor-Discovery path.

## Known plaintext only where it is known

Two kinds of frame look like ordinary WEP data frames and are not, and treating them as ordinary quietly damages a crack.

**Fragments.** WEP encrypts each 802.11 fragment on its own, with its own IV and its own ICV. Only the *first* fragment of a packet starts with the LLC/SNAP header; a later fragment starts somewhere in the middle of the payload. XORing it against the SNAP header yields a "keystream" that is pure noise, one bad vote per fragment. WEPWolf reads the fragment number from the (cleartext) 802.11 header and mines known plaintext only from first fragments. A first fragment with more to follow is mined for its SNAP header only, because its length is the fragment's, not the packet's, and the ARP test and the reconstructed IP length both lean on the packet's length. Every fragment still counts as a WEP frame, and every fragment can still confirm a key -- its ICV covers just that fragment.

**Frames cut short by the capture.** A capture taken with a snap length keeps only the front of each long frame; the capture record says so (its original length exceeds its captured length). The front is intact, so the IV and the SNAP keystream are still good. But the tail is gone, and with it the ICV: the last four captured octets are ordinary data, and no key will ever make them check out. If such frames filled the handful of slots kept for the verifier, the correct key would be found and then rejected. WEPWolf never retains a cut frame for verification, and does not use its (wrong) length to reconstruct plaintext. When it [carves](output.md#carving-the-wep-frames) such a frame it preserves the original length, so the carved file reads the same way.

The 40-bit brute force relies on the same discipline. Its fast path rejects candidates on the first four keystream octets of one frame, so that frame's leading plaintext has to be certain. WEPWolf anchors it on a first-fragment data frame (LLC/SNAP) or a Shared-Key authentication frame 3 (whose first four octets are fixed by the standard), never on whichever frame happened to be captured first.

## Two-keystream voting for the unpredictable octet

One IPv4 header octet -- the flags byte carrying the Don't-Fragment bit -- is `0x40` about 85% of the time and `0x00` the rest. Rather than guess, WEPWolf votes it **both ways**, weighted by the observed 220/36 split, so the key octet it feeds votes correctly whatever the frame's DF state. This mirrors aircrack-ng's `known_clear`.

## How the key bytes fall out: the cumulative-sum chain

The statistical attacks (PTW, the bias database) work in a key-independent frame: they simulate RC4's key schedule over the **IV octets only** and, for each position `i`, vote for the cumulative sum `sigma_i = K[0] + K[1] + ... + K[i]`. Recovering an individual key byte is then a subtraction: `K[i] = sigma_i - sigma_{i-1}`. This is why contiguity matters -- to get `K[i]` you need both `sigma_i` and `sigma_{i-1}`, which need keystream at consecutive positions. A gap in the known plaintext leaves a position the search must brute-force.

When the votes are clean the answer is just the most-voted value at each position. When a capture is marginal, the leading "strong" octets are confident but the trailing ones are ambiguous, so WEPWolf ranks the positions by how decisive their vote is and searches the least-confident ones more deeply under a bounded budget -- the deepest rung even sweeps a pair of fully-unknown octets (the IPv4 Identification field that real traffic leaves unpredictable).

## Distinct-IV voting

Because WEP reuses its 24-bit IV heavily, a replayed packet contributes the same IV, the same keystream, and therefore the same vote. Counting it more than once biases the result, so WEPWolf -- like aircrack-ng's unique-IV table -- tallies each **distinct** IV exactly once. This is also why feasibility is gauged by the distinct-IV count, not the raw frame count: a capture that replays one packet can be frame-rich yet IV-poor.

## The convergence floor

Each vote is only slightly better than chance, so the right answer emerges from thousands of them. Below a certain number of distinct IVs the vote tables are noise and a search over them can only run until its budget is spent. WEPWolf therefore runs the statistical attacks for a key length only once the capture holds that length's floor: **1,000** distinct IVs for WEP-40, **5,000** for WEP-104, **15,000** for WEP-232.

The WEP-40 floor is measured, not guessed. With random keys and the best possible material -- every IV carrying a fully known keystream -- and every statistical attack given its turn:

| Distinct IVs | Keys recovered |
|---|---|
| 8 to 512 | 0 of 400 at each of seven counts |
| 1,000 | 0 of 160 |
| 2,000 and 3,000 | 0 of 48 each |
| 5,000 | 6% |
| 8,000 | 44% |
| 20,000 | 97% |
| 40,000 | 100% |

So the floor sits a factor of three below the highest count at which nothing cracked, and real traffic, whose known plaintext is noisier, needs more IVs rather than fewer. The floor gates only the attacks that vote. The dictionary of common and default keys, your wordlist, key reuse, the potfile, and the brute force need no IVs and are tried on every network.

## Per-key-slot separation

A WEP access point can run up to four keys at once (Key ID 0-3), and their frames use different key schedules. Pooling every slot's votes into one table -- which is all keying by BSSID can do -- lets a busy slot drown the others. WEPWolf tags every sample with its Key ID and, for a multi-key access point, attacks each slot from only its own frames, recovering a key per slot.

## The one acceptance path

No statistical attack is trusted on its own. Every candidate key -- from any attack -- is routed through a single function that:

1. RC4-decrypts a retained frame with `IV || candidate`,
2. checks the decrypted plaintext's CRC-32 against the transmitted ICV,
3. requires **two** independent frames to agree.

A wrong key matches one frame's ICV with probability ~2⁻³², so two agreements bound a false accept at ~2⁻⁶⁴. This is the same standard aircrack-ng applies, and it is the only place in WEPWolf that can declare a key correct. WEP's ICV is the **IEEE CRC-32** (polynomial `0xEDB88320`), folded on PCLMULQDQ for speed -- not the CRC-32C the SSE4.2 `crc32` instruction computes.

A few complete frames are kept per key slot (up to eight) so that one corrupt frame cannot veto a correct key: any two agreeing is enough. Nearly every candidate a search tries is wrong, and proving a key wrong means failing all but one of those frames, so this check is where the searches spend their time. WEPWolf decrypts a candidate's frames side by side -- several independent RC4 streams advanced in step, which a CPU overlaps far better than one after another -- folds each frame's CRC as it decrypts, and stops the moment the outcome is settled. None of that changes the rule; it only makes each wrong key cheaper to reject.

## Next

- [The attacks](attacks.md) -- each attack and when it fires.
- [Tuning & performance](tuning.md) -- the search knobs and the feasibility floor.
