# FAQ

## What is WEPWolf for?

Recovering the WEP key from 802.11 traffic you have already captured to a file. It is an offline cracker: you give it a pcap/pcapng/gzip capture, it finds the WEP networks and recovers their keys. It is intended for authorized security research, penetration testing with permission, and education.

## Is it legal to use?

WEPWolf operates on capture files you already possess. Running it on traffic you do not own or lack written authorization to analyze is illegal in most jurisdictions. You are responsible for using it only where you have permission. See the disclaimer in the project README.

## Does it need a wordlist?

No. WEP's design leaks the key statistically, so WEPWolf recovers most keys from the captured IVs alone with no wordlist. A wordlist (`-w`) only adds the dictionary and passphrase-generator attacks, which help when the key is a known or guessable passphrase.

## Why didn't my capture crack?

Almost always: too few **distinct** IVs. WEP recovery is statistical and scales with unique IVs, and WEP reuses its 24-bit IV heavily, so a capture can have many frames but little real material. Run with `--debug` -- WEPWolf prints, per uncracked network, the distinct-IV count, the feasibility floor, and how far short you are. The practical floors are roughly a few thousand distinct IVs for WEP-40, tens of thousands for WEP-104, and more for WEP-232. The fix is more capture; see [Tuning & performance](guide/tuning.md).

## Why is it passive only? aircrack-ng can inject packets to get IVs faster.

By design. WEPWolf never captures, injects, deauthenticates, or touches a radio -- it only reads files. That keeps it safe to run anywhere and simple to reason about legally. Generating IVs on a live network is the job of the aircrack-ng suite's active tools (`aireplay-ng`, `airodump-ng`); WEPWolf is the offline cracker you point at the resulting capture. On that capture, it does more with the packets than aircrack-ng -- see [WEPWolf vs aircrack-ng](comparison.md).

## What key lengths does it support?

The three real WEP sizes: WEP-40 (5-octet secret), WEP-104 (13-octet), and WEP-232 (29-octet). The 16-octet "152-bit" vendor extension is deliberately rejected -- it is not a standard WEP size, and aircrack-ng rejects it too.

## Can it crack WPA / WPA2 / WPA3?

No. WEPWolf is WEP-only by design. It classifies WPA networks (and reports them in the banner) but does not attack them. WPA is a different cryptographic problem handled by other tools.

## How do I know a recovered key is correct?

Every key is confirmed before it is reported: WEPWolf RC4-decrypts at least two retained frames with the candidate and checks each plaintext's CRC-32 against the transmitted ICV. Two independent agreements make a false accept negligible (~2⁻⁶⁴). This is the same standard aircrack-ng uses; there is no heuristic acceptance.

## What capture formats does it read?

pcap, pcapng, and gzip-compressed versions of either, over raw 802.11, radiotap, Prism, AVS, PPI, and Linux cooked link layers, with tiered FCS recovery for malformed link headers. Point it at a file or a directory (directories are recursed and captures auto-discovered).

## Does it read or write aircrack's `.ivs` format?

Not currently. WEPWolf reads full captures (pcap/pcapng/gzip) and can write a carved pcap of the WEP frames (`--carve`), but it does not yet read or write aircrack's compact `.ivs`/`.ivs2` format.

## Is there a GPU mode?

Not yet. The attacks and the verifier are CPU-SIMD accelerated (PCLMULQDQ CRC-32, a batched-RC4 brute prefilter), and the brute backend has a seam for a future GPU implementation, but none ships today.

## How is it built and tested?

It is a single Rust binary built with `make release` (see [Installation](getting-started/installation.md)). The project is spec-driven: every requirement maps to a test, enforced by `make audit`, and a differential test confirms recovered keys equal aircrack-ng's. `make check-all` runs the full gate.

## Where do I report bugs or contribute?

On [GitHub](https://github.com/StrongWind1/WEPWolf). See `CONTRIBUTING.md` for the development workflow.
