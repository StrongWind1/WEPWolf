# Installation

WEPWolf is a single self-contained binary with no runtime dependencies. There are three ways to get it: install it from crates.io, download a prebuilt binary, or build it from source.

## From crates.io

```sh
cargo install wepwolf
```

This builds the latest published release with your local Rust toolchain and puts `wepwolf` in `~/.cargo/bin`. It needs Rust **1.95** or newer (the crate's minimum supported version); install Rust from [rustup.rs](https://rustup.rs/) if you do not have it.

## Prebuilt binaries

Every release publishes binaries on the [releases page](https://github.com/StrongWind1/WEPWolf/releases/latest):

| Platform | Asset |
|---|---|
| Linux x86_64 (static, musl) | `wepwolf-linux-x86_64` |
| Linux arm64 (static, musl) | `wepwolf-linux-arm64` |
| macOS (Apple Silicon and Intel in one file) | `wepwolf-macos-universal` |
| macOS, one architecture | `wepwolf-macos-arm64`, `wepwolf-macos-x86_64` |
| Windows x86_64 | `wepwolf-windows-x86_64-msvc.exe`, `wepwolf-windows-x86_64-gnu.exe` |
| Windows arm64 | `wepwolf-windows-arm64-msvc.exe` |

Download the one for your platform, make it executable, and put it on your `PATH`:

```sh
chmod +x wepwolf-linux-x86_64
mv wepwolf-linux-x86_64 ~/.local/bin/wepwolf
```

Each release also carries a `SHA256SUMS` file, a keyless Sigstore signature over it (`SHA256SUMS.sig`), and a build-provenance attestation per binary. To check a download against the checksums, and that it was built by this repository's release workflow:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify wepwolf-linux-x86_64 --repo StrongWind1/WEPWolf
```

The release binaries are built from a clean tree with no restored build cache.

## From source

You need a stable Rust toolchain, `git`, and `make` (the Makefile wraps the common cargo invocations; you can use `cargo` directly instead). The crate uses **edition 2024**, and the exact compiler version is pinned in `rust-toolchain.toml`, so `rustup` selects it automatically.

```sh
git clone https://github.com/StrongWind1/WEPWolf
cd WEPWolf
make release
```

`make release` produces an optimised native binary at `target/release/wepwolf`. The plain `cargo` equivalent is:

```sh
cargo build --release
```

Copy `target/release/wepwolf` onto your `PATH` (for example into `~/.local/bin` or `/usr/local/bin`) to run it as `wepwolf` from anywhere.

There is no Python, no `.NET`, and no external cracking tool to install. WEPWolf does its own RC4 and CRC-32.

## Verify the install

```sh
wepwolf --version
wepwolf --help
```

`--help` prints every option; the [CLI reference](../reference/cli.md) documents them in full.

## Run the test suite (optional)

From a source checkout, the project ships a comprehensive test suite and a set of spec audits:

```sh
make check       # fmt + clippy + tests + spec audits -- the merge gate
make check-all   # the full gate (adds supply-chain, docs, and hygiene checks)
cargo bench      # the throughput numbers quoted in these docs, on your machine
```

These also serve as living documentation of the expected behaviour: the parsing, the attacks, and the single verification path are all exercised end to end. The differential check against aircrack-ng runs when `aircrack-ng` and the reference capture are present, and skips cleanly otherwise.

## Platform notes

WEPWolf is developed and tested on Linux (`x86_64`). It is portable Rust and builds on macOS and Windows. The RC4 lane kernel behind the verifier and the brute prefilter is portable code and runs everywhere; the CRC-32 fold uses PCLMULQDQ on `x86_64` and the ARMv8 CRC instructions on `aarch64` when the CPU has them, and a table otherwise. Results are identical on every platform -- only throughput differs.

## Next steps

- [Guide -> Overview](../guide/index.md) -- the end-to-end workflow.
- [CLI Reference](../reference/cli.md) -- every flag and what it means.
- [WEPWolf vs aircrack-ng](../comparison.md) -- where it matches and where it pulls ahead.
