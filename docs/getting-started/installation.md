# Installation

WEPWolf is a single self-contained Rust binary with no runtime dependencies. You build it from source with a stable Rust toolchain.

## Prerequisites

- A stable Rust toolchain. The minimum supported version (MSRV) is **1.95**, and the crate uses **edition 2024**; the pinned toolchain is recorded in `rust-toolchain.toml`, so `rustup` selects the right version automatically. Install Rust from [rustup.rs](https://rustup.rs/) if you do not have it.
- `git`, and `make` (the Makefile wraps the common cargo invocations; you can use `cargo` directly instead).

There is no Python, no `.NET`, and no external cracking tool to install. WEPWolf does its own RC4 and CRC-32.

## Build from source

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

## Verify the build

```sh
./target/release/wepwolf --version
./target/release/wepwolf --help
```

`--help` prints every option; the [CLI reference](../reference/cli.md) documents them in full.

## Run the test suite (optional)

If you want to verify the build end to end, the project ships a comprehensive test suite and a set of spec audits:

```sh
make check       # fmt + clippy + tests + spec audits -- the merge gate
make check-all   # the full gate (adds supply-chain, docs, and hygiene checks)
```

These also serve as living documentation of the expected behaviour: the parsing, the attacks, and the single verification path are all exercised end to end.

## Platform notes

WEPWolf is developed and tested on Linux (`x86_64`). It is portable Rust and builds on macOS and Windows, but the SIMD acceleration (the PCLMULQDQ CRC-32 fold and the batched-RC4 prefilter) is `x86_64`-specific; on other architectures the tool transparently falls back to a byte-exact scalar path, so results are identical and only the brute-force throughput differs. The capture parser, the attacks, and the verifier are fully portable.

## Next steps

- [Guide -> Overview](../guide/index.md) -- the end-to-end workflow.
- [CLI Reference](../reference/cli.md) -- every flag and what it means.
- [WEPWolf vs aircrack-ng](../comparison.md) -- where it matches and where it pulls ahead.
