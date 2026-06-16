# Contributing to wepwolf

Thanks for wanting to contribute. `wepwolf` recovers WEP keys from offline 802.11 captures. The correctness bar is strict in one specific way: the tool must never report a key it has not confirmed against the capture. A confident wrong answer is the worst possible bug.

This project is an early scaffold -- the parsing and attack engine is still being built -- so most contributions right now are foundational: input handling, frame parsing, and the WEP extraction and recovery stages.

## Before you write code

1. Read the [README](README.md) for the attack model: IV collection from WEP data frames feeding the FMS / KoreK / PTW statistical recovery, with a dictionary fallback.
2. Keep the layers separate. Capture I/O, link-layer decode, 802.11 parsing, WEP extraction, the recovery attack, and CLI/output must not bleed into each other. Protocol logic must not depend on transport or CLI.
3. Cite the source for any protocol constant or attack step in a comment -- the IEEE 802.11 WEP clauses for wire format, and the FMS (2001), KoreK, and PTW (2007) publications for the attack math.

## Repository layout

```
wepwolf/
|-- src/            Rust source (modules added as the pipeline lands)
|-- tests/          Integration tests + capture fixtures (added with the code they cover)
|-- .github/        CI / Security / Release workflows + issue + PR templates
|-- README.md       Project intro, attack model, roadmap
|-- CONTRIBUTING.md  How to set up, lint, test, and submit a patch (this file)
|-- Cargo.toml       Crate config + strict lint policy
`-- Makefile         Developer workflow + cross-platform release builds
```

The project runs strict clippy (pedantic + nursery + cargo) with zero warnings.

## Before you open a PR

```sh
make check-all
```

`make check-all` runs, in order: `fmt`, `clippy` (zero warnings), `cargo deny`, `cargo check`, `cargo test`, `cargo doc` with warnings-as-errors, ASCII hygiene, LF hygiene, and unused-dependency detection. A green `check-all` is required for review.

Install the pre-commit hook so you catch lint failures before push:

```sh
make hooks
```

## Commit messages

- Imperative mood, first line <= 72 chars.
- Conventional prefix where it fits (`feat:`, `fix:`, `refactor:`, `docs:`, `ci:`, `test:`, `chore:`).
- No emoji.
- The body should describe *what the change does* and *why*. A future reader reconstructing intent should be able to do so from the message alone.

## Dependency additions

The runtime dependency budget is deliberately small; `wepwolf` currently has none. Any new runtime crate requires a paragraph-long justification in the PR body and is subject to the `cargo deny` licence allow-list. Prefer pure-Rust crates with no C build dependency.

## Adding a capture fixture

- Under 1 MiB, commit to `tests/fixtures/`.
- Over 1 MiB, keep out-of-tree and reference it from benchmarks only.
- **Redact** real ESSIDs and client MAC addresses unless the capture comes from a lab network you control. wireshark and `editcap` can help.

## Authorized use

All contributions must be framed for authorized defensive / research use. Do not submit features that capture traffic, inject frames, or otherwise move this tool out of the "offline capture analysis" lane.
