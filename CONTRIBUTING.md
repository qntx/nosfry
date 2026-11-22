# Contributing to nosfry

This document covers how to develop, test, and release nosfry. Please read it
before opening a pull request.

## Principles

- Prefer small, reviewable pull requests with a clear problem statement.
- Every protocol decision lives in `nosfry-core`, which stays sans-IO: no async
  runtime, no I/O, no clock, no randomness. The runtimes only execute the
  commands it emits.
- Both editions share behavior. A change to relay semantics lands in both the
  native server and the Workers edition, with a case in the conformance suite.
- Remove obsolete paths instead of adding compatibility layers. Choose the
  simplest implementation that fully meets the requirement.
- Every queue, buffer, scan, and session set is bounded.

By contributing, you agree that your contributions are dual-licensed under the
project's [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) terms.

## Prerequisites

| Tool                     | Notes                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------- |
| Rust                     | The pinned toolchain (`rust-toolchain.toml`) plus `.github/nightly-toolchain` for fmt/clippy |
| `wasm32-unknown-unknown` | Target for `nosfry-core`, `nosfry-sql`, and `nosfry-worker`                                  |
| clang with wasm32        | `CC_wasm32_unknown_unknown`, for libsecp256k1 (e.g. `brew install llvm`)                     |
| `cargo-deny`             | License, ban, and advisory checks                                                            |
| Node                     | `npx` runs taplo and wrangler                                                                |
| `worker-build` 0.8.7     | Workers edition builds (`cargo install worker-build --version 0.8.7 --locked`)               |
| `just`                   | Optional task runner (`Justfile`)                                                            |

## Local gate

Run before every pull request; CI runs the same checks.

```bash
npx --yes @taplo/cli@0.7.0 fmt --check
cargo +"$(cat .github/nightly-toolchain)" fmt --all -- --check
cargo +"$(cat .github/nightly-toolchain)" clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
    cargo check -p nosfry-core -p nosfry-sql -p nosfry-worker --target wasm32-unknown-unknown
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
    cargo clippy -p nosfry-worker --target wasm32-unknown-unknown -- -D warnings
```

The nightly in `.github/nightly-toolchain` is bumped deliberately by a
maintainer pull request that also fixes any new lints; GitHub Actions is
not allowed to create pull requests in this repository, so no bot does
this.

The black-box conformance suite runs the same cases against both editions:

```bash
crates/nosfry-conformance/run.sh native
crates/nosfry-conformance/run.sh worker
```

Longer checks before a release:

```bash
NOSFRY_CRASH_CYCLES=60 cargo test -p nosfry --test crash
cargo +"$(cat .github/nightly-toolchain)" fuzz run <target> -- -max_total_time=600
```

## Layout

```text
crates/
  nosfry-core/         sans-IO protocol core (native + wasm32)
  nosfry-lmdb/         LMDB event store
  nosfry/              native relay binary
  nosfry-sql/          SQL event store for Durable Object SQLite (native + wasm32)
  nosfry-worker/       Cloudflare Workers edition
  nosfry-testkit/      reference model and shared store differential suite
  nosfry-conformance/  URL-driven black-box suite for both editions
fuzz/                  cargo-fuzz targets
bench/                 benchmark and soak harnesses
```

## Testing rules

- A new store behavior goes into the shared differential suite in
  `nosfry-testkit`, so LMDB and SQL are checked against the same model. The
  model encodes the native rule and never adapts to make a store pass.
- A new client-visible behavior gets a conformance case that passes on both
  editions. Tests never rely on ordering across two connections; an
  impossible-filter `REQ` on the first connection is the barrier.
- Commit proptest regression files.

## Commits and pull requests

- Conventional Commits in English: `<type>(<scope>): <subject>`, imperative,
  at most 50 characters, with a body explaining why.
- Record user-visible changes in [`CHANGELOG.md`](CHANGELOG.md) under
  `[Unreleased]`.
- Never commit secrets. `docs/` is local-only and gitignored.

## Releases

Maintainers only. `.github/workflows/release.yml` is the whole pipeline.

1. Run it as a dry run first: `gh workflow run release.yml --ref main`. A
   manual run runs the CI gate, builds every archive (Linux binaries against
   glibc 2.31 with cargo-zigbuild, macOS natively), starts each Linux binary
   in Debian 11, Debian 12 and Ubuntu 22.04 containers, builds and tests the
   container image on both architectures, and publishes nothing. Once
   release.yml is on `main`, a dry run can also be dispatched on a branch:
   `gh workflow run release.yml --ref <branch>`.
2. Run the crash test at 60 cycles, the fuzz targets above, and the 72-hour
   soak on the candidate commit (bench/SOAK.md).
3. Move the `[Unreleased]` notes in `CHANGELOG.md` into a dated
   `## [X.Y.Z] - YYYY-MM-DD` section; that section becomes the release notes.
4. Bump the workspace `version` and the path dependency versions in the root
   `Cargo.toml`.
5. Land steps 3 and 4 as one PR through the merge queue
   (`gh pr merge --squash --auto`); `main` is protected and does not take
   direct pushes.
6. Tag the merge commit and push:
   `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`. The tag run
   repeats the gate on the tagged commit, then publishes in this order: a
   draft GitHub release with checksums, SBOMs and attestations, the
   `ghcr.io/qntx/nosfry` image, the crates (`nosfry-core`, `nosfry-lmdb`,
   `nosfry`, with the organization's crates.io token), and finally the public
   release.

## Security

See [SECURITY.md](SECURITY.md).
