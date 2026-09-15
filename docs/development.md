# Development

Read the [product contract](PRD.md) and [repository agent instructions](../AGENTS.md) before implementing changes. For installation and your first tenant read, use the [quickstart](quickstart.md).

## Build without installing

From the repository root, with the [build prerequisites](quickstart.md#1-install-the-cli) installed:

```bash
cargo build --release --locked
./target/release/reltio --version
```

This leaves the binary in the checkout. Use `./target/release/reltio` in place of `reltio` in examples, or add the build directory to PATH for the current terminal:

```bash
export PATH="$PWD/target/release:$PATH"
```

The repository pins Rust `1.85.0`. Use rustup so the selected toolchain follows `rust-toolchain.toml`.

## Run checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo run --locked -p reltio-cli -- api practices check --strict
```

The strict practice check requires a current documentation review. A stale review is a policy failure; passing tests or rebuilding does not renew it.

CI and release-readiness tests run only on GitHub-hosted `ubuntu-latest`. CI runs the debug workspace suite with all features and the complete release workspace suite with default shipped features. Windows-native tests, macOS execution, and ARM execution require separate validation before claiming support on those platforms.

## Release readiness

```bash
cargo run --locked -p reltio-cli -- api practices check --release-ready
```

This check is expected to fail during the incomplete alpha. It is a mandatory product-MVP gate before stable `v0.1.0`, not a replacement for platform tests, signing, provenance, packaging, or pilot approval. Signed release archives, checksums, provenance, crates.io publication, Homebrew, and Scoop are not yet approved distribution channels.

Stable readiness accepts only an exact `vMAJOR.MINOR.PATCH` tag, runs the default shipped feature set on Ubuntu, requires current upstream and dependency-policy evidence, and binds the tag, manifest target, and package version through `--expected-release`. Every required operation also needs independently approved, Cargo-discoverable implementation evidence; a command leaf or endpoint binding alone is insufficient.

Every Reltio API operation must update `endpoints.yaml`, `reltio-api-practices.yaml`, `test-evidence.yaml`, `release-requirements.yaml`, command metadata, tests, and user/agent guidance together. See [API coverage](api-coverage.md) for the current inventory and the required source-review process.
