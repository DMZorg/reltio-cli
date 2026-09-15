# reltio-cli

`reltio` is an independent, agent-native Rust CLI for Reltio public APIs. It gives humans, shell scripts, CI jobs, and AI agents one production-oriented layer for profiles, multi-service routing, OAuth credentials, stable JSON, retries, endpoint guidance, and tenant safety.

> [!IMPORTANT]
> This project is unofficial and is not affiliated with or endorsed by Reltio. The current version is an `0.1.0-alpha.1` foundation release. Its typed network surface is intentionally read-only while mutation-specific safeguards are completed and reviewed.

## What Works

- Deterministic profile, environment, tenant, and service URL resolution.
- Supplied bearer, client-credentials, and strict credential-process authentication; complete Windows broker lifecycle validation remains pilot-gated.
- Owner-only token cache with cross-process locking and single-flight acquisition; Windows DACL/owner enforcement remains native-runtime and pilot-gated.
- Opaque multi-kilobyte token support and unconditional secret redaction.
- Typed consistent entity get and crosswalk lookup, bounded history and stored potential matches, POST-body entity search, and resumable cursor scan.
- Controlled raw reads with protected headers, no credential-forwarding redirects, mutation dry runs, and a fail-closed audit-contract gate.
- Stable JSON success/error envelopes, JSONL scan events, YAML, table, and raw output.
- Source-linked API-practice and endpoint registries validated against statically attributed test functions at build time; CI execution is a separate gate.
- Embedded agent skills, command schemas, shell completions, and offline/online diagnostics.

## Build

The repository pins Rust `1.85.0` and uses rustls, so no system OpenSSL installation is required. Linux builds use the native ACL library to verify owner-only files; install its development package first (`libacl1-dev` on Debian/Ubuntu or `libacl-devel` on Fedora/RHEL).

This alpha is currently a source-built development snapshot. Signed release archives, checksums, provenance, crates.io publication, Homebrew, and Scoop are not yet approved distribution channels; do not treat a local build as a published production release.

```bash
cargo build --release --locked
./target/release/reltio --version
```

## Five-Minute Start

```bash
# Profiles never contain a raw secret by default.
reltio profile add dev --environment dev --tenant ExampleTenant

# The Unix hidden prompt has a pseudo-terminal runtime test source. The Windows native-console path remains pilot-gated.
reltio --profile dev auth login \
  --method client-credentials \
  --client-id "$RELTIO_CLIENT_ID"

reltio --profile dev auth check
reltio --profile dev entity get entities/00009qz
```

Headless authentication uses environment injection without putting a secret in an argument:

```bash
export RELTIO_CLIENT_ID='example-client'
export RELTIO_CLIENT_SECRET='injected-by-ci'
reltio --profile dev entity search \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --max-items 25
```

For exhaustive retrieval, stream checkpointed JSONL:

```bash
reltio --profile dev entity scan \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --page-size 100 \
  --resume-file organizations.resume.json \
  > organizations.part-0001.jsonl
```

Resume state is accepted only by the exact CLI version, target, route, query, and page size that created it. After a failed scan, resume into a new part file. Do not redirect a resumed command over an earlier part or blindly append: reconcile complete `meta.sequence` values with the resume-file sequence first because a crash between output flush and checkpoint commit can duplicate a page.

## Agent Discovery

```bash
reltio agent guide
reltio skills list
reltio skills get reltio-data
reltio command schema entity.get
reltio api practices list
reltio --profile dev doctor
```

Finite stdout is JSON by default, even on a TTY. Diagnostics go to stderr. See [the output contract](docs/output-contract.md) and [error reference](docs/errors.md).

`doctor` exits `0` only when every check passes. Warnings and failures return a guarded `doctor_unhealthy` error on stderr, with check details whenever they are safely representable.

## Safety

- A token never selects or proves the intended tenant.
- HTTP redirects are not followed with authorization.
- Unknown raw reads are labeled `practice_coverage: unknown` and receive no automatic retries.
- Mutation dry runs require the normal endpoint and target acknowledgements. Actual raw mutations are refused with `mutation_audit_unavailable` until the versioned audit-result contract has implementation evidence.
- `--dry-run` resolves and validates an API request without sending it; mutation planning remains its primary use.
- Raw API bodies are refused on terminal stdout; redirect them deliberately. Active credentials and credential-shaped JSON fields remain redacted without applying diagnostic heuristics to ordinary entity values.
- No general option disables TLS verification, redaction, target validation, or protected-header policy.

Review [the threat model](docs/threat-model.md) and [security policy](SECURITY.md) before production pilot use.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo run -p reltio-cli -- api practices check --strict
cargo run -p reltio-cli -- api practices check --release-ready
```

CI and release-readiness tests run only on GitHub-hosted `ubuntu-latest`. CI runs the debug workspace suite with all features and the complete release workspace suite with default shipped features. Windows-native tests, macOS execution, and ARM execution require separate validation before claiming support on those platforms.

The second check is expected to fail during this incomplete alpha and is one mandatory product-MVP gate before a stable `v0.1.0` release. It does not replace platform tests, signing, provenance, packaging, or pilot approval. Stable readiness accepts only an exact `vMAJOR.MINOR.PATCH` tag, runs the default shipped feature set on Ubuntu, requires current upstream and dependency-policy evidence, and binds the tag, manifest target, and package version through `--expected-release`. Every required operation also needs independently approved, Cargo-discoverable implementation evidence; a command leaf or endpoint binding alone is insufficient. Every Reltio API operation must update `docs/endpoints.yaml`, `docs/reltio-api-practices.yaml`, `docs/test-evidence.yaml`, `docs/release-requirements.yaml`, command metadata, tests, and user/agent guidance together. Read the [product contract](docs/PRD.md) and [repository agent instructions](AGENTS.md) before implementation work.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Authentication](docs/authentication.md)
- [Output contract](docs/output-contract.md)
- [Errors](docs/errors.md)
- [API coverage](docs/api-coverage.md)
- [Threat model](docs/threat-model.md)
- [Product requirements](docs/PRD.md)
