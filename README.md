# reltio-cli

`reltio` is an independent, agent-native Rust CLI for Reltio public APIs. It gives humans, shell scripts, CI jobs, and AI agents one production-oriented layer for profiles, multi-service routing, OAuth credentials, stable JSON, retries, endpoint guidance, and tenant safety.

> [!IMPORTANT]
> This project is unofficial and is not affiliated with or endorsed by Reltio. The current version is an `0.1.0-alpha.1` foundation release. Its typed network surface is intentionally read-only while mutation-specific safeguards are completed and reviewed.

## What Works

- Deterministic profile, environment, tenant, and service URL resolution.
- Supplied bearer, client-credentials, and strict credential-process authentication.
- Owner-only token cache with cross-process locking and single-flight acquisition.
- Opaque multi-kilobyte token support and unconditional secret redaction.
- Typed consistent entity get, POST-body entity search, and resumable cursor scan.
- Controlled raw requests with protected headers, no credential-forwarding redirects, dry runs, and unreviewed-mutation gates.
- Stable JSON success/error envelopes, JSONL scan events, YAML, table, and raw output.
- Source-linked API-practice and endpoint registries validated against real test evidence at build time.
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

# Interactive terminals receive a hidden secret prompt.
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
  > organizations.jsonl
```

Resume state is accepted only by the exact CLI version, target, route, query, and page size that created it.

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
- Unreviewed raw mutations require `--allow-unreviewed-endpoint --yes`; production, overridden, and profile-less targets also require exact `--confirm-tenant`.
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
```

Every Reltio API operation must update `docs/endpoints.yaml`, `docs/reltio-api-practices.yaml`, `docs/test-evidence.yaml`, command metadata, tests, and user/agent guidance together. Read the [product contract](docs/PRD.md) and [repository agent instructions](AGENTS.md) before implementation work.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Authentication](docs/authentication.md)
- [Output contract](docs/output-contract.md)
- [Errors](docs/errors.md)
- [API coverage](docs/api-coverage.md)
- [Threat model](docs/threat-model.md)
- [Product requirements](docs/PRD.md)
