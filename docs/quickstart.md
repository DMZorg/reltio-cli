# Quickstart

## 1. Build

```bash
cargo build --release --locked
export PATH="$PWD/target/release:$PATH"
reltio --version
```

## 2. Create A Profile

```bash
reltio profile add dev \
  --environment dev \
  --tenant ExampleTenant
```

The first profile becomes current. Use `reltio profile use <name>` to change the default. `--profile` always takes precedence for one invocation.

Resolution precedence is command flag, environment variable, selected profile, configured current profile, then safe defaults. Tenant and environment remain separate, and no value is inferred from an access token.

## 3. Authenticate

For a human workstation, configure a confidential client and enter the client secret through a hidden prompt:

```bash
reltio --profile dev auth login \
  --method client-credentials \
  --client-id example-client
```

For CI or an agent:

```bash
export RELTIO_CLIENT_ID='example-client'
export RELTIO_CLIENT_SECRET='injected-by-secret-manager'
reltio --profile dev auth check
```

The CLI caches only the access token in an owner-only local file. It does not copy a client secret into profile configuration. See [Authentication](authentication.md) for bearer, protected-file, and credential-process options.

## 4. Read Data

Direct reads are consistent:

```bash
reltio --profile dev --fields uri,label,type \
  entity get entities/00009qz
```

Indexed search is eventually consistent and bounded to 10,000 results:

```bash
reltio --profile dev entity search \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --max-items 25
```

Cursor scans are intended for exhaustive reads:

```bash
reltio --profile dev entity scan \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --max-items 1000 \
  --resume-file organizations.resume.json \
  > organizations.part-0001.jsonl
```

Resume files are bound to the exact CLI version, selected target and service route, normalized query, and page size that created them. Paths must be valid UTF-8. A mismatch or cursor older than the registry TTL fails before another request is sent, including during a long-running active scan. Cursor-bearing continuation requests are state-advancing and are never retried automatically after a transport failure; resume and reconcile rather than blindly replaying the cursor. Resume a failed scan into a new part file, then reconcile complete `meta.sequence` values against the resume sequence. Reusing `>` destroys the earlier part before the CLI starts, while blind `>>` can duplicate a page if output flushed before its checkpoint committed.

Repeated scan `--option` values are limited to the conservative locked-OpenAPI allowlist `sendHidden`, `searchByOv`, `ovOnly`, and `nonOvOnly`; `ovOnly` and `nonOvOnly` cannot be combined. The current English cursor documentation omits options, while OpenAPI and connector material use conflicting route and cursor contracts. The CLI refuses option transmission unless you explicitly add `--allow-unverified-scan-options`; verify behavior against a non-production tenant before using that acknowledgement.

## 5. Diagnose

```bash
reltio --profile dev auth status
reltio --profile dev doctor
reltio --profile dev doctor --online
reltio api practices check
```

`doctor` is offline unless `--online` is supplied. The online check performs the same reviewed one-record entity search as `auth check`. Exit `0` means every check passed; any warning or failure emits guarded `doctor_unhealthy` diagnostics on stderr, with the report under `error.details` when safely representable, and exits nonzero.
