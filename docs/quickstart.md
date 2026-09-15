# Quickstart

Go from a fresh checkout to your first Reltio read. The commands below use Bash or Zsh and the local profile name `dev`.

## Before you start

You need:

- Git and [Rust installed through rustup](https://rust-lang.org/tools/install/).
- A C/C++ build toolchain and, on Linux, the ACL development library (see below).
- Your Reltio environment and tenant ID, confirmed by your administrator.
- A confidential client's ID and secret with permission to read that tenant. If you only have a bearer token, use the [authentication guide](authentication.md) instead. Browser SSO login is not implemented yet.

This is a source-built alpha. CI runs on Ubuntu only; native Windows, macOS, and ARM need separate validation before support is claimed. The shell examples below are not PowerShell commands.

## 1. Install the CLI

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install --yes git build-essential libacl1-dev
```

On Fedora/RHEL, the ACL development package is `libacl-devel`; also install Git and your distribution's C/C++ build tools. On macOS, install Apple's Command Line Tools (`xcode-select --install`). Native Windows requires the Rust MSVC prerequisites described in the [Rust installation guide](https://rust-lang.org/tools/install/); native-console authentication has additional [pilot limitations](authentication.md#client-credentials).

After installing Rust, open a new terminal so Cargo is available. Then:

```bash
git clone https://github.com/aiadjacent/reltio-cli.git
cd reltio-cli
cargo install --path crates/reltio-cli --locked
export PATH="$HOME/.cargo/bin:$PATH"
reltio --version
```

Run the install command **inside the cloned repository**. It selects the pinned Rust `1.85.0` toolchain through rustup, builds an optimized executable, and normally installs it to `~/.cargo/bin/reltio`. If you customized `CARGO_HOME` or Cargo's install root, use that location's `bin` directory instead. No system OpenSSL installation is needed; the CLI uses rustls.

The first build can take several minutes. Successful version output identifies `reltio` and the current alpha version. The `export PATH` line lasts for this terminal session; add that same line to your shell's startup file (`~/.bashrc` for interactive Bash or `~/.zshrc` for Zsh) if rustup has not already configured it.

Prefer to keep the executable in the checkout? See [local development builds](development.md#build-without-installing).

## 2. Save your tenant details

Replace every `YOUR_…` placeholder with your own value:

```bash
reltio profile add dev \
  --environment 'YOUR_ENVIRONMENT' \
  --tenant 'YOUR_TENANT_ID'

reltio profile show dev
```

`dev` is a name you choose for this saved profile. It is separate from the actual environment and tenant. For a Data API URL shaped like:

```text
https://YOUR_ENVIRONMENT.reltio.com/reltio/api/YOUR_TENANT_ID
```

use the host prefix for `--environment` and the segment after `/api/` for `--tenant`. Do not paste the entire API path into the tenant field. Confirm the target with your administrator rather than inferring it from an access token.

For a custom Data API host, supply its HTTPS origin with `--base-url` when creating the profile:

```bash
reltio profile add custom \
  --environment 'YOUR_ENVIRONMENT' \
  --base-url 'https://YOUR_DATA_API_HOST' \
  --tenant 'YOUR_TENANT_ID'
```

Use `--profile custom` in subsequent commands if you choose this alternative. The origin should contain only the scheme and host (plus a port if needed), not `/reltio/api/...`. Authentication still uses the centralized service by default; service-specific overrides are available through `reltio profile add --help`.

The first profile becomes the default. You can change it later:

```bash
reltio profile use dev
reltio profile list
```

This guide keeps `--profile dev` explicit so each example names its target. Command flags override environment variables, which override saved profile values. Existing `RELTIO_ENVIRONMENT` or `RELTIO_TENANT` variables can therefore affect the target even with a selected profile; inspect `reltio --profile dev doctor` if the resolved target is unexpected.

## 3. Log in and verify access

```bash
reltio --profile dev auth login \
  --method client-credentials \
  --client-id 'YOUR_CLIENT_ID'
```

At the hidden prompt, paste your client secret and press Enter. Nothing is displayed as you type. If `RELTIO_CLIENT_SECRET` is already set, the CLI uses it instead of prompting. The secret is not copied into the profile; only the access token is cached in an owner-only file.

Now verify that these credentials can read the selected tenant:

```bash
reltio --profile dev auth check
```

This sends a small, one-record entity search. Success returns `"ok": true`; it checks tenant access as well as authentication. Login alone does not prove access to a particular tenant.

After a prompted login's token expires, run the same login command again. Ordinary data commands do not prompt for a missing client secret. For automatic acquisition, configure an [owner-only secret file or credential process](authentication.md), or use the CI pattern below.

## 4. Read and save data

### Fetch a few entities

```bash
reltio --profile dev entity search --max-items 5
```

Results appear as JSON. `data` contains the upstream result and `meta` describes the request. An empty result is valid when no visible entities match.

### Read one known entity

Replace `YOUR_ENTITY_ID` with an ID returned by the search. A full `entities/...` URI also works:

```bash
reltio --profile dev --fields uri,label,type \
  entity get 'YOUR_ENTITY_ID'
```

A direct entity read is consistent. Indexed search is eventually consistent, so a recent change can appear in a direct read before it appears in search.

### Filter by an entity type

Replace `YOUR_ENTITY_TYPE` with a type configured in your tenant:

```bash
reltio --profile dev entity search \
  --filter "equals(type,'configuration/entityTypes/YOUR_ENTITY_TYPE')" \
  --max-items 25
```

Search is bounded to the first 10,000 results. For larger retrievals, use a cursor scan as described below.

### Save a result

Choose a new filename; `>` overwrites an existing file:

```bash
reltio --profile dev entity search --max-items 5 > entities.json
```

Check the command's exit status before using the file. Errors go to stderr, so a failed command can leave an empty output file. See the [output contract](output-contract.md) for other formats and automation details.

## Use in CI or an agent

On a fresh CI runner, configure your secret manager to inject `RELTIO_CLIENT_ID` and `RELTIO_CLIENT_SECRET`. Supply the non-secret `RELTIO_ENVIRONMENT` and `RELTIO_TENANT` as job variables. No saved profile or interactive login is needed:

```bash
reltio auth check
reltio entity search --max-items 5 > entities.json
```

Run these only after the four variables are set and the CLI is installed. Keep shell tracing (`set -x`) off around secrets, and do not paste secret values into command arguments or commit them to scripts. The client ID and secret must be available when a new token is needed. See [Authentication](authentication.md) for managed bearer and broker alternatives.

For command discovery:

```bash
reltio agent guide
reltio skills list
reltio command schema entity.get
```

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `cargo: command not found` | Install Rust with rustup, then open a new terminal. |
| `reltio: command not found` | Add Cargo's `bin` directory to PATH as shown in step 1. Confirm the install command completed successfully. |
| Build cannot find `acl` or `sys/acl.h` | Install `libacl1-dev` on Ubuntu/Debian or `libacl-devel` on Fedora/RHEL, then rebuild. |
| `profile_already_exists` | Run `reltio profile show dev` and reuse it if correct, or choose a new profile name. |
| `client_secret_missing` after an earlier login | The cached token may have expired. Repeat the login command or configure a reusable secret source. |
| Login works but `auth check` fails | Check the environment, tenant ID, client permissions, and any tenant IP allowlist with your administrator. |
| Search returns no entities | Verify the tenant and read permissions; try the unfiltered five-entity example before using a type filter. |
| `doctor_unhealthy` | Inspect the reported checks. Warnings, including an expired documentation review, also produce this nonzero result; it does not always mean the network is broken. |
| `practice_review_stale` | Update to a revision with a renewed source review, or report it to the maintainers. Rebuilding the same revision does not renew its review. |

Useful diagnostics:

```bash
reltio --profile dev auth status
reltio --profile dev doctor
reltio --profile dev doctor --online
reltio api practices check
reltio entity search --help
```

`doctor` is offline by default. `--online` adds the same small tenant read used by `auth check`. Exit `0` means every check passed; warnings and failures return nonzero with guarded details on stderr. Consult the [error reference](errors.md) for specific codes and recovery.

## Advanced: stream a larger scan

Use a tenant-specific filter and a new output filename:

```bash
reltio --profile dev entity scan \
  --filter "equals(type,'configuration/entityTypes/YOUR_ENTITY_TYPE')" \
  --page-size 100 \
  --resume-file entities.resume.json \
  > entities.part-0001.jsonl
```

This streams JSONL and writes a checkpoint. Resume files are bound to the exact CLI version, target, service route, normalized query, and page size that created them. Paths must be valid UTF-8. A mismatch or cursor older than the registry TTL fails before another request, including during a long-running scan.

After failure, resume with the same options into a **new part file**. Cursor-bearing requests advance server state and are never retried automatically after a transport failure. Reconcile complete `meta.sequence` values with the checkpoint before combining files: a crash after output flush but before checkpoint commit can duplicate a page. Reusing `>` destroys an earlier part; blind `>>` can duplicate output. See the [streaming output contract](output-contract.md) before automating recovery.

Scan `--option` values are restricted to `sendHidden`, `searchByOv`, `ovOnly`, and `nonOvOnly`; the last two cannot be combined. The English documentation omits these options while OpenAPI and connector routes conflict. Transmission requires `--allow-unverified-scan-options` and remains provisional; verify against a non-production tenant before using it. The basic scan above does not need that acknowledgement.
