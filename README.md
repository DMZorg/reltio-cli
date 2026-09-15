# reltio-cli

Read and search Reltio data from your terminal. `reltio` manages tenant profiles, authentication, and structured output for people, scripts, and AI agents.

**Start here:** [Quickstart](docs/quickstart.md) · [Authentication options](docs/authentication.md) · [Troubleshooting](docs/quickstart.md#troubleshooting)

> [!IMPORTANT]
> This is an unofficial project, not affiliated with or endorsed by Reltio. The current version is `0.1.0-alpha.1`, built from source. Typed network commands are read-only; actual raw mutations are blocked while their safeguards are completed. Published packages and signed release downloads are not yet available as approved distribution channels.

## Quickstart

These examples use Bash or Zsh. You need Git, [Rust installed with rustup](https://rust-lang.org/tools/install/), and a Reltio client ID and secret with read access to your tenant. Ask your Reltio administrator for your environment, tenant ID, and credentials. Browser SSO login is not implemented in this alpha.

### 1. Install

On Ubuntu/Debian, install the build prerequisites first:

```bash
sudo apt-get update
sudo apt-get install --yes git build-essential libacl1-dev
```

Then clone and install the CLI:

```bash
git clone https://github.com/aiadjacent/reltio-cli.git
cd reltio-cli
cargo install --path crates/reltio-cli --locked
export PATH="$HOME/.cargo/bin:$PATH"
reltio --version
```

The first build may take several minutes. The repository pins Rust `1.85.0`; rustup selects it when you work inside the repository. The PATH line applies to this terminal; see the [installation notes](docs/quickstart.md#1-install-the-cli) for persistent setup and other platforms. CI currently validates Ubuntu only.

### 2. Save your tenant details

Replace the `YOUR_…` values before running these commands. `dev` is just a local profile name; it does not select a Reltio environment by itself.

```bash
reltio profile add dev \
  --environment 'YOUR_ENVIRONMENT' \
  --tenant 'YOUR_TENANT_ID'

reltio profile show dev
```

For a Data API URL of `https://YOUR_ENVIRONMENT.reltio.com/reltio/api/YOUR_TENANT_ID`, use the host prefix as the environment and the value after `/api/` as the tenant ID. Confirm these with your administrator. [Custom host?](docs/quickstart.md#2-save-your-tenant-details)

### 3. Log in and check access

```bash
reltio --profile dev auth login \
  --method client-credentials \
  --client-id 'YOUR_CLIENT_ID'

reltio --profile dev auth check
```

Enter your client secret at the hidden prompt. The CLI caches the access token, not the prompted secret. When that token expires, log in again or configure a [reusable secret source](docs/authentication.md#client-credentials). For automated runs, use [secret-manager injection](docs/quickstart.md#use-in-ci-or-an-agent).

### 4. Read your first entities

```bash
reltio --profile dev entity search --max-items 5
```

A successful command returns JSON with `"ok": true`, the result in `data`, and request context in `meta`. An empty result can be valid. No entity ID or entity-type name is needed for this first search.

**You're ready.** Continue with the [quickstart examples](docs/quickstart.md#4-read-and-save-data) to fetch a known entity, filter results, save JSON, or stream a larger scan.

## Common commands

| I want to… | Command |
| --- | --- |
| See saved profiles | `reltio profile list` |
| Choose a default profile | `reltio profile use dev` |
| Inspect cached authentication | `reltio --profile dev auth status` |
| Check tenant access | `reltio --profile dev auth check` |
| Read an entity by ID | `reltio --profile dev entity get YOUR_ENTITY_ID` |
| Check local setup | `reltio --profile dev doctor` |
| Include an online access check | `reltio --profile dev doctor --online` |
| Find command options | `reltio entity search --help` |
| Get agent instructions | `reltio agent guide` |
| Inspect a command schema | `reltio command schema entity.get` |

JSON is the default output, including in an interactive terminal. Errors go to stderr and return a nonzero exit code. `doctor` also returns nonzero for warnings; read its check details before treating that as a connection failure. See the [output contract](docs/output-contract.md) and [error reference](docs/errors.md).

## What you can do today

- Keep separate profiles for different environments and tenants.
- Authenticate with client credentials, supplied bearer tokens, or a credential process.
- Retrieve entities by ID or crosswalk, search, scan, and inspect history or stored potential matches.
- Use JSON, JSONL, YAML, table, or guarded raw output where supported.
- Discover command schemas, embedded skills, shell completions, and source-linked API guidance.

See [API coverage](docs/api-coverage.md) for exact limits and deferred features. A token does not choose your tenant. Unknown raw reads are marked as unreviewed, authenticated redirects are not followed, and there is no general switch to disable TLS verification or secret redaction. Review the [security policy](SECURITY.md) and [threat model](docs/threat-model.md) before pilot use.

## Documentation

| Guide | Use it for |
| --- | --- |
| [Quickstart](docs/quickstart.md) | Installation, first read, examples, and common setup problems |
| [Authentication](docs/authentication.md) | Bearer tokens, secret files, CI, and credential brokers |
| [Output contract](docs/output-contract.md) | Parsing results and handling streams |
| [Errors](docs/errors.md) | Error codes, exit codes, and recovery |
| [API coverage](docs/api-coverage.md) | Supported operations, safeguards, and release readiness |
| [Development](docs/development.md) | Building, testing, and contributing |
| [Product requirements](docs/PRD.md) | Project direction and planned capabilities |
