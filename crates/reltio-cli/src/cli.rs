use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use reltio_client::config::AuthMethod;
use reltio_client::service::Service;

#[derive(Debug, Parser)]
#[command(
    name = "reltio",
    version,
    about = "Agent-native CLI for safe Reltio data and platform operations",
    long_about = "A JSON-first, profile-aware CLI for Reltio public APIs. It centralizes routing, authentication, safety policy, API-practice enforcement, and stable automation contracts.",
    disable_help_subcommand = true,
    propagate_version = true,
    next_line_help = true
)]
pub struct Cli {
    /// Select a named profile for this invocation.
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Override the Reltio environment namespace or environment origin URL.
    #[arg(long, global = true)]
    pub environment: Option<String>,

    /// Override the Reltio tenant ID.
    #[arg(long, global = true)]
    pub tenant: Option<String>,

    /// Select output rendering. JSON is the finite-command default; scans default to JSONL.
    #[arg(long, global = true, value_enum)]
    pub output: Option<OutputFormat>,

    /// Emit compact JSON rather than indented JSON.
    #[arg(long, global = true)]
    pub compact: bool,

    /// Select response fields. Get Entity accepts lowercase fields and `attributes.<path>`.
    #[arg(long, global = true)]
    pub fields: Option<String>,

    /// Overall request or scan timeout (for example, 30s or 5m).
    #[arg(long, global = true, value_parser = parse_duration)]
    pub timeout: Option<Duration>,

    /// HTTP connection timeout.
    #[arg(long, global = true, value_parser = parse_duration)]
    pub connect_timeout: Option<Duration>,

    /// Disable all automatic safe retries, including a one-time auth replay.
    #[arg(long, global = true)]
    pub no_retry: bool,

    /// Resolve and validate an `api request` without sending it.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Confirm a non-interactive action. This never bypasses tenant checks.
    #[arg(long, global = true)]
    pub yes: bool,

    /// Confirm the exact tenant for a production, overridden, or profile-less mutation target.
    #[arg(long, global = true)]
    pub confirm_tenant: Option<String>,

    /// Suppress non-error diagnostics.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Increase diagnostic detail without exposing secrets.
    #[arg(long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Maximum buffered response size for finite API commands.
    #[arg(long, global = true, default_value_t = 32 * 1024 * 1024)]
    pub max_response_bytes: usize,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Table,
    Yaml,
    Raw,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage named routing, authentication, and safety profiles.
    Profile(ProfileCommand),
    /// Configure, inspect, validate, or clear authentication.
    Auth(AuthCommand),
    /// Retrieve or search Reltio entities.
    Entity(EntityCommand),
    /// Access reviewed API practices or issue a controlled raw request.
    Api(ApiCommand),
    /// Retrieve embedded, version-matched agent skills.
    Skills(SkillsCommand),
    /// Print concise instructions for autonomous agents.
    Agent(AgentCommand),
    /// Inspect stable machine-readable command metadata.
    #[command(name = "command")]
    Metadata(CommandMetadataCommand),
    /// Generate shell completion scripts.
    Completion(CompletionCommand),
    /// Diagnose configuration, routing, authentication, and practice freshness.
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
pub struct ProfileCommand {
    #[command(subcommand)]
    pub command: ProfileSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileSubcommand {
    /// List profiles without resolving credentials.
    List,
    /// Show one profile. Defaults to the selected/current profile.
    Show { name: Option<String> },
    /// Add a profile without storing a raw secret.
    Add(ProfileAddArgs),
    /// Update non-secret profile settings.
    Update(ProfileUpdateArgs),
    /// Make a profile the configured default.
    Use { name: String },
    /// Remove a profile and its selection state.
    Remove { name: String },
}

#[derive(Debug, Args)]
pub struct ProfileAddArgs {
    pub name: String,
    #[arg(long)]
    pub environment: Option<String>,
    /// Custom environment origin, such as <https://example.reltio.com>.
    #[arg(long)]
    pub base_url: Option<String>,
    #[arg(long)]
    pub tenant: Option<String>,
    #[arg(long)]
    pub production: bool,
    #[arg(long, value_parser = parse_profile_auth_method)]
    pub auth_method: Option<AuthMethod>,
    #[arg(long)]
    pub client_id: Option<String>,
    /// Owner-only file containing a client secret. The secret itself is never copied.
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// Service-specific URL override in SERVICE=URL form. Repeat as needed.
    #[arg(long = "service-url", value_name = "SERVICE=URL")]
    pub service_urls: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ProfileUpdateArgs {
    pub name: String,
    #[arg(long)]
    pub environment: Option<String>,
    #[arg(long)]
    pub base_url: Option<String>,
    #[arg(long)]
    pub tenant: Option<String>,
    #[arg(long, value_parser = clap::value_parser!(bool))]
    pub production: Option<bool>,
    #[arg(long, value_parser = parse_profile_auth_method)]
    pub auth_method: Option<AuthMethod>,
    #[arg(long)]
    pub client_id: Option<String>,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    #[arg(long = "service-url", value_name = "SERVICE=URL")]
    pub service_urls: Vec<String>,
    /// Remove all configured authentication metadata from this profile.
    #[arg(long)]
    pub clear_auth: bool,
}

#[derive(Debug, Args)]
pub struct AuthCommand {
    #[command(subcommand)]
    pub command: AuthSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthSubcommand {
    /// Configure a provider and acquire/import a token without a secret CLI argument.
    Login(AuthLoginArgs),
    /// Inspect provider and cache state without a network request.
    Status,
    /// Validate auth and tenant access with a one-record reviewed search.
    Check,
    /// Deliberately reveal the selected access token.
    Token {
        /// Required acknowledgement that token material will be written to stdout.
        #[arg(long)]
        show: bool,
    },
    /// Clear local cached token material. Remote revocation is not implied.
    Logout,
}

#[derive(Debug, Args)]
pub struct AuthLoginArgs {
    #[arg(long, value_parser = parse_auth_method)]
    pub method: AuthMethod,
    #[arg(long)]
    pub client_id: Option<String>,
    /// Read the client secret from stdin. Otherwise use `RELTIO_CLIENT_SECRET`, a secret file, or a hidden TTY prompt.
    #[arg(long)]
    pub secret_stdin: bool,
    /// Read an imported bearer token from stdin. Otherwise use `RELTIO_ACCESS_TOKEN`.
    #[arg(long)]
    pub token_stdin: bool,
    /// Optional lifetime for an imported bearer token.
    #[arg(long, value_parser = parse_duration)]
    pub expires_in: Option<Duration>,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// Credential-process executable. It is invoked directly, never through a shell.
    #[arg(long)]
    pub credential_process: Option<String>,
    /// Argument passed to the credential process. Repeat to preserve argument boundaries.
    #[arg(long = "credential-process-arg", allow_hyphen_values = true)]
    pub credential_process_args: Vec<String>,
}

#[derive(Debug, Args)]
pub struct EntityCommand {
    #[command(subcommand)]
    pub command: EntitySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum EntitySubcommand {
    /// Get one entity by ID or canonical `entities/<id>` URI (consistent read).
    Get(EntityGetArgs),
    /// Search the entity index with POST-body parameters (eventually consistent).
    Search(EntitySearchArgs),
    /// Stream an exhaustive cursor search as checkpointed JSONL.
    Scan(EntityScanArgs),
}

#[derive(Debug, Args)]
pub struct EntityGetArgs {
    pub entity: String,
    /// Retrieve the entity as of this Unix timestamp in milliseconds.
    #[arg(long = "time", value_name = "EPOCH_MILLISECONDS")]
    pub time: Option<u64>,
    /// Reviewed Get Entity response option. Repeat; inspect command schema for allowed values.
    #[arg(long = "option")]
    pub options: Vec<String>,
    /// Ask Reltio to merge duplicate crosswalks in the returned entity.
    #[arg(long)]
    pub merge_duplicate_crosswalks: bool,
    /// Limit values returned per attribute. This can intentionally truncate upstream values.
    #[arg(long)]
    pub default_max_values: Option<u32>,
    /// Override the survivorship group used for OV calculation.
    #[arg(long)]
    pub explicit_survivorship_group: Option<String>,
    /// Reverse-transcode RDM lookups for this destination system (Reltio Preview capability).
    #[arg(long)]
    pub reverse_transcode_lookups: Option<String>,
    /// Request masked values for viewing-mode entity retrieval.
    #[arg(long)]
    pub send_masked: bool,
}

#[derive(Debug, Args)]
pub struct EntitySearchArgs {
    #[arg(long)]
    pub filter: Option<String>,
    #[arg(long = "max-items", alias = "max", default_value_t = 50)]
    pub max_items: u32,
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    #[arg(long)]
    pub sort: Option<String>,
    #[arg(long, value_parser = ["asc", "desc"])]
    pub order: Option<String>,
    #[arg(long = "option")]
    pub options: Vec<String>,
    /// Limit values returned per attribute. This can intentionally truncate upstream values.
    #[arg(long)]
    pub default_max_values: Option<u32>,
    #[arg(long, value_parser = ["active", "all", "not_active"])]
    pub activeness: Option<String>,
    #[arg(long)]
    pub score_enabled: bool,
}

#[derive(Debug, Args)]
pub struct EntityScanArgs {
    #[arg(long)]
    pub filter: String,
    #[arg(long, default_value_t = 100)]
    pub page_size: u32,
    #[arg(long)]
    pub max_items: Option<u64>,
    #[arg(long)]
    pub max_pages: Option<u64>,
    /// Owner-only UTF-8 checkpoint state path.
    #[arg(long)]
    pub resume_file: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    pub checkpoint_every: u64,
    #[arg(long = "option")]
    pub options: Vec<String>,
    #[arg(long, value_parser = ["active", "all", "not_active"])]
    pub activeness: Option<String>,
}

#[derive(Debug, Args)]
pub struct ApiCommand {
    #[command(subcommand)]
    pub command: ApiSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ApiSubcommand {
    /// Issue a request through known service, auth, redaction, and safety policy.
    Request(ApiRequestArgs),
    /// Inspect source-linked upstream API practices.
    Practices(ApiPracticesCommand),
}

#[derive(Debug, Args)]
pub struct ApiRequestArgs {
    pub method: String,
    pub path: String,
    /// Named service. Workflow, RDM, and DTSS require an explicit {tenant}-scoped service URL.
    #[arg(long, value_parser = parse_service)]
    pub service: Service,
    #[arg(long, value_name = "KEY=VALUE")]
    pub query: Vec<String>,
    #[arg(long, value_name = "NAME: VALUE")]
    pub header: Vec<String>,
    /// JSON/text body, @path, or - for stdin.
    #[arg(long)]
    pub data: Option<String>,
    #[arg(long)]
    pub include_headers: bool,
    /// Required in addition to normal confirmations for an unreviewed mutation.
    #[arg(long)]
    pub allow_unreviewed_endpoint: bool,
}

#[derive(Debug, Args)]
pub struct ApiPracticesCommand {
    #[command(subcommand)]
    pub command: ApiPracticesSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ApiPracticesSubcommand {
    List,
    Show {
        id: String,
    },
    /// Validate catalog joins and optionally enforce the 14-day release freshness gate.
    Check {
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Debug, Args)]
pub struct SkillsCommand {
    #[command(subcommand)]
    pub command: SkillsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SkillsSubcommand {
    List,
    Get { name: String },
    Path { name: String },
}

#[derive(Debug, Args)]
pub struct AgentCommand {
    #[command(subcommand)]
    pub command: AgentSubcommand,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum AgentSubcommand {
    Guide,
}

#[derive(Debug, Args)]
pub struct CommandMetadataCommand {
    #[command(subcommand)]
    pub command: CommandMetadataSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CommandMetadataSubcommand {
    Schema { command: Option<String> },
}

#[derive(Debug, Args)]
pub struct CompletionCommand {
    #[command(subcommand)]
    pub command: CompletionSubcommand,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum CompletionSubcommand {
    Generate {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    #[value(name = "powershell", alias = "power-shell")]
    PowerShell,
    Zsh,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Also acquire credentials and perform a minimal reviewed tenant read.
    #[arg(long)]
    pub online: bool,
}

pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let duration = humantime::parse_duration(value).map_err(|error| error.to_string())?;
    if duration.is_zero() || duration > reltio_client::MAX_OPERATION_TIMEOUT {
        Err("duration must be greater than zero and at most 24 hours".to_owned())
    } else {
        Ok(duration)
    }
}

fn parse_auth_method(value: &str) -> Result<AuthMethod, String> {
    value
        .parse()
        .map_err(|error: reltio_client::ReltioError| error.to_string())
}

fn parse_profile_auth_method(value: &str) -> Result<AuthMethod, String> {
    let method = parse_auth_method(value)?;
    if method == AuthMethod::CredentialProcess {
        Err(
            "credential-process must be configured with `auth login` so arguments are preserved"
                .to_owned(),
        )
    } else {
        Ok(method)
    }
}

fn parse_service(value: &str) -> Result<Service, String> {
    value
        .parse()
        .map_err(|error: reltio_client::ReltioError| error.to_string())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_tree_is_internally_consistent() {
        Cli::command().debug_assert();
    }
}
