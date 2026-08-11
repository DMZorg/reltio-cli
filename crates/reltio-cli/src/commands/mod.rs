mod api;
mod auth;
mod discovery;
mod doctor;
mod entity;
mod profile;

use std::time::{Duration, Instant};

use reltio_client::auth::{TokenManager, TokenManagerOptions};
use reltio_client::cancellation::CancellationToken;
use reltio_client::config::{
    ConfigFile, ConfigPaths, ConfigStore, Environment, ResolutionOverrides, ResolvedTarget,
    resolve_target,
};
use reltio_client::entities::EntitiesClient;
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::http::{HttpClient, HttpOptions};
use reltio_client::redaction::OutputGuard;
use reltio_client::service::ServiceResolver;

use crate::cli::{ApiSubcommand, AuthSubcommand, Cli, Command, EntitySubcommand, OutputFormat};
use crate::output::RenderOptions;

#[derive(Debug, Clone)]
pub struct Globals {
    pub profile: Option<String>,
    pub environment: Option<String>,
    pub tenant: Option<String>,
    pub fields: Option<String>,
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    pub no_retry: bool,
    pub dry_run: bool,
    pub yes: bool,
    pub confirm_tenant: Option<String>,
    pub quiet: bool,
    pub verbose: u8,
    pub max_response_bytes: usize,
}

#[derive(Debug)]
pub struct Runtime {
    pub globals: Globals,
    pub cancellation: CancellationToken,
    pub environment: Environment,
    pub paths: ConfigPaths,
    pub store: ConfigStore,
    pub render: RenderOptions,
}

impl Runtime {
    pub fn new(
        cli: &Cli,
        environment: Environment,
        render: RenderOptions,
        cancellation: CancellationToken,
    ) -> Result<Self> {
        let paths = ConfigPaths::discover(&environment)?;
        let store = ConfigStore::new(paths.config_file.clone());
        Ok(Self {
            globals: Globals {
                profile: cli.profile.clone(),
                environment: cli.environment.clone(),
                tenant: cli.tenant.clone(),
                fields: cli.fields.clone(),
                timeout: cli.timeout,
                connect_timeout: cli.connect_timeout,
                no_retry: cli.no_retry,
                dry_run: cli.dry_run,
                yes: cli.yes,
                confirm_tenant: cli.confirm_tenant.clone().or_else(|| {
                    environment
                        .get("RELTIO_CONFIRM_TENANT")
                        .map(ToOwned::to_owned)
                }),
                quiet: cli.quiet,
                verbose: cli.verbose,
                max_response_bytes: cli.max_response_bytes,
            },
            cancellation,
            environment,
            paths,
            store,
            render,
        })
    }

    pub async fn dispatch(&self, command: Command) -> Result<()> {
        if self.cancellation.is_cancelled() {
            let output_guard = self.local_output_guard();
            return Err(ReltioError::new(
                "request_canceled",
                ErrorCategory::Canceled,
                "the command was canceled",
            )
            .with_details(serde_json::json!({
                "attempts": 0,
                "phase": "before_dispatch",
                "remote_response_received": false,
                "remote_request_completed": false,
                "remote_operation_completed": false,
                "remote_operation_state": "request_not_sent",
                "safe_to_replay": true
            }))
            .with_output_guard(output_guard));
        }
        if self.render.format == OutputFormat::Raw
            && !matches!(
                &command,
                Command::Api(crate::cli::ApiCommand {
                    command: ApiSubcommand::Request(_)
                }) | Command::Entity(crate::cli::EntityCommand {
                    command: EntitySubcommand::Get(_)
                        | EntitySubcommand::ByCrosswalk(_)
                        | EntitySubcommand::Search(_)
                        | EntitySubcommand::History(_)
                        | EntitySubcommand::Matches(_)
                }) | Command::Auth(crate::cli::AuthCommand {
                    command: AuthSubcommand::Token { .. }
                })
            )
        {
            return Err(ReltioError::usage(
                "raw_output_unsupported",
                "--output raw is supported only for API/entity response bodies and explicit token disclosure",
            ));
        }
        if self.render.format == OutputFormat::Raw && self.globals.dry_run {
            return Err(ReltioError::usage(
                "dry_run_raw_output_unsupported",
                "--output raw cannot represent a dry-run plan; use json or yaml",
            ));
        }
        if self.globals.dry_run
            && !matches!(
                &command,
                Command::Api(crate::cli::ApiCommand {
                    command: crate::cli::ApiSubcommand::Request(_)
                })
            )
        {
            return Err(ReltioError::usage(
                "dry_run_unsupported",
                "--dry-run is supported only by `api request`; it is never silently ignored",
            ));
        }
        match command {
            Command::Profile(command) => profile::run(self, command.command),
            Command::Auth(command) => auth::run(self, command.command).await,
            Command::Entity(command) => entity::run(self, command.command).await,
            Command::Api(command) => api::run(self, command.command).await,
            Command::Skills(command) => discovery::run_skills(self, command.command),
            Command::Agent(command) => discovery::run_agent(self, command.command),
            Command::Metadata(command) => discovery::run_command_metadata(self, command.command),
            Command::Completion(command) => discovery::run_completion(self, command.command),
            Command::Doctor(arguments) => doctor::run(self, arguments).await,
        }
    }

    pub fn config_and_target(&self) -> Result<(ConfigFile, ResolvedTarget)> {
        let config = self.store.load()?;
        let target = resolve_target(
            &config,
            &self.environment,
            &ResolutionOverrides {
                profile: self.globals.profile.clone(),
                environment: self.globals.environment.clone(),
                tenant: self.globals.tenant.clone(),
            },
        )?;
        Ok((config, target))
    }

    pub fn environment_output_guard(&self) -> OutputGuard {
        OutputGuard::from_known_secrets(
            &["RELTIO_ACCESS_TOKEN", "RELTIO_CLIENT_SECRET"]
                .into_iter()
                .filter_map(|name| self.environment.get(name))
                .collect::<Vec<_>>(),
        )
    }

    pub fn local_output_guard(&self) -> OutputGuard {
        let mut guard = self.environment_output_guard();
        match TokenManager::cache_output_guard(&self.paths.cache_dir) {
            Ok(cache_guard) => guard.merge(&cache_guard),
            Err(error) => match error.output_guard() {
                Some(cache_guard) => guard.merge(cache_guard),
                None => guard.merge(&OutputGuard::deny_all()),
            },
        }
        guard
    }

    pub fn timeout(&self) -> Result<Duration> {
        if let Some(timeout) = self.globals.timeout {
            return positive_timeout(timeout);
        }
        if let Some(value) = self.environment.get("RELTIO_TIMEOUT") {
            let parsed = humantime::parse_duration(value).map_err(|error| {
                ReltioError::usage(
                    "invalid_timeout",
                    format!("RELTIO_TIMEOUT is invalid: {error}"),
                )
            })?;
            return positive_timeout(parsed);
        }
        Ok(Duration::from_secs(30))
    }

    pub fn deadline_from(&self, started: Instant) -> Result<Instant> {
        started
            .checked_add(self.timeout()?)
            .ok_or_else(|| ReltioError::usage("invalid_timeout", "timeout is too large"))
    }

    pub fn ensure_not_cancelled(
        &self,
        phase: &'static str,
        local_state_committed: bool,
    ) -> Result<()> {
        if !self.cancellation.is_cancelled() {
            return Ok(());
        }
        Err(ReltioError::new(
            "request_canceled",
            ErrorCategory::Canceled,
            "the command was canceled",
        )
        .with_details(serde_json::json!({
            "phase": phase,
            "remote_response_received": false,
            "remote_request_completed": false,
            "remote_operation_completed": false,
            "remote_operation_state": "request_not_sent",
            "local_state_committed": local_state_committed,
            "safe_to_replay": !local_state_committed
        })))
    }

    pub fn token_manager(
        &self,
        target: &ResolvedTarget,
        options: TokenManagerOptions,
    ) -> Result<TokenManager> {
        self.token_manager_with_environment(target, &self.environment, options)
    }

    pub fn token_manager_with_environment(
        &self,
        target: &ResolvedTarget,
        environment: &Environment,
        mut options: TokenManagerOptions,
    ) -> Result<TokenManager> {
        options.no_retry |= self.globals.no_retry;
        TokenManager::from_target(
            target,
            environment,
            self.paths.cache_dir.clone(),
            options,
            self.timeout()?,
        )
    }

    pub fn http_client(&self) -> Result<HttpClient> {
        self.http_client_with_timeout(self.timeout()?)
    }

    pub fn http_client_until(&self, deadline: Instant) -> Result<HttpClient> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReltioError::new(
                "request_timeout",
                ErrorCategory::Timeout,
                "the command exceeded the overall timeout before the request was sent",
            )
            .with_details(serde_json::json!({
                "phase": "before_request",
                "remote_response_received": false,
                "remote_request_completed": false,
                "remote_operation_completed": false,
                "remote_operation_state": "request_not_sent",
                "local_state_committed": false,
                "safe_to_replay": true
            })));
        }
        self.http_client_with_timeout(remaining)
    }

    fn http_client_with_timeout(&self, timeout: Duration) -> Result<HttpClient> {
        HttpClient::new_with_cancellation(
            HttpOptions {
                timeout,
                connect_timeout: self
                    .globals
                    .connect_timeout
                    .unwrap_or(Duration::from_secs(10))
                    .min(timeout),
                no_retry: self.globals.no_retry,
                max_response_bytes: self.globals.max_response_bytes,
                retry_delay_cap: None,
            },
            self.cancellation.clone(),
        )
    }

    pub fn entities_client(
        &self,
        target: &ResolvedTarget,
        token_manager: TokenManager,
    ) -> Result<EntitiesClient> {
        Ok(EntitiesClient::new(
            ServiceResolver::new(target.clone()),
            self.http_client()?,
            token_manager,
        ))
    }

    pub fn entities_client_until(
        &self,
        target: &ResolvedTarget,
        token_manager: TokenManager,
        deadline: Instant,
    ) -> Result<EntitiesClient> {
        Ok(EntitiesClient::new(
            ServiceResolver::new(target.clone()),
            self.http_client_until(deadline)?,
            token_manager,
        ))
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn positive_timeout(timeout: Duration) -> Result<Duration> {
    if timeout.is_zero() || timeout > reltio_client::MAX_OPERATION_TIMEOUT {
        Err(ReltioError::usage(
            "invalid_timeout",
            "timeout must be greater than zero and at most 24 hours",
        ))
    } else {
        Ok(timeout)
    }
}
