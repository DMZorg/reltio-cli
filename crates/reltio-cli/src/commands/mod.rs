mod api;
mod auth;
mod discovery;
mod doctor;
mod entity;
mod profile;

use std::time::{Duration, Instant};

use reltio_client::auth::{
    CacheOutputGuardLease, TokenManager, TokenManagerOptions, TokenStatus,
    environment_credential_output_guard,
};
use reltio_client::cancellation::CancellationToken;
use reltio_client::config::{
    ConfigFile, ConfigPaths, ConfigReadLease, ConfigStore, Environment, ResolutionOverrides,
    ResolvedTarget, resolve_target,
};
use reltio_client::entities::EntitiesClient;
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::http::{HttpClient, HttpOptions};
use reltio_client::redaction::OutputGuard;
use reltio_client::service::ServiceResolver;

use crate::cli::{ApiSubcommand, AuthSubcommand, Cli, Command, EntitySubcommand, OutputFormat};
use crate::output::{
    Meta, OutputContext, PreparedOutput, RenderOptions, prepare_raw_guarded,
    prepare_success_guarded, prepare_warning_guarded,
};

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
    stderr_context: OutputContext,
    invocation_deadline: Instant,
}

#[derive(Debug)]
pub(crate) struct FinalOutputGuardLease {
    _cache: CacheOutputGuardLease,
    _config: ConfigReadLease,
    output_guard: OutputGuard,
}

impl FinalOutputGuardLease {
    pub fn output_guard(&self) -> &OutputGuard {
        &self.output_guard
    }
}

#[derive(Debug)]
struct ConfigOutputGuardLease {
    _config: ConfigReadLease,
    output_guard: OutputGuard,
}

impl ConfigOutputGuardLease {
    fn output_guard(&self) -> &OutputGuard {
        &self.output_guard
    }
}

pub(crate) async fn acquire_final_output_guard_lease(
    paths: &ConfigPaths,
    environment: &Environment,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<FinalOutputGuardLease> {
    let cache_dir = paths.cache_dir.clone();
    let store = ConfigStore::new(paths.config_file.clone());
    let environment = environment.clone();
    let cancellation = cancellation.clone();
    tokio::task::spawn_blocking(move || {
        let cache = TokenManager::cache_output_guard_lease_until(
            &cache_dir,
            deadline,
            Some(&cancellation),
        )?;
        let config = store
            .read_lease_until(deadline, || cancellation.is_cancelled())
            .map_err(|error| error.with_output_guard(cache.output_guard().clone()))?;
        let mut output_guard = environment_credential_output_guard(&environment);
        output_guard.merge(cache.output_guard());
        merge_configured_credential_guard_until(
            &mut output_guard,
            &config,
            &environment,
            deadline,
            &cancellation,
        )?;
        Ok(FinalOutputGuardLease {
            _cache: cache,
            _config: config,
            output_guard,
        })
    })
    .await
    .map_err(|error| {
        ReltioError::internal(format!("the final output-guard task failed: {error}"))
            .with_output_guard(OutputGuard::deny_all())
    })?
}

fn merge_configured_credential_guard_until(
    output_guard: &mut OutputGuard,
    config: &ConfigReadLease,
    environment: &Environment,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(config) = config.config() else {
        return Ok(());
    };
    let configured = TokenManager::configured_config_credential_output_guard_until(
        config,
        environment,
        false,
        deadline,
        Some(cancellation),
    )
    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(&configured);
    Ok(())
}

impl Runtime {
    pub fn new(
        cli: &Cli,
        environment: Environment,
        render: RenderOptions,
        cancellation: CancellationToken,
        invocation_deadline: Instant,
        stderr_context: OutputContext,
    ) -> Result<Self> {
        validate_global_options(cli)?;
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
            stderr_context,
            invocation_deadline,
        })
    }

    pub async fn dispatch(&self, command: Command) -> Result<()> {
        if self.cancellation.is_cancelled() {
            let output_guard = self.environment_output_guard();
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
        let logout = matches!(
            &command,
            Command::Auth(crate::cli::AuthCommand {
                command: AuthSubcommand::Logout
            })
        );
        if !logout {
            if let Some((recovered, output_guard)) =
                self.recover_pending_imported_bearer_cleanups().await?
            {
                return Err(ReltioError::new(
                    "imported_bearer_cleanup_recovered",
                    ErrorCategory::Conflict,
                    "an interrupted imported-bearer cleanup was recovered before the requested command ran",
                )
                .with_details(serde_json::json!({
                    "recovered_profiles": recovered,
                    "remote_response_received": false,
                    "remote_request_completed": false,
                    "remote_operation_completed": false,
                    "remote_operation_state": "request_not_sent",
                    "local_state_committed": true,
                    "requested_command_started": false,
                    "safe_to_replay": true
                }))
                .with_hint(
                    "The pending imported-bearer cleanup completed. Rerun the requested command.",
                )
                .with_output_guard(output_guard));
            }
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
            Command::Profile(command) => profile::run(self, command.command).await,
            Command::Auth(command) => auth::run(self, command.command).await,
            Command::Entity(command) => entity::run(self, command.command).await,
            Command::Api(command) => api::run(self, command.command).await,
            Command::Skills(command) => discovery::run_skills(self, command.command).await,
            Command::Agent(command) => discovery::run_agent(self, command.command).await,
            Command::Metadata(command) => {
                discovery::run_command_metadata(self, command.command).await
            }
            Command::Completion(command) => discovery::run_completion(self, command.command).await,
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
        reltio_client::auth::environment_credential_output_guard(&self.environment)
    }

    pub fn local_output_guard_snapshot(&self) -> OutputGuard {
        let mut guard = self.environment_output_guard();
        match TokenManager::cache_output_guard_snapshot_until(
            &self.paths.cache_dir,
            self.invocation_deadline,
            Some(&self.cancellation),
        ) {
            Ok(cache_guard) => guard.merge(&cache_guard),
            Err(error) => match error.output_guard() {
                Some(cache_guard) => guard.merge(cache_guard),
                None => guard.merge(&OutputGuard::deny_all()),
            },
        }
        if let Ok(config) = self.store.load() {
            match TokenManager::configured_config_credential_output_guard_until(
                &config,
                &self.environment,
                false,
                self.invocation_deadline,
                Some(&self.cancellation),
            ) {
                Ok(config_guard) => guard.merge(&config_guard),
                Err(error) => match error.output_guard() {
                    Some(config_guard) => guard.merge(config_guard),
                    None => guard.merge(&OutputGuard::deny_all()),
                },
            }
        }
        guard
    }

    pub async fn acquire_output_guard_lease(
        &self,
        deadline: Instant,
    ) -> Result<FinalOutputGuardLease> {
        acquire_final_output_guard_lease(
            &self.paths,
            &self.environment,
            deadline,
            &self.cancellation,
        )
        .await
    }

    async fn acquire_config_output_guard_lease(
        &self,
        deadline: Instant,
        environment_guard: OutputGuard,
    ) -> Result<ConfigOutputGuardLease> {
        let store = self.store.clone();
        let environment = self.environment.clone();
        let cancellation = self.cancellation.clone();
        tokio::task::spawn_blocking(move || {
            let config = store.read_lease_until(deadline, || cancellation.is_cancelled())?;
            let mut output_guard = environment_guard;
            merge_configured_credential_guard_until(
                &mut output_guard,
                &config,
                &environment,
                deadline,
                &cancellation,
            )?;
            Ok(ConfigOutputGuardLease {
                _config: config,
                output_guard,
            })
        })
        .await
        .map_err(|error| {
            ReltioError::internal(format!("the config output-guard task failed: {error}"))
                .with_output_guard(OutputGuard::deny_all())
        })?
    }

    pub(crate) async fn recover_pending_imported_bearer_cleanups(
        &self,
    ) -> Result<Option<(Vec<String>, OutputGuard)>> {
        // Commands such as doctor and logout intentionally handle malformed or
        // inaccessible configuration themselves. Recovery must not preempt
        // those command-specific fail-closed paths.
        let Ok(config) = self.store.load() else {
            return Ok(None);
        };
        let pending = config.pending_imported_bearer_cleanups;
        if pending.is_empty() {
            return Ok(None);
        }
        let deadline = self.invocation_deadline;
        let store = self.store.clone();
        let cache_dir = self.paths.cache_dir.clone();
        let cancellation = self.cancellation.clone();
        tokio::task::spawn_blocking(move || {
            recover_pending_imported_bearer_cleanups_sync(
                pending,
                &store,
                &cache_dir,
                deadline,
                &cancellation,
            )
        })
        .await
        .map_err(|error| {
            ReltioError::internal(format!("the profile-removal recovery task failed: {error}"))
                .with_output_guard(OutputGuard::deny_all())
        })?
    }

    pub async fn emit_prepared(&self, output: PreparedOutput, deadline: Instant) -> Result<()> {
        let lease = self.acquire_output_guard_lease(deadline).await?;
        let output = output.with_additional_guard(lease.output_guard())?;
        output
            .write_stdout_with_owner(lease, deadline, &self.cancellation)
            .await
    }

    pub async fn emit_prepared_with_owner<Owner>(
        &self,
        output: PreparedOutput,
        owner: Owner,
        owner_guard: &OutputGuard,
        deadline: Instant,
    ) -> Result<()>
    where
        Owner: Send + 'static,
    {
        let config_lease = self
            .acquire_config_output_guard_lease(deadline, self.environment_output_guard())
            .await?;
        output
            .with_additional_guard(owner_guard)?
            .with_additional_guard(config_lease.output_guard())?
            .write_stdout_with_owner((owner, config_lease), deadline, &self.cancellation)
            .await
    }

    pub async fn emit_prepared_disclosing_with_owner<Owner>(
        &self,
        output: PreparedOutput,
        owner: Owner,
        owner_guard: &OutputGuard,
        deadline: Instant,
        failure_guard: OutputGuard,
    ) -> Result<()>
    where
        Owner: Send + 'static,
    {
        let non_disclosable_environment_guard =
            reltio_client::auth::environment_non_disclosable_output_guard(&self.environment);
        let config_lease = self
            .acquire_config_output_guard_lease(deadline, non_disclosable_environment_guard)
            .await?;
        let mut failure_guard = failure_guard;
        failure_guard.merge(config_lease.output_guard());
        output
            .with_additional_guard(owner_guard)?
            .with_additional_guard(config_lease.output_guard())?
            .write_stdout_disclosing_with_owner(
                (owner, config_lease),
                deadline,
                &self.cancellation,
                failure_guard,
            )
            .await
    }

    pub async fn emit_success(
        &self,
        data: &serde_json::Value,
        meta: &Meta,
        deadline: Instant,
        guard: &OutputGuard,
    ) -> Result<()> {
        self.emit_prepared(
            prepare_success_guarded(data, meta, self.render, guard)?,
            deadline,
        )
        .await
    }

    pub async fn emit_raw(
        &self,
        bytes: &[u8],
        newline: bool,
        deadline: Instant,
        guard: &OutputGuard,
    ) -> Result<()> {
        self.emit_prepared(prepare_raw_guarded(bytes, newline, guard)?, deadline)
            .await
    }

    pub async fn emit_stderr_raw(
        &self,
        bytes: &[u8],
        deadline: Instant,
        guard: &OutputGuard,
    ) -> Result<()> {
        let lease = self.acquire_output_guard_lease(deadline).await?;
        let output = prepare_raw_guarded(bytes, false, guard)?
            .with_context(&self.stderr_context)
            .with_additional_guard(lease.output_guard())?;
        output
            .write_stderr_with_owner(lease, deadline, &self.cancellation)
            .await
    }

    pub async fn emit_warning(
        &self,
        message: &str,
        deadline: Instant,
        guard: &OutputGuard,
    ) -> Result<()> {
        let Some(output) = prepare_warning_guarded(message, self.globals.quiet, guard)? else {
            return Ok(());
        };
        let lease = self.acquire_output_guard_lease(deadline).await?;
        let output = output
            .with_context(&self.stderr_context)
            .with_additional_guard(lease.output_guard())?;
        output
            .write_stderr_with_owner(lease, deadline, &self.cancellation)
            .await
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
        let command_deadline = started
            .checked_add(self.timeout()?)
            .ok_or_else(|| ReltioError::usage("invalid_timeout", "timeout is too large"))?;
        Ok(command_deadline.min(self.invocation_deadline))
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
        TokenManager::from_target_scoped(
            target,
            environment,
            &self.paths.config_file,
            self.paths.cache_dir.clone(),
            options,
            self.timeout()?,
        )
    }

    pub async fn token_manager_output_guard(
        &self,
        manager: &TokenManager,
        deadline: Instant,
    ) -> Result<OutputGuard> {
        let manager = manager.clone();
        let cancellation = self.cancellation.clone();
        tokio::task::spawn_blocking(move || {
            manager.output_guard_until(deadline, Some(&cancellation))
        })
        .await
        .map_err(|error| {
            ReltioError::internal(format!("the token output-guard task failed: {error}"))
                .with_output_guard(OutputGuard::deny_all())
        })?
    }

    pub async fn token_disclosure_output_guard_lease(
        &self,
        manager: &TokenManager,
        token: &reltio_client::auth::AccessToken,
        deadline: Instant,
    ) -> Result<CacheOutputGuardLease> {
        let manager = manager.clone();
        let token = token.clone();
        let cancellation = self.cancellation.clone();
        tokio::task::spawn_blocking(move || {
            manager.access_token_disclosure_guard_lease_until(&token, deadline, Some(&cancellation))
        })
        .await
        .map_err(|error| {
            ReltioError::internal(format!("the token disclosure-guard task failed: {error}"))
                .with_output_guard(OutputGuard::deny_all())
        })?
    }

    pub async fn token_manager_status(
        &self,
        manager: &TokenManager,
        deadline: Instant,
    ) -> Result<TokenStatus> {
        let manager = manager.clone();
        let cancellation = self.cancellation.clone();
        tokio::task::spawn_blocking(move || {
            manager.status_until_controlled(deadline, &cancellation)
        })
        .await
        .map_err(|error| {
            ReltioError::internal(format!("the token status task failed: {error}"))
                .with_output_guard(OutputGuard::deny_all())
        })?
    }

    pub async fn profile_output_guard(
        &self,
        target: &ResolvedTarget,
        deadline: Instant,
    ) -> Result<OutputGuard> {
        let target = target.clone();
        let environment = self.environment.clone();
        let cache_dir = self.paths.cache_dir.clone();
        let cancellation = self.cancellation.clone();
        tokio::task::spawn_blocking(move || {
            TokenManager::profile_output_guard_until(
                &target,
                &environment,
                &cache_dir,
                deadline,
                &cancellation,
            )
        })
        .await
        .map_err(|error| {
            ReltioError::internal(format!("the profile output-guard task failed: {error}"))
                .with_output_guard(OutputGuard::deny_all())
        })?
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

fn validate_global_options(cli: &Cli) -> Result<()> {
    if cli.max_response_bytes == 0 {
        return Err(ReltioError::usage(
            "invalid_response_limit",
            "maximum response size must be greater than zero",
        ));
    }
    if cli.fields.is_some()
        && !matches!(
            &cli.command,
            Command::Entity(crate::cli::EntityCommand {
                command: EntitySubcommand::Get(_)
                    | EntitySubcommand::Search(_)
                    | EntitySubcommand::Scan(_)
            })
        )
    {
        return Err(ReltioError::usage(
            "fields_unsupported",
            "--fields is supported only by `entity get`, `entity search`, and `entity scan`; it is never silently ignored",
        ));
    }
    Ok(())
}

fn recover_pending_imported_bearer_cleanups_sync(
    pending: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    store: &ConfigStore,
    cache_dir: &std::path::Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Option<(Vec<String>, OutputGuard)>> {
    let mut recovered = Vec::with_capacity(pending.len());
    let mut recovery_guard = OutputGuard::default();
    for (profile, cache_keys) in pending {
        let already_recovered = recovered.clone();
        let mut plan = TokenManager::prepare_imported_bearer_removal_until(
            cache_dir,
            &cache_keys,
            deadline,
            cancellation,
        )
        .map_err(|mut error| {
            "imported_bearer_cleanup_failed".clone_into(&mut error.code);
            error.message =
                format!("failed to prepare imported-bearer recovery for profile {profile:?}");
            let cause = std::mem::take(&mut error.details);
            error.details = serde_json::json!({
                "profile": profile,
                "cause": cause,
                "recovered_profiles": already_recovered,
                "local_profile_committed": true,
                "local_cache_committed": serde_json::Value::Null,
                "cleanup_pending": true,
                "local_state_committed": true,
                "safe_to_replay": true
            });
            error.with_output_guard(recovery_guard.clone())
        })?;
        recovery_guard.merge(plan.output_guard());
        let mut cache_committed = false;
        let result = store.modify_until(
            deadline,
            || cancellation.is_cancelled(),
            |config| {
                if config.pending_imported_bearer_cleanups.get(&profile) != Some(&cache_keys) {
                    return Ok(false);
                }
                if config
                    .profiles
                    .get(&profile)
                    .and_then(|current| current.auth.bearer_cache_key.as_ref())
                    .is_some_and(|active| cache_keys.contains(active))
                {
                    return Err(ReltioError::profile(
                        "pending_bearer_cleanup_conflict",
                        format!(
                            "profile {profile:?} actively references a pending bearer cleanup key"
                        ),
                    ));
                }
                plan.commit_with_cancellation(cancellation)
                    .map_err(|mut error| {
                        let cache_restored = error.details["local_cache_restored"].as_bool();
                        "imported_bearer_cleanup_failed".clone_into(&mut error.code);
                        error.message = format!(
                            "failed to finish imported-bearer cleanup for profile {profile:?}"
                        );
                        error.details = serde_json::json!({
                            "profile": profile,
                            "cause": error.details,
                            "recovered_profiles": already_recovered,
                            "local_profile_committed": true,
                            "local_cache_committed": cache_restored.map(|restored| !restored),
                            "cleanup_pending": true,
                            "local_state_committed": true,
                            "safe_to_replay": true
                        });
                        error.with_output_guard(recovery_guard.clone())
                    })?;
                cache_committed = true;
                config.pending_imported_bearer_cleanups.remove(&profile);
                Ok(true)
            },
        );
        let recovered_profile = match result {
            Ok(recovered_profile) => recovered_profile,
            Err(error) if error.code == "imported_bearer_cleanup_failed" => return Err(error),
            Err(mut error) => {
                let marker_clear_committed = error.details["committed"].as_bool() == Some(true);
                "imported_bearer_cleanup_state_failed".clone_into(&mut error.code);
                error.message = format!(
                    "bearer cleanup for profile {profile:?} could not finish its durable recovery state"
                );
                error.details = serde_json::json!({
                    "profile": profile,
                    "cause": error.details,
                    "recovered_profiles": already_recovered,
                    "local_profile_committed": true,
                    "local_cache_committed": cache_committed,
                    "cleanup_pending": !marker_clear_committed,
                    "local_state_committed": true,
                    "safe_to_replay": true
                });
                return Err(error.with_output_guard(recovery_guard.clone()));
            }
        };
        drop(plan);
        if recovered_profile {
            recovered.push(profile);
        }
    }
    if recovered.is_empty() {
        Ok(None)
    } else {
        Ok(Some((recovered, recovery_guard)))
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

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use secrecy::SecretString;

    use super::*;

    #[test]
    fn stale_profile_removal_recovery_does_not_delete_a_restored_bearer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let config_path = directory.path().join("config.toml");
        let cache_dir = directory.path().join("cache");
        let store = ConfigStore::new(config_path.clone());
        store
            .modify_until(
                Instant::now() + Duration::from_secs(5),
                || false,
                |config| {
                    config.current_profile = Some("restored".to_owned());
                    config.profiles.insert(
                        "restored".to_owned(),
                        reltio_client::config::Profile {
                            environment: Some("dev".to_owned()),
                            tenant: Some("RestoredTenant".to_owned()),
                            auth: reltio_client::config::AuthProfile {
                                method: Some(reltio_client::config::AuthMethod::Bearer),
                                ..reltio_client::config::AuthProfile::default()
                            },
                            ..reltio_client::config::Profile::default()
                        },
                    );
                    Ok(())
                },
            )
            .expect("restored profile config");
        let token = "restored-bearer-token";
        let target = resolve_target(
            &store.load().expect("load restored profile config"),
            &Environment::default(),
            &ResolutionOverrides {
                profile: Some("restored".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("resolve restored profile");
        let cache_key = reltio_client::auth::imported_bearer_cache_key(&config_path, &target)
            .expect("derive restored bearer cache key");
        TokenManager::import_bearer(
            &cache_dir,
            &config_path,
            &target,
            SecretString::from(token),
            Some(Utc::now() + TimeDelta::hours(1)),
        )
        .expect("restored bearer cache");
        let stale_pending = [(
            "restored".to_owned(),
            std::collections::BTreeSet::from([cache_key]),
        )]
        .into_iter()
        .collect();

        let result = recover_pending_imported_bearer_cleanups_sync(
            stale_pending,
            &store,
            &cache_dir,
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
        )
        .expect("stale recovery is skipped");

        assert!(result.is_none());
        let config = store.load().expect("restored config remains readable");
        assert!(config.profiles.contains_key("restored"));
        assert!(config.pending_imported_bearer_cleanups.is_empty());
        let guard = TokenManager::cache_output_guard(&cache_dir).expect("cache guard");
        assert!(!guard.permits(token.as_bytes()));
    }
}
