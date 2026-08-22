use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
#[cfg(not(windows))]
use std::time::Duration;
use std::time::Instant;

use chrono::{TimeDelta, Utc};
use is_terminal::IsTerminal;
use reltio_client::auth::{
    AccessToken, TokenManager, TokenManagerOptions, imported_bearer_cache_key,
    new_imported_bearer_cache_generation, stored_imported_bearer_cache_key,
};
use reltio_client::config::{
    AuthMethod, AuthProfile, ConfigFile, Profile, ResolutionOverrides, resolve_target,
};
use reltio_client::entities::EntitySearchRequest;
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::registry::PracticeCoverage;
use reltio_client::service::{Service, ServiceResolver};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::{AuthLoginArgs, AuthSubcommand, OutputFormat};
use crate::commands::Runtime;
use crate::output::{Meta, prepare_raw_guarded, prepare_success_guarded};

const SECRET_INPUT_LIMIT: u64 = 1024 * 1024;
const LOGIN_EXPIRY_SKEW_SECONDS: i64 = 5;

enum PendingLogin {
    Bearer {
        token: SecretString,
        expires_at: Option<chrono::DateTime<Utc>>,
    },
    Managed {
        manager: Box<TokenManager>,
        token: AccessToken,
    },
}

#[derive(Clone, Copy)]
enum AuthRemoteOutcome {
    NotSent,
    Unknown,
    Succeeded,
}

pub async fn run(runtime: &Runtime, command: AuthSubcommand) -> Result<()> {
    match command {
        AuthSubcommand::Login(arguments) => login(runtime, arguments).await,
        AuthSubcommand::Status => status(runtime).await,
        AuthSubcommand::Check => check(runtime).await,
        AuthSubcommand::Token { show } => reveal_token(runtime, show).await,
        AuthSubcommand::Logout => logout(runtime).await,
    }
}

async fn login(runtime: &Runtime, arguments: AuthLoginArgs) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    validate_login_arguments(&arguments)?;
    if runtime.environment.contains("RELTIO_ACCESS_TOKEN") && arguments.method != AuthMethod::Bearer
    {
        return Err(ReltioError::auth(
            "access_token_override_active",
            "RELTIO_ACCESS_TOKEN overrides profile authentication",
        )
        .with_hint("Unset RELTIO_ACCESS_TOKEN before configuring another provider."));
    }
    let config = runtime.store.load()?;
    let profile_name = selected_profile(runtime, &config)?;
    let resolution_overrides = ResolutionOverrides {
        profile: runtime.globals.profile.clone(),
        environment: runtime.globals.environment.clone(),
        tenant: runtime.globals.tenant.clone(),
    };
    let previous_target = resolve_target(&config, &runtime.environment, &resolution_overrides)?;
    if previous_target.routing_overridden || previous_target.tenant_overridden {
        return Err(ReltioError::new(
            "auth_login_target_override",
            ErrorCategory::Safety,
            "auth login cannot commit credentials while invocation-scoped routing or tenant changes are active",
        )
        .with_details(json!({
            "routing_overridden": previous_target.routing_overridden,
            "tenant_overridden": previous_target.tenant_overridden,
            "secret_input_consumed": false,
            "network_request_sent": false,
            "local_state_committed": false,
            "safe_to_replay": true
        }))
        .with_hint(
            "Update the stored profile first, or remove the invocation-only environment, base, Auth URL, and tenant overrides before login.",
        ));
    }

    let secret_file = arguments
        .secret_file
        .as_deref()
        .map(|path| absolute_local_path(path, false, "secret-file"))
        .transpose()?;
    let credential_process = arguments
        .credential_process
        .as_deref()
        .map(|executable| {
            let executable =
                absolute_local_path(Path::new(executable), true, "credential-process executable")?;
            let mut command = vec![executable.to_string_lossy().into_owned()];
            command.extend(arguments.credential_process_args.clone());
            Ok::<Vec<String>, ReltioError>(command)
        })
        .transpose()?;
    let client_id = arguments
        .client_id
        .clone()
        .or_else(|| {
            runtime
                .environment
                .get("RELTIO_CLIENT_ID")
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            config
                .profiles
                .get(&profile_name)
                .and_then(|profile| profile.auth.client_id.clone())
        });
    let auth_profile = AuthProfile {
        method: Some(arguments.method),
        client_id: client_id.clone(),
        secret_file,
        credential_process: credential_process.clone(),
        bearer_cache_key: None,
        bearer_cache_generation: (arguments.method == AuthMethod::Bearer)
            .then(new_imported_bearer_cache_generation),
    };
    let previous_profile = config
        .profiles
        .get(&profile_name)
        .ok_or_else(|| {
            ReltioError::profile(
                "profile_not_found",
                format!("profile {profile_name:?} does not exist"),
            )
        })?
        .clone();
    let retired_bearer_cache_key =
        stored_imported_bearer_cache_key(&previous_profile.auth)?.map(ToOwned::to_owned);
    let previous_output_guard = runtime
        .profile_output_guard(&previous_target, deadline)
        .await
        .map_err(|error| error.with_output_guard(runtime.environment_output_guard()))?;
    let mut candidate = config.clone();
    candidate
        .profiles
        .get_mut(&profile_name)
        .ok_or_else(|| {
            ReltioError::profile(
                "profile_not_found",
                format!("profile {profile_name:?} does not exist"),
            )
        })?
        .auth = auth_profile.clone();
    let mut target = resolve_target(&candidate, &runtime.environment, &resolution_overrides)?;
    if arguments.method == AuthMethod::Bearer {
        let cache_key = imported_bearer_cache_key(&runtime.paths.config_file, &target)?;
        if retired_bearer_cache_key.as_deref() == Some(cache_key.as_str()) {
            return Err(ReltioError::new(
                "auth_login_cache_generation_conflict",
                ErrorCategory::Conflict,
                "the generated imported-bearer cache identity collided with the active generation",
            )
            .with_details(json!({
                "network_request_sent": false,
                "local_state_committed": false,
                "safe_to_replay": true
            })));
        }
        candidate
            .profiles
            .get_mut(&profile_name)
            .expect("the candidate profile was resolved above")
            .auth
            .bearer_cache_key = Some(cache_key.clone());
        target.auth.bearer_cache_key = Some(cache_key);
    }
    let candidate_profile = candidate
        .profiles
        .get(&profile_name)
        .expect("the candidate profile was resolved above")
        .clone();
    let mut input_output_guard = runtime.environment_output_guard();
    input_output_guard.merge(&previous_output_guard);
    let mut one_shot_secret = if arguments.secret_stdin {
        let secret = read_secret_from_stdin("client secret", deadline, &runtime.cancellation)
            .await
            .map_err(|error| error.with_output_guard(input_output_guard.clone()))?;
        input_output_guard.merge(&reltio_client::redaction::OutputGuard::from_known_secrets(
            &[secret.expose_secret()],
        ));
        Some(secret)
    } else {
        None
    };
    if arguments.method == AuthMethod::ClientCredentials
        && one_shot_secret.is_none()
        && !runtime.environment.contains("RELTIO_CLIENT_SECRET")
        && arguments.secret_file.is_none()
        && io::stdin().is_terminal()
    {
        runtime
            .emit_stderr_raw(b"Reltio client secret: ", deadline, &input_output_guard)
            .await?;
        let secret = read_hidden_secret(deadline, &runtime.cancellation).await?;
        let secret: SecretString = secret.into();
        input_output_guard.merge(&reltio_client::redaction::OutputGuard::from_known_secrets(
            &[secret.expose_secret()],
        ));
        runtime
            .emit_stderr_raw(b"\n", deadline, &input_output_guard)
            .await?;
        one_shot_secret = Some(secret);
    }
    runtime
        .ensure_not_cancelled("credential_input", false)
        .map_err(|error| error.with_output_guard(input_output_guard.clone()))?;
    let (provider, expires_at, cache_hit, mut output_guard, pending_login) = match arguments.method
    {
        AuthMethod::Bearer => {
            let token = if arguments.token_stdin {
                read_secret_from_stdin("access token", deadline, &runtime.cancellation)
                    .await
                    .map_err(|error| error.with_output_guard(input_output_guard.clone()))?
            } else {
                runtime
                    .environment
                    .secret("RELTIO_ACCESS_TOKEN")
                    .ok_or_else(|| {
                        ReltioError::auth(
                            "bearer_token_missing",
                            "bearer login requires --token-stdin or RELTIO_ACCESS_TOKEN",
                        )
                    })?
            };
            let mut output_guard = input_output_guard.clone();
            output_guard.merge(&reltio_client::redaction::OutputGuard::from_known_secrets(
                &[token.expose_secret()],
            ));
            let expires_at = arguments
                .expires_in
                .map(TimeDelta::from_std)
                .transpose()
                .map_err(|_| {
                    ReltioError::usage("invalid_token_lifetime", "token lifetime is too large")
                })?
                .map(|duration| Utc::now() + duration);
            (
                "bearer".to_owned(),
                expires_at,
                false,
                output_guard,
                PendingLogin::Bearer { token, expires_at },
            )
        }
        AuthMethod::ClientCredentials | AuthMethod::CredentialProcess => {
            let mut manager_environment = runtime.environment.clone();
            if arguments.client_id.is_some() {
                manager_environment = manager_environment.without("RELTIO_CLIENT_ID");
            }
            if arguments.secret_stdin || arguments.secret_file.is_some() {
                manager_environment = manager_environment.without("RELTIO_CLIENT_SECRET");
            }
            let manager = runtime
                .token_manager_with_environment(
                    &target,
                    &manager_environment,
                    TokenManagerOptions {
                        client_secret: one_shot_secret.take(),
                        no_retry: runtime.globals.no_retry,
                    },
                )
                .map_err(|error| error.with_output_guard(input_output_guard.clone()))?;
            let mut output_guard = input_output_guard.clone();
            let manager_guard = runtime
                .token_manager_output_guard(&manager, deadline)
                .await
                .map_err(|error| error.with_output_guard(output_guard.clone()))?;
            output_guard.merge(&manager_guard);
            let token = {
                let acquisition = manager.acquire_for_login_until(deadline);
                tokio::pin!(acquisition);
                tokio::select! {
                    biased;
                    () = runtime.cancellation.cancelled() => {
                        return Err(auth_command_canceled(
                            "authentication",
                            false,
                            &output_guard,
                            true,
                            AuthRemoteOutcome::Unknown,
                        ));
                    },
                    result = &mut acquisition => result
                        .map_err(|error| error.with_output_guard(output_guard.clone()))?,
                }
            };
            output_guard.merge(token.output_guard());
            (
                token.provider.clone(),
                token.expires_at,
                token.cache_hit,
                output_guard,
                PendingLogin::Managed {
                    manager: Box::new(manager),
                    token,
                },
            )
        }
    };
    let remote_outcome = match arguments.method {
        AuthMethod::Bearer => AuthRemoteOutcome::NotSent,
        AuthMethod::ClientCredentials if cache_hit => AuthRemoteOutcome::NotSent,
        AuthMethod::ClientCredentials => AuthRemoteOutcome::Succeeded,
        AuthMethod::CredentialProcess => AuthRemoteOutcome::Unknown,
    };
    let mut cache_plan = match &pending_login {
        PendingLogin::Bearer { token, expires_at } => {
            let preparation = TokenManager::prepare_bearer_login_until(
                &runtime.paths.cache_dir,
                &runtime.paths.config_file,
                &target,
                token.clone(),
                *expires_at,
                deadline,
            );
            tokio::pin!(preparation);
            tokio::select! {
                biased;
                result = &mut preparation => result,
                () = runtime.cancellation.cancelled() => {
                    return Err(auth_command_canceled(
                        "token_cache_snapshot",
                        false,
                        &output_guard,
                        false,
                        remote_outcome,
                    ));
                }
            }
        }
        PendingLogin::Managed { manager, token } => {
            let preparation = manager.prepare_managed_login_until(token, deadline);
            tokio::pin!(preparation);
            tokio::select! {
                biased;
                result = &mut preparation => result,
                () = runtime.cancellation.cancelled() => {
                    return Err(auth_command_canceled(
                        "token_cache_snapshot",
                        false,
                        &output_guard,
                        false,
                        remote_outcome,
                    ));
                }
            }
        }
    }
    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(cache_plan.output_guard());
    output_guard.merge(
        &cache_plan
            .profile_output_guard(&previous_target, &runtime.environment)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?,
    );

    let mut meta = Meta::new("auth.login").with_target(&target, Some("auth"));
    meta.elapsed_ms = started.elapsed().as_millis();
    meta.auth_source = Some(provider.clone());
    meta.practice_ids = vec![
        "AUTH-TOKEN-CACHE-001".to_owned(),
        "AUTH-OPAQUE-TOKEN-001".to_owned(),
    ];
    if arguments.method == AuthMethod::ClientCredentials {
        meta.practice_ids.push("AUTH-TOKEN-REISSUE-001".to_owned());
        let centralized = ServiceResolver::new(target.clone())
            .base_url(Service::Auth)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?
            .as_str()
            == "https://auth.reltio.com/";
        if centralized {
            meta.practice_ids.push("AUTH-CENTRALIZED-001".to_owned());
            meta.practice_coverage = Some(PracticeCoverage::Reviewed);
        } else {
            meta.practice_coverage = Some(PracticeCoverage::Partial);
            meta.warnings.push(
                "custom authentication URL is explicit but is not covered by the centralized Reltio authentication-endpoint review"
                    .to_owned(),
            );
        }
        meta.practice_ids
            .push("AUTH-CLIENT-CREDENTIALS-001".to_owned());
    } else {
        meta.practice_coverage = Some(PracticeCoverage::Reviewed);
    }
    if !runtime.globals.quiet {
        meta.warnings.push(
            "access tokens are cached in an owner-only local file; configure managed secret injection if local plaintext cache is prohibited"
                .to_owned(),
        );
    }
    let data = json!({
        "authenticated": true,
        "provider": provider,
        "expires_at": expires_at,
        "cache_hit": cache_hit,
        "client_secret_persisted": false,
        "access_token_cached": true,
        "token_cache": "owner_only_file"
    });
    let success = prepare_success_guarded(&data, &meta, runtime.render, &output_guard)?;
    drop(pending_login);

    if runtime.cancellation.is_cancelled() {
        return Err(auth_command_canceled(
            "before_token_cache_commit",
            false,
            &output_guard,
            false,
            remote_outcome,
        ));
    }
    if let Err(error) = cache_plan.commit_with_cancellation(&runtime.cancellation) {
        return Err(login_cache_error(error, output_guard, remote_outcome));
    }
    if runtime.cancellation.is_cancelled() {
        let cancellation = auth_command_canceled(
            "after_token_cache_commit",
            false,
            &output_guard,
            false,
            remote_outcome,
        );
        let rollback = cache_plan.rollback();
        drop(cache_plan);
        if let Err(rollback_error) = rollback {
            return Err(login_cache_rollback_error(
                &cancellation,
                &rollback_error,
                output_guard,
                remote_outcome,
            ));
        }
        return Err(login_profile_commit_error(
            cancellation,
            output_guard,
            remote_outcome,
        ));
    }
    if let Err(error) = commit_auth_profile(
        runtime,
        &profile_name,
        &previous_profile,
        &candidate_profile,
        retired_bearer_cache_key.as_deref(),
        expires_at,
        deadline,
    )
    .map_err(|error| error.with_output_guard(output_guard.clone()))
    {
        if error.details["committed"] == true {
            drop(cache_plan);
            return Err(login_commit_state_error(
                error,
                output_guard,
                remote_outcome,
            ));
        }
        let rollback = cache_plan.rollback();
        drop(cache_plan);
        if let Err(rollback_error) = rollback {
            return Err(login_cache_rollback_error(
                &error,
                &rollback_error,
                output_guard,
                remote_outcome,
            ));
        }
        return Err(login_profile_commit_error(
            error,
            output_guard,
            remote_outcome,
        ));
    }
    if let Err(error) = validate_login_candidate_expiry(expires_at) {
        return Err(login_post_commit_error(error, output_guard, remote_outcome));
    }
    if runtime.cancellation.is_cancelled() {
        return Err(auth_command_canceled(
            "before_auth_login_output",
            true,
            &output_guard,
            false,
            remote_outcome,
        ));
    }

    if retired_bearer_cache_key.is_some() {
        drop(cache_plan);
        if let Some((_, cleanup_guard)) = runtime
            .recover_pending_imported_bearer_cleanups()
            .await
            .map_err(|error| {
            login_post_commit_error(error, output_guard.clone(), remote_outcome)
        })? {
            output_guard.merge(&cleanup_guard);
        }
        return runtime
            .emit_prepared(success, deadline)
            .await
            .map_err(|error| login_output_error(error, output_guard, remote_outcome));
    }
    let plan_guard = cache_plan.output_guard().clone();
    runtime
        .emit_prepared_with_owner(success, cache_plan, &plan_guard, deadline)
        .await
        .map_err(|error| login_output_error(error, output_guard, remote_outcome))
}

fn commit_auth_profile(
    runtime: &Runtime,
    profile_name: &str,
    previous: &Profile,
    candidate: &Profile,
    retired_bearer_cache_key: Option<&str>,
    expires_at: Option<chrono::DateTime<Utc>>,
    deadline: Instant,
) -> Result<()> {
    let mut winning_config = None;
    let result = runtime.store.modify_until(
        deadline,
        || runtime.cancellation.is_cancelled(),
        |config| {
            let current = config.profiles.get(profile_name).cloned().ok_or_else(|| {
                ReltioError::profile(
                    "profile_not_found",
                    format!("profile {profile_name:?} does not exist"),
                )
            })?;
            if &current != previous {
                winning_config = Some(config.clone());
                return Err(ReltioError::new(
                    "auth_login_commit_conflict",
                    ErrorCategory::Conflict,
                    "the selected profile changed concurrently; refusing to commit authentication",
                ));
            }
            validate_login_candidate_expiry(expires_at)?;
            if let Some(cache_key) = retired_bearer_cache_key {
                config
                    .pending_imported_bearer_cleanups
                    .entry(profile_name.to_owned())
                    .or_default()
                    .insert(cache_key.to_owned());
            }
            config
                .profiles
                .get_mut(profile_name)
                .expect("the selected profile was resolved above")
                .clone_from(candidate);
            Ok(())
        },
    );
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.code == "auth_login_commit_conflict" => {
            let winner_guard = winning_config
                .as_ref()
                .and_then(|config| {
                    resolve_target(
                        config,
                        &runtime.environment,
                        &ResolutionOverrides {
                            profile: runtime.globals.profile.clone(),
                            environment: runtime.globals.environment.clone(),
                            tenant: runtime.globals.tenant.clone(),
                        },
                    )
                    .ok()
                })
                .map(|target| {
                    TokenManager::profile_credential_output_guard(&target, &runtime.environment)
                });
            let guard = match winner_guard {
                Some(Ok(winner_guard)) => winner_guard,
                Some(Err(guard_error)) => guard_error
                    .output_guard()
                    .cloned()
                    .unwrap_or_else(reltio_client::redaction::OutputGuard::deny_all),
                None => reltio_client::redaction::OutputGuard::deny_all(),
            };
            Err(error.with_output_guard(guard))
        }
        Err(error) => Err(error),
    }
}

fn validate_login_candidate_expiry(expires_at: Option<chrono::DateTime<Utc>>) -> Result<()> {
    let Some(expires_at) = expires_at else {
        return Err(ReltioError::auth(
            "auth_token_expiry_missing",
            "persisted access tokens require a declared expiry",
        ));
    };
    if expires_at <= Utc::now() + TimeDelta::seconds(LOGIN_EXPIRY_SKEW_SECONDS) {
        return Err(ReltioError::auth(
            "auth_token_expiry_too_soon",
            "the acquired token became unusable before login could commit",
        )
        .with_details(json!({
            "expires_at": expires_at,
            "minimum_remaining_seconds": LOGIN_EXPIRY_SKEW_SECONDS
        }))
        .with_hint(
            "Acquire a token with more remaining lifetime before retrying authentication.",
        ));
    }
    Ok(())
}

fn auth_command_canceled(
    phase: &'static str,
    local_state_committed: bool,
    output_guard: &reltio_client::redaction::OutputGuard,
    uninspected_provider_output: bool,
    remote_outcome: AuthRemoteOutcome,
) -> ReltioError {
    let mut guard = output_guard.clone();
    if uninspected_provider_output {
        guard.merge(&reltio_client::redaction::OutputGuard::deny_all());
    }
    let (remote_response_received, remote_request_completed, remote_operation_completed, state) =
        auth_remote_outcome(remote_outcome);
    ReltioError::new(
        "request_canceled",
        ErrorCategory::Canceled,
        "authentication was canceled",
    )
    .with_details(json!({
        "phase": phase,
        "remote_response_received": remote_response_received,
        "remote_request_completed": remote_request_completed,
        "remote_operation_completed": remote_operation_completed,
        "remote_operation_state": state,
        "local_state_committed": local_state_committed,
        "safe_to_replay": false
    }))
    .with_output_guard(guard)
}

fn auth_remote_outcome(remote_outcome: AuthRemoteOutcome) -> (Value, Value, Value, &'static str) {
    match remote_outcome {
        AuthRemoteOutcome::NotSent => (
            Value::Bool(false),
            Value::Bool(false),
            Value::Bool(false),
            "request_not_sent",
        ),
        AuthRemoteOutcome::Unknown => (
            Value::Null,
            Value::Null,
            Value::Null,
            "authentication_completion_unknown",
        ),
        AuthRemoteOutcome::Succeeded => (
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(true),
            "authentication_succeeded",
        ),
    }
}

fn login_cache_error(
    mut error: ReltioError,
    output_guard: reltio_client::redaction::OutputGuard,
    remote_outcome: AuthRemoteOutcome,
) -> ReltioError {
    let local_cache_restored = error.details["local_cache_restored"] == true;
    let local_cache_committed = local_cache_restored.then_some(false);
    let local_state_committed = local_cache_restored.then_some(false);
    let cache_details = std::mem::take(&mut error.details);
    let (response_received, request_completed, operation_completed, operation_state) =
        auth_remote_outcome(remote_outcome);
    error.details = json!({
        "cache_error": cache_details,
        "remote_response_received": response_received,
        "remote_request_completed": request_completed,
        "remote_operation_completed": operation_completed,
        "remote_operation_state": operation_state,
        "local_profile_changed": false,
        "local_cache_restored": local_cache_restored,
        "local_cache_committed": local_cache_committed,
        "local_state_committed": local_state_committed,
        "safe_to_replay": false
    });
    error.hint = Some(
        "The prior profile remains selected. Inspect `reltio auth status` before deliberately retrying login."
            .to_owned(),
    );
    error.with_output_guard(output_guard)
}

fn login_profile_commit_error(
    mut error: ReltioError,
    output_guard: reltio_client::redaction::OutputGuard,
    remote_outcome: AuthRemoteOutcome,
) -> ReltioError {
    let profile_details = std::mem::take(&mut error.details);
    let (response_received, request_completed, operation_completed, operation_state) =
        auth_remote_outcome(remote_outcome);
    error.details = json!({
        "profile_error": profile_details,
        "remote_response_received": response_received,
        "remote_request_completed": request_completed,
        "remote_operation_completed": operation_completed,
        "remote_operation_state": operation_state,
        "local_profile_committed": false,
        "local_cache_restored": true,
        "local_state_committed": false,
        "safe_to_replay": false
    });
    error.hint = Some(
        "This login did not change the selected profile, and its candidate cache image was restored. Resolve the profile error before deliberately retrying login."
            .to_owned(),
    );
    error.with_output_guard(output_guard)
}

fn login_cache_rollback_error(
    profile_error: &ReltioError,
    rollback_error: &ReltioError,
    output_guard: reltio_client::redaction::OutputGuard,
    remote_outcome: AuthRemoteOutcome,
) -> ReltioError {
    let (response_received, request_completed, operation_completed, operation_state) =
        auth_remote_outcome(remote_outcome);
    ReltioError::new(
        "auth_login_rollback_failed",
        ErrorCategory::Internal,
        "profile persistence failed and authentication cache rollback did not complete",
    )
    .with_details(json!({
        "profile_error": profile_error.code,
        "rollback_error": rollback_error.code,
        "remote_response_received": response_received,
        "remote_request_completed": request_completed,
        "remote_operation_completed": operation_completed,
        "remote_operation_state": operation_state,
        "local_profile_committed": false,
        "local_cache_restored": false,
        "local_cache_committed": Value::Null,
        "local_state_committed": Value::Null,
        "local_state_uncertain": true,
        "safe_to_replay": false
    }))
    .with_hint(
        "Inspect `reltio auth status`; do not retry login until the reported local state is resolved.",
    )
    .with_output_guard(output_guard)
}

fn login_commit_state_error(
    mut error: ReltioError,
    output_guard: reltio_client::redaction::OutputGuard,
    remote_outcome: AuthRemoteOutcome,
) -> ReltioError {
    let commit_details = std::mem::take(&mut error.details);
    let (response_received, request_completed, operation_completed, operation_state) =
        auth_remote_outcome(remote_outcome);
    error.details = json!({
        "config_commit_error": commit_details,
        "remote_response_received": response_received,
        "remote_request_completed": request_completed,
        "remote_operation_completed": operation_completed,
        "remote_operation_state": operation_state,
        "local_profile_committed": true,
        "local_cache_committed": true,
        "local_state_committed": true,
        "safe_to_replay": false
    });
    error.hint = Some(
        "Authentication was committed locally with uncertain configuration durability; inspect `reltio auth status` instead of replaying login."
            .to_owned(),
    );
    error.with_output_guard(output_guard)
}

fn login_output_error(
    mut error: ReltioError,
    output_guard: reltio_client::redaction::OutputGuard,
    remote_outcome: AuthRemoteOutcome,
) -> ReltioError {
    let output_details = std::mem::take(&mut error.details);
    let (response_received, request_completed, operation_completed, operation_state) =
        auth_remote_outcome(remote_outcome);
    error.details = json!({
        "output_error": output_details,
        "remote_response_received": response_received,
        "remote_request_completed": request_completed,
        "remote_operation_completed": operation_completed,
        "remote_operation_state": operation_state,
        "local_profile_committed": true,
        "local_cache_committed": true,
        "local_state_committed": true,
        "safe_to_replay": false
    });
    error.hint = Some(
        "Authentication was committed locally even though output failed; inspect `reltio auth status` instead of replaying login."
            .to_owned(),
    );
    error.with_output_guard(output_guard)
}

fn login_post_commit_error(
    mut error: ReltioError,
    output_guard: reltio_client::redaction::OutputGuard,
    remote_outcome: AuthRemoteOutcome,
) -> ReltioError {
    let post_commit_details = std::mem::take(&mut error.details);
    let (response_received, request_completed, operation_completed, operation_state) =
        auth_remote_outcome(remote_outcome);
    error.details = json!({
        "post_commit_error": post_commit_details,
        "remote_response_received": response_received,
        "remote_request_completed": request_completed,
        "remote_operation_completed": operation_completed,
        "remote_operation_state": operation_state,
        "local_profile_committed": true,
        "local_cache_committed": true,
        "local_state_committed": true,
        "safe_to_replay": false
    });
    error.hint = Some(
        "Authentication committed locally; inspect `reltio auth status` and pending cleanup state instead of replaying login."
            .to_owned(),
    );
    error.with_output_guard(output_guard)
}

async fn status(runtime: &Runtime) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    runtime.ensure_not_cancelled("before_auth_status", false)?;
    let (_, target) = runtime.config_and_target()?;
    let (status, output_guard) =
        match runtime.token_manager(&target, TokenManagerOptions::default()) {
            Ok(manager) => {
                let output_guard = runtime
                    .token_manager_output_guard(&manager, deadline)
                    .await?;
                let status = runtime
                    .token_manager_status(&manager, deadline)
                    .await
                    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
                (status, output_guard)
            }
            Err(error) if error.code == "auth_unconfigured" => {
                let mut meta = Meta::new("auth.status").with_target(&target, Some("auth"));
                meta.elapsed_ms = started.elapsed().as_millis();
                let data = json!({
                    "configured": false,
                    "provider": null,
                    "cache_state": "not_applicable",
                    "configuration_sources": target.sources
                });
                return runtime
                    .emit_success(&data, &meta, deadline, &runtime.environment_output_guard())
                    .await;
            }
            Err(error) => return Err(error),
        };
    let mut meta = Meta::new("auth.status").with_target(&target, Some("auth"));
    meta.elapsed_ms = started.elapsed().as_millis();
    meta.auth_source = Some(status.source.clone());
    if status.environment_override {
        meta.warnings.push(
            "environment credentials override part or all of the selected profile authentication provider"
                .to_owned(),
        );
    }
    runtime
        .ensure_not_cancelled("before_auth_status_output", false)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let data = json!({
        "configured": status.configured,
        "provider": status.provider,
        "source": status.source,
        "cache_state": status.cache_state,
        "expires_at": status.expires_at,
        "environment_override": status.environment_override,
        "configuration_sources": target.sources
    });
    runtime
        .emit_success(&data, &meta, deadline, &output_guard)
        .await
}

async fn check(runtime: &Runtime) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let auth_status = runtime
        .token_manager_status(&manager, deadline)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let entities = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let page = entities
        .search(&EntitySearchRequest {
            select: Some("URI".to_owned()),
            max: 1,
            ..EntitySearchRequest::default()
        })
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(&page.response.output_guard());
    let mut meta = Meta::new("auth.check").with_target(&target, Some("data"));
    meta.elapsed_ms = started.elapsed().as_millis();
    meta.request_id.clone_from(&page.response.request_id);
    meta.http_status = Some(page.response.status);
    meta.attempts = Some(page.response.attempts);
    meta.consistency = Some(page.consistency);
    meta.auth_source = Some(auth_status.source);
    meta.practice_coverage = Some(PracticeCoverage::Reviewed);
    meta.practice_ids
        .clone_from(&page.response.applied_practice_ids);
    let data = json!({
        "valid": true,
        "tenant_access": true,
        "provider": auth_status.provider,
        "sample_entities_returned": page.entities.len()
    });
    runtime
        .emit_success(&data, &meta, deadline, &output_guard)
        .await
}

async fn reveal_token(runtime: &Runtime, show: bool) -> Result<()> {
    if !show {
        return Err(ReltioError::new(
            "token_disclosure_not_acknowledged",
            ErrorCategory::Safety,
            "auth token requires the explicit --show acknowledgement",
        ));
    }
    if io::stdout().is_terminal() && !runtime.globals.yes {
        return Err(ReltioError::new(
            "token_tty_refused",
            ErrorCategory::Safety,
            "refusing to print an access token to a terminal without --yes",
        )
        .with_hint("Redirect stdout to the intended process or add --yes deliberately."));
    }
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let manager_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let acquisition = manager.token_until(false, deadline);
    tokio::pin!(acquisition);
    let token = tokio::select! {
        biased;
        result = &mut acquisition => result?,
        () = runtime.cancellation.cancelled() => {
            return Err(auth_command_canceled(
                "authentication",
                false,
                &manager_guard,
                manager.can_reacquire(),
                AuthRemoteOutcome::Unknown,
            ));
        }
    };
    if runtime.cancellation.is_cancelled() {
        return Err(auth_command_canceled(
            "before_token_output",
            false,
            token.output_guard(),
            false,
            token_remote_outcome(&token),
        ));
    }
    let output_lease = runtime
        .token_disclosure_output_guard_lease(&manager, &token, deadline)
        .await?;
    runtime
        .ensure_not_cancelled("before_token_output", false)
        .map_err(|error| error.with_output_guard(output_lease.output_guard().clone()))?;
    let lease_disclosure_guard = output_lease.output_guard().clone();
    let mut disclosure_guard = token.disclosure_output_guard().clone();
    disclosure_guard.merge(&lease_disclosure_guard);
    disclosure_guard.merge(&manager.non_disclosable_credential_output_guard()?);
    let mut failure_guard = token.output_guard().clone();
    failure_guard.merge(output_lease.output_guard());
    failure_guard.merge(&manager.non_disclosable_credential_output_guard()?);
    let prepared = if runtime.render.format == OutputFormat::Raw {
        prepare_raw_guarded(token.expose_secret().as_bytes(), true, &disclosure_guard)?
    } else {
        let mut meta = Meta::new("auth.token").with_target(&target, Some("auth"));
        meta.elapsed_ms = started.elapsed().as_millis();
        meta.auth_source = Some(token.provider.clone());
        meta.warnings
            .push("stdout intentionally contains access-token material".to_owned());
        prepare_success_guarded(
            &json!({
            "access_token": token.expose_secret(),
            "token_type": "Bearer",
            "expires_at": token.expires_at
            }),
            &meta,
            runtime.render,
            &disclosure_guard,
        )?
    };
    runtime
        .emit_prepared_disclosing_with_owner(
            prepared,
            output_lease,
            &lease_disclosure_guard,
            deadline,
            failure_guard,
        )
        .await
}

async fn logout(runtime: &Runtime) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let cache_lease = TokenManager::clear_local_cache_until(
        &runtime.paths.cache_dir,
        deadline,
        &runtime.cancellation,
    )?;
    let removed = cache_lease.removed();
    let mut output_guard = cache_lease.output_guard().clone();
    let cleared = removed > 0;
    let mut imported_bearer_profiles_cleared = 0_usize;
    let mut pending_bearer_cleanups_cleared = false;
    if runtime.store.load().is_ok_and(|config| {
        !config.pending_imported_bearer_cleanups.is_empty()
            || config
                .profiles
                .values()
                .any(|profile| profile.auth.method == Some(AuthMethod::Bearer))
    }) {
        let cleared_configuration = runtime
            .store
            .modify_until(
                deadline,
                || runtime.cancellation.is_cancelled(),
                |config| {
                    let had_pending = !config.pending_imported_bearer_cleanups.is_empty();
                    let mut count = 0_usize;
                    for profile in config.profiles.values_mut() {
                        if profile.auth.method == Some(AuthMethod::Bearer) {
                            profile.auth = AuthProfile::default();
                            count = count.saturating_add(1);
                        }
                    }
                    config.pending_imported_bearer_cleanups.clear();
                    Ok((count, had_pending))
                },
            )
            .map_err(|mut error| {
                let config_committed = error.details["committed"].as_bool();
                let config_error = std::mem::take(&mut error.details);
                error.details = json!({
                    "config_error": config_error,
                    "local_cache_cleared": cleared,
                    "local_config_committed": config_committed,
                    "local_state_committed": if cleared { Value::Bool(true) } else { config_committed.map_or(Value::Null, Value::Bool) },
                    "safe_to_replay": true
                });
                error.with_output_guard(output_guard.clone())
            })?;
        imported_bearer_profiles_cleared = cleared_configuration.0;
        pending_bearer_cleanups_cleared = cleared_configuration.1;
    }
    cache_lease.release().map_err(|mut error| {
        let cache_error = std::mem::take(&mut error.details);
        error.details = json!({
            "cache_error": cache_error,
            "local_cache_cleared": cleared,
            "imported_bearer_profiles_cleared": imported_bearer_profiles_cleared,
            "pending_bearer_cleanups_cleared": pending_bearer_cleanups_cleared,
            "local_state_committed": cleared || imported_bearer_profiles_cleared > 0 || pending_bearer_cleanups_cleared,
            "safe_to_replay": true
        });
        error.with_output_guard(output_guard.clone())
    })?;
    let mut meta = Meta::new("auth.logout");
    match runtime.config_and_target() {
        Ok((_, target)) => meta = meta.with_target(&target, Some("auth")),
        Err(error) => meta.warnings.push(format!(
            "target metadata was unavailable during cache cleanup ({})",
            error.code
        )),
    }
    meta.elapsed_ms = started.elapsed().as_millis();
    if runtime.environment.contains("RELTIO_ACCESS_TOKEN") {
        meta.warnings.push(
            "RELTIO_ACCESS_TOKEN remains active in the invoking environment and cannot be cleared by the CLI"
                .to_owned(),
        );
    }
    output_guard.merge(&runtime.environment_output_guard());
    runtime
        .ensure_not_cancelled("before_auth_logout_output", cleared)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let data = json!({
        "local_cache_cleared": cleared,
        "imported_bearer_profiles_cleared": imported_bearer_profiles_cleared,
        "pending_bearer_cleanups_cleared": pending_bearer_cleanups_cleared,
        "remote_revocation_attempted": false,
        "environment_token_cleared": false
    });
    runtime
        .emit_success(&data, &meta, deadline, &output_guard)
        .await
        .map_err(|mut error| {
            let output_error = std::mem::take(&mut error.details);
            error.details = json!({
                "output_error": output_error,
                "local_cache_cleared": cleared,
                "imported_bearer_profiles_cleared": imported_bearer_profiles_cleared,
                "pending_bearer_cleanups_cleared": pending_bearer_cleanups_cleared,
                "remote_revocation_attempted": false,
                "output_omitted": true,
                "safe_to_replay": true,
                "local_state_committed": cleared || imported_bearer_profiles_cleared > 0 || pending_bearer_cleanups_cleared
            });
            error
        })
}

fn token_remote_outcome(token: &AccessToken) -> AuthRemoteOutcome {
    if token.cache_hit || matches!(token.provider.as_str(), "environment" | "bearer") {
        AuthRemoteOutcome::NotSent
    } else if token.provider == "client_credentials" {
        AuthRemoteOutcome::Succeeded
    } else {
        AuthRemoteOutcome::Unknown
    }
}

fn selected_profile(runtime: &Runtime, config: &ConfigFile) -> Result<String> {
    runtime
        .globals
        .profile
        .clone()
        .or_else(|| {
            runtime
                .environment
                .get("RELTIO_PROFILE")
                .map(ToOwned::to_owned)
        })
        .or_else(|| config.current_profile.clone())
        .ok_or_else(|| {
            ReltioError::profile("profile_required", "auth login requires a named profile")
                .with_hint("Create and select a profile before storing provider metadata.")
        })
}

fn validate_login_arguments(arguments: &AuthLoginArgs) -> Result<()> {
    match arguments.method {
        AuthMethod::Bearer => {
            if arguments.secret_stdin
                || arguments.client_id.is_some()
                || arguments.secret_file.is_some()
                || arguments.credential_process.is_some()
                || !arguments.credential_process_args.is_empty()
            {
                return Err(ReltioError::usage(
                    "auth_login_argument_conflict",
                    "bearer login accepts --token-stdin and --expires-in, not client credential options",
                ));
            }
            if arguments.expires_in.is_none() {
                return Err(ReltioError::usage(
                    "bearer_expiry_required",
                    "persisted bearer login requires --expires-in so the token cannot remain usable indefinitely",
                ));
            }
        }
        AuthMethod::ClientCredentials => {
            if arguments.secret_stdin && arguments.secret_file.is_some() {
                return Err(ReltioError::usage(
                    "auth_login_argument_conflict",
                    "--secret-stdin and --secret-file are mutually exclusive",
                ));
            }
            if arguments.token_stdin
                || arguments.expires_in.is_some()
                || arguments.credential_process.is_some()
                || !arguments.credential_process_args.is_empty()
            {
                return Err(ReltioError::usage(
                    "auth_login_argument_conflict",
                    "client-credentials login received an option for another provider",
                ));
            }
        }
        AuthMethod::CredentialProcess => {
            if arguments.credential_process.is_none()
                || arguments.secret_stdin
                || arguments.token_stdin
                || arguments.expires_in.is_some()
                || arguments.client_id.is_some()
                || arguments.secret_file.is_some()
            {
                return Err(ReltioError::usage(
                    "auth_login_argument_conflict",
                    "credential-process login requires --credential-process and no direct secret options",
                ));
            }
        }
    }
    Ok(())
}

async fn read_secret_from_stdin(
    label: &'static str,
    deadline: Instant,
    cancellation: &reltio_client::cancellation::CancellationToken,
) -> Result<SecretString> {
    if io::stdin().is_terminal() {
        return Err(ReltioError::usage(
            "secret_stdin_is_tty",
            format!("refusing to read {label} visibly from terminal stdin"),
        )
        .with_hint("Pipe the secret or omit the stdin flag to use a hidden prompt."));
    }
    let (sender, mut read) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("reltio-secret-input".to_owned())
        .spawn(move || {
            let _ = sender.send(read_secret_from_stdin_blocking(label));
        })
        .map_err(|error| {
            ReltioError::io("failed to start the secret-input reader", &error)
                .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
        })?;
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timeout);
    tokio::select! {
        biased;
        result = &mut read => result.map_err(|_| {
            ReltioError::internal("the secret-input thread terminated without a result")
                .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
        })?,
        () = cancellation.cancelled() => Err(secret_input_control_error(
            "request_canceled",
            ErrorCategory::Canceled,
            "credential input was canceled",
        )),
        () = &mut timeout => Err(secret_input_control_error(
            "request_timeout",
            ErrorCategory::Timeout,
            "credential input exceeded the overall timeout",
        )),
    }
}

fn read_secret_from_stdin_blocking(label: &str) -> Result<SecretString> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(SECRET_INPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ReltioError::io(&format!("failed to read {label}"), &error)
                .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
        })?;
    if bytes.len() as u64 > SECRET_INPUT_LIMIT {
        return Err(ReltioError::usage(
            "secret_input_too_large",
            format!("{label} exceeds the 1 MB local safety limit"),
        )
        .with_output_guard(reltio_client::redaction::OutputGuard::deny_all()));
    }
    let text = Zeroizing::new(String::from_utf8(bytes).map_err(|_| {
        ReltioError::usage("secret_input_not_utf8", format!("{label} must be UTF-8"))
            .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
    })?);
    let secret = text.trim_end_matches(['\r', '\n']).to_owned();
    if secret.is_empty() || secret.contains(['\r', '\n']) {
        return Err(ReltioError::usage(
            "secret_input_invalid",
            format!("{label} is empty or contains an embedded line break"),
        )
        .with_output_guard(reltio_client::redaction::OutputGuard::deny_all()));
    }
    Ok(secret.into())
}

#[cfg(not(any(unix, windows)))]
async fn read_hidden_secret(
    deadline: Instant,
    cancellation: &reltio_client::cancellation::CancellationToken,
) -> Result<String> {
    let (sender, mut read) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("reltio-hidden-input".to_owned())
        .spawn(move || {
            let _ = sender.send(rpassword::read_password());
        })
        .map_err(|error| {
            ReltioError::io("failed to start the hidden-input reader", &error)
                .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
        })?;
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timeout);
    tokio::select! {
        biased;
        result = &mut read => result
            .map_err(|_| {
                ReltioError::internal("the hidden-input thread terminated without a result")
                    .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
            })?
            .map_err(|error| {
                ReltioError::io("failed to read hidden client secret", &error)
                    .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
            }),
        () = cancellation.cancelled() => Err(secret_input_control_error(
            "request_canceled",
            ErrorCategory::Canceled,
            "hidden credential input was canceled",
        )),
        () = &mut timeout => Err(secret_input_control_error(
            "request_timeout",
            ErrorCategory::Timeout,
            "hidden credential input exceeded the overall timeout",
        )),
    }
}

#[cfg(windows)]
async fn read_hidden_secret(
    deadline: Instant,
    cancellation: &reltio_client::cancellation::CancellationToken,
) -> Result<String> {
    let cancellation = cancellation.clone();
    let (sender, read) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("reltio-hidden-input".to_owned())
        .spawn(move || {
            let result = reltio_windows_security::read_hidden_console_line_until(
                deadline,
                SECRET_INPUT_LIMIT,
                || cancellation.is_cancelled(),
            )
            .map_err(|error| map_windows_hidden_input_error(&error));
            let _ = sender.send(result);
        })
        .map_err(|error| {
            ReltioError::io("failed to start the hidden-input reader", &error)
                .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
        })?;
    read.await.map_err(|_| {
        ReltioError::internal("the hidden-input thread terminated without a result")
            .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
    })?
}

#[cfg(windows)]
fn map_windows_hidden_input_error(error: &reltio_windows_security::Error) -> ReltioError {
    use reltio_windows_security::ErrorKind;

    let mapped = match error.kind() {
        ErrorKind::Canceled => secret_input_control_error(
            "request_canceled",
            ErrorCategory::Canceled,
            "hidden credential input was canceled",
        ),
        ErrorKind::TimedOut => secret_input_control_error(
            "request_timeout",
            ErrorCategory::Timeout,
            "hidden credential input exceeded the overall timeout",
        ),
        ErrorKind::TooLarge => ReltioError::usage(
            "secret_input_too_large",
            "hidden client secret exceeds the 1 MB local safety limit",
        ),
        ErrorKind::InvalidUnicode => ReltioError::usage(
            "secret_input_not_utf8",
            "hidden client secret contains invalid Unicode input",
        ),
        ErrorKind::ConsoleUnavailable => ReltioError::usage(
            "hidden_input_unavailable",
            "a native Windows console is required for hidden credential input",
        )
        .with_hint("Use --secret-stdin or --secret-file outside a native Windows console."),
        ErrorKind::InputCleanup => ReltioError::new(
            "hidden_input_cleanup_failed",
            ErrorCategory::Safety,
            "abandoned Windows credential input could not be cleared safely",
        ),
        _ => {
            if let Some(source) = error.io_error() {
                ReltioError::io("failed to read hidden client secret", source)
            } else {
                ReltioError::new(
                    "hidden_input_failed",
                    ErrorCategory::Internal,
                    "failed to read hidden client secret",
                )
            }
        }
    };
    mapped.with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
}

#[cfg(unix)]
async fn read_hidden_secret(
    deadline: Instant,
    cancellation: &reltio_client::cancellation::CancellationToken,
) -> Result<String> {
    let cancellation = cancellation.clone();
    let (sender, read) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("reltio-hidden-input".to_owned())
        .spawn(move || {
            let _ = sender.send(read_hidden_secret_unix_from(
                Path::new("/dev/tty"),
                deadline,
                &cancellation,
            ));
        })
        .map_err(|error| {
            ReltioError::io("failed to start the hidden-input reader", &error)
                .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
        })?;
    read.await.map_err(|_| {
        ReltioError::internal("the hidden-input thread terminated without a result")
            .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
    })?
}

#[cfg(unix)]
fn read_hidden_secret_unix_from(
    terminal_path: &Path,
    deadline: Instant,
    cancellation: &reltio_client::cancellation::CancellationToken,
) -> Result<String> {
    use std::fs::{File, OpenOptions};
    use std::os::fd::AsFd as _;

    use rustix::fs::OFlags;
    use rustix::termios::{LocalModes, OptionalActions, Termios};

    struct TerminalRestore {
        terminal: File,
        original: Termios,
        restored: bool,
    }

    impl TerminalRestore {
        fn restore_with(&mut self, action: OptionalActions) -> io::Result<()> {
            if !self.restored {
                rustix::termios::tcsetattr(&self.terminal, action, &self.original)
                    .map_err(io::Error::from)?;
                self.restored = true;
            }
            Ok(())
        }

        fn restore(&mut self) -> io::Result<()> {
            self.restore_with(OptionalActions::Now)
        }
    }

    impl Drop for TerminalRestore {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open(terminal_path)
        .map_err(|error| {
            hidden_input_io_error("failed to open the controlling terminal", &error)
        })?;
    let original = rustix::termios::tcgetattr(&terminal).map_err(|error| {
        hidden_input_io_error(
            "failed to inspect terminal input settings",
            &io::Error::from(error),
        )
    })?;
    let mut restore = TerminalRestore {
        terminal: terminal.try_clone().map_err(|error| {
            hidden_input_io_error("failed to retain terminal restoration state", &error)
        })?,
        original: original.clone(),
        restored: false,
    };
    let mut hidden = original.clone();
    hidden
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ECHONL);
    rustix::termios::tcsetattr(&terminal, OptionalActions::Now, &hidden).map_err(|error| {
        hidden_input_io_error(
            "failed to hide terminal credential input",
            &io::Error::from(error),
        )
    })?;
    let read_result = (|| -> Result<String> {
        let flags = rustix::fs::fcntl_getfl(terminal.as_fd()).map_err(|error| {
            hidden_input_io_error(
                "failed to inspect terminal input flags",
                &io::Error::from(error),
            )
        })?;
        rustix::fs::fcntl_setfl(terminal.as_fd(), flags | OFlags::NONBLOCK).map_err(|error| {
            hidden_input_io_error(
                "failed to bound terminal credential input",
                &io::Error::from(error),
            )
        })?;

        let mut bytes = Zeroizing::new(Vec::new());
        let mut buffer = [0_u8; 256];
        loop {
            if cancellation.is_cancelled() {
                break Err(secret_input_control_error(
                    "request_canceled",
                    ErrorCategory::Canceled,
                    "hidden credential input was canceled",
                ));
            }
            if Instant::now() >= deadline {
                break Err(secret_input_control_error(
                    "request_timeout",
                    ErrorCategory::Timeout,
                    "hidden credential input exceeded the overall timeout",
                ));
            }
            match terminal.read(&mut buffer) {
                Ok(0) => {
                    break Err(hidden_input_io_error(
                        "failed to read hidden client secret",
                        &io::Error::new(io::ErrorKind::UnexpectedEof, "terminal input ended"),
                    ));
                }
                Ok(read) => {
                    bytes.extend_from_slice(&buffer[..read]);
                    if bytes.len() as u64 > SECRET_INPUT_LIMIT {
                        break Err(ReltioError::usage(
                            "secret_input_too_large",
                            "hidden client secret exceeds the 1 MB local safety limit",
                        )
                        .with_output_guard(reltio_client::redaction::OutputGuard::deny_all()));
                    }
                    if let Some(line_end) =
                        bytes.iter().position(|byte| matches!(byte, b'\r' | b'\n'))
                    {
                        bytes.truncate(line_end);
                        break String::from_utf8(bytes.to_vec()).map_err(|_| {
                            ReltioError::usage(
                                "secret_input_not_utf8",
                                "hidden client secret must be UTF-8",
                            )
                            .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
                        });
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => {
                    break Err(hidden_input_io_error(
                        "failed to read hidden client secret",
                        &error,
                    ));
                }
            }
        }
    })();
    let restore_result = if read_result.is_err() {
        restore
            .restore_with(OptionalActions::Flush)
            .map_err(|error| {
                hidden_input_cleanup_error(
                    "terminal input could not be atomically flushed and restored",
                    &error,
                )
            })
    } else {
        restore.restore().map_err(|error| {
            hidden_input_cleanup_error("terminal input settings could not be restored", &error)
        })
    };
    match (read_result, restore_result) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => result,
    }
}

#[cfg(unix)]
fn hidden_input_io_error(message: &'static str, error: &io::Error) -> ReltioError {
    ReltioError::io(message, error)
        .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
}

#[cfg(unix)]
fn hidden_input_cleanup_error(message: &'static str, error: &io::Error) -> ReltioError {
    ReltioError::new(
        "hidden_input_cleanup_failed",
        ErrorCategory::Safety,
        message,
    )
    .with_details(json!({ "reason": format!("{:?}", error.kind()) }))
    .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
}

fn secret_input_control_error(
    code: &'static str,
    category: ErrorCategory,
    message: &'static str,
) -> ReltioError {
    ReltioError::new(code, category, message)
        .with_details(json!({
            "phase": "credential_input",
            "remote_response_received": false,
            "remote_request_completed": false,
            "remote_operation_completed": false,
            "remote_operation_state": "request_not_sent",
            "local_state_committed": false,
            "safe_to_replay": true
        }))
        .with_output_guard(reltio_client::redaction::OutputGuard::deny_all())
}

fn absolute_local_path(path: &Path, require_absolute: bool, label: &str) -> Result<PathBuf> {
    if require_absolute && !path.is_absolute() {
        return Err(ReltioError::usage(
            "local_path_must_be_absolute",
            format!("{label} must use an absolute path"),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ReltioError::usage(
            "local_path_unsupported",
            format!("{label} may not contain parent-directory components"),
        ));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|error| ReltioError::io("failed to resolve a local path", &error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_metadata_preserves_known_authentication_completion() {
        let error = auth_command_canceled(
            "before_auth_login_output",
            true,
            &reltio_client::redaction::OutputGuard::default(),
            false,
            AuthRemoteOutcome::Succeeded,
        );

        assert_eq!(error.details["remote_response_received"], true);
        assert_eq!(error.details["remote_request_completed"], true);
        assert_eq!(error.details["remote_operation_completed"], true);
        assert_eq!(
            error.details["remote_operation_state"],
            "authentication_succeeded"
        );
        assert_eq!(error.details["local_state_committed"], true);
        assert_eq!(error.details["safe_to_replay"], false);
    }

    #[test]
    fn local_auth_cancellation_does_not_claim_a_remote_request() {
        let error = auth_command_canceled(
            "token_cache_snapshot",
            false,
            &reltio_client::redaction::OutputGuard::default(),
            false,
            AuthRemoteOutcome::NotSent,
        );

        assert_eq!(error.details["remote_response_received"], false);
        assert_eq!(error.details["remote_request_completed"], false);
        assert_eq!(error.details["remote_operation_completed"], false);
        assert_eq!(error.details["remote_operation_state"], "request_not_sent");
    }

    #[cfg(unix)]
    #[test]
    fn hidden_input_timeout_flushes_pending_input_and_restores_terminal_settings() {
        use std::ffi::OsStr;
        use std::fs::OpenOptions;
        use std::os::unix::ffi::OsStrExt as _;

        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("open pseudoterminal master");
        grantpt(&master).expect("grant pseudoterminal");
        unlockpt(&master).expect("unlock pseudoterminal");
        let slave_name = ptsname(&master, Vec::new()).expect("pseudoterminal slave path");
        let slave_path = Path::new(OsStr::from_bytes(slave_name.as_bytes()));
        let mut slave = OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path)
            .expect("open pseudoterminal slave");
        let before = rustix::termios::tcgetattr(&slave).expect("initial terminal settings");
        assert!(
            before
                .local_modes
                .contains(rustix::termios::LocalModes::ICANON),
            "the flush regression requires canonical input"
        );
        let reader_path = slave_path.to_path_buf();
        let reader = std::thread::spawn(move || {
            read_hidden_secret_unix_from(
                &reader_path,
                Instant::now() + Duration::from_millis(250),
                &reltio_client::cancellation::CancellationToken::new(),
            )
        });

        let mut echo_disabled = false;
        for _ in 0..100 {
            let current = rustix::termios::tcgetattr(&slave).expect("inspect hidden settings");
            if !current
                .local_modes
                .contains(rustix::termios::LocalModes::ECHO)
            {
                echo_disabled = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(echo_disabled, "hidden-input reader did not disable echo");
        assert_eq!(
            rustix::io::write(&master, b"abandoned-secret").expect("write pending input"),
            b"abandoned-secret".len()
        );

        let error = reader
            .join()
            .expect("hidden-input reader thread completes")
            .expect_err("partial hidden input reaches its deadline");

        assert_eq!(error.code, "request_timeout");
        let after = rustix::termios::tcgetattr(&slave).expect("restored terminal settings");
        assert_eq!(format!("{after:?}"), format!("{before:?}"));

        assert_eq!(
            rustix::io::write(&master, b"\n").expect("finish the post-timeout line"),
            1
        );
        let mut line = [0_u8; 64];
        let read = slave.read(&mut line).expect("read post-timeout line");
        assert_eq!(
            &line[..read],
            b"\n",
            "partial credential input remained queued after echo restoration"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hidden_input_cleanup_failures_are_safety_errors() {
        let source = io::Error::other("synthetic terminal cleanup failure");
        let error = hidden_input_cleanup_error("terminal cleanup failed", &source);

        assert_eq!(error.code, "hidden_input_cleanup_failed");
        assert_eq!(error.category, ErrorCategory::Safety);
        assert!(
            !error
                .output_guard()
                .expect("cleanup failure denies output")
                .permits(b"unrelated-output")
        );
    }
}
