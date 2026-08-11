use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use chrono::{TimeDelta, Utc};
use is_terminal::IsTerminal;
use reltio_client::auth::{AccessToken, TokenManager, TokenManagerOptions};
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
use crate::output::{Meta, prepare_success_guarded, write_raw_guarded, write_success_guarded};

const SECRET_INPUT_LIMIT: u64 = 1024 * 1024;

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

pub async fn run(runtime: &Runtime, command: AuthSubcommand) -> Result<()> {
    match command {
        AuthSubcommand::Login(arguments) => login(runtime, arguments).await,
        AuthSubcommand::Status => status(runtime),
        AuthSubcommand::Check => check(runtime).await,
        AuthSubcommand::Token { show } => reveal_token(runtime, show).await,
        AuthSubcommand::Logout => logout(runtime),
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
    let previous_output_guard = TokenManager::profile_output_guard(
        &previous_target,
        &runtime.environment,
        &runtime.paths.cache_dir,
    )
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
    let candidate_profile = candidate
        .profiles
        .get(&profile_name)
        .unwrap_or_else(|| unreachable!("the candidate profile was resolved above"))
        .clone();
    let target = resolve_target(&candidate, &runtime.environment, &resolution_overrides)?;
    let mut input_output_guard = runtime.environment_output_guard();
    input_output_guard.merge(&previous_output_guard);
    let mut one_shot_secret = if arguments.secret_stdin {
        let secret = read_secret_from_stdin("client secret")
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
        let secret = rpassword::prompt_password("Reltio client secret: ")
            .map_err(|error| ReltioError::io("failed to read hidden client secret", &error))?;
        let secret: SecretString = secret.into();
        input_output_guard.merge(&reltio_client::redaction::OutputGuard::from_known_secrets(
            &[secret.expose_secret()],
        ));
        one_shot_secret = Some(secret);
    }
    runtime
        .ensure_not_cancelled("credential_input", false)
        .map_err(|error| error.with_output_guard(input_output_guard.clone()))?;
    let (provider, expires_at, cache_hit, mut output_guard, pending_login) = match arguments.method
    {
        AuthMethod::Bearer => {
            let token = if arguments.token_stdin {
                read_secret_from_stdin("access token")
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
            let manager_guard = manager
                .output_guard()
                .map_err(|error| error.with_output_guard(output_guard.clone()))?;
            output_guard.merge(&manager_guard);
            let token = {
                let acquisition = manager.acquire_for_login_until(deadline);
                tokio::pin!(acquisition);
                tokio::select! {
                    biased;
                    result = &mut acquisition => result
                        .map_err(|error| error.with_output_guard(output_guard.clone()))?,
                    () = runtime.cancellation.cancelled() => {
                        return Err(auth_command_canceled(
                            "authentication",
                            false,
                            &output_guard,
                            true,
                        ));
                    }
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
    let mut cache_plan = match &pending_login {
        PendingLogin::Bearer { token, expires_at } => {
            let preparation = TokenManager::prepare_bearer_login_until(
                &runtime.paths.cache_dir,
                &profile_name,
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
                    ));
                }
            }
        }
    }
    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(cache_plan.output_guard());
    output_guard.merge(
        &TokenManager::profile_output_guard(
            &previous_target,
            &runtime.environment,
            &runtime.paths.cache_dir,
        )
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

    runtime
        .ensure_not_cancelled("before_token_cache_commit", false)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    if let Err(error) = cache_plan.commit_with_cancellation(&runtime.cancellation) {
        return Err(login_cache_error(error, output_guard));
    }
    if runtime.cancellation.is_cancelled() {
        let cancellation =
            auth_command_canceled("after_token_cache_commit", false, &output_guard, false);
        let rollback = cache_plan.rollback();
        drop(cache_plan);
        if let Err(rollback_error) = rollback {
            return Err(login_cache_rollback_error(
                &cancellation,
                &rollback_error,
                output_guard,
            ));
        }
        return Err(login_profile_commit_error(cancellation, output_guard));
    }
    if let Err(error) = commit_auth_profile(
        runtime,
        &profile_name,
        &previous_profile,
        &candidate_profile,
        deadline,
        &output_guard,
    ) {
        if error.details["committed"] == true {
            drop(cache_plan);
            return Err(login_commit_state_error(error, output_guard));
        }
        let rollback = cache_plan.rollback();
        drop(cache_plan);
        if let Err(rollback_error) = rollback {
            return Err(login_cache_rollback_error(
                &error,
                &rollback_error,
                output_guard,
            ));
        }
        return Err(login_profile_commit_error(error, output_guard));
    }
    drop(cache_plan);

    runtime
        .ensure_not_cancelled("before_auth_login_output", true)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;

    success
        .write_stdout()
        .map_err(|error| login_output_error(error, output_guard))
}

fn commit_auth_profile(
    runtime: &Runtime,
    profile_name: &str,
    previous: &Profile,
    candidate: &Profile,
    deadline: Instant,
    output_guard: &reltio_client::redaction::OutputGuard,
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
            let mut guard = output_guard.clone();
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
                    TokenManager::profile_output_guard(
                        &target,
                        &runtime.environment,
                        &runtime.paths.cache_dir,
                    )
                });
            match winner_guard {
                Some(Ok(winner_guard)) => guard.merge(&winner_guard),
                Some(Err(guard_error)) => {
                    if let Some(error_guard) = guard_error.output_guard() {
                        guard.merge(error_guard);
                    } else {
                        guard.merge(&reltio_client::redaction::OutputGuard::deny_all());
                    }
                }
                None => guard.merge(&reltio_client::redaction::OutputGuard::deny_all()),
            }
            Err(error.with_output_guard(guard))
        }
        Err(error) => Err(error.with_output_guard(output_guard.clone())),
    }
}

fn auth_command_canceled(
    phase: &'static str,
    local_state_committed: bool,
    output_guard: &reltio_client::redaction::OutputGuard,
    uninspected_provider_output: bool,
) -> ReltioError {
    let mut guard = output_guard.clone();
    if uninspected_provider_output {
        guard.merge(&reltio_client::redaction::OutputGuard::deny_all());
    }
    ReltioError::new(
        "request_canceled",
        ErrorCategory::Canceled,
        "authentication was canceled",
    )
    .with_details(json!({
        "phase": phase,
        "remote_response_received": false,
        "remote_request_completed": Value::Null,
        "remote_operation_completed": Value::Null,
        "remote_operation_state": "authentication_completion_unknown",
        "local_state_committed": local_state_committed,
        "safe_to_replay": false
    }))
    .with_output_guard(guard)
}

fn login_cache_error(
    mut error: ReltioError,
    output_guard: reltio_client::redaction::OutputGuard,
) -> ReltioError {
    let local_cache_restored = error.details["local_cache_restored"] == true;
    let cache_details = std::mem::take(&mut error.details);
    error.details = json!({
        "cache_error": cache_details,
        "local_profile_changed": false,
        "local_cache_restored": local_cache_restored,
        "local_state_committed": false,
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
) -> ReltioError {
    let profile_details = std::mem::take(&mut error.details);
    error.details = json!({
        "profile_error": profile_details,
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
) -> ReltioError {
    ReltioError::new(
        "auth_login_rollback_failed",
        ErrorCategory::Internal,
        "profile persistence failed and authentication cache rollback did not complete",
    )
    .with_details(json!({
        "profile_error": profile_error.code,
        "rollback_error": rollback_error.code,
        "local_profile_committed": false,
        "local_cache_restored": false,
        "local_state_committed": false,
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
) -> ReltioError {
    let commit_details = std::mem::take(&mut error.details);
    error.details = json!({
        "config_commit_error": commit_details,
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
) -> ReltioError {
    let output_details = std::mem::take(&mut error.details);
    error.details = json!({
        "output_error": output_details,
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

fn status(runtime: &Runtime) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    runtime.ensure_not_cancelled("before_auth_status", false)?;
    let (_, target) = runtime.config_and_target()?;
    let (status, output_guard) =
        match runtime.token_manager(&target, TokenManagerOptions::default()) {
            Ok(manager) => {
                let output_guard = manager.output_guard()?;
                let status = manager
                    .status_until(deadline)
                    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
                (status, output_guard)
            }
            Err(error) if error.code == "auth_unconfigured" => {
                let mut meta = Meta::new("auth.status").with_target(&target, Some("auth"));
                meta.elapsed_ms = started.elapsed().as_millis();
                return write_success_guarded(
                    &json!({
                        "configured": false,
                        "provider": null,
                        "cache_state": "not_applicable",
                        "configuration_sources": target.sources
                    }),
                    &meta,
                    runtime.render,
                    &runtime.local_output_guard(),
                );
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
    write_success_guarded(
        &json!({
            "configured": status.configured,
            "provider": status.provider,
            "source": status.source,
            "cache_state": status.cache_state,
            "expires_at": status.expires_at,
            "environment_override": status.environment_override,
            "configuration_sources": target.sources
        }),
        &meta,
        runtime.render,
        &output_guard,
    )
}

async fn check(runtime: &Runtime) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = manager.output_guard()?;
    let auth_status = manager
        .status_until(deadline)
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
    write_success_guarded(
        &json!({
            "valid": true,
            "tenant_access": true,
            "provider": auth_status.provider,
            "sample_entities_returned": page.entities.len()
        }),
        &meta,
        runtime.render,
        &output_guard,
    )
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
    let manager_guard = manager.output_guard()?;
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
            ));
        }
    };
    if runtime.cancellation.is_cancelled() {
        return Err(auth_command_canceled(
            "before_token_output",
            false,
            token.output_guard(),
            false,
        ));
    }
    let disclosure_guard = token.output_guard().excluding_secret(token.expose_secret());
    if runtime.render.format == OutputFormat::Raw {
        return write_raw_guarded(token.expose_secret().as_bytes(), true, &disclosure_guard);
    }
    let mut meta = Meta::new("auth.token").with_target(&target, Some("auth"));
    meta.elapsed_ms = started.elapsed().as_millis();
    meta.auth_source = Some(token.provider.clone());
    meta.warnings
        .push("stdout intentionally contains access-token material".to_owned());
    write_success_guarded(
        &json!({
            "access_token": token.expose_secret(),
            "token_type": "Bearer",
            "expires_at": token.expires_at
        }),
        &meta,
        runtime.render,
        &disclosure_guard,
    )
}

fn logout(runtime: &Runtime) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let (removed, mut output_guard) = TokenManager::clear_local_cache_until(
        &runtime.paths.cache_dir,
        deadline,
        &runtime.cancellation,
    )?;
    let cleared = removed > 0;
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
    output_guard.merge(&reltio_client::redaction::OutputGuard::from_known_secrets(
        &["RELTIO_ACCESS_TOKEN", "RELTIO_CLIENT_SECRET"]
            .into_iter()
            .filter_map(|name| runtime.environment.get(name))
            .collect::<Vec<_>>(),
    ));
    runtime
        .ensure_not_cancelled("before_auth_logout_output", cleared)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    write_success_guarded(
        &json!({
            "local_cache_cleared": cleared,
            "remote_revocation_attempted": false,
            "environment_token_cleared": false
        }),
        &meta,
        runtime.render,
        &output_guard,
    )
    .map_err(|mut error| {
        error.details = json!({
            "local_cache_cleared": cleared,
            "remote_revocation_attempted": false,
            "output_omitted": true,
            "safe_to_replay": false,
            "local_state_committed": cleared
        });
        error
    })
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

fn read_secret_from_stdin(label: &str) -> Result<SecretString> {
    if io::stdin().is_terminal() {
        return Err(ReltioError::usage(
            "secret_stdin_is_tty",
            format!("refusing to read {label} visibly from terminal stdin"),
        )
        .with_hint("Pipe the secret or omit the stdin flag to use a hidden prompt."));
    }
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
