use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use reltio_client::auth::{TokenManager, stored_imported_bearer_cache_key};
use reltio_client::config::{
    AuthMethod, AuthProfile, ConfigFile, ConfigStore, Profile, validate_profile_name,
    validate_tenant,
};
use reltio_client::error::{ReltioError, Result};
use reltio_client::service::{Service, validate_service_url};
use serde_json::{Value, json};

use crate::cli::{ProfileAddArgs, ProfileSubcommand, ProfileUpdateArgs};
use crate::commands::Runtime;
use crate::output::{Meta, PreparedOutput, prepare_success_guarded};

const PROFILE_REMOVE_COMPENSATION_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run(runtime: &Runtime, command: ProfileSubcommand) -> Result<()> {
    let started = Instant::now();
    let output_guard = runtime.local_output_guard_snapshot();
    match command {
        ProfileSubcommand::List => {
            let config = runtime.store.load()?;
            let data = Value::Array(
                config
                    .profiles
                    .iter()
                    .map(|(name, profile)| {
                        profile_summary(
                            name,
                            profile,
                            config.current_profile.as_deref() == Some(name),
                        )
                    })
                    .collect(),
            );
            write_local(runtime, "profile.list", &data, started, &output_guard).await
        }
        ProfileSubcommand::Show { name } => {
            let config = runtime.store.load()?;
            let selected = name
                .or_else(|| runtime.globals.profile.clone())
                .or_else(|| {
                    runtime
                        .environment
                        .get("RELTIO_PROFILE")
                        .map(ToOwned::to_owned)
                })
                .or_else(|| config.current_profile.clone())
                .ok_or_else(|| {
                    ReltioError::profile(
                        "profile_unresolved",
                        "no profile name was supplied or configured",
                    )
                })?;
            let profile = config.profiles.get(&selected).ok_or_else(|| {
                ReltioError::profile(
                    "profile_not_found",
                    format!("profile {selected:?} does not exist"),
                )
            })?;
            write_local(
                runtime,
                "profile.show",
                &profile_view(
                    &selected,
                    profile,
                    config.current_profile.as_deref() == Some(&selected),
                ),
                started,
                &output_guard,
            )
            .await
        }
        ProfileSubcommand::Add(arguments) => {
            let name = arguments.name.clone();
            let profile = build_profile(arguments)?;
            commit_profile_change(
                runtime,
                "profile.add",
                started,
                &output_guard,
                move |config| {
                    if config.profiles.contains_key(&name) {
                        return Err(ReltioError::profile(
                            "profile_already_exists",
                            format!("profile {name:?} already exists"),
                        ));
                    }
                    config.profiles.insert(name.clone(), profile.clone());
                    if config.current_profile.is_none() {
                        config.current_profile = Some(name.clone());
                    }
                    Ok(profile_view(
                        &name,
                        &profile,
                        config.current_profile.as_deref() == Some(&name),
                    ))
                },
            )
            .await
        }
        ProfileSubcommand::Update(arguments) => {
            let mut arguments = arguments;
            arguments.secret_file = arguments
                .secret_file
                .as_deref()
                .map(absolute_local_path)
                .transpose()?;
            let name = arguments.name.clone();
            commit_profile_change(
                runtime,
                "profile.update",
                started,
                &output_guard,
                move |config| {
                    let profile = update_profile(config, &arguments)?;
                    Ok(profile_view(
                        &name,
                        &profile,
                        config.current_profile.as_deref() == Some(&name),
                    ))
                },
            )
            .await
        }
        ProfileSubcommand::Use { name } => {
            validate_profile_name(&name)?;
            commit_profile_change(
                runtime,
                "profile.use",
                started,
                &output_guard,
                move |config| {
                    if !config.profiles.contains_key(&name) {
                        return Err(ReltioError::profile(
                            "profile_not_found",
                            format!("profile {name:?} does not exist"),
                        ));
                    }
                    config.current_profile = Some(name.clone());
                    Ok(json!({ "current_profile": name }))
                },
            )
            .await
        }
        ProfileSubcommand::Remove { name } => {
            validate_profile_name(&name)?;
            let deadline = runtime.deadline_from(started)?;
            let mut remove_guard = output_guard.clone();
            let initial_config = runtime.store.load()?;
            let expected_profile =
                initial_config.profiles.get(&name).cloned().ok_or_else(|| {
                    ReltioError::profile(
                        "profile_not_found",
                        format!("profile {name:?} does not exist"),
                    )
                })?;
            let bearer_cache_keys =
                profile_bearer_cleanup_keys(&initial_config, &name, &expected_profile)?;
            let has_bearer_cache = !bearer_cache_keys.is_empty();
            let mut cache_plan = match TokenManager::prepare_imported_bearer_removal_until(
                &runtime.paths.cache_dir,
                &bearer_cache_keys,
                deadline,
                &runtime.cancellation,
            ) {
                Ok(plan) => plan,
                Err(mut error) => {
                    if let Some(guard) = error.output_guard() {
                        remove_guard.merge(guard);
                    }
                    "profile_remove_cache_prepare_failed".clone_into(&mut error.code);
                    "profile removal could not prepare imported-bearer cleanup"
                        .clone_into(&mut error.message);
                    return Err(profile_remove_state_error(
                        error,
                        Some(false),
                        Some(false),
                        Some(false),
                        true,
                        &remove_guard,
                    ));
                }
            };
            remove_guard.merge(cache_plan.output_guard());
            runtime
                .ensure_not_cancelled("before_profile_remove_commit", false)
                .map_err(|error| error.with_output_guard(remove_guard.clone()))?;
            let config_result = runtime.store.modify_until(
                deadline,
                || runtime.cancellation.is_cancelled(),
                |config| {
                    let profile = config.profiles.get(&name).cloned().ok_or_else(|| {
                        ReltioError::profile(
                            "profile_not_found",
                            format!("profile {name:?} does not exist"),
                        )
                    })?;
                    if profile != expected_profile {
                        return Err(ReltioError::new(
                            "profile_remove_commit_conflict",
                            reltio_client::error::ErrorCategory::Conflict,
                            "the selected profile changed concurrently; refusing to remove it with a stale bearer cache identity",
                        ));
                    }
                    let profile_guard = TokenManager::configured_profile_credential_output_guard(
                        &profile.auth,
                        &runtime.environment,
                        false,
                    )
                    .map_err(|error| error.with_output_guard(remove_guard.clone()))?;
                    remove_guard.merge(&profile_guard);
                    let data = json!({ "removed": name });
                    let mut meta = Meta::new("profile.remove");
                    meta.elapsed_ms = started.elapsed().as_millis();
                    let success =
                        prepare_success_guarded(&data, &meta, runtime.render, &remove_guard)
                            .map_err(|error| {
                                profile_remove_state_error(
                                    error,
                                    Some(false),
                                    Some(false),
                                    Some(false),
                                    true,
                                    &remove_guard,
                                )
                            })?;
                    let removed_was_current = config.current_profile.as_deref() == Some(&name);
                    config.profiles.remove(&name);
                    if removed_was_current {
                        config.current_profile = None;
                    }
                    if has_bearer_cache {
                        config
                            .pending_imported_bearer_cleanups
                            .entry(name.clone())
                            .or_default()
                            .extend(bearer_cache_keys.iter().cloned());
                    }
                    Ok((success, profile, removed_was_current))
                },
            );
            let (success, removed_profile, removed_was_current) = match config_result {
                Ok(result) => result,
                Err(mut error) => {
                    if error.details.get("local_profile_committed").is_some() {
                        drop(cache_plan);
                        return Err(error);
                    }
                    if error.details["committed"].as_bool() == Some(true) {
                        "profile_remove_config_commit_uncertain".clone_into(&mut error.code);
                        "profile removal may have committed, but configuration durability could not be fully confirmed"
                            .clone_into(&mut error.message);
                        drop(cache_plan);
                        return Err(profile_remove_state_error(
                            error,
                            Some(true),
                            Some(false),
                            None,
                            false,
                            &remove_guard,
                        ));
                    }
                    drop(cache_plan);
                    if error.code != "profile_not_found" {
                        "profile_remove_config_failed".clone_into(&mut error.code);
                        "profile removal could not commit the configuration change"
                            .clone_into(&mut error.message);
                    }
                    return Err(profile_remove_state_error(
                        error,
                        Some(false),
                        Some(false),
                        Some(false),
                        true,
                        &remove_guard,
                    ));
                }
            };

            if runtime.cancellation.is_cancelled() {
                let cancellation = runtime
                    .ensure_not_cancelled("after_profile_remove_commit", true)
                    .expect_err("the cancellation token was observed above")
                    .with_output_guard(remove_guard.clone());
                drop(cache_plan);
                return Err(profile_remove_state_error(
                    cancellation,
                    Some(true),
                    Some(false),
                    Some(has_bearer_cache),
                    true,
                    &remove_guard,
                ));
            }

            if let Err(mut error) = cache_plan.commit_with_cancellation(&runtime.cancellation) {
                let restored = error.details["local_cache_restored"].as_bool() == Some(true);
                if restored {
                    "profile_remove_cache_failed".clone_into(&mut error.code);
                    "imported-bearer cleanup failed; restoring the removed profile"
                        .clone_into(&mut error.message);
                    let profile = removed_profile.clone();
                    let rollback = compensate_failed_profile_cache_removal(
                        &runtime.store,
                        &name,
                        &profile,
                        &bearer_cache_keys,
                        removed_was_current,
                    );
                    if let Err(rollback_error) = rollback {
                        let cache_error = error;
                        drop(cache_plan);
                        return Err(ReltioError::new(
                            "profile_remove_rollback_failed",
                            reltio_client::error::ErrorCategory::Internal,
                            "imported-bearer cleanup failed and the removed profile could not be restored",
                        )
                        .with_details(json!({
                            "cache_error": cache_error.code,
                            "config_rollback_error": rollback_error.code,
                            "local_profile_committed": Value::Null,
                            "local_cache_committed": false,
                            "cleanup_pending": true,
                            "local_state_committed": Value::Null,
                            "safe_to_replay": false
                        }))
                        .with_hint(
                            "Inspect profile and authentication state before retrying removal.",
                        )
                        .with_output_guard(remove_guard));
                    }
                    drop(cache_plan);
                    return Err(profile_remove_state_error(
                        error,
                        Some(false),
                        Some(false),
                        Some(false),
                        true,
                        &remove_guard,
                    ));
                }
                "profile_remove_cache_state_uncertain".clone_into(&mut error.code);
                "the profile was removed, but imported-bearer cleanup could not be verified"
                    .clone_into(&mut error.message);
                drop(cache_plan);
                return Err(profile_remove_state_error(
                    error,
                    Some(true),
                    None,
                    Some(true),
                    true,
                    &remove_guard,
                ));
            }

            let cleanup_result = if has_bearer_cache {
                runtime.store.modify_until(
                    deadline,
                    || runtime.cancellation.is_cancelled(),
                    |config| {
                        if config.profiles.contains_key(&name) {
                            return Err(ReltioError::profile(
                                "pending_bearer_cleanup_conflict",
                                format!(
                                    "profile {name:?} was recreated before bearer cleanup completed"
                                ),
                            ));
                        }
                        if config.pending_imported_bearer_cleanups.get(&name)
                            != Some(&bearer_cache_keys)
                        {
                            return Err(ReltioError::profile(
                                "pending_bearer_cleanup_conflict",
                                format!(
                                    "profile {name:?} bearer cleanup marker changed concurrently"
                                ),
                            ));
                        }
                        config.pending_imported_bearer_cleanups.remove(&name);
                        Ok(())
                    },
                )
            } else {
                Ok(())
            };
            if let Err(mut error) = cleanup_result {
                let committed = error.details["committed"].as_bool() == Some(true);
                "profile_remove_cleanup_state_failed".clone_into(&mut error.code);
                "the profile and imported bearer were removed, but cleanup-marker durability could not be confirmed"
                    .clone_into(&mut error.message);
                drop(cache_plan);
                return Err(profile_remove_state_error(
                    error,
                    Some(true),
                    Some(true),
                    (!committed).then_some(true),
                    !committed,
                    &remove_guard,
                ));
            }
            runtime
                .ensure_not_cancelled("before_profile_remove_output", true)
                .map_err(|error| error.with_output_guard(remove_guard.clone()))?;
            let plan_guard = cache_plan.output_guard().clone();
            runtime
                .emit_prepared_with_owner(success, cache_plan, &plan_guard, deadline)
                .await
                .map_err(|error| {
                    profile_remove_state_error(
                        error,
                        Some(true),
                        Some(has_bearer_cache),
                        Some(false),
                        false,
                        &remove_guard,
                    )
                })
        }
    }
}

fn profile_remove_state_error(
    mut error: ReltioError,
    profile_committed: Option<bool>,
    cache_committed: Option<bool>,
    cleanup_pending: Option<bool>,
    safe_to_replay: bool,
    output_guard: &reltio_client::redaction::OutputGuard,
) -> ReltioError {
    let local_state_committed = match (profile_committed, cache_committed) {
        (Some(true), _) | (_, Some(true)) => Value::Bool(true),
        (Some(false), Some(false)) => Value::Bool(false),
        _ => Value::Null,
    };
    let cause = std::mem::take(&mut error.details);
    error.details = json!({
        "cause": cause,
        "local_profile_committed": profile_committed,
        "local_cache_committed": cache_committed,
        "cleanup_pending": cleanup_pending,
        "local_state_committed": local_state_committed,
        "safe_to_replay": safe_to_replay
    });
    error.retryable = false;
    error.with_output_guard(output_guard.clone())
}

fn restore_removed_profile(
    config: &mut ConfigFile,
    name: &str,
    profile: &Profile,
    bearer_cache_keys: &BTreeSet<String>,
    removed_was_current: bool,
) -> Result<()> {
    if config.profiles.contains_key(name) {
        return Err(ReltioError::profile(
            "profile_remove_rollback_conflict",
            format!("profile {name:?} was recreated before rollback completed"),
        ));
    }
    if config.pending_imported_bearer_cleanups.get(name) != Some(bearer_cache_keys) {
        return Err(ReltioError::profile(
            "profile_remove_rollback_conflict",
            format!("profile {name:?} cleanup marker changed before rollback completed"),
        ));
    }
    config.pending_imported_bearer_cleanups.remove(name);
    config.profiles.insert(name.to_owned(), profile.clone());
    if removed_was_current && config.current_profile.is_none() {
        config.current_profile = Some(name.to_owned());
    }
    Ok(())
}

fn profile_bearer_cleanup_keys(
    config: &ConfigFile,
    name: &str,
    profile: &Profile,
) -> Result<BTreeSet<String>> {
    let mut keys = config
        .pending_imported_bearer_cleanups
        .get(name)
        .cloned()
        .unwrap_or_default();
    if let Some(active) = stored_imported_bearer_cache_key(&profile.auth)? {
        keys.insert(active.to_owned());
    }
    Ok(keys)
}

fn compensate_failed_profile_cache_removal(
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    bearer_cache_keys: &BTreeSet<String>,
    removed_was_current: bool,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(PROFILE_REMOVE_COMPENSATION_TIMEOUT)
        .ok_or_else(|| ReltioError::internal("profile-removal compensation deadline overflowed"))?;
    store.modify_until(
        deadline,
        || false,
        |config| {
            restore_removed_profile(
                config,
                name,
                profile,
                bearer_cache_keys,
                removed_was_current,
            )
        },
    )
}

async fn commit_profile_change(
    runtime: &Runtime,
    command: &str,
    started: Instant,
    initial_guard: &reltio_client::redaction::OutputGuard,
    update: impl FnOnce(&mut ConfigFile) -> Result<Value>,
) -> Result<()> {
    let deadline = runtime.deadline_from(started)?;
    let mut precommit_guard = initial_guard.clone();
    precommit_guard.merge(&runtime.local_output_guard_snapshot());
    let mut committed_guard = precommit_guard.clone();
    let prepared = runtime.store.modify_until(
        deadline,
        || runtime.cancellation.is_cancelled(),
        |config| {
            let preimage_guard = TokenManager::configured_config_credential_output_guard_until(
                config,
                &runtime.environment,
                false,
                deadline,
                Some(&runtime.cancellation),
            )
            .map_err(|error| error.with_output_guard(committed_guard.clone()))?;
            committed_guard.merge(&preimage_guard);
            let data = update(config)?;
            let postimage_guard = TokenManager::configured_config_credential_output_guard_until(
                config,
                &runtime.environment,
                true,
                deadline,
                Some(&runtime.cancellation),
            )
            .map_err(|error| error.with_output_guard(committed_guard.clone()))?;
            committed_guard.merge(&postimage_guard);
            let mut meta = Meta::new(command);
            meta.elapsed_ms = started.elapsed().as_millis();
            prepare_success_guarded(&data, &meta, runtime.render, &committed_guard).map_err(
                |error| profile_change_state_error(error, false, true, false, &committed_guard),
            )
        },
    );
    let prepared: PreparedOutput = match prepared {
        Ok(prepared) => prepared,
        Err(error) if error.details.get("local_state_committed").is_some() => return Err(error),
        Err(error) if error.details["committed"].as_bool() == Some(true) => {
            return Err(profile_change_state_error(
                error,
                true,
                false,
                true,
                &committed_guard,
            ));
        }
        Err(error) => return Err(error.with_output_guard(committed_guard)),
    };
    if let Some((_, cleanup_guard)) = runtime
        .recover_pending_imported_bearer_cleanups()
        .await
        .map_err(|error| profile_change_state_error(error, true, false, false, &committed_guard))?
    {
        committed_guard.merge(&cleanup_guard);
    }
    runtime
        .ensure_not_cancelled("before_profile_output", true)
        .map_err(|error| profile_change_state_error(error, true, false, false, &committed_guard))?;
    runtime
        .emit_prepared(prepared, deadline)
        .await
        .map_err(|error| profile_change_state_error(error, true, false, false, &committed_guard))
}

fn profile_change_state_error(
    mut error: ReltioError,
    local_state_committed: bool,
    safe_to_replay: bool,
    durability_uncertain: bool,
    output_guard: &reltio_client::redaction::OutputGuard,
) -> ReltioError {
    let mut details = match std::mem::take(&mut error.details) {
        Value::Object(details) => details,
        cause => serde_json::Map::from_iter([("cause".to_owned(), cause)]),
    };
    details.insert(
        "local_state_committed".to_owned(),
        Value::Bool(local_state_committed),
    );
    details.insert("safe_to_replay".to_owned(), Value::Bool(safe_to_replay));
    details.insert(
        "durability_uncertain".to_owned(),
        Value::Bool(durability_uncertain),
    );
    error.details = Value::Object(details);
    error.retryable = false;
    if durability_uncertain {
        error.hint = Some(
            "The profile change was installed locally but durability could not be confirmed; inspect profile state instead of replaying the command."
                .to_owned(),
        );
    } else if local_state_committed {
        error.hint = Some(
            "The profile change committed locally even though output failed; inspect profile state instead of replaying the command."
                .to_owned(),
        );
    }
    error.with_output_guard(output_guard.clone())
}

fn build_profile(arguments: ProfileAddArgs) -> Result<Profile> {
    validate_profile_name(&arguments.name)?;
    if let Some(tenant) = arguments.tenant.as_deref() {
        validate_tenant(tenant)?;
    }
    if let Some(base_url) = arguments.base_url.as_deref() {
        validate_service_url(base_url)?;
    }
    if let Some(method) = arguments.auth_method {
        match method {
            reltio_client::config::AuthMethod::Bearer => {
                return Err(ReltioError::usage(
                    "bearer_configuration_requires_login",
                    "configure persisted bearer authentication with `reltio auth login --method bearer` so cache material is bound to this profile and target",
                ));
            }
            reltio_client::config::AuthMethod::CredentialProcess => {
                return Err(ReltioError::usage(
                    "credential_process_requires_login",
                    "configure a credential process with `reltio auth login --method credential-process` so its executable and arguments are validated together",
                ));
            }
            reltio_client::config::AuthMethod::ClientCredentials => {}
        }
    }
    let secret_file = arguments
        .secret_file
        .as_deref()
        .map(absolute_local_path)
        .transpose()?;
    Ok(Profile {
        environment: arguments.environment,
        base_url: arguments.base_url,
        tenant: arguments.tenant,
        production: arguments.production,
        services: parse_service_urls(&arguments.service_urls)?,
        auth: AuthProfile {
            method: arguments.auth_method,
            client_id: arguments.client_id,
            secret_file,
            credential_process: None,
            bearer_cache_key: None,
            bearer_cache_generation: None,
        },
    })
}

fn update_profile(config: &mut ConfigFile, arguments: &ProfileUpdateArgs) -> Result<Profile> {
    validate_profile_name(&arguments.name)?;
    validate_update_conflicts(arguments)?;
    if arguments.auth_method == Some(reltio_client::config::AuthMethod::Bearer) {
        return Err(ReltioError::usage(
            "bearer_configuration_requires_login",
            "configure persisted bearer authentication with `reltio auth login --method bearer` so stale cache material cannot be reactivated",
        ));
    }
    let service_urls = parse_service_urls(&arguments.service_urls)?;
    if arguments
        .remove_service_urls
        .iter()
        .any(|service| service_urls.contains_key(service))
    {
        return Err(ReltioError::usage(
            "profile_update_argument_conflict",
            "the same service URL cannot be set and removed in one profile update",
        ));
    }
    let previous = config
        .profiles
        .get(&arguments.name)
        .cloned()
        .ok_or_else(|| {
            ReltioError::profile(
                "profile_not_found",
                format!("profile {:?} does not exist", arguments.name),
            )
        })?;
    let mut profile = previous.clone();
    if arguments.clear_environment {
        profile.environment = None;
    } else if let Some(environment) = &arguments.environment {
        profile.environment = Some(environment.clone());
    }
    if arguments.clear_base_url {
        profile.base_url = None;
    } else if let Some(base_url) = &arguments.base_url {
        validate_service_url(base_url)?;
        profile.base_url = Some(base_url.clone());
    }
    if arguments.clear_tenant {
        profile.tenant = None;
    } else if let Some(tenant) = &arguments.tenant {
        validate_tenant(tenant)?;
        profile.tenant = Some(tenant.clone());
    }
    if let Some(production) = arguments.production {
        profile.production = production;
    }
    if arguments.clear_auth {
        profile.auth = AuthProfile::default();
    } else {
        if let Some(method) = arguments.auth_method {
            if method == reltio_client::config::AuthMethod::CredentialProcess {
                return Err(ReltioError::usage(
                    "credential_process_requires_login",
                    "configure a credential process with `reltio auth login --method credential-process` so its executable and arguments are validated together",
                ));
            }
            profile.auth.method = Some(method);
        }
        if let Some(client_id) = &arguments.client_id {
            profile.auth.client_id = Some(client_id.clone());
        } else if arguments.clear_client_id {
            profile.auth.client_id = None;
        }
        if let Some(secret_file) = &arguments.secret_file {
            profile.auth.secret_file = Some(secret_file.clone());
        } else if arguments.clear_secret_file {
            profile.auth.secret_file = None;
        }
    }
    if arguments.clear_service_urls {
        profile.services.clear();
    } else {
        for service in &arguments.remove_service_urls {
            profile.services.remove(service);
        }
        profile.services.extend(service_urls);
    }
    let routing_changed = previous.environment != profile.environment
        || previous.base_url != profile.base_url
        || previous.tenant != profile.tenant
        || previous.services != profile.services;
    if routing_changed && previous.auth.method.is_some() && !arguments.clear_auth {
        return Err(ReltioError::new(
            "profile_reauthentication_required",
            reltio_client::error::ErrorCategory::Safety,
            "profile routing cannot change while retaining authentication from the previous target",
        )
        .with_hint(
            "Repeat the update with --clear-auth, then authenticate explicitly for the new target.",
        ));
    }
    if previous.auth.method == Some(AuthMethod::Bearer)
        && (routing_changed || profile.auth.method != Some(AuthMethod::Bearer))
    {
        let cache_key = stored_imported_bearer_cache_key(&previous.auth)?
            .expect("the previous authentication method is bearer");
        config
            .pending_imported_bearer_cleanups
            .entry(arguments.name.clone())
            .or_default()
            .insert(cache_key.to_owned());
        profile.auth.bearer_cache_key = None;
        profile.auth.bearer_cache_generation = None;
    }
    config
        .profiles
        .insert(arguments.name.clone(), profile.clone());
    Ok(profile)
}

fn validate_update_conflicts(arguments: &ProfileUpdateArgs) -> Result<()> {
    let conflicting_pair = arguments.environment.is_some() && arguments.clear_environment
        || arguments.base_url.is_some() && arguments.clear_base_url
        || arguments.tenant.is_some() && arguments.clear_tenant
        || arguments.client_id.is_some() && arguments.clear_client_id
        || arguments.secret_file.is_some() && arguments.clear_secret_file;
    let clear_auth_conflict = arguments.clear_auth
        && (arguments.auth_method.is_some()
            || arguments.client_id.is_some()
            || arguments.clear_client_id
            || arguments.secret_file.is_some()
            || arguments.clear_secret_file);
    let clear_services_conflict = arguments.clear_service_urls
        && (!arguments.service_urls.is_empty() || !arguments.remove_service_urls.is_empty());
    if conflicting_pair || clear_auth_conflict || clear_services_conflict {
        return Err(ReltioError::usage(
            "profile_update_argument_conflict",
            "profile setters and their clearing/removal controls are mutually exclusive",
        ));
    }
    Ok(())
}

fn absolute_local_path(path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ReltioError::usage(
            "local_path_unsupported",
            "secret-file paths may not contain parent-directory components",
        ));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|error| ReltioError::io("failed to resolve the secret-file path", &error))
    }
}

fn parse_service_urls(values: &[String]) -> Result<BTreeMap<Service, String>> {
    let mut service_urls = BTreeMap::new();
    for value in values {
        let (service, url) = value.split_once('=').ok_or_else(|| {
            ReltioError::usage(
                "invalid_service_override",
                "service URL override must use SERVICE=URL",
            )
        })?;
        let service: Service = service.parse()?;
        if service_urls.contains_key(&service) {
            return Err(ReltioError::usage(
                "duplicate_service_override",
                format!("service {service} is assigned more than once in this invocation"),
            ));
        }
        let expanded = url
            .replace("{tenant}", "tenant")
            .replace("{environment}", "env");
        validate_service_url(&expanded)?;
        service_urls.insert(service, url.to_owned());
    }
    Ok(service_urls)
}

fn profile_summary(name: &str, profile: &Profile, current: bool) -> Value {
    json!({
        "name": name,
        "current": current,
        "environment": profile.environment,
        "tenant": profile.tenant,
        "production": profile.production,
        "auth_method": profile.auth.method.map(|method| method.to_string())
    })
}

fn profile_view(name: &str, profile: &Profile, current: bool) -> Value {
    json!({
        "name": name,
        "current": current,
        "environment": profile.environment,
        "base_url": profile.base_url,
        "tenant": profile.tenant,
        "production": profile.production,
        "services": profile.services,
        "auth": {
            "method": profile.auth.method.map(|method| method.to_string()),
            "client_id": profile.auth.client_id,
            "secret_source": profile.auth.secret_file.as_ref().map(|_| "protected_file"),
            "secret_file": profile.auth.secret_file,
            "credential_process": profile.auth.credential_process.as_ref().map(|command| json!({
                "executable": command.first(),
                "argument_count": command.len().saturating_sub(1)
            }))
        }
    })
}

async fn write_local(
    runtime: &Runtime,
    command: &str,
    data: &Value,
    started: Instant,
    initial_guard: &reltio_client::redaction::OutputGuard,
) -> Result<()> {
    let deadline = runtime.deadline_from(started)?;
    let mut meta = Meta::new(command);
    meta.elapsed_ms = started.elapsed().as_millis();
    let output_guard = initial_guard.clone();
    runtime
        .ensure_not_cancelled("before_profile_output", false)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    runtime
        .emit_success(data, &meta, deadline, &output_guard)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_arguments() -> ProfileUpdateArgs {
        ProfileUpdateArgs {
            name: "test".to_owned(),
            environment: None,
            clear_environment: false,
            base_url: None,
            clear_base_url: false,
            tenant: None,
            clear_tenant: false,
            production: None,
            auth_method: None,
            client_id: None,
            clear_client_id: false,
            secret_file: None,
            clear_secret_file: false,
            service_urls: Vec::new(),
            remove_service_urls: Vec::new(),
            clear_service_urls: false,
            clear_auth: false,
        }
    }

    fn config_with_profile() -> ConfigFile {
        ConfigFile {
            profiles: BTreeMap::from([(
                "test".to_owned(),
                Profile {
                    tenant: Some("OriginalTenant".to_owned()),
                    auth: AuthProfile {
                        method: Some(reltio_client::config::AuthMethod::Bearer),
                        client_id: Some("original-client".to_owned()),
                        ..AuthProfile::default()
                    },
                    ..Profile::default()
                },
            )]),
            ..ConfigFile::default()
        }
    }

    #[test]
    fn runtime_clear_auth_conflict_is_rejected_before_mutation() {
        let mut config = config_with_profile();
        let before = config.profiles.clone();
        let mut arguments = update_arguments();
        arguments.clear_auth = true;
        arguments.client_id = Some("replacement-client".to_owned());

        let error = update_profile(&mut config, &arguments)
            .expect_err("runtime validation must reject clear-auth with a setter");

        assert_eq!(error.code, "profile_update_argument_conflict");
        assert_eq!(config.profiles, before);
    }

    #[test]
    fn routing_change_requires_clear_auth_even_with_provider_irrelevant_setters() {
        let mut config = config_with_profile();
        let before = config.profiles.clone();
        let mut arguments = update_arguments();
        arguments.tenant = Some("ReplacementTenant".to_owned());
        arguments.client_id = Some("irrelevant-client".to_owned());

        let error = update_profile(&mut config, &arguments)
            .expect_err("routing changes cannot retain bearer authentication");

        assert_eq!(error.code, "profile_reauthentication_required");
        assert_eq!(config.profiles, before);
    }

    #[test]
    fn duplicate_service_aliases_and_set_remove_conflicts_are_runtime_errors() {
        let duplicate = parse_service_urls(&[
            "physical-config=https://one.example".to_owned(),
            "physical_config=https://two.example".to_owned(),
        ])
        .expect_err("service aliases identify the same assignment");
        assert_eq!(duplicate.code, "duplicate_service_override");

        let mut config = config_with_profile();
        let before = config.profiles.clone();
        let mut arguments = update_arguments();
        arguments.service_urls = vec!["physical-config=https://one.example".to_owned()];
        arguments.remove_service_urls = vec![Service::PhysicalConfig];
        let conflict = update_profile(&mut config, &arguments)
            .expect_err("one service cannot be set and removed together");
        assert_eq!(conflict.code, "profile_update_argument_conflict");
        assert_eq!(config.profiles, before);
    }

    #[test]
    fn profile_removal_rollback_preserves_a_concurrent_current_profile_winner() {
        let removed = Profile {
            environment: Some("dev".to_owned()),
            tenant: Some("RemovedTenant".to_owned()),
            ..Profile::default()
        };
        let mut config = ConfigFile {
            current_profile: Some("winner".to_owned()),
            profiles: BTreeMap::from([("winner".to_owned(), Profile::default())]),
            pending_imported_bearer_cleanups: [(
                "removed".to_owned(),
                BTreeSet::from(["a".repeat(64)]),
            )]
            .into_iter()
            .collect(),
            ..ConfigFile::default()
        };

        restore_removed_profile(
            &mut config,
            "removed",
            &removed,
            &BTreeSet::from(["a".repeat(64)]),
            true,
        )
        .expect("rollback restores the removed profile");

        assert_eq!(config.current_profile.as_deref(), Some("winner"));
        assert_eq!(config.profiles.get("removed"), Some(&removed));
        assert!(config.pending_imported_bearer_cleanups.is_empty());
    }

    #[test]
    fn profile_removal_includes_already_pending_retired_bearers() {
        let active = "b".repeat(64);
        let retired = "a".repeat(64);
        let profile = Profile {
            auth: AuthProfile {
                method: Some(AuthMethod::Bearer),
                bearer_cache_key: Some(active.clone()),
                bearer_cache_generation: Some("c".repeat(64)),
                ..AuthProfile::default()
            },
            ..Profile::default()
        };
        let config = ConfigFile {
            profiles: BTreeMap::from([("profile".to_owned(), profile.clone())]),
            pending_imported_bearer_cleanups: BTreeMap::from([(
                "profile".to_owned(),
                BTreeSet::from([retired.clone()]),
            )]),
            ..ConfigFile::default()
        };

        let keys = profile_bearer_cleanup_keys(&config, "profile", &profile)
            .expect("active and pending bearer keys are valid");

        assert_eq!(keys, BTreeSet::from([active, retired]));
    }

    #[test]
    fn profile_removal_compensation_uses_a_fresh_uncancelled_budget() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = ConfigStore::new(directory.path().join("config.toml"));
        let cache_keys = BTreeSet::from(["a".repeat(64)]);
        let removed = Profile {
            environment: Some("dev".to_owned()),
            tenant: Some("RemovedTenant".to_owned()),
            ..Profile::default()
        };
        store
            .modify_until(
                Instant::now() + Duration::from_secs(1),
                || false,
                |config| {
                    config
                        .pending_imported_bearer_cleanups
                        .insert("removed".to_owned(), cache_keys.clone());
                    Ok(())
                },
            )
            .expect("seed post-removal configuration");

        let cancellation = reltio_client::cancellation::CancellationToken::new();
        cancellation.cancel();
        let canceled = store
            .modify_until(
                Instant::now() + Duration::from_secs(1),
                || cancellation.is_cancelled(),
                |_| Ok(()),
            )
            .expect_err("the original cancellation rejects ordinary config work");
        assert_eq!(canceled.code, "request_canceled");
        let expired = store
            .modify_until(
                Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .expect("past deadline"),
                || false,
                |_| Ok(()),
            )
            .expect_err("the original deadline rejects ordinary config work");
        assert_eq!(expired.code, "config_timeout");

        compensate_failed_profile_cache_removal(&store, "removed", &removed, &cache_keys, true)
            .expect("bounded compensation ignores original command control state");

        let restored = store.load().expect("load compensated configuration");
        assert_eq!(restored.current_profile.as_deref(), Some("removed"));
        assert_eq!(restored.profiles.get("removed"), Some(&removed));
        assert!(restored.pending_imported_bearer_cleanups.is_empty());
    }
}
