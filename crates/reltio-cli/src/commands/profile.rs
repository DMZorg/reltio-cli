use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use reltio_client::auth::TokenManager;
use reltio_client::config::{
    AuthProfile, ConfigFile, Profile, validate_profile_name, validate_tenant,
};
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::service::{Service, validate_service_url};
use serde_json::{Value, json};

use crate::cli::{ProfileAddArgs, ProfileSubcommand, ProfileUpdateArgs};
use crate::commands::Runtime;
use crate::output::{Meta, prepare_success_guarded, write_success_guarded};

pub fn run(runtime: &Runtime, command: ProfileSubcommand) -> Result<()> {
    let started = Instant::now();
    let output_guard = runtime.local_output_guard();
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
            write_local(runtime, "profile.list", &data, started, &output_guard)
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
        }
        ProfileSubcommand::Add(arguments) => {
            let name = arguments.name.clone();
            let profile = build_profile(arguments)?;
            runtime.store.modify(|config| {
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
                Ok(())
            })?;
            let config = runtime.store.load()?;
            write_local(
                runtime,
                "profile.add",
                &profile_view(
                    &name,
                    &profile,
                    config.current_profile.as_deref() == Some(&name),
                ),
                started,
                &output_guard,
            )
        }
        ProfileSubcommand::Update(arguments) => {
            let mut arguments = arguments;
            arguments.secret_file = arguments
                .secret_file
                .as_deref()
                .map(absolute_local_path)
                .transpose()?;
            let name = arguments.name.clone();
            runtime
                .store
                .modify(|config| update_profile(config, arguments))?;
            let config = runtime.store.load()?;
            let profile = config.profiles.get(&name).expect("updated profile exists");
            write_local(
                runtime,
                "profile.update",
                &profile_view(
                    &name,
                    profile,
                    config.current_profile.as_deref() == Some(&name),
                ),
                started,
                &output_guard,
            )
        }
        ProfileSubcommand::Use { name } => {
            validate_profile_name(&name)?;
            runtime.store.modify(|config| {
                if !config.profiles.contains_key(&name) {
                    return Err(ReltioError::profile(
                        "profile_not_found",
                        format!("profile {name:?} does not exist"),
                    ));
                }
                config.current_profile = Some(name.clone());
                Ok(())
            })?;
            write_local(
                runtime,
                "profile.use",
                &json!({ "current_profile": name }),
                started,
                &output_guard,
            )
        }
        ProfileSubcommand::Remove { name } => {
            validate_profile_name(&name)?;
            let mut remove_guard = output_guard.clone();
            let mut cache_plan = match TokenManager::prepare_imported_bearer_removal(
                &runtime.paths.cache_dir,
                &name,
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
                        true,
                        &remove_guard,
                    ));
                }
            };
            remove_guard.merge(cache_plan.output_guard());
            let data = json!({ "removed": name });
            let mut meta = Meta::new("profile.remove");
            meta.elapsed_ms = started.elapsed().as_millis();
            let success = prepare_success_guarded(&data, &meta, runtime.render, &remove_guard)
                .map_err(|error| {
                    profile_remove_state_error(error, Some(false), Some(false), true, &remove_guard)
                })?;

            if let Err(mut error) = cache_plan.commit() {
                let restored = error.details["local_cache_restored"].as_bool() == Some(true);
                if restored {
                    "profile_remove_cache_failed".clone_into(&mut error.code);
                    "profile removal could not delete the imported bearer cache"
                        .clone_into(&mut error.message);
                } else {
                    "profile_remove_cache_rollback_failed".clone_into(&mut error.code);
                    "profile removal cache cleanup failed and exact rollback could not be verified"
                        .clone_into(&mut error.message);
                }
                drop(cache_plan);
                return Err(profile_remove_state_error(
                    error,
                    Some(false),
                    restored.then_some(false),
                    restored,
                    &remove_guard,
                ));
            }

            let config_result = runtime.store.modify(|config| {
                if config.profiles.remove(&name).is_none() {
                    return Err(ReltioError::profile(
                        "profile_not_found",
                        format!("profile {name:?} does not exist"),
                    ));
                }
                if config.current_profile.as_deref() == Some(&name) {
                    config.current_profile = None;
                }
                Ok(())
            });
            if let Err(mut error) = config_result {
                if error.details["committed"].as_bool() == Some(true) {
                    "profile_remove_config_commit_uncertain".clone_into(&mut error.code);
                    "the profile and imported bearer were removed, but configuration durability could not be fully confirmed"
                        .clone_into(&mut error.message);
                    drop(cache_plan);
                    return Err(profile_remove_state_error(
                        error,
                        Some(true),
                        Some(true),
                        false,
                        &remove_guard,
                    ));
                }
                let rollback = cache_plan.rollback();
                drop(cache_plan);
                if let Err(rollback_error) = rollback {
                    return Err(profile_remove_rollback_error(
                        &error,
                        &rollback_error,
                        &remove_guard,
                    ));
                }
                if error.code != "profile_not_found" {
                    "profile_remove_config_failed".clone_into(&mut error.code);
                    "profile removal could not commit the configuration change"
                        .clone_into(&mut error.message);
                }
                return Err(profile_remove_state_error(
                    error,
                    Some(false),
                    Some(false),
                    true,
                    &remove_guard,
                ));
            }
            drop(cache_plan);
            success.write_stdout().map_err(|error| {
                profile_remove_state_error(error, Some(true), Some(true), false, &remove_guard)
            })
        }
    }
}

fn profile_remove_state_error(
    mut error: ReltioError,
    profile_committed: Option<bool>,
    cache_committed: Option<bool>,
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
        "local_state_committed": local_state_committed,
        "safe_to_replay": safe_to_replay
    });
    error.retryable = false;
    error.with_output_guard(output_guard.clone())
}

fn profile_remove_rollback_error(
    config_error: &ReltioError,
    rollback_error: &ReltioError,
    output_guard: &reltio_client::redaction::OutputGuard,
) -> ReltioError {
    let mut guard = output_guard.clone();
    if let Some(rollback_guard) = rollback_error.output_guard() {
        guard.merge(rollback_guard);
    }
    ReltioError::new(
        "profile_remove_rollback_failed",
        ErrorCategory::Internal,
        "profile removal did not commit, but exact imported-bearer restoration could not be verified",
    )
    .with_details(json!({
        "config_error": config_error.code,
        "rollback_error": rollback_error.code,
        "local_profile_committed": false,
        "local_cache_committed": Value::Null,
        "local_state_committed": Value::Null,
        "safe_to_replay": false
    }))
    .with_hint("Inspect the selected profile and run `reltio auth logout` before retrying.")
    .with_output_guard(guard)
}

fn build_profile(arguments: ProfileAddArgs) -> Result<Profile> {
    validate_profile_name(&arguments.name)?;
    if let Some(tenant) = arguments.tenant.as_deref() {
        validate_tenant(tenant)?;
    }
    if let Some(base_url) = arguments.base_url.as_deref() {
        validate_service_url(base_url)?;
    }
    if arguments.auth_method == Some(reltio_client::config::AuthMethod::CredentialProcess) {
        return Err(ReltioError::usage(
            "credential_process_requires_login",
            "configure a credential process with `reltio auth login --method credential-process` so its executable and arguments are validated together",
        ));
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
        },
    })
}

fn update_profile(config: &mut ConfigFile, arguments: ProfileUpdateArgs) -> Result<()> {
    validate_profile_name(&arguments.name)?;
    let profile = config.profiles.get_mut(&arguments.name).ok_or_else(|| {
        ReltioError::profile(
            "profile_not_found",
            format!("profile {:?} does not exist", arguments.name),
        )
    })?;
    if let Some(environment) = arguments.environment {
        profile.environment = Some(environment);
    }
    if let Some(base_url) = arguments.base_url {
        validate_service_url(&base_url)?;
        profile.base_url = Some(base_url);
    }
    if let Some(tenant) = arguments.tenant {
        validate_tenant(&tenant)?;
        profile.tenant = Some(tenant);
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
        if let Some(client_id) = arguments.client_id {
            profile.auth.client_id = Some(client_id);
        }
        if let Some(secret_file) = arguments.secret_file {
            profile.auth.secret_file = Some(secret_file);
        }
    }
    profile
        .services
        .extend(parse_service_urls(&arguments.service_urls)?);
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
    values
        .iter()
        .map(|value| {
            let (service, url) = value.split_once('=').ok_or_else(|| {
                ReltioError::usage(
                    "invalid_service_override",
                    "service URL override must use SERVICE=URL",
                )
            })?;
            let service: Service = service.parse()?;
            let expanded = url
                .replace("{tenant}", "tenant")
                .replace("{environment}", "env");
            validate_service_url(&expanded)?;
            Ok((service, url.to_owned()))
        })
        .collect()
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

fn write_local(
    runtime: &Runtime,
    command: &str,
    data: &Value,
    started: Instant,
    initial_guard: &reltio_client::redaction::OutputGuard,
) -> Result<()> {
    let mut meta = Meta::new(command);
    meta.elapsed_ms = started.elapsed().as_millis();
    let mut output_guard = initial_guard.clone();
    output_guard.merge(&runtime.local_output_guard());
    write_success_guarded(data, &meta, runtime.render, &output_guard)
}
