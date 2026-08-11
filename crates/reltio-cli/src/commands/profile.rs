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
use crate::output::{Meta, PreparedOutput, prepare_success_guarded, write_success_guarded};

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
                    let profile = update_profile(config, arguments)?;
                    Ok(profile_view(
                        &name,
                        &profile,
                        config.current_profile.as_deref() == Some(&name),
                    ))
                },
            )
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
        }
        ProfileSubcommand::Remove { name } => {
            validate_profile_name(&name)?;
            let deadline = runtime.deadline_from(started)?;
            let mut remove_guard = output_guard.clone();
            let mut cache_plan = match TokenManager::prepare_imported_bearer_removal_until(
                &runtime.paths.cache_dir,
                &name,
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

            runtime
                .ensure_not_cancelled("before_profile_cache_commit", false)
                .map_err(|error| error.with_output_guard(remove_guard.clone()))?;
            if let Err(mut error) = cache_plan.commit_with_cancellation(&runtime.cancellation) {
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

            if runtime.cancellation.is_cancelled() {
                let cancellation = runtime
                    .ensure_not_cancelled("after_profile_cache_commit", false)
                    .expect_err("the cancellation token was observed above")
                    .with_output_guard(remove_guard.clone());
                let rollback = cache_plan.rollback();
                drop(cache_plan);
                if let Err(rollback_error) = rollback {
                    return Err(profile_remove_rollback_error(
                        &cancellation,
                        &rollback_error,
                        &remove_guard,
                    ));
                }
                return Err(profile_remove_state_error(
                    cancellation,
                    Some(false),
                    Some(false),
                    true,
                    &remove_guard,
                ));
            }

            let config_result = runtime.store.modify_until(
                deadline,
                || runtime.cancellation.is_cancelled(),
                |config| {
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
                },
            );
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
            runtime
                .ensure_not_cancelled("before_profile_remove_output", true)
                .map_err(|error| error.with_output_guard(remove_guard.clone()))?;
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

fn commit_profile_change(
    runtime: &Runtime,
    command: &str,
    started: Instant,
    initial_guard: &reltio_client::redaction::OutputGuard,
    update: impl FnOnce(&mut ConfigFile) -> Result<Value>,
) -> Result<()> {
    let deadline = runtime.deadline_from(started)?;
    let prepared = runtime.store.modify_until(
        deadline,
        || runtime.cancellation.is_cancelled(),
        |config| {
            let data = update(config)?;
            let mut output_guard = initial_guard.clone();
            output_guard.merge(&runtime.local_output_guard());
            let mut meta = Meta::new(command);
            meta.elapsed_ms = started.elapsed().as_millis();
            prepare_success_guarded(&data, &meta, runtime.render, &output_guard)
                .map_err(|error| profile_change_state_error(error, false, true, false))
        },
    );
    let prepared: PreparedOutput = match prepared {
        Ok(prepared) => prepared,
        Err(error) if error.details.get("local_state_committed").is_some() => return Err(error),
        Err(error) if error.details["committed"].as_bool() == Some(true) => {
            return Err(profile_change_state_error(error, true, false, true));
        }
        Err(error) => return Err(error),
    };
    runtime
        .ensure_not_cancelled("before_profile_output", true)
        .map_err(|error| profile_change_state_error(error, true, false, false))?;
    prepared
        .write_stdout()
        .map_err(|error| profile_change_state_error(error, true, false, false))
}

fn profile_change_state_error(
    mut error: ReltioError,
    local_state_committed: bool,
    safe_to_replay: bool,
    durability_uncertain: bool,
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
    error
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

fn update_profile(config: &mut ConfigFile, arguments: ProfileUpdateArgs) -> Result<Profile> {
    validate_profile_name(&arguments.name)?;
    validate_update_conflicts(&arguments)?;
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
    let mut profile = config
        .profiles
        .get(&arguments.name)
        .cloned()
        .ok_or_else(|| {
            ReltioError::profile(
                "profile_not_found",
                format!("profile {:?} does not exist", arguments.name),
            )
        })?;
    if arguments.clear_environment {
        profile.environment = None;
    } else if let Some(environment) = arguments.environment {
        profile.environment = Some(environment);
    }
    if arguments.clear_base_url {
        profile.base_url = None;
    } else if let Some(base_url) = arguments.base_url {
        validate_service_url(&base_url)?;
        profile.base_url = Some(base_url);
    }
    if arguments.clear_tenant {
        profile.tenant = None;
    } else if let Some(tenant) = arguments.tenant {
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
        } else if arguments.clear_client_id {
            profile.auth.client_id = None;
        }
        if let Some(secret_file) = arguments.secret_file {
            profile.auth.secret_file = Some(secret_file);
        } else if arguments.clear_secret_file {
            profile.auth.secret_file = None;
        }
    }
    if arguments.clear_service_urls {
        profile.services.clear();
    } else {
        for service in arguments.remove_service_urls {
            profile.services.remove(&service);
        }
        profile.services.extend(service_urls);
    }
    config.profiles.insert(arguments.name, profile.clone());
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
    runtime
        .ensure_not_cancelled("before_profile_output", false)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    write_success_guarded(data, &meta, runtime.render, &output_guard)
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

        let error = update_profile(&mut config, arguments)
            .expect_err("runtime validation must reject clear-auth with a setter");

        assert_eq!(error.code, "profile_update_argument_conflict");
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
        let conflict = update_profile(&mut config, arguments)
            .expect_err("one service cannot be set and removed together");
        assert_eq!(conflict.code, "profile_update_argument_conflict");
        assert_eq!(config.profiles, before);
    }
}
