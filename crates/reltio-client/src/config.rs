use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use directories::ProjectDirs;
use fs2::FileExt;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{ErrorCategory, ReltioError, Result};
use crate::fs::{
    atomic_write_private, is_lock_contended, open_private_lock, private_file_status,
    read_bounded_optional, storage_path_is_same_or_descendant,
};
use crate::service::{Service, validate_service_url};

const CONFIG_VERSION: u32 = 1;
const CONFIG_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);
const ENV_KEYS: &[&str] = &[
    "RELTIO_CONFIG",
    "RELTIO_CACHE_DIR",
    "RELTIO_STATE_DIR",
    "RELTIO_PROFILE",
    "RELTIO_ENVIRONMENT",
    "RELTIO_BASE_URL",
    "RELTIO_TENANT",
    "RELTIO_AUTH_URL",
    "RELTIO_ACCESS_TOKEN",
    "RELTIO_CLIENT_ID",
    "RELTIO_CLIENT_SECRET",
    "RELTIO_OUTPUT",
    "RELTIO_TIMEOUT",
    "RELTIO_CONFIRM_TENANT",
];

#[derive(Clone, Default)]
#[must_use]
pub struct Environment {
    values: BTreeMap<String, SecretString>,
}

impl Environment {
    pub fn capture() -> Self {
        let values = ENV_KEYS
            .iter()
            .filter_map(|key| {
                std::env::var(key)
                    .ok()
                    .map(|value| ((*key).to_owned(), value.into()))
            })
            .collect();
        Self { values }
    }

    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            values: pairs
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(ExposeSecret::expose_secret)
    }

    pub fn secret(&self, key: &str) -> Option<SecretString> {
        self.values.get(key).cloned()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn without(&self, key: &str) -> Self {
        let mut copy = self.clone();
        copy.values.remove(key);
        copy
    }
}

impl fmt::Debug for Environment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Environment")
            .field("keys", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub config_file: PathBuf,
    pub cache_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl ConfigPaths {
    pub fn discover(environment: &Environment) -> Result<Self> {
        let project = ProjectDirs::from("com", "aiadjacent", "reltio").ok_or_else(|| {
            ReltioError::profile(
                "config_location_unavailable",
                "unable to determine platform configuration directories",
            )
        })?;
        let config_file = environment
            .get("RELTIO_CONFIG")
            .map_or_else(|| project.config_dir().join("config.toml"), PathBuf::from);
        let cache_dir = environment
            .get("RELTIO_CACHE_DIR")
            .map_or_else(|| project.cache_dir().to_path_buf(), PathBuf::from);
        let state_dir = environment
            .get("RELTIO_STATE_DIR")
            .map_or_else(|| project.data_local_dir().join("state"), PathBuf::from);
        let paths = Self {
            config_file: normalized_absolute_path(&config_file)?,
            cache_dir: normalized_absolute_path(&cache_dir)?,
            state_dir: normalized_absolute_path(&state_dir)?,
        };
        validate_distinct_storage_paths(&paths)?;
        Ok(paths)
    }
}

pub(crate) fn normalized_absolute_path(path: &Path) -> Result<PathBuf> {
    crate::fs::normalize_storage_path(path)
}

fn validate_distinct_storage_paths(paths: &ConfigPaths) -> Result<()> {
    let config_lock = config_lock_path(&paths.config_file);
    let config_in_cache = storage_path_is_same_or_descendant(&paths.config_file, &paths.cache_dir)?;
    let cache_in_config = storage_path_is_same_or_descendant(&paths.cache_dir, &paths.config_file)?;
    let config_in_state = storage_path_is_same_or_descendant(&paths.config_file, &paths.state_dir)?;
    let state_in_config = storage_path_is_same_or_descendant(&paths.state_dir, &paths.config_file)?;
    let lock_in_cache = storage_path_is_same_or_descendant(&config_lock, &paths.cache_dir)?;
    let cache_in_lock = storage_path_is_same_or_descendant(&paths.cache_dir, &config_lock)?;
    let lock_in_state = storage_path_is_same_or_descendant(&config_lock, &paths.state_dir)?;
    let state_in_lock = storage_path_is_same_or_descendant(&paths.state_dir, &config_lock)?;
    let cache_and_state_overlap =
        storage_path_is_same_or_descendant(&paths.cache_dir, &paths.state_dir)?
            || storage_path_is_same_or_descendant(&paths.state_dir, &paths.cache_dir)?;
    if config_in_cache
        || cache_in_config
        || config_in_state
        || state_in_config
        || lock_in_cache
        || cache_in_lock
        || lock_in_state
        || state_in_lock
        || cache_and_state_overlap
    {
        return Err(ReltioError::profile(
            "storage_path_conflict",
            "configuration, configuration lock, cache, and state locations must not overlap",
        )
        .with_details(serde_json::json!({
            "config_in_cache": config_in_cache,
            "cache_in_config": cache_in_config,
            "config_in_state": config_in_state,
            "state_in_config": state_in_config,
            "lock_in_cache": lock_in_cache,
            "cache_in_lock": cache_in_lock,
            "lock_in_state": lock_in_state,
            "state_in_lock": state_in_lock,
            "cache_and_state_overlap": cache_and_state_overlap,
            "local_state_committed": false,
            "safe_to_replay": true
        })));
    }
    Ok(())
}

fn config_lock_path(config_file: &Path) -> PathBuf {
    let mut lock_name = config_file.as_os_str().to_os_string();
    lock_name.push(".lock");
    PathBuf::from(lock_name)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default = "config_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pending_imported_bearer_cleanups: BTreeMap<String, BTreeSet<String>>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            current_profile: None,
            profiles: BTreeMap::new(),
            pending_imported_bearer_cleanups: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default)]
    pub production: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<Service, String>,
    #[serde(default)]
    pub auth: AuthProfile,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_process: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_cache_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_cache_generation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Bearer,
    ClientCredentials,
    CredentialProcess,
}

impl AuthMethod {
    pub const fn cli_values() -> &'static [&'static str] {
        &["bearer", "client-credentials", "credential-process"]
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bearer => "bearer",
            Self::ClientCredentials => "client_credentials",
            Self::CredentialProcess => "credential_process",
        })
    }
}

impl std::str::FromStr for AuthMethod {
    type Err = ReltioError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "bearer" => Ok(Self::Bearer),
            "client-credentials" | "client_credentials" => Ok(Self::ClientCredentials),
            "credential-process" | "credential_process" => Ok(Self::CredentialProcess),
            _ => Err(ReltioError::usage(
                "invalid_auth_method",
                format!("unsupported authentication method {value:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigStore {
    path: PathBuf,
}

pub struct ConfigReadLease {
    _lock: std::fs::File,
    config: Option<ConfigFile>,
}

impl fmt::Debug for ConfigReadLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigReadLease")
            .field("config_available", &self.config.is_some())
            .finish_non_exhaustive()
    }
}

impl ConfigReadLease {
    pub fn config(&self) -> Option<&ConfigFile> {
        self.config.as_ref()
    }
}

impl ConfigStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<ConfigFile> {
        let Some(bytes) = read_bounded_optional(&self.path, true)? else {
            return Ok(ConfigFile::default());
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            ReltioError::profile(
                "config_not_utf8",
                format!("configuration file {} is not UTF-8", self.path.display()),
            )
        })?;
        let config: ConfigFile = toml::from_str(text).map_err(|error| {
            let span = error.span();
            ReltioError::profile(
                "config_parse_failed",
                format!("failed to parse {} as TOML", self.path.display()),
            )
            .with_details(serde_json::json!({
                "reason": "invalid_toml_or_schema",
                "byte_range": span.map(|span| [span.start, span.end])
            }))
        })?;
        validate_config(&config)?;
        Ok(config)
    }

    pub fn read_lease_until(
        &self,
        deadline: Instant,
        is_cancelled: impl Fn() -> bool,
    ) -> Result<ConfigReadLease> {
        let lock = open_private_lock(&self.lock_path())?;
        loop {
            ensure_config_operation_active(deadline, &is_cancelled, "config_read_lock", false)?;
            match FileExt::try_lock_shared(&lock) {
                Ok(()) => break,
                Err(error) if is_lock_contended(&error) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(CONFIG_LOCK_POLL_INTERVAL.min(remaining));
                }
                Err(error) => {
                    return Err(ReltioError::io(
                        "failed to lock configuration for output",
                        &error,
                    ));
                }
            }
        }
        ensure_config_operation_active(deadline, &is_cancelled, "config_read", false)?;
        // Invalid configuration cannot activate a profile credential. Retain the
        // lock so a repair cannot activate one until the guarded output finishes.
        let config = self.load().ok();
        ensure_config_operation_active(deadline, &is_cancelled, "config_read", false)?;
        Ok(ConfigReadLease {
            _lock: lock,
            config,
        })
    }

    pub fn try_read_lease(&self) -> Result<Option<ConfigReadLease>> {
        let lock = open_private_lock(&self.lock_path())?;
        match FileExt::try_lock_shared(&lock) {
            Ok(()) => {}
            Err(error) if is_lock_contended(&error) => return Ok(None),
            Err(error) => {
                return Err(ReltioError::io(
                    "failed to lock configuration for output",
                    &error,
                ));
            }
        }
        Ok(Some(ConfigReadLease {
            _lock: lock,
            config: self.load().ok(),
        }))
    }

    pub fn modify_until<T>(
        &self,
        deadline: Instant,
        is_cancelled: impl Fn() -> bool,
        update: impl FnOnce(&mut ConfigFile) -> Result<T>,
    ) -> Result<T> {
        let lock = open_private_lock(&self.lock_path())?;
        loop {
            ensure_config_operation_active(deadline, &is_cancelled, "config_lock", false)?;
            match FileExt::try_lock_exclusive(&lock) {
                Ok(()) => break,
                Err(error) if is_lock_contended(&error) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(CONFIG_LOCK_POLL_INTERVAL.min(remaining));
                }
                Err(error) => {
                    return Err(ReltioError::io("failed to lock configuration", &error));
                }
            }
        }
        ensure_config_operation_active(deadline, &is_cancelled, "config_read", false)?;
        let mut config = self.load()?;
        ensure_config_operation_active(deadline, &is_cancelled, "config_update", false)?;
        let result = update(&mut config)?;
        validate_config(&config)?;
        let encoded = toml::to_string_pretty(&config)
            .map_err(|error| ReltioError::internal(format!("failed to encode config: {error}")))?;
        ensure_config_operation_active(deadline, &is_cancelled, "config_commit", false)?;
        atomic_write_private(&self.path, encoded.as_bytes())?;
        let control_result =
            ensure_config_operation_active(deadline, &is_cancelled, "config_commit", true);
        let unlock_result = FileExt::unlock(&lock).map_err(|error| {
            ReltioError::io("failed to unlock configuration", &error).with_details(
                serde_json::json!({
                    "kind": format!("{:?}", error.kind()),
                    "committed": true
                }),
            )
        });
        control_result?;
        unlock_result?;
        Ok(result)
    }

    pub fn permissions_are_private(&self) -> Result<Option<bool>> {
        private_file_status(&self.path)
    }

    fn lock_path(&self) -> PathBuf {
        config_lock_path(&self.path)
    }
}

fn ensure_config_operation_active(
    deadline: Instant,
    is_cancelled: &impl Fn() -> bool,
    stage: &'static str,
    committed: bool,
) -> Result<()> {
    if is_cancelled() {
        return Err(ReltioError::new(
            "request_canceled",
            ErrorCategory::Canceled,
            "the local configuration operation was canceled",
        )
        .with_details(serde_json::json!({
            "phase": stage,
            "remote_response_received": false,
            "remote_request_completed": false,
            "remote_operation_completed": false,
            "remote_operation_state": "request_not_sent",
            "local_state_committed": committed,
            "committed": committed,
            "safe_to_replay": !committed
        })));
    }
    if Instant::now() >= deadline {
        return Err(ReltioError::new(
            "config_timeout",
            ErrorCategory::Timeout,
            "the local configuration operation exceeded the overall timeout",
        )
        .with_details(serde_json::json!({
            "phase": stage,
            "local_state_committed": committed,
            "committed": committed,
            "safe_to_replay": !committed
        })));
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct ResolutionOverrides {
    pub profile: Option<String>,
    pub environment: Option<String>,
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedTarget {
    pub profile: Option<String>,
    pub environment: String,
    pub tenant: String,
    pub production: bool,
    /// True when invocation routing changed or an invocation-scoped tenant was supplied.
    pub target_overridden: bool,
    /// True when invocation-scoped environment, base, or Auth routing genuinely changed.
    pub routing_overridden: bool,
    /// True when an invocation-scoped tenant genuinely changed the selected tenant.
    pub tenant_overridden: bool,
    #[serde(skip)]
    pub base_url: Option<Url>,
    #[serde(skip)]
    pub service_urls: BTreeMap<Service, String>,
    #[serde(skip)]
    pub auth: AuthProfile,
    pub sources: BTreeMap<String, String>,
}

pub fn resolve_target(
    config: &ConfigFile,
    environment: &Environment,
    overrides: &ResolutionOverrides,
) -> Result<ResolvedTarget> {
    let (profile_name, profile_source) = first_value([
        overrides.profile.as_deref().map(|v| (v, "flag")),
        environment
            .get("RELTIO_PROFILE")
            .map(|v| (v, "environment")),
        config
            .current_profile
            .as_deref()
            .map(|v| (v, "current_profile")),
    ])
    .map_or((None, None), |(value, source)| {
        (Some(value.to_owned()), Some(source.to_owned()))
    });

    let profile = if let Some(name) = profile_name.as_deref() {
        Some(config.profiles.get(name).ok_or_else(|| {
            ReltioError::profile(
                "profile_not_found",
                format!("profile {name:?} does not exist"),
            )
            .with_hint("Run `reltio profile list` or create the profile first.")
        })?)
    } else {
        None
    };

    let mut sources = BTreeMap::new();
    if let Some(source) = profile_source {
        sources.insert("profile".to_owned(), source);
    }

    let (explicit_environment, explicit_environment_source) = first_value([
        overrides.environment.as_deref().map(|v| (v, "flag")),
        environment
            .get("RELTIO_ENVIRONMENT")
            .map(|v| (v, "environment")),
    ])
    .map_or((None, None), |(value, source)| (Some(value), Some(source)));
    let profile_environment = profile.and_then(|value| value.environment.as_deref());
    let environment_routing_equivalent = match (explicit_environment, profile_environment) {
        (Some(explicit), Some(profile_value)) => {
            environments_are_equivalent(explicit, profile_value)?
        }
        _ => false,
    };
    if environment_routing_equivalent {
        sources.insert(
            "environment_routing".to_owned(),
            "equivalent_to_profile".to_owned(),
        );
    }

    let explicit_environment_flag = explicit_environment_source == Some("flag");
    let flag_environment_is_url =
        explicit_environment_flag && explicit_environment.is_some_and(looks_like_http_url);
    let environment_base_url_is_used =
        !flag_environment_is_url && environment.contains("RELTIO_BASE_URL");
    let (invocation_base_value, invocation_base_source) = if flag_environment_is_url {
        (explicit_environment, Some("flag"))
    } else if environment_base_url_is_used {
        (environment.get("RELTIO_BASE_URL"), Some("environment"))
    } else if !explicit_environment_flag
        && explicit_environment_source == Some("environment")
        && explicit_environment.is_some_and(looks_like_http_url)
    {
        (explicit_environment, Some("environment"))
    } else {
        (None, None)
    };
    let invocation_base_url = invocation_base_value
        .map(validate_environment_origin)
        .transpose()?;
    let profile_base_url = profile.map(profile_base_url).transpose()?.flatten();
    let profile_effective_origin = profile
        .map(|profile| profile_effective_origin(profile, profile_base_url.as_ref()))
        .transpose()?
        .flatten();
    let base_routing_equivalent = invocation_base_url
        .as_ref()
        .zip(profile_effective_origin.as_ref())
        .is_some_and(|(explicit, selected)| canonical_origins_are_equal(explicit, selected));
    if base_routing_equivalent {
        sources.insert(
            "base_url_routing".to_owned(),
            "equivalent_to_profile".to_owned(),
        );
    }

    let environment_changed =
        profile.is_some() && explicit_environment.is_some() && !environment_routing_equivalent;
    let base_changed =
        profile.is_some() && invocation_base_url.is_some() && !base_routing_equivalent;
    let data_routing_overridden = environment_changed || base_changed;
    let has_invocation_base_url = invocation_base_url.is_some();
    let base_url = if profile.is_some() && !data_routing_overridden {
        profile_base_url
    } else {
        invocation_base_url
    };

    let resolved_environment_value = if environment_routing_equivalent {
        profile_environment
    } else {
        explicit_environment.or(profile_environment)
    };
    let resolved_environment = resolved_environment_value
        .map(ToOwned::to_owned)
        .or_else(|| {
            base_url
                .as_ref()
                .and_then(Url::host_str)
                .map(ToOwned::to_owned)
        })
        .ok_or_else(|| {
            ReltioError::profile(
                "environment_unresolved",
                "Reltio environment is not configured",
            )
            .with_hint("Set --environment, RELTIO_ENVIRONMENT, or a profile environment.")
        })?;
    if !looks_like_http_url(&resolved_environment) {
        validate_namespace(&resolved_environment)?;
    }
    sources.insert(
        "environment".to_owned(),
        explicit_environment_source
            .or(profile_environment.map(|_| "profile"))
            .unwrap_or("base_url")
            .to_owned(),
    );
    if let Some(source) = invocation_base_source {
        sources.insert("base_url".to_owned(), source.to_owned());
    } else if base_url.is_some() {
        sources.insert("base_url".to_owned(), "profile".to_owned());
    }

    let (tenant, tenant_source) = first_value([
        overrides.tenant.as_deref().map(|v| (v, "flag")),
        environment.get("RELTIO_TENANT").map(|v| (v, "environment")),
        profile
            .and_then(|p| p.tenant.as_deref())
            .map(|v| (v, "profile")),
    ])
    .ok_or_else(|| {
        ReltioError::profile("tenant_unresolved", "Reltio tenant is not configured")
            .with_hint("Set --tenant, RELTIO_TENANT, or a profile tenant.")
    })?;
    validate_tenant(tenant)?;
    sources.insert("tenant".to_owned(), tenant_source.to_owned());
    let tenant_explicit = matches!(tenant_source, "flag" | "environment");
    let tenant_overridden = if tenant_explicit {
        profile.is_none_or(|selected| selected.tenant.as_deref() != Some(tenant))
    } else {
        false
    };

    let mut service_urls = profile.map_or_else(BTreeMap::new, |p| p.services.clone());
    let explicit_auth_url = environment
        .get("RELTIO_AUTH_URL")
        .map(validate_service_url)
        .transpose()?;
    let profile_auth_url = profile
        .map(|selected| {
            profile_auth_url(
                selected,
                profile_environment.unwrap_or(&resolved_environment),
                tenant,
            )
        })
        .transpose()?;
    let auth_routing_equivalent = explicit_auth_url
        .as_ref()
        .zip(profile_auth_url.as_ref())
        .is_some_and(|(explicit, selected)| canonical_service_routes_are_equal(explicit, selected));
    if auth_routing_equivalent {
        sources.insert(
            "auth_url_routing".to_owned(),
            "equivalent_to_profile".to_owned(),
        );
    }
    let auth_routing_overridden =
        profile.is_some() && explicit_auth_url.is_some() && !auth_routing_equivalent;
    let routing_overridden = if profile.is_some() {
        data_routing_overridden || auth_routing_overridden
    } else {
        explicit_environment.is_some() || has_invocation_base_url || explicit_auth_url.is_some()
    };

    if profile.is_some() && routing_overridden {
        validate_profile_routing_override(
            environment,
            tenant_source,
            ProfileRoutingOverride {
                data_changed: data_routing_overridden,
                explicit_destination_origin: flag_environment_is_url
                    || environment_base_url_is_used,
                auth_changed: auth_routing_overridden,
                custom_profile_auth_displaced: profile
                    .is_some_and(|selected| selected.services.contains_key(&Service::Auth)),
            },
        )?;
    }

    if data_routing_overridden && !service_urls.is_empty() {
        service_urls.clear();
        sources.insert(
            "profile_service_urls".to_owned(),
            "ignored_for_target_override".to_owned(),
        );
    }
    if let Some(auth_url) = environment.get("RELTIO_AUTH_URL") {
        if data_routing_overridden || !auth_routing_equivalent || profile.is_none() {
            service_urls.insert(Service::Auth, auth_url.to_owned());
        }
        sources.insert("auth_url".to_owned(), "environment".to_owned());
    } else if !data_routing_overridden && service_urls.contains_key(&Service::Auth) {
        sources.insert("auth_url".to_owned(), "profile".to_owned());
    } else {
        sources.insert("auth_url".to_owned(), "default".to_owned());
    }

    let target_overridden = routing_overridden || tenant_explicit;
    let auth = if profile.is_some() && routing_overridden {
        AuthProfile::default()
    } else {
        profile.map_or_else(AuthProfile::default, |selected| selected.auth.clone())
    };

    Ok(ResolvedTarget {
        profile: profile_name,
        environment: resolved_environment,
        tenant: tenant.to_owned(),
        production: profile.is_some_and(|p| p.production),
        target_overridden,
        routing_overridden,
        tenant_overridden,
        base_url,
        service_urls,
        auth,
        sources,
    })
}

fn profile_base_url(profile: &Profile) -> Result<Option<Url>> {
    if let Some(environment) = profile
        .environment
        .as_deref()
        .filter(|value| looks_like_http_url(value))
    {
        return validate_environment_origin(environment).map(Some);
    }
    profile
        .base_url
        .as_deref()
        .map(validate_environment_origin)
        .transpose()
}

fn profile_effective_origin(profile: &Profile, base_url: Option<&Url>) -> Result<Option<Url>> {
    if let Some(base_url) = base_url {
        return Ok(Some(base_url.clone()));
    }
    profile
        .environment
        .as_deref()
        .filter(|value| !looks_like_http_url(value))
        .map(|namespace| {
            validate_namespace(namespace)?;
            validate_environment_origin(&format!("https://{namespace}.reltio.com"))
        })
        .transpose()
}

fn environments_are_equivalent(explicit: &str, selected: &str) -> Result<bool> {
    match (looks_like_http_url(explicit), looks_like_http_url(selected)) {
        (true, true) => Ok(canonical_origins_are_equal(
            &validate_environment_origin(explicit)?,
            &validate_environment_origin(selected)?,
        )),
        (false, false) => Ok(explicit == selected),
        _ => Ok(false),
    }
}

fn profile_auth_url(profile: &Profile, environment: &str, tenant: &str) -> Result<Url> {
    let value = profile
        .services
        .get(&Service::Auth)
        .map_or("https://auth.reltio.com", String::as_str);
    let expanded = value
        .replace("{tenant}", tenant)
        .replace("{environment}", environment);
    validate_service_url(&expanded)
}

fn canonical_origins_are_equal(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn canonical_service_routes_are_equal(left: &Url, right: &Url) -> bool {
    canonical_origins_are_equal(left, right)
        && canonical_service_path(left) == canonical_service_path(right)
}

fn canonical_service_path(url: &Url) -> String {
    if url.path().ends_with('/') {
        url.path().to_owned()
    } else {
        format!("{}/", url.path())
    }
}

#[derive(Clone, Copy)]
struct ProfileRoutingOverride {
    data_changed: bool,
    explicit_destination_origin: bool,
    auth_changed: bool,
    custom_profile_auth_displaced: bool,
}

fn validate_profile_routing_override(
    environment: &Environment,
    tenant_source: &str,
    routing: ProfileRoutingOverride,
) -> Result<()> {
    let has_bearer = environment.contains("RELTIO_ACCESS_TOKEN");
    let has_client_id = environment.contains("RELTIO_CLIENT_ID");
    let has_client_secret = environment.contains("RELTIO_CLIENT_SECRET");
    let complete_client_credentials = has_client_id && has_client_secret;
    if has_client_id != has_client_secret {
        return Err(unsafe_profile_routing_error(
            if routing.data_changed { "data" } else { "auth" },
            &["both RELTIO_CLIENT_ID and RELTIO_CLIENT_SECRET"],
            "partial_environment_client_credentials",
        ));
    }

    if routing.data_changed {
        let mut missing = Vec::new();
        if !routing.explicit_destination_origin {
            missing.push("an explicit destination origin (--environment URL or RELTIO_BASE_URL)");
        }
        if !matches!(tenant_source, "flag" | "environment") {
            missing.push("an explicit tenant (--tenant or RELTIO_TENANT)");
        }
        if !(has_bearer || complete_client_credentials) {
            missing.push(
                "invocation-owned auth (RELTIO_ACCESS_TOKEN or complete environment client credentials)",
            );
        }
        if !has_bearer
            && complete_client_credentials
            && routing.custom_profile_auth_displaced
            && !environment.contains("RELTIO_AUTH_URL")
        {
            missing.push("RELTIO_AUTH_URL for the displaced custom profile Auth route");
        }
        if !missing.is_empty() {
            return Err(unsafe_profile_routing_error(
                "data",
                &missing,
                "independent_invocation_context_required",
            ));
        }
    } else if routing.auth_changed && !(has_bearer || complete_client_credentials) {
        return Err(unsafe_profile_routing_error(
            "auth",
            &["RELTIO_ACCESS_TOKEN or both RELTIO_CLIENT_ID and RELTIO_CLIENT_SECRET"],
            "profile_credentials_refused_for_changed_auth_route",
        ));
    }
    Ok(())
}

fn unsafe_profile_routing_error(
    routing_change: &str,
    missing: &[&str],
    reason: &str,
) -> ReltioError {
    ReltioError::new(
        "unsafe_profile_routing_override",
        crate::error::ErrorCategory::Safety,
        "invocation routing would displace the selected profile without an independently safe target and credential context",
    )
    .with_details(serde_json::json!({
        "routing_change": routing_change,
        "reason": reason,
        "missing": missing,
        "network_request_sent": false,
        "local_state_committed": false,
        "safe_to_replay": true
    }))
    .with_hint(
        "Use an equivalent override, or supply the destination origin, explicit tenant, and invocation-owned environment credentials required for the changed route.",
    )
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    validate_identifier(name, "profile", "invalid_profile_name")
}

pub fn validate_tenant(tenant: &str) -> Result<()> {
    validate_identifier(tenant, "tenant", "invalid_tenant")
}

fn validate_namespace(namespace: &str) -> Result<()> {
    validate_identifier(namespace, "environment", "invalid_environment")
}

fn validate_identifier(value: &str, label: &str, code: &str) -> Result<()> {
    let valid = !value.is_empty()
        && !matches!(value, "." | "..")
        && value.len() <= 200
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(ReltioError::usage(
            code,
            format!("{label} is invalid or contains unsupported characters"),
        ))
    }
}

fn validate_config(config: &ConfigFile) -> Result<()> {
    if config.version != CONFIG_VERSION {
        return Err(ReltioError::profile(
            "config_version_unsupported",
            format!("configuration version {} is not supported", config.version),
        ));
    }
    if let Some(current) = config.current_profile.as_deref() {
        validate_profile_name(current)?;
        if !config.profiles.contains_key(current) {
            return Err(ReltioError::profile(
                "current_profile_missing",
                format!("current profile {current:?} does not exist"),
            ));
        }
    }
    for (pending, cache_keys) in &config.pending_imported_bearer_cleanups {
        validate_profile_name(pending)?;
        if cache_keys.is_empty()
            || cache_keys.iter().any(|cache_key| {
                cache_key.len() != 64
                    || !cache_key
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(ReltioError::profile(
                "pending_bearer_cleanup_invalid",
                format!("profile {pending:?} has an invalid bearer cleanup key set"),
            ));
        }
        if config
            .profiles
            .get(pending)
            .and_then(|profile| profile.auth.bearer_cache_key.as_ref())
            .is_some_and(|active| cache_keys.contains(active))
        {
            return Err(ReltioError::profile(
                "pending_bearer_cleanup_conflict",
                format!("profile {pending:?} cannot actively reference a pending cleanup key"),
            ));
        }
    }
    for (name, profile) in &config.profiles {
        validate_profile_name(name)?;
        if let Some(tenant) = profile.tenant.as_deref() {
            validate_tenant(tenant)?;
        }
        if let Some(environment) = profile.environment.as_deref() {
            if looks_like_http_url(environment) {
                validate_environment_origin(environment)?;
            } else {
                validate_namespace(environment)?;
            }
        }
        if let Some(base_url) = profile.base_url.as_deref() {
            validate_environment_origin(base_url)?;
        }
        for (service, url) in &profile.services {
            if matches!(service, Service::Data | Service::Tasks)
                && !service_template_has_tenant_segment(url)?
            {
                return Err(ReltioError::profile(
                    "tenant_placeholder_required",
                    format!(
                        "profile {name:?} {service} service URL must contain {{tenant}} as a complete path segment"
                    ),
                ));
            }
            let expanded = url
                .replace("{tenant}", "tenant")
                .replace("{environment}", "env");
            if expanded.contains(['{', '}']) {
                return Err(ReltioError::profile(
                    "service_placeholder_invalid",
                    format!("profile {name:?} {service} service URL has an unknown placeholder"),
                ));
            }
            validate_service_url(&expanded)?;
        }
        if profile
            .auth
            .client_id
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.contains(['\r', '\n', '\0']))
        {
            return Err(ReltioError::profile(
                "invalid_client_id",
                format!("profile {name:?} client ID is empty or contains a control character"),
            ));
        }
        if let Some(cache_key) = profile.auth.bearer_cache_key.as_deref() {
            if cache_key.len() != 64
                || !cache_key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ReltioError::profile(
                    "bearer_cache_key_invalid",
                    format!("profile {name:?} has an invalid imported-bearer cache key"),
                ));
            }
            if profile.auth.method != Some(AuthMethod::Bearer) {
                return Err(ReltioError::profile(
                    "bearer_cache_key_conflict",
                    format!(
                        "profile {name:?} retains an imported-bearer key without bearer authentication"
                    ),
                ));
            }
        }
        if let Some(generation) = profile.auth.bearer_cache_generation.as_deref() {
            if generation.len() != 64
                || !generation
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ReltioError::profile(
                    "bearer_cache_generation_invalid",
                    format!("profile {name:?} has an invalid imported-bearer generation"),
                ));
            }
            if profile.auth.method != Some(AuthMethod::Bearer)
                || profile.auth.bearer_cache_key.is_none()
            {
                return Err(ReltioError::profile(
                    "bearer_cache_generation_conflict",
                    format!(
                        "profile {name:?} retains an imported-bearer generation without a complete bearer cache identity"
                    ),
                ));
            }
        }
        if profile
            .auth
            .secret_file
            .as_deref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(ReltioError::profile(
                "secret_file_not_absolute",
                format!("profile {name:?} secret-file path must be absolute"),
            ));
        }
        if profile.auth.method == Some(AuthMethod::CredentialProcess)
            && profile
                .auth
                .credential_process
                .as_ref()
                .is_none_or(Vec::is_empty)
        {
            return Err(ReltioError::profile(
                "credential_process_missing",
                format!("profile {name:?} has no credential process command"),
            ));
        }
        if profile
            .auth
            .credential_process
            .as_ref()
            .is_some_and(|command| {
                command
                    .iter()
                    .any(|argument| argument.is_empty() || argument.contains('\0'))
            })
        {
            return Err(ReltioError::profile(
                "credential_process_invalid",
                format!("profile {name:?} credential process contains an invalid argument"),
            ));
        }
        if profile
            .auth
            .credential_process
            .as_ref()
            .and_then(|command| command.first())
            .is_some_and(|executable| !Path::new(executable).is_absolute())
        {
            return Err(ReltioError::profile(
                "credential_process_not_absolute",
                format!("profile {name:?} credential-process executable must be absolute"),
            ));
        }
    }
    Ok(())
}

fn validate_environment_origin(value: &str) -> Result<Url> {
    let url = validate_service_url(value)?;
    if !matches!(url.path(), "" | "/") {
        return Err(ReltioError::profile(
            "environment_origin_has_path",
            "environment/base URL must be an origin without a path; use a service-specific URL override for a path-prefixed proxy",
        ));
    }
    Ok(url)
}

fn looks_like_http_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn service_template_has_tenant_segment(value: &str) -> Result<bool> {
    const MARKER: &str = "reltio-tenant-placeholder";
    let expanded = value
        .replace("{tenant}", MARKER)
        .replace("{environment}", "environment");
    let url = validate_service_url(&expanded)?;
    Ok(url
        .path_segments()
        .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
        == Some(MARKER))
}

fn first_value<'a, const N: usize>(
    candidates: [Option<(&'a str, &'a str)>; N],
) -> Option<(&'a str, &'a str)> {
    candidates.into_iter().flatten().next()
}

const fn config_version() -> u32 {
    CONFIG_VERSION
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn routed_config() -> ConfigFile {
        let mut config = ConfigFile {
            current_profile: Some("dev".to_owned()),
            ..ConfigFile::default()
        };
        config.profiles.insert(
            "dev".to_owned(),
            Profile {
                environment: Some("dev".to_owned()),
                base_url: Some("https://private.example:443".to_owned()),
                tenant: Some("ProfileTenant".to_owned()),
                services: BTreeMap::from([
                    (
                        Service::Data,
                        "https://data.private.example/reltio/api/{tenant}".to_owned(),
                    ),
                    (
                        Service::Tasks,
                        "https://tasks.private.example/reltio/api/{tenant}".to_owned(),
                    ),
                    (Service::Auth, "https://login.example:443/oauth".to_owned()),
                ]),
                auth: AuthProfile {
                    method: Some(AuthMethod::Bearer),
                    client_id: Some("profile-client".to_owned()),
                    secret_file: Some(PathBuf::from("/profile/secret")),
                    credential_process: None,
                    bearer_cache_key: None,
                    bearer_cache_generation: None,
                },
                ..Profile::default()
            },
        );
        config
    }

    #[test]
    fn storage_paths_reject_config_cache_and_state_aliases() {
        let current = std::env::current_dir().expect("current test directory");
        let directory = tempfile::Builder::new()
            .prefix(".reltio-config-")
            .tempdir_in(current)
            .expect("temporary directory without an inherited 8.3 alias");
        let cache_dir = directory.path().join("cache");
        let state_dir = directory.path().join("state");
        let environment = Environment::from_pairs([
            (
                "RELTIO_CONFIG".to_owned(),
                cache_dir
                    .join("tokens/cache-maintenance")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RELTIO_CACHE_DIR".to_owned(),
                cache_dir.to_string_lossy().into_owned(),
            ),
            (
                "RELTIO_STATE_DIR".to_owned(),
                state_dir.to_string_lossy().into_owned(),
            ),
        ]);

        let error = ConfigPaths::discover(&environment)
            .expect_err("configuration inside the cache must fail before locking");
        assert_eq!(error.code, "storage_path_conflict");
        assert_eq!(error.details["config_in_cache"], true);

        let overlapping = Environment::from_pairs([
            (
                "RELTIO_CONFIG".to_owned(),
                directory
                    .path()
                    .join("config.toml")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RELTIO_CACHE_DIR".to_owned(),
                cache_dir.to_string_lossy().into_owned(),
            ),
            (
                "RELTIO_STATE_DIR".to_owned(),
                cache_dir.join("state").to_string_lossy().into_owned(),
            ),
        ]);
        let error = ConfigPaths::discover(&overlapping)
            .expect_err("cache and state ancestry must be rejected");
        assert_eq!(error.code, "storage_path_conflict");
        assert_eq!(error.details["cache_and_state_overlap"], true);

        let config_parent = directory.path().join("configuration-root");
        let reverse = Environment::from_pairs([
            (
                "RELTIO_CONFIG".to_owned(),
                config_parent.to_string_lossy().into_owned(),
            ),
            (
                "RELTIO_CACHE_DIR".to_owned(),
                config_parent.join("cache").to_string_lossy().into_owned(),
            ),
            (
                "RELTIO_STATE_DIR".to_owned(),
                state_dir.to_string_lossy().into_owned(),
            ),
        ]);
        let error = ConfigPaths::discover(&reverse)
            .expect_err("cache ancestry beneath the config path must be rejected");
        assert_eq!(error.code, "storage_path_conflict");
        assert_eq!(error.details["cache_in_config"], true);

        let config_file = directory.path().join("lock-collision.toml");
        let lock_path = config_lock_path(&config_file);
        for (variable, detail) in [
            ("RELTIO_CACHE_DIR", "lock_in_cache"),
            ("RELTIO_STATE_DIR", "lock_in_state"),
        ] {
            let mut pairs = vec![
                (
                    "RELTIO_CONFIG".to_owned(),
                    config_file.to_string_lossy().into_owned(),
                ),
                (
                    "RELTIO_CACHE_DIR".to_owned(),
                    directory
                        .path()
                        .join("separate-cache")
                        .to_string_lossy()
                        .into_owned(),
                ),
                (
                    "RELTIO_STATE_DIR".to_owned(),
                    directory
                        .path()
                        .join("separate-state")
                        .to_string_lossy()
                        .into_owned(),
                ),
            ];
            pairs
                .iter_mut()
                .find(|(name, _)| name == variable)
                .expect("storage variable")
                .1 = lock_path.to_string_lossy().into_owned();
            let error = ConfigPaths::discover(&Environment::from_pairs(pairs))
                .expect_err("the configuration lock cannot be a storage root");
            assert_eq!(error.code, "storage_path_conflict");
            assert_eq!(error.details[detail], true);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn storage_paths_reject_case_aliased_cache_names_on_macos() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let environment = Environment::from_pairs([
            (
                "RELTIO_CONFIG".to_owned(),
                directory
                    .path()
                    .join("Cache/tokens/cache-maintenance.lock")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RELTIO_CACHE_DIR".to_owned(),
                directory
                    .path()
                    .join("cache")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RELTIO_STATE_DIR".to_owned(),
                directory
                    .path()
                    .join("state")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ]);

        let error = ConfigPaths::discover(&environment)
            .expect_err("case-aliased cache ancestry must be rejected on macOS");
        assert_eq!(error.code, "storage_path_conflict");
        assert_eq!(error.details["config_in_cache"], true);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn storage_paths_reject_users_firmlink_alias_when_available() {
        use std::os::unix::fs::MetadataExt as _;

        let users = Path::new("/Users");
        let data_users = Path::new("/System/Volumes/Data/Users");
        let (Ok(users_metadata), Ok(data_metadata)) =
            (std::fs::metadata(users), std::fs::metadata(data_users))
        else {
            return;
        };
        if users_metadata.dev() != data_metadata.dev()
            || users_metadata.ino() != data_metadata.ino()
        {
            return;
        }
        let missing = "__reltio_config_firmlink_test_missing__";
        if users.join(missing).exists() || data_users.join(missing).exists() {
            return;
        }
        let environment = Environment::from_pairs([
            (
                "RELTIO_CONFIG".to_owned(),
                users
                    .join(missing)
                    .join("cache/config.toml")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RELTIO_CACHE_DIR".to_owned(),
                data_users
                    .join(missing)
                    .join("cache")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RELTIO_STATE_DIR".to_owned(),
                users
                    .join(missing)
                    .join("state")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ]);

        let error = ConfigPaths::discover(&environment)
            .expect_err("APFS firmlink aliases must not bypass storage isolation");
        assert_eq!(error.code, "storage_path_conflict");
        assert_eq!(error.details["config_in_cache"], true);
    }

    #[cfg(unix)]
    #[test]
    fn storage_path_normalization_does_not_follow_untrusted_deep_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let real = directory.path().join("real");
        std::fs::create_dir(&real).expect("real directory");
        let alias = directory.path().join("alias");
        symlink(&real, &alias).expect("deep symlink");

        let expected_alias = normalized_absolute_path(&alias).expect("normalized alias");
        let expected_real = normalized_absolute_path(&real).expect("normalized target");
        let normalized = normalized_absolute_path(&alias.join("config.toml"))
            .expect("storage normalization is lexical below trusted roots");

        assert!(normalized.starts_with(&expected_alias));
        assert!(!normalized.starts_with(&expected_real));
    }

    #[test]
    fn same_environment_flag_and_environment_value_preserve_all_profile_routing_and_auth() {
        let config = routed_config();
        let selected = config.profiles.get("dev").expect("profile");
        for (environment, overrides, expected_source) in [
            (
                Environment::default(),
                ResolutionOverrides {
                    environment: Some("dev".to_owned()),
                    ..ResolutionOverrides::default()
                },
                "flag",
            ),
            (
                Environment::from_pairs([("RELTIO_ENVIRONMENT".to_owned(), "dev".to_owned())]),
                ResolutionOverrides::default(),
                "environment",
            ),
        ] {
            let target = resolve_target(&config, &environment, &overrides)
                .expect("same environment resolves");

            assert_eq!(target.environment, "dev");
            assert_eq!(target.sources["environment"], expected_source);
            assert_eq!(
                target.sources["environment_routing"],
                "equivalent_to_profile"
            );
            assert_eq!(
                target.base_url.as_ref().and_then(Url::host_str),
                Some("private.example")
            );
            assert_eq!(target.service_urls, selected.services);
            assert_eq!(target.auth, selected.auth);
            assert!(!target.routing_overridden);
            assert!(!target.tenant_overridden);
            assert!(!target.target_overridden);
        }
    }

    #[test]
    fn canonically_equal_base_and_auth_urls_are_routing_noops() {
        let config = routed_config();
        let selected = config.profiles.get("dev").expect("profile");
        let environment = Environment::from_pairs([
            (
                "RELTIO_BASE_URL".to_owned(),
                "https://PRIVATE.example/".to_owned(),
            ),
            (
                "RELTIO_AUTH_URL".to_owned(),
                "https://LOGIN.example/oauth/".to_owned(),
            ),
        ]);
        let target = resolve_target(&config, &environment, &ResolutionOverrides::default())
            .expect("equivalent URLs resolve");

        assert_eq!(target.sources["base_url_routing"], "equivalent_to_profile");
        assert_eq!(target.sources["auth_url_routing"], "equivalent_to_profile");
        assert_eq!(target.service_urls, selected.services);
        assert_eq!(target.auth, selected.auth);
        assert!(!target.routing_overridden);
        assert!(!target.target_overridden);
    }

    #[test]
    fn canonical_route_equality_does_not_accept_host_or_path_prefixes() {
        let config = routed_config();
        let base_target = resolve_target(
            &config,
            &Environment::from_pairs([
                (
                    "RELTIO_BASE_URL".to_owned(),
                    "https://private.example.evil".to_owned(),
                ),
                ("RELTIO_TENANT".to_owned(), "NewTenant".to_owned()),
                (
                    "RELTIO_ACCESS_TOKEN".to_owned(),
                    "invocation-token".to_owned(),
                ),
            ]),
            &ResolutionOverrides::default(),
        )
        .expect("explicit independent base target resolves");
        assert!(base_target.routing_overridden);
        assert_eq!(
            base_target.base_url.as_ref().and_then(Url::host_str),
            Some("private.example.evil")
        );

        let auth_target = resolve_target(
            &config,
            &Environment::from_pairs([
                (
                    "RELTIO_AUTH_URL".to_owned(),
                    "https://login.example/oauth/child".to_owned(),
                ),
                (
                    "RELTIO_ACCESS_TOKEN".to_owned(),
                    "invocation-token".to_owned(),
                ),
            ]),
            &ResolutionOverrides::default(),
        )
        .expect("bearer makes a changed Auth route unused");
        assert!(auth_target.routing_overridden);
        assert_eq!(
            auth_target
                .service_urls
                .get(&Service::Auth)
                .map(String::as_str),
            Some("https://login.example/oauth/child")
        );
    }

    #[test]
    fn changed_namespace_is_refused_without_an_explicit_destination_origin() {
        let config = routed_config();
        let environment = Environment::from_pairs([(
            "RELTIO_ACCESS_TOKEN".to_owned(),
            "invocation-token".to_owned(),
        )]);
        let error = resolve_target(
            &config,
            &environment,
            &ResolutionOverrides {
                environment: Some("prod".to_owned()),
                tenant: Some("FlagTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect_err("a changed namespace is not an independently explicit origin");

        assert_eq!(error.code, "unsafe_profile_routing_override");
        assert_eq!(error.category, crate::error::ErrorCategory::Safety);
        assert!(error.details["missing"].as_array().is_some_and(|missing| {
            missing.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|value| value.contains("destination origin"))
            })
        }));

        let target = resolve_target(
            &config,
            &Environment::from_pairs([
                (
                    "RELTIO_BASE_URL".to_owned(),
                    "https://destination.example".to_owned(),
                ),
                (
                    "RELTIO_ACCESS_TOKEN".to_owned(),
                    "invocation-token".to_owned(),
                ),
            ]),
            &ResolutionOverrides {
                environment: Some("prod".to_owned()),
                tenant: Some("FlagTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("changed namespace with an explicit base origin resolves");
        assert_eq!(target.environment, "prod");
        assert_eq!(
            target.base_url.as_ref().and_then(Url::host_str),
            Some("destination.example")
        );
    }

    #[test]
    fn changed_url_route_compares_custom_auth_template_using_profile_environment() {
        let mut config = routed_config();
        config
            .profiles
            .get_mut("dev")
            .expect("profile")
            .services
            .insert(
                Service::Auth,
                "https://{environment}.login.example/oauth".to_owned(),
            );
        let target = resolve_target(
            &config,
            &Environment::from_pairs([(
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "invocation-token".to_owned(),
            )]),
            &ResolutionOverrides {
                environment: Some("https://destination.example".to_owned()),
                tenant: Some("FlagTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("independent changed URL target resolves");

        assert!(target.routing_overridden);
        assert!(target.service_urls.is_empty());
        assert_eq!(target.auth, AuthProfile::default());
    }

    #[test]
    fn changed_data_route_refuses_inherited_tenant_and_profile_auth() {
        let config = routed_config();
        let inherited_tenant = Environment::from_pairs([
            (
                "RELTIO_BASE_URL".to_owned(),
                "https://destination.example".to_owned(),
            ),
            (
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "invocation-token".to_owned(),
            ),
        ]);
        let error = resolve_target(&config, &inherited_tenant, &ResolutionOverrides::default())
            .expect_err("profile tenant must not follow a changed route");
        assert!(error.details["missing"].as_array().is_some_and(|missing| {
            missing.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|value| value.contains("explicit tenant"))
            })
        }));

        let inherited_auth = Environment::from_pairs([
            (
                "RELTIO_BASE_URL".to_owned(),
                "https://destination.example".to_owned(),
            ),
            ("RELTIO_TENANT".to_owned(), "NewTenant".to_owned()),
        ]);
        let error = resolve_target(&config, &inherited_auth, &ResolutionOverrides::default())
            .expect_err("profile auth must not follow a changed route");
        assert!(error.details["missing"].as_array().is_some_and(|missing| {
            missing.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|value| value.contains("invocation-owned auth"))
            })
        }));
    }

    #[test]
    fn changed_route_rejects_partial_environment_client_credentials() {
        let config = routed_config();
        for (key, value) in [
            ("RELTIO_CLIENT_ID", "invocation-client"),
            ("RELTIO_CLIENT_SECRET", "invocation-secret"),
        ] {
            let environment = Environment::from_pairs([
                (
                    "RELTIO_BASE_URL".to_owned(),
                    "https://destination.example".to_owned(),
                ),
                ("RELTIO_TENANT".to_owned(), "NewTenant".to_owned()),
                (key.to_owned(), value.to_owned()),
            ]);
            let error = resolve_target(&config, &environment, &ResolutionOverrides::default())
                .expect_err("partial client credentials must fail closed");
            assert_eq!(
                error.details["reason"],
                "partial_environment_client_credentials"
            );
        }
    }

    #[test]
    fn explicit_route_tenant_and_environment_bearer_form_an_independent_target() {
        let config = routed_config();
        let environment = Environment::from_pairs([(
            "RELTIO_ACCESS_TOKEN".to_owned(),
            "invocation-token".to_owned(),
        )]);
        let target = resolve_target(
            &config,
            &environment,
            &ResolutionOverrides {
                environment: Some("https://destination.example".to_owned()),
                tenant: Some("NewTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("independently authenticated target resolves");

        assert_eq!(target.environment, "https://destination.example");
        assert_eq!(target.tenant, "NewTenant");
        assert_eq!(
            target.base_url.as_ref().and_then(Url::host_str),
            Some("destination.example")
        );
        assert!(target.service_urls.is_empty());
        assert_eq!(target.auth, AuthProfile::default());
        assert!(target.routing_overridden);
        assert!(target.tenant_overridden);
        assert!(target.target_overridden);
    }

    #[test]
    fn complete_environment_client_credentials_can_use_central_auth_after_route_change() {
        let mut config = routed_config();
        config
            .profiles
            .get_mut("dev")
            .expect("profile")
            .services
            .remove(&Service::Auth);
        let environment = Environment::from_pairs([
            (
                "RELTIO_BASE_URL".to_owned(),
                "https://destination.example".to_owned(),
            ),
            ("RELTIO_TENANT".to_owned(), "NewTenant".to_owned()),
            ("RELTIO_CLIENT_ID".to_owned(), "env-client".to_owned()),
            ("RELTIO_CLIENT_SECRET".to_owned(), "env-secret".to_owned()),
        ]);
        let target = resolve_target(&config, &environment, &ResolutionOverrides::default())
            .expect("complete environment credentials resolve");

        assert!(target.service_urls.is_empty());
        assert_eq!(target.auth, AuthProfile::default());
        assert!(target.routing_overridden);
    }

    #[test]
    fn displaced_custom_auth_requires_an_explicit_environment_auth_url_for_client_credentials() {
        let config = routed_config();
        let pairs = [
            (
                "RELTIO_BASE_URL".to_owned(),
                "https://destination.example".to_owned(),
            ),
            ("RELTIO_TENANT".to_owned(), "NewTenant".to_owned()),
            ("RELTIO_CLIENT_ID".to_owned(), "env-client".to_owned()),
            ("RELTIO_CLIENT_SECRET".to_owned(), "env-secret".to_owned()),
        ];
        let error = resolve_target(
            &config,
            &Environment::from_pairs(pairs.clone()),
            &ResolutionOverrides::default(),
        )
        .expect_err("a custom profile Auth route cannot silently become central Auth");
        assert!(error.details["missing"].as_array().is_some_and(|missing| {
            missing.iter().any(|value| {
                value.as_str().is_some_and(|value| {
                    value == "RELTIO_AUTH_URL for the displaced custom profile Auth route"
                })
            })
        }));

        let target = resolve_target(
            &config,
            &Environment::from_pairs(pairs.into_iter().chain([(
                "RELTIO_AUTH_URL".to_owned(),
                "https://invocation-login.example".to_owned(),
            )])),
            &ResolutionOverrides::default(),
        )
        .expect("explicit environment Auth route resolves");
        assert_eq!(target.service_urls.len(), 1);
        assert_eq!(
            target.service_urls.get(&Service::Auth).map(String::as_str),
            Some("https://invocation-login.example")
        );
        assert_eq!(target.auth, AuthProfile::default());
    }

    #[test]
    fn changed_auth_route_alone_never_uses_profile_credentials() {
        let config = routed_config();
        let changed_auth = (
            "RELTIO_AUTH_URL".to_owned(),
            "https://other-login.example".to_owned(),
        );
        let error = resolve_target(
            &config,
            &Environment::from_pairs([changed_auth.clone()]),
            &ResolutionOverrides::default(),
        )
        .expect_err("profile credentials cannot follow a changed Auth route");
        assert_eq!(
            error.details["reason"],
            "profile_credentials_refused_for_changed_auth_route"
        );

        for credentials in [
            vec![
                changed_auth.clone(),
                (
                    "RELTIO_ACCESS_TOKEN".to_owned(),
                    "invocation-token".to_owned(),
                ),
            ],
            vec![
                changed_auth.clone(),
                ("RELTIO_CLIENT_ID".to_owned(), "env-client".to_owned()),
                ("RELTIO_CLIENT_SECRET".to_owned(), "env-secret".to_owned()),
            ],
        ] {
            let target = resolve_target(
                &config,
                &Environment::from_pairs(credentials),
                &ResolutionOverrides::default(),
            )
            .expect("invocation-owned auth permits an auth-only route change");
            assert_eq!(target.tenant, "ProfileTenant");
            assert!(target.service_urls.contains_key(&Service::Data));
            assert_eq!(
                target.service_urls.get(&Service::Auth).map(String::as_str),
                Some("https://other-login.example")
            );
            assert_eq!(target.auth, AuthProfile::default());
            assert!(target.routing_overridden);
            assert!(!target.tenant_overridden);
        }
    }

    #[test]
    fn explicit_environment_url_wins_over_environment_base_url() {
        let config = ConfigFile::default();
        let environment = Environment::from_pairs([
            (
                "RELTIO_BASE_URL".to_owned(),
                "https://environment.example".to_owned(),
            ),
            ("RELTIO_TENANT".to_owned(), "Tenant".to_owned()),
        ]);
        let target = resolve_target(
            &config,
            &environment,
            &ResolutionOverrides {
                environment: Some("https://flag.example".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("target resolves");

        assert_eq!(
            target.base_url.as_ref().and_then(Url::host_str),
            Some("flag.example")
        );
        assert_eq!(target.sources["base_url"], "flag");
    }

    #[test]
    fn tenant_only_override_preserves_profile_service_routes() {
        let config = routed_config();
        let selected = config.profiles.get("dev").expect("profile");
        let target = resolve_target(
            &config,
            &Environment::default(),
            &ResolutionOverrides {
                tenant: Some("NewTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("target resolves");

        assert_eq!(target.service_urls.len(), 3);
        assert_eq!(target.service_urls, selected.services);
        assert_eq!(target.auth, selected.auth);
        assert!(!target.routing_overridden);
        assert!(target.tenant_overridden);
        assert!(target.target_overridden);
    }

    #[test]
    fn profileless_explicit_bootstrap_remains_supported() {
        let target = resolve_target(
            &ConfigFile::default(),
            &Environment::from_pairs([
                ("RELTIO_ENVIRONMENT".to_owned(), "dev".to_owned()),
                ("RELTIO_TENANT".to_owned(), "Tenant".to_owned()),
                (
                    "RELTIO_ACCESS_TOKEN".to_owned(),
                    "invocation-token".to_owned(),
                ),
            ]),
            &ResolutionOverrides::default(),
        )
        .expect("profileless environment bootstrap resolves");

        assert!(target.profile.is_none());
        assert_eq!(target.environment, "dev");
        assert_eq!(target.tenant, "Tenant");
        assert!(target.routing_overridden);
        assert!(target.tenant_overridden);
        assert_eq!(target.auth, AuthProfile::default());
    }

    #[test]
    fn safety_relevant_unknown_fields_are_rejected() {
        let error = toml::from_str::<ConfigFile>(
            r#"
version = 1
[profiles.prod]
environment = "prod"
tenant = "ProdTenant"
productionn = true
"#,
        )
        .expect_err("unknown production field must fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn tenant_dot_segments_are_rejected() {
        for tenant in [".", ".."] {
            let error = validate_tenant(tenant).expect_err("dot segment must fail");
            assert_eq!(error.code, "invalid_tenant");
        }
    }

    #[test]
    fn environment_base_must_be_an_origin() {
        let mut config = ConfigFile::default();
        config.profiles.insert(
            "dev".to_owned(),
            Profile {
                base_url: Some("https://example.com/unexpected/path".to_owned()),
                tenant: Some("Tenant".to_owned()),
                ..Profile::default()
            },
        );
        let error = validate_config(&config).expect_err("path-prefixed base must fail");
        assert_eq!(error.code, "environment_origin_has_path");
    }

    #[test]
    fn tenant_scoped_service_override_requires_path_template() {
        let mut config = ConfigFile::default();
        config.profiles.insert(
            "dev".to_owned(),
            Profile {
                environment: Some("dev".to_owned()),
                tenant: Some("Tenant".to_owned()),
                services: BTreeMap::from([(
                    Service::Data,
                    "https://example.com/reltio/api/AnotherTenant".to_owned(),
                )]),
                ..Profile::default()
            },
        );
        let error = validate_config(&config).expect_err("static tenant route must fail");
        assert_eq!(error.code, "tenant_placeholder_required");
    }

    #[test]
    fn token_is_not_visible_in_environment_debug() {
        let environment = Environment::from_pairs([(
            "RELTIO_ACCESS_TOKEN".to_owned(),
            "secret-value".to_owned(),
        )]);
        let rendered = format!("{environment:?}");
        assert!(!rendered.contains("secret-value"));
    }

    #[test]
    fn config_lock_wait_observes_cancellation_without_late_commit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("config.toml");
        let store = ConfigStore::new(path.clone());
        let lock_path = PathBuf::from(format!("{}.lock", path.to_string_lossy()));
        let held = open_private_lock(&lock_path).expect("open configuration lock");
        FileExt::try_lock_exclusive(&held).expect("hold configuration lock");
        let canceled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&canceled);
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            signal.store(true, Ordering::Release);
        });
        let started = Instant::now();

        let error = store
            .modify_until(
                started + Duration::from_secs(2),
                || canceled.load(Ordering::Acquire),
                |config| {
                    config.current_profile = Some("late-write".to_owned());
                    Ok(())
                },
            )
            .expect_err("cancellation must stop lock polling");

        setter.join().expect("cancellation thread completes");
        assert_eq!(error.code, "request_canceled");
        assert_eq!(error.details["local_state_committed"], false);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!path.exists(), "canceled config mutation committed later");
        FileExt::unlock(&held).expect("release configuration lock");
    }
}
