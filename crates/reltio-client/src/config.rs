use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use fs2::FileExt;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{ReltioError, Result};
use crate::fs::{
    atomic_write_private, open_private_lock, private_file_status, read_bounded_optional,
};
use crate::service::{Service, validate_service_url};

const CONFIG_VERSION: u32 = 1;
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
        Ok(Self {
            config_file,
            cache_dir,
            state_dir,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default = "config_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            current_profile: None,
            profiles: BTreeMap::new(),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Bearer,
    ClientCredentials,
    CredentialProcess,
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

    pub fn modify<T>(&self, update: impl FnOnce(&mut ConfigFile) -> Result<T>) -> Result<T> {
        let mut lock_name = self.path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        let lock = open_private_lock(&lock_path)?;
        FileExt::lock_exclusive(&lock)
            .map_err(|error| ReltioError::io("failed to lock configuration", &error))?;
        let mut config = self.load()?;
        let result = update(&mut config)?;
        validate_config(&config)?;
        let encoded = toml::to_string_pretty(&config)
            .map_err(|error| ReltioError::internal(format!("failed to encode config: {error}")))?;
        atomic_write_private(&self.path, encoded.as_bytes())?;
        FileExt::unlock(&lock).map_err(|error| {
            ReltioError::io("failed to unlock configuration", &error).with_details(
                serde_json::json!({
                    "kind": format!("{:?}", error.kind()),
                    "committed": true
                }),
            )
        })?;
        Ok(result)
    }

    pub fn permissions_are_private(&self) -> Result<Option<bool>> {
        private_file_status(&self.path)
    }
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
    /// True when invocation-scoped routing values displaced the selected profile.
    pub target_overridden: bool,
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

    let (environment_value, environment_source) = first_value([
        overrides.environment.as_deref().map(|v| (v, "flag")),
        environment
            .get("RELTIO_ENVIRONMENT")
            .map(|v| (v, "environment")),
        profile
            .and_then(|p| p.environment.as_deref())
            .map(|v| (v, "profile")),
    ])
    .map_or((None, None), |(value, source)| (Some(value), Some(source)));
    let environment_overridden = matches!(environment_source, Some("flag" | "environment"));

    let environment_is_url = environment_value.is_some_and(looks_like_http_url);
    let explicit_environment_flag = environment_source == Some("flag");
    let (base_value, base_source) = first_value([
        explicit_environment_flag
            .then_some(environment_value)
            .flatten()
            .filter(|_| environment_is_url)
            .map(|v| (v, "flag")),
        (!explicit_environment_flag)
            .then(|| environment.get("RELTIO_BASE_URL"))
            .flatten()
            .map(|v| (v, "environment")),
        (!explicit_environment_flag)
            .then_some(environment_value)
            .flatten()
            .filter(|_| environment_is_url)
            .map(|v| (v, environment_source.unwrap_or("profile"))),
        (!environment_overridden)
            .then(|| profile.and_then(|p| p.base_url.as_deref()))
            .flatten()
            .map(|v| (v, "profile")),
    ])
    .map_or((None, None), |(value, source)| (Some(value), Some(source)));

    let base_url = base_value.map(validate_environment_origin).transpose()?;
    let resolved_environment = environment_value
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
        environment_source.unwrap_or("base_url").to_owned(),
    );
    if let Some(source) = base_source {
        sources.insert("base_url".to_owned(), source.to_owned());
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
    let environment_routing_overridden =
        environment_overridden || environment.contains("RELTIO_BASE_URL");
    let target_overridden =
        environment_routing_overridden || matches!(tenant_source, "flag" | "environment");

    let mut service_urls = profile.map_or_else(BTreeMap::new, |p| p.services.clone());
    if environment_routing_overridden && !service_urls.is_empty() {
        service_urls.clear();
        sources.insert(
            "profile_service_urls".to_owned(),
            "ignored_for_target_override".to_owned(),
        );
    }
    if let Some(auth_url) = environment.get("RELTIO_AUTH_URL") {
        validate_service_url(auth_url)?;
        service_urls.insert(Service::Auth, auth_url.to_owned());
        sources.insert("auth_url".to_owned(), "environment".to_owned());
    } else if service_urls.contains_key(&Service::Auth) {
        sources.insert("auth_url".to_owned(), "profile".to_owned());
    } else {
        sources.insert("auth_url".to_owned(), "default".to_owned());
    }

    Ok(ResolvedTarget {
        profile: profile_name,
        environment: resolved_environment,
        tenant: tenant.to_owned(),
        production: profile.is_some_and(|p| p.production),
        target_overridden,
        base_url,
        service_urls,
        auth: profile.map_or_else(AuthProfile::default, |p| p.auth.clone()),
        sources,
    })
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
    use super::*;

    #[test]
    fn explicit_target_values_win() {
        let mut config = ConfigFile {
            current_profile: Some("dev".to_owned()),
            ..ConfigFile::default()
        };
        config.profiles.insert(
            "dev".to_owned(),
            Profile {
                environment: Some("dev".to_owned()),
                tenant: Some("ProfileTenant".to_owned()),
                ..Profile::default()
            },
        );
        let environment = Environment::from_pairs([
            ("RELTIO_ENVIRONMENT".to_owned(), "test".to_owned()),
            ("RELTIO_TENANT".to_owned(), "EnvTenant".to_owned()),
        ]);
        let target = resolve_target(
            &config,
            &environment,
            &ResolutionOverrides {
                environment: Some("prod".to_owned()),
                tenant: Some("FlagTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("target resolves");
        assert_eq!(target.environment, "prod");
        assert_eq!(target.tenant, "FlagTenant");
        assert_eq!(target.sources["environment"], "flag");
        assert_eq!(target.sources["tenant"], "flag");
        assert!(target.target_overridden);
    }

    #[test]
    fn explicit_environment_discards_profile_routing_overrides() {
        let mut config = ConfigFile {
            current_profile: Some("dev".to_owned()),
            ..ConfigFile::default()
        };
        config.profiles.insert(
            "dev".to_owned(),
            Profile {
                environment: Some("dev".to_owned()),
                base_url: Some("https://private.example.com".to_owned()),
                tenant: Some("ProfileTenant".to_owned()),
                services: BTreeMap::from([(
                    Service::Data,
                    "https://private.example.com/reltio/api/{tenant}".to_owned(),
                )]),
                ..Profile::default()
            },
        );

        let target = resolve_target(
            &config,
            &Environment::default(),
            &ResolutionOverrides {
                environment: Some("prod".to_owned()),
                tenant: Some("FlagTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("target resolves");

        assert_eq!(target.environment, "prod");
        assert_eq!(target.tenant, "FlagTenant");
        assert!(target.base_url.is_none());
        assert!(target.service_urls.is_empty());
        assert_eq!(
            target.sources["profile_service_urls"],
            "ignored_for_target_override"
        );
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
        let mut config = ConfigFile {
            current_profile: Some("dev".to_owned()),
            ..ConfigFile::default()
        };
        config.profiles.insert(
            "dev".to_owned(),
            Profile {
                environment: Some("dev".to_owned()),
                tenant: Some("OldTenant".to_owned()),
                services: BTreeMap::from([
                    (
                        Service::Data,
                        "https://private.example/reltio/api/{tenant}".to_owned(),
                    ),
                    (Service::Auth, "https://login.example".to_owned()),
                ]),
                ..Profile::default()
            },
        );
        let target = resolve_target(
            &config,
            &Environment::default(),
            &ResolutionOverrides {
                tenant: Some("NewTenant".to_owned()),
                ..ResolutionOverrides::default()
            },
        )
        .expect("target resolves");

        assert_eq!(target.service_urls.len(), 2);
        assert!(target.service_urls.contains_key(&Service::Data));
        assert!(target.service_urls.contains_key(&Service::Auth));
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
}
