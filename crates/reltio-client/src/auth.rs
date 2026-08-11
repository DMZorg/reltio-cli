use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use chrono::{DateTime, TimeDelta, Utc};
use fs2::FileExt;
use futures_util::StreamExt;
use rand::Rng;
use reqwest::redirect::Policy;
use secrecy::{ExposeSecret, SecretString};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use zeroize::{Zeroize, Zeroizing};

use crate::MAX_OPERATION_TIMEOUT;
use crate::cancellation::CancellationToken;
use crate::config::{AuthMethod, Environment, ResolvedTarget};
use crate::error::{ErrorCategory, ReltioError, Result, json_parse_details};
use crate::fs::{
    atomic_write_private, open_private_lock, read_bounded_optional_with_limit,
    read_bounded_with_limit, remove_private_file, validate_private_executable,
};
use crate::redaction::{
    OutputGuard, redact_json, redact_known_secrets_json, redact_text, sanitize_json_serialization,
};
use crate::service::{Service, ServiceResolver, validate_auth_token_url};

const AUTH_RESPONSE_LIMIT: usize = 1024 * 1024;
const MAX_JSON_ESCAPE_BYTES_PER_TOKEN_BYTE: usize = 6;
// The compact v1 schema's non-token maximum is 204 bytes: 105 bytes of field
// syntax, 10 for u32, 18 for the longest provider, two 33-byte chrono values,
// and 5 for bool. The extra 52 bytes are fixed serialization headroom.
const TOKEN_CACHE_SCHEMA_METADATA_MAX: usize = 204;
const TOKEN_CACHE_METADATA_BUDGET: usize = TOKEN_CACHE_SCHEMA_METADATA_MAX + 52;
const TOKEN_CACHE_LIMIT: u64 = (AUTH_RESPONSE_LIMIT * MAX_JSON_ESCAPE_BYTES_PER_TOKEN_BYTE
    + TOKEN_CACHE_METADATA_BUDGET) as u64;
const EXPIRY_SKEW_SECONDS: i64 = 5;
const TOKEN_REQUESTS_PER_SECOND: usize = 10;
const RATE_WINDOW_MILLIS: i64 = 1_000;
// `{"request_millis":[]}` plus ten 20-byte i64 values and nine commas.
const TOKEN_RATE_STATE_LIMIT: u64 = 21 + (TOKEN_REQUESTS_PER_SECOND as u64 * 20) + 9;
const AUTH_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_LOCAL_AUTH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct AccessToken {
    secret: SecretString,
    output_guard: OutputGuard,
    pub expires_at: Option<DateTime<Utc>>,
    pub provider: String,
    pub cache_hit: bool,
    obtained_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    pub fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }

    pub fn output_guard(&self) -> &OutputGuard {
        &self.output_guard
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessToken")
            .field("secret", &"[REDACTED]")
            .field("output_guard", &self.output_guard)
            .field("expires_at", &self.expires_at)
            .field("provider", &self.provider)
            .field("cache_hit", &self.cache_hit)
            .field("obtained_at", &self.obtained_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenStatus {
    pub provider: String,
    pub source: String,
    pub configured: bool,
    pub cache_state: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub environment_override: bool,
}

#[derive(Default)]
pub struct TokenManagerOptions {
    pub client_secret: Option<SecretString>,
    pub no_retry: bool,
}

pub struct LoginCachePlan {
    _maintenance: fs::File,
    changes: Vec<CacheEntryChange>,
    output_guard: OutputGuard,
    deadline: Instant,
    state: LoginCachePlanState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginCachePlanState {
    Prepared,
    Committed,
    Finished,
}

impl fmt::Debug for LoginCachePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginCachePlan")
            .field("entry_count", &self.changes.len())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

struct CacheEntryChange {
    path: PathBuf,
    before: Option<Zeroizing<Vec<u8>>>,
    after: Option<Zeroizing<Vec<u8>>>,
}

impl LoginCachePlan {
    fn new(
        maintenance: fs::File,
        updates: Vec<(PathBuf, Option<Zeroizing<Vec<u8>>>)>,
        mut output_guard: OutputGuard,
        deadline: Instant,
    ) -> Result<Self> {
        let mut changes = Vec::with_capacity(updates.len());
        for (path, after) in updates {
            let before = read_bounded_optional_with_limit(&path, true, TOKEN_CACHE_LIMIT)
                .map_err(|error| error.with_output_guard(output_guard.clone()))?
                .map(Zeroizing::new);
            if let Some(bytes) = &before {
                merge_cached_token_guard(bytes, &mut output_guard)
                    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
            }
            if let Some(bytes) = &after {
                validate_cache_image_bound(bytes)
                    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
                merge_cached_token_guard(bytes, &mut output_guard)
                    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
            }
            changes.push(CacheEntryChange {
                path,
                before,
                after,
            });
        }
        ensure_auth_deadline(deadline, "token_cache_snapshot")
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        Ok(Self {
            _maintenance: maintenance,
            changes,
            output_guard,
            deadline,
            state: LoginCachePlanState::Prepared,
        })
    }

    pub fn output_guard(&self) -> &OutputGuard {
        &self.output_guard
    }

    pub fn commit(&mut self) -> Result<()> {
        self.commit_controlled(None)
    }

    pub fn commit_with_cancellation(&mut self, cancellation: &CancellationToken) -> Result<()> {
        self.commit_controlled(Some(cancellation))
    }

    fn commit_controlled(&mut self, cancellation: Option<&CancellationToken>) -> Result<()> {
        if self.state != LoginCachePlanState::Prepared {
            return Err(ReltioError::internal(
                "authentication cache plan was committed more than once",
            )
            .with_output_guard(self.output_guard.clone()));
        }
        if let Err(error) =
            ensure_login_plan_active(self.deadline, cancellation, "token_cache_commit")
        {
            self.state = LoginCachePlanState::Finished;
            return Err(cache_plan_commit_error(error, &[], &self.output_guard));
        }
        for change in &self.changes {
            if let Some(bytes) = &change.after {
                let cached = decode_cached_token(bytes)
                    .map_err(|error| error.with_output_guard(self.output_guard.clone()))?;
                validate_token_expiry(cached.expires_at, Utc::now()).map_err(|mut error| {
                    error.details["local_cache_restored"] = Value::Bool(true);
                    error.with_output_guard(self.output_guard.clone())
                })?;
            }
        }
        if let Err(error) =
            ensure_login_plan_active(self.deadline, cancellation, "token_cache_commit")
        {
            self.state = LoginCachePlanState::Finished;
            return Err(cache_plan_commit_error(error, &[], &self.output_guard));
        }
        for (index, change) in self.changes.iter().enumerate() {
            if let Err(error) =
                ensure_login_plan_active(self.deadline, cancellation, "token_cache_commit")
            {
                let rollback_errors = restore_cache_changes(&self.changes[..index], &self.changes);
                self.state = LoginCachePlanState::Finished;
                return Err(cache_plan_commit_error(
                    error,
                    &rollback_errors,
                    &self.output_guard,
                ));
            }
            if let Err(error) = install_cache_image(
                &change.path,
                change.after.as_ref().map(|bytes| bytes.as_slice()),
            ) {
                let rollback_errors = restore_cache_changes(&self.changes[..=index], &self.changes);
                self.state = LoginCachePlanState::Finished;
                return Err(cache_plan_commit_error(
                    error,
                    &rollback_errors,
                    &self.output_guard,
                ));
            }
            if let Err(error) =
                ensure_login_plan_active(self.deadline, cancellation, "token_cache_commit")
            {
                let rollback_errors = restore_cache_changes(&self.changes[..=index], &self.changes);
                self.state = LoginCachePlanState::Finished;
                return Err(cache_plan_commit_error(
                    error,
                    &rollback_errors,
                    &self.output_guard,
                ));
            }
        }
        self.state = LoginCachePlanState::Committed;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        if self.state != LoginCachePlanState::Committed {
            return Err(ReltioError::internal(
                "authentication cache plan cannot be rolled back before a successful commit",
            )
            .with_output_guard(self.output_guard.clone()));
        }
        // Restoration remains mandatory even if the acquisition deadline has elapsed.
        let rollback_errors = restore_cache_changes(&self.changes, &self.changes);
        self.state = LoginCachePlanState::Finished;
        if rollback_errors.is_empty() {
            Ok(())
        } else {
            Err(ReltioError::new(
                "auth_login_cache_rollback_failed",
                ErrorCategory::Internal,
                "exact authentication cache rollback did not complete",
            )
            .with_details(json!({
                "rollback_errors": rollback_errors,
                "local_cache_restored": false,
                "safe_to_replay": false
            }))
            .with_hint(
                "Inspect `reltio auth status`; do not retry login until the reported local cache state is resolved.",
            )
            .with_output_guard(self.output_guard.clone()))
        }
    }
}

impl fmt::Debug for TokenManagerOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenManagerOptions")
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("no_retry", &self.no_retry)
            .finish()
    }
}

#[derive(Clone)]
pub struct TokenManager {
    source: CredentialSource,
    environment_output_guard: OutputGuard,
    cache_dir: PathBuf,
    client: reqwest::Client,
    timeout: Duration,
    no_retry: bool,
}

impl fmt::Debug for TokenManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenManager")
            .field("provider", &self.source.provider())
            .field("cache_dir", &self.cache_dir)
            .field("timeout", &self.timeout)
            .field("no_retry", &self.no_retry)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
enum CredentialSource {
    SuppliedEnvironment {
        token: SecretString,
    },
    ImportedBearer {
        cache_key: String,
    },
    ClientCredentials {
        cache_key: String,
        client_id: String,
        client_secret: Option<SecretString>,
        secret_file: Option<PathBuf>,
        token_url: url::Url,
        environment_override: bool,
    },
    CredentialProcess {
        cache_key: String,
        command: Vec<String>,
    },
}

impl CredentialSource {
    fn provider(&self) -> &'static str {
        match self {
            Self::SuppliedEnvironment { .. } | Self::ImportedBearer { .. } => "bearer",
            Self::ClientCredentials { .. } => "client_credentials",
            Self::CredentialProcess { .. } => "credential_process",
        }
    }

    fn cache_key(&self) -> Option<&str> {
        match self {
            Self::SuppliedEnvironment { .. } => None,
            Self::ImportedBearer { cache_key }
            | Self::ClientCredentials { cache_key, .. }
            | Self::CredentialProcess { cache_key, .. } => Some(cache_key),
        }
    }
}

fn environment_credential_guard(environment: &Environment) -> OutputGuard {
    OutputGuard::from_known_secrets(
        &["RELTIO_ACCESS_TOKEN", "RELTIO_CLIENT_SECRET"]
            .into_iter()
            .filter_map(|name| environment.get(name))
            .collect::<Vec<_>>(),
    )
}

fn resolve_credential_source(
    target: &ResolvedTarget,
    environment: &Environment,
    client_secret: Option<SecretString>,
) -> Result<CredentialSource> {
    if let Some(token) = environment.secret("RELTIO_ACCESS_TOKEN") {
        validate_token(token.expose_secret())?;
        return Ok(CredentialSource::SuppliedEnvironment { token });
    }
    let inferred_client_credentials =
        environment.contains("RELTIO_CLIENT_ID") || environment.contains("RELTIO_CLIENT_SECRET");
    let method = target
        .auth
        .method
        .or(inferred_client_credentials.then_some(AuthMethod::ClientCredentials))
        .ok_or_else(|| {
            ReltioError::auth(
                "auth_unconfigured",
                "no authentication provider is configured",
            )
            .with_hint(
                "Set RELTIO_ACCESS_TOKEN or run `reltio auth login` for the selected profile.",
            )
        })?;
    match method {
        AuthMethod::Bearer => {
            let identity = target.profile.as_deref().ok_or_else(|| {
                ReltioError::auth(
                    "bearer_profile_required",
                    "persisted bearer authentication requires a named profile",
                )
            })?;
            Ok(CredentialSource::ImportedBearer {
                cache_key: cache_identity(&json!({
                    "version": 2,
                    "provider": "bearer",
                    "profile": identity
                })),
            })
        }
        AuthMethod::ClientCredentials => {
            let environment_override = environment.contains("RELTIO_CLIENT_ID")
                || environment.contains("RELTIO_CLIENT_SECRET");
            let client_id = environment
                .get("RELTIO_CLIENT_ID")
                .map(ToOwned::to_owned)
                .or_else(|| target.auth.client_id.clone())
                .ok_or_else(|| {
                    ReltioError::auth(
                        "client_id_missing",
                        "client credentials authentication requires a client ID",
                    )
                })?;
            if client_id.is_empty() || client_id.contains(['\r', '\n']) {
                return Err(ReltioError::auth(
                    "invalid_client_id",
                    "client ID is empty or contains a line break",
                ));
            }
            let auth_base = ServiceResolver::new(target.clone()).base_url(Service::Auth)?;
            let token_url = auth_base.join("oauth/token").map_err(|error| {
                ReltioError::internal(format!("failed to build token URL: {error}"))
            })?;
            validate_auth_token_url(&token_url)?;
            let secret = client_secret.or_else(|| environment.secret("RELTIO_CLIENT_SECRET"));
            Ok(CredentialSource::ClientCredentials {
                cache_key: cache_identity(&json!({
                    "version": 2,
                    "provider": "client_credentials",
                    "token_url": token_url,
                    "client_id": client_id
                })),
                client_id,
                client_secret: secret,
                secret_file: target.auth.secret_file.clone(),
                token_url,
                environment_override,
            })
        }
        AuthMethod::CredentialProcess => {
            let command = target.auth.credential_process.clone().ok_or_else(|| {
                ReltioError::auth(
                    "credential_process_missing",
                    "credential process authentication has no command",
                )
            })?;
            validate_process_command(&command)?;
            Ok(CredentialSource::CredentialProcess {
                cache_key: cache_identity(&json!({
                    "version": 2,
                    "provider": "credential_process",
                    "profile": target.profile,
                    "environment": target.environment,
                    "tenant": target.tenant,
                    "command": command
                })),
                command,
            })
        }
    }
}

impl TokenManager {
    pub fn from_target(
        target: &ResolvedTarget,
        environment: &Environment,
        cache_dir: PathBuf,
        options: TokenManagerOptions,
        timeout: Duration,
    ) -> Result<Self> {
        let TokenManagerOptions {
            client_secret,
            no_retry,
        } = options;
        let environment_output_guard = environment_credential_guard(environment);
        if timeout.is_zero() || timeout > MAX_OPERATION_TIMEOUT {
            return Err(ReltioError::usage(
                "invalid_timeout",
                "authentication timeout must be greater than zero and at most 24 hours",
            )
            .with_output_guard(environment_output_guard));
        }
        let source = resolve_credential_source(target, environment, client_secret)
            .map_err(|error| error.with_output_guard(environment_output_guard.clone()))?;

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .build()
            .map_err(|error| {
                ReltioError::internal(format!("failed to create authentication client: {error}"))
                    .with_output_guard(environment_output_guard.clone())
            })?;
        Ok(Self {
            source,
            environment_output_guard,
            cache_dir,
            client,
            timeout,
            no_retry,
        })
    }

    pub async fn token(&self, force_reacquire: bool) -> Result<AccessToken> {
        let deadline = auth_deadline_after(self.timeout)?;
        self.token_until(force_reacquire, deadline).await
    }

    /// Acquires a token without exceeding an absolute monotonic deadline.
    pub async fn token_until(
        &self,
        force_reacquire: bool,
        deadline: Instant,
    ) -> Result<AccessToken> {
        let mode = if force_reacquire {
            TokenAcquisition::Explicit
        } else {
            TokenAcquisition::Normal
        };
        self.token_with_mode_until(mode, true, deadline).await
    }

    pub async fn acquire_for_login(&self) -> Result<AccessToken> {
        let deadline = auth_deadline_after(self.timeout)?;
        self.acquire_for_login_until(deadline).await
    }

    pub async fn acquire_for_login_until(&self, deadline: Instant) -> Result<AccessToken> {
        self.token_with_mode_until(TokenAcquisition::Explicit, false, deadline)
            .await
    }

    pub async fn token_after_rejection(&self, rejected: &AccessToken) -> Result<AccessToken> {
        let deadline = auth_deadline_after(self.timeout)?;
        self.token_after_rejection_until(rejected, deadline).await
    }

    /// Reacquires a rejected token without exceeding an absolute monotonic deadline.
    pub async fn token_after_rejection_until(
        &self,
        rejected: &AccessToken,
        deadline: Instant,
    ) -> Result<AccessToken> {
        self.token_with_mode_until(TokenAcquisition::AfterRejection(rejected), true, deadline)
            .await
    }

    async fn token_with_mode_until(
        &self,
        mode: TokenAcquisition<'_>,
        persist: bool,
        deadline: Instant,
    ) -> Result<AccessToken> {
        let output_guard = self.output_guard()?;
        let mut timeout_output_guard = output_guard.clone();
        if matches!(
            self.source,
            CredentialSource::ClientCredentials { .. } | CredentialSource::CredentialProcess { .. }
        ) {
            timeout_output_guard.merge(&OutputGuard::deny_all());
        }
        ensure_auth_deadline(deadline, "authentication")
            .map_err(|error| error.with_output_guard(timeout_output_guard.clone()))?;
        let mut token = self
            .token_inner(mode, persist, deadline)
            .await
            .map_err(|error| {
                if error.code == "auth_timeout" {
                    error.with_output_guard(timeout_output_guard)
                } else {
                    error.with_output_guard(output_guard.clone())
                }
            })?;
        token.output_guard.merge(&output_guard);
        Ok(token)
    }

    async fn token_inner(
        &self,
        mode: TokenAcquisition<'_>,
        persist: bool,
        deadline: Instant,
    ) -> Result<AccessToken> {
        if let CredentialSource::SuppliedEnvironment { token } = &self.source {
            return Ok(AccessToken {
                output_guard: OutputGuard::from_known_secrets(&[token.expose_secret()]),
                secret: token.clone(),
                expires_at: None,
                provider: "bearer".to_owned(),
                cache_hit: false,
                obtained_at: None,
            });
        }

        let key = self
            .source
            .cache_key()
            .expect("non-environment sources have cache keys");
        let _maintenance =
            acquire_shared_lock_until(self.maintenance_lock_path(), deadline).await?;
        let lock = acquire_lock_until(self.lock_path(key), deadline).await?;
        ensure_auth_deadline(deadline, "token_cache")?;
        let mut cache_guard = OutputGuard::default();
        let prior_cached = match self.read_cache(key)? {
            Some(cached) => {
                cache_guard.merge(&cached.output_guard());
                if cached.is_valid() {
                    let reuse = match mode {
                        TokenAcquisition::Normal => true,
                        TokenAcquisition::Explicit => false,
                        TokenAcquisition::AfterRejection(rejected) => {
                            if cached.reissued_after_rejection
                                && cached.access_token.expose_secret() == rejected.expose_secret()
                            {
                                let output_guard = cached.output_guard();
                                ensure_auth_deadline(deadline, "token_cache").map_err(|error| {
                                    error.with_output_guard(output_guard.clone())
                                })?;
                                FileExt::unlock(&lock).map_err(|error| {
                                    ReltioError::io("failed to unlock token cache", &error)
                                        .with_output_guard(output_guard.clone())
                                })?;
                                return Err(unchanged_rejected_token_error()
                                    .with_output_guard(output_guard));
                            }
                            cached.replaces_rejected(rejected)
                        }
                    };
                    if reuse {
                        let output_guard = cached.output_guard();
                        ensure_auth_deadline(deadline, "token_cache")
                            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
                        FileExt::unlock(&lock).map_err(|error| {
                            ReltioError::io("failed to unlock token cache", &error)
                                .with_output_guard(output_guard.clone())
                        })?;
                        let mut token = cached.into_access_token(true);
                        token.output_guard.merge(&output_guard);
                        return Ok(token);
                    }
                }
                Some(cached)
            }
            None => None,
        };
        ensure_auth_deadline(deadline, "token_cache")
            .map_err(|error| error.with_output_guard(cache_guard.clone()))?;

        let acquired = match &self.source {
            CredentialSource::ImportedBearer { .. } => {
                FileExt::unlock(&lock).map_err(|error| {
                    ReltioError::io("failed to unlock token cache", &error)
                        .with_output_guard(cache_guard.clone())
                })?;
                return Err(ReltioError::auth(
                    "bearer_token_missing",
                    "no usable imported bearer token is cached",
                )
                .with_hint("Set RELTIO_ACCESS_TOKEN or run `reltio auth login --method bearer`.")
                .with_output_guard(cache_guard));
            }
            CredentialSource::ClientCredentials {
                client_id,
                client_secret,
                secret_file,
                token_url,
                ..
            } => {
                let secret = resolve_client_secret(client_secret.clone(), secret_file.as_deref())?;
                let basic_credential = base64::engine::general_purpose::STANDARD
                    .encode(format!("{client_id}:{}", secret.expose_secret()));
                let mut output_guard = OutputGuard::from_known_secrets(&[
                    secret.expose_secret(),
                    basic_credential.as_str(),
                ]);
                output_guard.merge(&cache_guard);
                let mut acquired = self
                    .acquire_client_credentials(client_id, &secret, token_url, deadline)
                    .await
                    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
                acquired.output_guard.merge(&output_guard);
                acquired
            }
            CredentialSource::CredentialProcess { command, .. } => self
                .acquire_credential_process(command, deadline)
                .await
                .map_err(|error| error.with_output_guard(cache_guard.clone()))?,
            CredentialSource::SuppliedEnvironment { .. } => unreachable!("handled above"),
        };
        let mut token = acquired.token;
        let mut output_guard = acquired.output_guard;
        output_guard.merge(&cache_guard);
        ensure_auth_deadline(deadline, "credential_processing")
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        if matches!(self.source, CredentialSource::ClientCredentials { .. }) {
            if let Some(cached) = prior_cached.as_ref() {
                if token.access_token.expose_secret() == cached.access_token.expose_secret() {
                    token.obtained_at = cached.obtained_at;
                    if let (Some(acquired_expiry), Some(cached_expiry)) =
                        (token.expires_at, cached.expires_at)
                    {
                        token.expires_at = Some(acquired_expiry.min(cached_expiry));
                    }
                }
            }
        }
        validate_token_expiry(token.expires_at, Utc::now())
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        if let TokenAcquisition::AfterRejection(rejected) = mode {
            if token.access_token.expose_secret() == rejected.expose_secret() {
                token.reissued_after_rejection = true;
                self.write_cache_until(key, &token, deadline, "token_cache_commit")
                    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
                FileExt::unlock(&lock).map_err(|error| {
                    ReltioError::io("failed to unlock token cache", &error)
                        .with_output_guard(output_guard.clone())
                })?;
                return Err(unchanged_rejected_token_error().with_output_guard(output_guard));
            }
        }
        if persist {
            self.write_cache_until(key, &token, deadline, "token_cache_commit")
                .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        } else {
            ensure_auth_deadline(deadline, "credential_processing")
                .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        }
        FileExt::unlock(&lock).map_err(|error| {
            ReltioError::io("failed to unlock token cache", &error)
                .with_output_guard(output_guard.clone())
        })?;
        let mut access_token = token.into_access_token(false);
        access_token.output_guard.merge(&output_guard);
        Ok(access_token)
    }

    pub async fn persist_access_token(&self, token: &AccessToken) -> Result<()> {
        let deadline = auth_deadline_after(self.timeout)
            .map_err(|error| error.with_output_guard(token.output_guard.clone()))?;
        validate_token_expiry(token.expires_at, Utc::now())
            .map_err(|error| error.with_output_guard(token.output_guard.clone()))?;
        let key = self.source.cache_key().ok_or_else(|| {
            ReltioError::internal("environment access tokens cannot be persisted as provider cache")
        })?;
        let output_guard = token.output_guard.clone();
        let _maintenance = acquire_shared_lock_until(self.maintenance_lock_path(), deadline)
            .await
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let lock = acquire_lock_until(self.lock_path(key), deadline)
            .await
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let cached = CachedToken {
            version: 1,
            provider: token.provider.clone(),
            access_token: token.secret.clone(),
            expires_at: token.expires_at,
            obtained_at: token.obtained_at.unwrap_or_else(Utc::now),
            reissued_after_rejection: false,
        };
        self.write_cache_until(key, &cached, deadline, "token_cache_commit")
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        FileExt::unlock(&lock).map_err(|error| {
            ReltioError::io("failed to unlock token cache", &error).with_output_guard(output_guard)
        })
    }

    pub async fn prepare_managed_login(&self, token: &AccessToken) -> Result<LoginCachePlan> {
        let deadline = auth_deadline_after(self.timeout)
            .map_err(|error| error.with_output_guard(token.output_guard.clone()))?;
        self.prepare_managed_login_until(token, deadline).await
    }

    pub async fn prepare_managed_login_until(
        &self,
        token: &AccessToken,
        deadline: Instant,
    ) -> Result<LoginCachePlan> {
        validate_token_expiry(token.expires_at, Utc::now())
            .map_err(|error| error.with_output_guard(token.output_guard.clone()))?;
        let key = self.source.cache_key().ok_or_else(|| {
            ReltioError::internal("environment access tokens cannot be persisted as provider cache")
        })?;
        let output_guard = token.output_guard.clone();
        let maintenance = acquire_exclusive_lock_until(self.maintenance_lock_path(), deadline)
            .await
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let cached = CachedToken {
            version: 1,
            provider: token.provider.clone(),
            access_token: token.secret.clone(),
            expires_at: token.expires_at,
            obtained_at: token.obtained_at.unwrap_or_else(Utc::now),
            reissued_after_rejection: false,
        };
        ensure_auth_deadline(deadline, "token_cache_snapshot")
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let encoded = encode_cached_token(&cached)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let managed_path = self.cache_path(key);
        LoginCachePlan::new(
            maintenance,
            vec![(managed_path, Some(encoded))],
            output_guard,
            deadline,
        )
    }

    pub async fn prepare_bearer_login(
        cache_dir: &Path,
        profile: &str,
        token: SecretString,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<LoginCachePlan> {
        let deadline = auth_deadline_after(DEFAULT_LOCAL_AUTH_TIMEOUT)?;
        Self::prepare_bearer_login_until(cache_dir, profile, token, expires_at, deadline).await
    }

    pub async fn prepare_bearer_login_until(
        cache_dir: &Path,
        profile: &str,
        token: SecretString,
        expires_at: Option<DateTime<Utc>>,
        deadline: Instant,
    ) -> Result<LoginCachePlan> {
        validate_token(token.expose_secret())?;
        let expires_at = expires_at.ok_or_else(|| {
            ReltioError::usage(
                "bearer_expiry_required",
                "persisted bearer tokens require an explicit expiry",
            )
        })?;
        let output_guard = OutputGuard::from_known_secrets(&[token.expose_secret()]);
        validate_token_expiry(Some(expires_at), Utc::now())
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let manager = Self::cache_only(cache_dir.to_path_buf())?;
        let maintenance = acquire_exclusive_lock_until(manager.maintenance_lock_path(), deadline)
            .await
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_auth_deadline(deadline, "token_cache_snapshot")
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let encoded = encode_cached_token(&CachedToken {
            version: 1,
            provider: "bearer".to_owned(),
            access_token: token,
            expires_at: Some(expires_at),
            obtained_at: Utc::now(),
            reissued_after_rejection: false,
        })
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        LoginCachePlan::new(
            maintenance,
            vec![(
                manager.cache_path(&imported_bearer_key(profile)),
                Some(encoded),
            )],
            output_guard,
            deadline,
        )
    }

    pub fn can_reacquire(&self) -> bool {
        matches!(
            self.source,
            CredentialSource::ClientCredentials { .. } | CredentialSource::CredentialProcess { .. }
        )
    }

    pub fn status(&self) -> Result<TokenStatus> {
        let deadline = auth_deadline_after(self.timeout)?;
        self.status_until(deadline)
    }

    pub fn status_until(&self, deadline: Instant) -> Result<TokenStatus> {
        if matches!(self.source, CredentialSource::SuppliedEnvironment { .. }) {
            return Ok(TokenStatus {
                provider: "bearer".to_owned(),
                source: "environment".to_owned(),
                configured: true,
                cache_state: "not_applicable".to_owned(),
                expires_at: None,
                environment_override: true,
            });
        }
        let key = self.source.cache_key().expect("source has cache key");
        let maintenance_path = self.maintenance_lock_path();
        let maintenance = acquire_shared_lock_until_sync(&maintenance_path, deadline)?;
        let cached = self.read_cache(key);
        let deadline_result = ensure_auth_deadline(deadline, "token_cache");
        let unlock = FileExt::unlock(&maintenance)
            .map_err(|error| ReltioError::io("failed to unlock token cache maintenance", &error));
        let cached = cached?;
        if let Err(error) = deadline_result {
            return Err(if let Some(token) = &cached {
                error.with_output_guard(token.output_guard())
            } else {
                error
            });
        }
        if let Err(error) = unlock {
            return Err(if let Some(token) = &cached {
                error.with_output_guard(token.output_guard())
            } else {
                error
            });
        }
        let (cache_state, expires_at) = match cached {
            Some(token) if token.is_valid() => ("valid", token.expires_at),
            Some(token) => ("expired", token.expires_at),
            None => ("missing", None),
        };
        let (source, environment_override) = match &self.source {
            CredentialSource::ImportedBearer { .. } => ("imported_cache", false),
            CredentialSource::ClientCredentials {
                environment_override,
                ..
            } => ("profile_or_environment", *environment_override),
            CredentialSource::CredentialProcess { .. } => ("profile", false),
            CredentialSource::SuppliedEnvironment { .. } => unreachable!(),
        };
        Ok(TokenStatus {
            provider: self.source.provider().to_owned(),
            source: source.to_owned(),
            configured: true,
            cache_state: cache_state.to_owned(),
            expires_at,
            environment_override,
        })
    }

    /// Credentials already available locally that must not be recreated by
    /// command metadata or other generated output.
    pub fn output_guard(&self) -> Result<OutputGuard> {
        let mut guard = self.environment_output_guard.clone();
        match &self.source {
            CredentialSource::SuppliedEnvironment { token } => {
                guard.merge(&OutputGuard::from_known_secrets(&[token.expose_secret()]));
            }
            CredentialSource::ClientCredentials {
                client_id,
                client_secret,
                secret_file,
                ..
            } => {
                if client_secret.is_some() || secret_file.is_some() {
                    let secret =
                        resolve_client_secret(client_secret.clone(), secret_file.as_deref())
                            .map_err(|error| error.with_output_guard(guard.clone()))?;
                    let basic_credential = base64::engine::general_purpose::STANDARD
                        .encode(format!("{client_id}:{}", secret.expose_secret()));
                    guard.merge(&OutputGuard::from_known_secrets(&[
                        secret.expose_secret(),
                        basic_credential.as_str(),
                    ]));
                }
            }
            CredentialSource::ImportedBearer { .. }
            | CredentialSource::CredentialProcess { .. } => {}
        }
        if let Some(key) = self.source.cache_key() {
            if let Some(token) = self
                .read_cache(key)
                .map_err(|error| error.with_output_guard(guard.clone()))?
            {
                guard.merge(&OutputGuard::from_known_secrets(&[token
                    .access_token
                    .expose_secret()]));
            }
        }
        let cache_guard = Self::cache_output_guard(&self.cache_dir)
            .map_err(|error| error.with_output_guard(guard.clone()))?;
        guard.merge(&cache_guard);
        Ok(guard)
    }

    pub fn cache_output_guard(cache_dir: &Path) -> Result<OutputGuard> {
        let mut guard = OutputGuard::default();
        merge_all_cached_token_guards(cache_dir, &mut guard)?;
        Ok(guard)
    }

    pub fn profile_output_guard(
        target: &ResolvedTarget,
        environment: &Environment,
        cache_dir: &Path,
    ) -> Result<OutputGuard> {
        let mut guard = environment_credential_guard(environment);
        let manager = Self::cache_only(cache_dir.to_path_buf())
            .map_err(|error| error.with_output_guard(guard.clone()))?;
        let mut cache_keys = Vec::new();
        let inferred_client_credentials = environment.contains("RELTIO_CLIENT_ID")
            || environment.contains("RELTIO_CLIENT_SECRET");
        match target
            .auth
            .method
            .or(inferred_client_credentials.then_some(AuthMethod::ClientCredentials))
        {
            Some(AuthMethod::Bearer) => {
                if let Some(profile) = target.profile.as_deref() {
                    cache_keys.push(imported_bearer_key(profile));
                }
            }
            Some(AuthMethod::ClientCredentials) => {
                let mut client_ids = Vec::new();
                if let Some(client_id) = environment.get("RELTIO_CLIENT_ID") {
                    client_ids.push(client_id.to_owned());
                }
                if let Some(client_id) = target.auth.client_id.as_deref() {
                    if !client_ids.iter().any(|current| current == client_id) {
                        client_ids.push(client_id.to_owned());
                    }
                }
                let mut secrets = Vec::new();
                if let Some(secret) = environment.secret("RELTIO_CLIENT_SECRET") {
                    secrets.push(secret);
                }
                if let Some(secret_file) = target.auth.secret_file.as_deref() {
                    let secret = resolve_client_secret(None, Some(secret_file))
                        .map_err(|error| error.with_output_guard(guard.clone()))?;
                    if !secrets.iter().any(|current: &SecretString| {
                        current.expose_secret() == secret.expose_secret()
                    }) {
                        secrets.push(secret);
                    }
                }
                for secret in &secrets {
                    guard.merge(&OutputGuard::from_known_secrets(&[secret.expose_secret()]));
                    for client_id in &client_ids {
                        let basic_credential = base64::engine::general_purpose::STANDARD
                            .encode(format!("{client_id}:{}", secret.expose_secret()));
                        guard.merge(&OutputGuard::from_known_secrets(&[&basic_credential]));
                    }
                }
                if !client_ids.is_empty() {
                    let auth_base = ServiceResolver::new(target.clone())
                        .base_url(Service::Auth)
                        .map_err(|error| error.with_output_guard(guard.clone()))?;
                    let token_url = auth_base.join("oauth/token").map_err(|error| {
                        ReltioError::internal(format!("failed to build token URL: {error}"))
                            .with_output_guard(guard.clone())
                    })?;
                    validate_auth_token_url(&token_url)
                        .map_err(|error| error.with_output_guard(guard.clone()))?;
                    for client_id in client_ids {
                        cache_keys.push(cache_identity(&json!({
                            "version": 2,
                            "provider": "client_credentials",
                            "token_url": token_url,
                            "client_id": client_id
                        })));
                    }
                }
            }
            Some(AuthMethod::CredentialProcess) => {
                if let Some(command) = target.auth.credential_process.as_ref() {
                    cache_keys.push(cache_identity(&json!({
                        "version": 2,
                        "provider": "credential_process",
                        "profile": target.profile,
                        "environment": target.environment,
                        "tenant": target.tenant,
                        "command": command
                    })));
                }
            }
            None => {}
        }
        cache_keys.sort_unstable();
        cache_keys.dedup();
        for cache_key in cache_keys {
            if let Some(token) = manager
                .read_cache_any(&cache_key)
                .map_err(|error| error.with_output_guard(guard.clone()))?
            {
                guard.merge(&token.output_guard());
            }
        }
        merge_all_cached_token_guards(cache_dir, &mut guard)?;
        Ok(guard)
    }

    pub fn redact_local_credentials(
        &self,
        value: &mut Value,
        additional_secrets: &[&str],
    ) -> Result<OutputGuard> {
        let cached = self
            .source
            .cache_key()
            .map(|key| self.read_cache(key))
            .transpose()?
            .flatten();
        let file_secret = match &self.source {
            CredentialSource::ClientCredentials {
                client_secret: None,
                secret_file: Some(path),
                ..
            } => Some(resolve_client_secret(None, Some(path))?),
            _ => None,
        };
        let mut secrets = additional_secrets.to_vec();
        match &self.source {
            CredentialSource::SuppliedEnvironment { token } => {
                secrets.push(token.expose_secret());
            }
            CredentialSource::ClientCredentials {
                client_secret: Some(secret),
                ..
            } => secrets.push(secret.expose_secret()),
            CredentialSource::ImportedBearer { .. }
            | CredentialSource::ClientCredentials { .. }
            | CredentialSource::CredentialProcess { .. } => {}
        }
        if let Some(secret) = &file_secret {
            secrets.push(secret.expose_secret());
        }
        if let Some(token) = &cached {
            secrets.push(token.access_token.expose_secret());
        }
        let outcome = redact_known_secrets_json(value, &secrets);
        if !outcome.is_complete() || sanitize_json_serialization(value, &secrets).is_none() {
            *value = Value::Null;
        }
        let mut output_guard = self.output_guard()?;
        output_guard.merge(&OutputGuard::from_known_secrets(&secrets));
        Ok(output_guard)
    }

    pub fn logout(&self) -> Result<(bool, OutputGuard)> {
        let (removed, guard) = Self::clear_local_cache_with_timeout(&self.cache_dir, self.timeout)?;
        Ok((removed > 0, guard))
    }

    pub fn import_bearer(
        cache_dir: &Path,
        profile: &str,
        token: SecretString,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        Self::import_bearer_with_timeout(
            cache_dir,
            profile,
            token,
            expires_at,
            DEFAULT_LOCAL_AUTH_TIMEOUT,
        )
    }

    pub fn import_bearer_with_timeout(
        cache_dir: &Path,
        profile: &str,
        token: SecretString,
        expires_at: Option<DateTime<Utc>>,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = auth_deadline_after(timeout)?;
        validate_token(token.expose_secret())?;
        let expires_at = expires_at.ok_or_else(|| {
            ReltioError::usage(
                "bearer_expiry_required",
                "persisted bearer tokens require an explicit expiry",
            )
        })?;
        let output_guard = OutputGuard::from_known_secrets(&[token.expose_secret()]);
        validate_token_expiry(Some(expires_at), Utc::now())
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let manager = Self::cache_only(cache_dir.to_path_buf())?;
        let key = imported_bearer_key(profile);
        let maintenance_path = manager.maintenance_lock_path();
        let maintenance = acquire_shared_lock_until_sync(&maintenance_path, deadline)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let result = manager
            .write_cache_until(
                &key,
                &CachedToken {
                    version: 1,
                    provider: "bearer".to_owned(),
                    access_token: token,
                    expires_at: Some(expires_at),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: false,
                },
                deadline,
                "token_cache_commit",
            )
            .map_err(|error| error.with_output_guard(output_guard.clone()));
        FileExt::unlock(&maintenance).map_err(|error| {
            ReltioError::io("failed to unlock token cache", &error).with_output_guard(output_guard)
        })?;
        result
    }

    pub fn prepare_imported_bearer_removal(
        cache_dir: &Path,
        profile: &str,
    ) -> Result<LoginCachePlan> {
        Self::prepare_imported_bearer_removal_with_timeout(
            cache_dir,
            profile,
            DEFAULT_LOCAL_AUTH_TIMEOUT,
        )
    }

    pub fn prepare_imported_bearer_removal_with_timeout(
        cache_dir: &Path,
        profile: &str,
        timeout: Duration,
    ) -> Result<LoginCachePlan> {
        let deadline = auth_deadline_after(timeout)?;
        Self::prepare_imported_bearer_removal_until(
            cache_dir,
            profile,
            deadline,
            &CancellationToken::new(),
        )
    }

    pub fn prepare_imported_bearer_removal_until(
        cache_dir: &Path,
        profile: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<LoginCachePlan> {
        let token_dir = cache_dir.join("tokens");
        let maintenance = acquire_exclusive_lock_until_sync_cancellable(
            &token_dir.join("cache-maintenance.lock"),
            deadline,
            cancellation,
        )
        .map_err(|error| error.with_output_guard(OutputGuard::deny_all()))?;
        let mut output_guard = OutputGuard::default();
        merge_all_cached_token_guards(cache_dir, &mut output_guard)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_auth_deadline(deadline, "token_cache_snapshot")
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let plan = LoginCachePlan::new(
            maintenance,
            vec![(
                token_dir.join(format!("{}.json", imported_bearer_key(profile))),
                None,
            )],
            output_guard,
            deadline,
        )?;
        Ok(plan)
    }

    pub fn clear_local_cache(cache_dir: &Path) -> Result<(usize, OutputGuard)> {
        Self::clear_local_cache_with_timeout(cache_dir, DEFAULT_LOCAL_AUTH_TIMEOUT)
    }

    pub fn clear_local_cache_with_timeout(
        cache_dir: &Path,
        timeout: Duration,
    ) -> Result<(usize, OutputGuard)> {
        let deadline = auth_deadline_after(timeout)?;
        clear_token_cache(cache_dir, deadline, None)
    }

    pub fn clear_local_cache_until(
        cache_dir: &Path,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(usize, OutputGuard)> {
        clear_token_cache(cache_dir, deadline, Some(cancellation))
    }

    fn cache_only(cache_dir: PathBuf) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(|error| ReltioError::internal(format!("failed to create client: {error}")))?;
        Ok(Self {
            source: CredentialSource::ImportedBearer {
                cache_key: String::new(),
            },
            environment_output_guard: OutputGuard::default(),
            cache_dir,
            client,
            timeout: DEFAULT_LOCAL_AUTH_TIMEOUT,
            no_retry: true,
        })
    }

    async fn acquire_client_credentials(
        &self,
        client_id: &str,
        client_secret: &SecretString,
        token_url: &url::Url,
        deadline: Instant,
    ) -> Result<AcquiredToken> {
        ensure_auth_deadline(deadline, "token_request")?;
        let basic_credential = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:{}", client_secret.expose_secret()));
        let mut attempts = 0_u32;
        let mut prior_response_guard = OutputGuard::default();
        let (bytes, attempts, prior_response_guard) = loop {
            self.wait_for_token_rate_limit(token_url, deadline).await?;
            attempts += 1;
            let remaining = auth_remaining(deadline, "token_request")?;
            let sent = tokio::time::timeout(
                remaining,
                self.client
                    .post(token_url.clone())
                    .basic_auth(client_id, Some(client_secret.expose_secret()))
                    .header(reqwest::header::ACCEPT, "application/json")
                    .form(&[("grant_type", "client_credentials")])
                    .send(),
            )
            .await;
            let response = match sent {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    return Err(auth_transport_error(&error)
                        .with_output_guard(prior_response_guard.clone()));
                }
                Err(_) => {
                    return Err(auth_timeout_error("token_request")
                        .with_output_guard(prior_response_guard.clone()));
                }
            };
            let status = response.status();
            let retry_after = crate::http::parse_retry_after(response.headers());
            let remaining = auth_remaining(deadline, "token_response_body")
                .map_err(|error| error.with_output_guard(prior_response_guard.clone()))?;
            let (bytes, body_omitted) =
                match tokio::time::timeout(remaining, read_auth_response(response)).await {
                    Ok(Ok(bytes)) => (bytes, false),
                    Ok(Err(error))
                        if !status.is_success() && error.code == "auth_response_too_large" =>
                    {
                        if let Some(guard) = error.output_guard() {
                            prior_response_guard.merge(guard);
                        }
                        // Uninspected provider bytes cannot safely participate in output.
                        prior_response_guard.merge(&OutputGuard::deny_all());
                        (Vec::new(), true)
                    }
                    Ok(Err(error)) => {
                        return Err(error.with_output_guard(prior_response_guard.clone()));
                    }
                    Err(_) => {
                        let mut guard = prior_response_guard.clone();
                        guard.merge(&OutputGuard::deny_all());
                        return Err(
                            auth_timeout_error("token_response_body").with_output_guard(guard)
                        );
                    }
                };
            let response_guard = if body_omitted {
                OutputGuard::default()
            } else {
                untrusted_json_output_guard(&bytes)
            };
            if status.as_u16() == 429 && !self.no_retry && attempts < 2 {
                prior_response_guard.merge(&response_guard);
                sleep_auth_retry(attempts, retry_after, deadline)
                    .await
                    .map_err(|error| error.with_output_guard(prior_response_guard.clone()))?;
                continue;
            }
            if !status.is_success() {
                let known = [client_secret.expose_secret(), basic_credential.as_str()];
                prior_response_guard.merge(&response_guard);
                prior_response_guard.merge(&OutputGuard::from_known_secrets(&known));
                let mut details = if body_omitted {
                    json!({
                        "body_omitted": true,
                        "reason": "auth_response_too_large"
                    })
                } else {
                    parse_redacted_details(&bytes, &known)
                };
                let outcome = redact_json(&mut details, &known);
                if !outcome.is_complete()
                    || sanitize_json_serialization(&mut details, &known).is_none()
                {
                    details = json!({"body_omitted": true});
                }
                return Err(ReltioError::auth(
                    if status.as_u16() == 429 {
                        "auth_rate_limited"
                    } else {
                        "auth_token_request_failed"
                    },
                    format!("token endpoint returned HTTP {}", status.as_u16()),
                )
                .with_http_status(status.as_u16())
                .with_details(json!({
                    "response": details,
                    "response_body_truncated": body_omitted,
                    "attempts": attempts,
                    "safe_to_replay": true,
                    "practice_id": "AUTH-TOKEN-RETRY-001"
                }))
                .retryable(status.as_u16() == 429)
                .with_hint(if status.as_u16() == 429 {
                    "Reuse cached tokens and retry after the server-provided delay."
                } else {
                    "Check the client ID, secret source, and confidential-client configuration."
                })
                .with_output_guard(prior_response_guard));
            }
            break (bytes, attempts, prior_response_guard);
        };
        let mut parse_guard = prior_response_guard.clone();
        parse_guard.merge(&untrusted_json_output_guard(&bytes));
        ensure_auth_deadline(deadline, "credential_processing")
            .map_err(|error| error.with_output_guard(parse_guard.clone()))?;
        let parsed: TokenResponse = serde_json::from_slice(&bytes).map_err(|error| {
            ReltioError::auth(
                "auth_response_invalid",
                "token endpoint returned an invalid authentication response",
            )
            .with_details(json!({
                "attempts": attempts,
                "parser_category": format!("{:?}", error.classify()).to_ascii_lowercase(),
                "line": error.line(),
                "column": error.column()
            }))
            .with_output_guard(parse_guard.clone())
        })?;
        let mut output_guard = parsed.output_guard();
        output_guard.merge(&parse_guard);
        validate_token(parsed.access_token.expose_secret())
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        validate_refresh_token(parsed.refresh_token.as_ref())
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        if parsed
            .token_type
            .as_deref()
            .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
        {
            return Err(ReltioError::auth(
                "auth_token_type_unsupported",
                "token endpoint returned a non-bearer token",
            )
            .with_output_guard(output_guard));
        }
        let now = Utc::now();
        let expires_at = checked_expiry(now, parsed.expires_in.unwrap_or(3_600).max(0))
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        validate_token_expiry(Some(expires_at), now)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        Ok(AcquiredToken {
            token: CachedToken {
                version: 1,
                provider: "client_credentials".to_owned(),
                access_token: parsed.access_token,
                expires_at: Some(expires_at),
                obtained_at: now,
                reissued_after_rejection: false,
            },
            output_guard,
        })
    }

    async fn wait_for_token_rate_limit(
        &self,
        token_url: &url::Url,
        deadline: Instant,
    ) -> Result<()> {
        let key = cache_key(&format!(
            "token_rate|{}",
            token_url.origin().ascii_serialization()
        ));
        let state_path = self
            .cache_dir
            .join("tokens")
            .join(format!("rate-{key}.json"));
        let lock_path = self
            .cache_dir
            .join("tokens")
            .join(format!("rate-{key}.lock"));
        loop {
            let lock = acquire_rate_lock_until(lock_path.clone(), deadline).await?;
            let now = Utc::now().timestamp_millis();
            let mut state = if let Some(bytes) =
                read_bounded_optional_with_limit(&state_path, true, TOKEN_RATE_STATE_LIMIT)?
            {
                serde_json::from_slice::<TokenRateState>(&bytes).map_err(|error| {
                    ReltioError::auth(
                        "auth_rate_state_invalid",
                        format!("token rate-limit state is invalid: {error}"),
                    )
                })?
            } else {
                TokenRateState::default()
            };
            if state.request_millis.len() > TOKEN_REQUESTS_PER_SECOND {
                return Err(ReltioError::auth(
                    "auth_rate_state_invalid",
                    "token rate-limit state contains too many reservations",
                ));
            }
            if state
                .request_millis
                .iter()
                .any(|timestamp| *timestamp > now.saturating_add(RATE_WINDOW_MILLIS))
            {
                return Err(ReltioError::auth(
                    "auth_rate_state_invalid",
                    "token rate-limit state contains a future timestamp",
                ));
            }
            state
                .request_millis
                .retain(|timestamp| now.saturating_sub(*timestamp) < RATE_WINDOW_MILLIS);
            if state.request_millis.len() < TOKEN_REQUESTS_PER_SECOND {
                ensure_auth_deadline(deadline, "rate_reservation")?;
                state.request_millis.push(now);
                let encoded = serde_json::to_vec(&state).map_err(|error| {
                    ReltioError::internal(format!(
                        "failed to encode token rate-limit state: {error}"
                    ))
                })?;
                if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > TOKEN_RATE_STATE_LIMIT {
                    return Err(ReltioError::internal(
                        "encoded token rate-limit state exceeded its fixed bound",
                    ));
                }
                ensure_auth_deadline(deadline, "rate_reservation")?;
                // This synchronous atomic write is the reservation commit barrier: once
                // started, cancellation cannot report a timeout before the result is known.
                atomic_write_private(&state_path, &encoded)?;
                FileExt::unlock(&lock)
                    .map_err(|error| ReltioError::io("failed to unlock auth rate state", &error))?;
                return Ok(());
            }
            let oldest = state.request_millis.iter().min().copied().unwrap_or(now);
            let wait_millis = oldest
                .saturating_add(RATE_WINDOW_MILLIS)
                .saturating_sub(now)
                .max(1);
            FileExt::unlock(&lock)
                .map_err(|error| ReltioError::io("failed to unlock auth rate state", &error))?;
            drop(lock);
            sleep_with_auth_deadline(
                Duration::from_millis(u64::try_from(wait_millis).unwrap_or(u64::MAX)),
                deadline,
                "rate_limit",
            )
            .await?;
        }
    }

    async fn acquire_credential_process(
        &self,
        command: &[String],
        deadline: Instant,
    ) -> Result<AcquiredToken> {
        validate_process_command(command)?;
        ensure_auth_deadline(deadline, "credential_process")?;
        let executable = Path::new(&command[0]);
        let working_directory = executable.parent().ok_or_else(|| {
            ReltioError::auth(
                "credential_process_invalid",
                "credential process executable has no parent directory",
            )
        })?;
        let mut process = Command::new(executable);
        process
            .args(&command[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .current_dir(working_directory)
            .env_remove("RELTIO_ACCESS_TOKEN")
            .env_remove("RELTIO_CLIENT_SECRET")
            .env_remove("PATH")
            .kill_on_drop(true);
        #[cfg(unix)]
        process.process_group(0);
        #[cfg(unix)]
        for variable in [
            "BASH_ENV",
            "DYLD_FALLBACK_FRAMEWORK_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_IMAGE_SUFFIX",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_PRINT_TO_FILE",
            "DYLD_ROOT_PATH",
            "ENV",
            "GLIBC_TUNABLES",
            "LD_AUDIT",
            "LD_DEBUG",
            "LD_DEBUG_OUTPUT",
            "LD_LIBRARY_PATH",
            "LD_ORIGIN_PATH",
            "LD_PRELOAD",
            "LD_PROFILE",
            "LIBPATH",
            "SHLIB_PATH",
        ] {
            process.env_remove(variable);
        }
        #[cfg(windows)]
        let windows_job = reltio_windows_security::CredentialProcessJob::prepare(&mut process)
            .map_err(|error| credential_process_containment_error(&error))?;
        let spawned = {
            let _executable_guard = validate_private_executable(executable)?;
            ensure_auth_deadline(deadline, "credential_process")?;
            process.spawn()
        };
        let mut child = spawned
            .map_err(|error| ReltioError::io("failed to execute credential process", &error))?;
        let mut process_group = CredentialProcessGroup::new(&child);
        #[cfg(windows)]
        if let Err(error) = process_group.assign_windows_job_and_resume(windows_job, &child) {
            terminate_and_reap_credential_process(&mut child, &mut process_group).await;
            return Err(credential_process_containment_error(&error));
        }
        let Some(stdout) = child.stdout.take() else {
            terminate_and_reap_credential_process(&mut child, &mut process_group).await;
            return Err(
                ReltioError::internal("credential process stdout pipe was not created")
                    .with_output_guard(OutputGuard::deny_all()),
            );
        };
        let remaining = match auth_remaining(deadline, "credential_process") {
            Ok(remaining) => remaining,
            Err(error) => {
                terminate_and_reap_credential_process(&mut child, &mut process_group).await;
                return Err(error.with_output_guard(OutputGuard::deny_all()));
            }
        };
        let completed = tokio::time::timeout(remaining, async {
            let wait = child.wait();
            let read = async move {
                let mut bounded =
                    stdout.take(u64::try_from(AUTH_RESPONSE_LIMIT).unwrap_or(u64::MAX) + 1);
                let mut bytes = Vec::new();
                bounded.read_to_end(&mut bytes).await.map_err(|error| {
                    ReltioError::io("failed to read credential process", &error)
                })?;
                Ok::<Vec<u8>, ReltioError>(bytes)
            };
            tokio::try_join!(
                async {
                    wait.await.map_err(|error| {
                        ReltioError::io("failed to wait for credential process", &error)
                    })
                },
                read
            )
        })
        .await;
        let (status, bytes) = match completed {
            Ok(Ok(completed)) => completed,
            Ok(Err(error)) => {
                terminate_and_reap_credential_process(&mut child, &mut process_group).await;
                return Err(error.with_output_guard(OutputGuard::deny_all()));
            }
            Err(_) => {
                terminate_and_reap_credential_process(&mut child, &mut process_group).await;
                return Err(auth_timeout_error("credential_process")
                    .with_output_guard(OutputGuard::deny_all()));
            }
        };
        process_group.disarm();
        let response_guard = untrusted_json_output_guard(&bytes);
        ensure_auth_deadline(deadline, "credential_processing")
            .map_err(|error| error.with_output_guard(response_guard.clone()))?;
        if bytes.len() > AUTH_RESPONSE_LIMIT {
            return Err(ReltioError::auth(
                "credential_process_output_too_large",
                "credential process output exceeded 1 MB",
            )
            .with_output_guard(response_guard));
        }
        if !status.success() {
            return Err(ReltioError::auth(
                "credential_process_failed",
                format!("credential process exited with {status}"),
            )
            .with_hint("Inspect the credential process directly; its output is withheld to protect secrets.")
            .with_output_guard(response_guard));
        }
        let parsed: CredentialProcessResponse =
            serde_json::from_slice(&bytes).map_err(|error| {
                ReltioError::auth(
                    "credential_process_output_invalid",
                    "credential process did not return the required JSON contract",
                )
                .with_details(json_parse_details(&error))
                .with_output_guard(response_guard.clone())
            })?;
        let mut output_guard = parsed.output_guard();
        output_guard.merge(&response_guard);
        validate_token(parsed.access_token.expose_secret())
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        validate_refresh_token(parsed.refresh_token.as_ref())
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let now = Utc::now();
        let expires_at = parsed
            .expires_at
            .map_or_else(
                || checked_expiry(now, parsed.expires_in.unwrap_or(3_600)),
                Ok,
            )
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        validate_token_expiry(Some(expires_at), now)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        Ok(AcquiredToken {
            token: CachedToken {
                version: 1,
                provider: "credential_process".to_owned(),
                access_token: parsed.access_token,
                expires_at: Some(expires_at),
                obtained_at: now,
                reissued_after_rejection: false,
            },
            output_guard,
        })
    }

    fn read_cache(&self, key: &str) -> Result<Option<CachedToken>> {
        self.read_cache_for_provider(key, Some(self.source.provider()))
    }

    fn read_cache_any(&self, key: &str) -> Result<Option<CachedToken>> {
        self.read_cache_for_provider(key, None)
    }

    fn read_cache_for_provider(
        &self,
        key: &str,
        expected_provider: Option<&str>,
    ) -> Result<Option<CachedToken>> {
        let path = self.cache_path(key);
        let Some(bytes) = read_bounded_optional_with_limit(&path, true, TOKEN_CACHE_LIMIT)? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        decode_cached_token_for_provider(&bytes, expected_provider).map(Some)
    }

    fn write_cache_until(
        &self,
        key: &str,
        token: &CachedToken,
        deadline: Instant,
        stage: &'static str,
    ) -> Result<()> {
        ensure_auth_deadline(deadline, stage)?;
        let encoded = encode_cached_token(token)?;
        ensure_auth_deadline(deadline, stage)?;
        atomic_write_private(&self.cache_path(key), &encoded)
    }

    fn cache_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join("tokens").join(format!("{key}.json"))
    }

    fn lock_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join("tokens").join(format!("{key}.lock"))
    }

    fn maintenance_lock_path(&self) -> PathBuf {
        self.cache_dir.join("tokens").join("cache-maintenance.lock")
    }
}

#[derive(Clone, Copy)]
enum TokenAcquisition<'a> {
    Normal,
    Explicit,
    AfterRejection(&'a AccessToken),
}

#[derive(Debug)]
struct CredentialProcessGroup {
    #[cfg(unix)]
    leader: Option<rustix::process::Pid>,
    #[cfg(windows)]
    windows_job: Option<reltio_windows_security::CredentialProcessJob>,
}

impl CredentialProcessGroup {
    fn new(child: &tokio::process::Child) -> Self {
        #[cfg(unix)]
        {
            let leader = child
                .id()
                .and_then(|id| i32::try_from(id).ok())
                .and_then(rustix::process::Pid::from_raw);
            Self { leader }
        }
        #[cfg(not(unix))]
        {
            let _ = child;
            Self {
                #[cfg(windows)]
                windows_job: None,
            }
        }
    }

    #[cfg(windows)]
    fn assign_windows_job_and_resume(
        &mut self,
        job: reltio_windows_security::CredentialProcessJob,
        child: &tokio::process::Child,
    ) -> std::result::Result<(), reltio_windows_security::Error> {
        self.windows_job = Some(job);
        self.windows_job
            .as_ref()
            .unwrap_or_else(|| unreachable!("the Windows Job was installed above"))
            .assign_and_resume(child)
    }

    fn terminate(&self) {
        #[cfg(unix)]
        if let Some(leader) = self.leader {
            let _ = rustix::process::kill_process_group(leader, rustix::process::Signal::KILL);
        }
        #[cfg(windows)]
        if let Some(job) = &self.windows_job {
            let _ = job.terminate();
        }
    }

    fn disarm(&mut self) {
        #[cfg(unix)]
        {
            self.leader = None;
        }
        #[cfg(windows)]
        {
            self.windows_job = None;
        }
    }
}

#[cfg(windows)]
fn credential_process_containment_error(error: &reltio_windows_security::Error) -> ReltioError {
    ReltioError::new(
        "credential_process_containment_failed",
        ErrorCategory::Safety,
        "the credential process could not be contained before execution",
    )
    .with_details(json!({
        "platform": "windows",
        "reason": format!("{:?}", error.kind()),
        "network_request_sent": false,
        "local_state_committed": false,
        "safe_to_replay": true
    }))
    .with_hint(
        "An enclosing Windows Job may prohibit nested containment. Update the host policy; the CLI will not run the broker uncontained.",
    )
}

impl Drop for CredentialProcessGroup {
    fn drop(&mut self) {
        self.terminate();
    }
}

async fn terminate_and_reap_credential_process(
    child: &mut tokio::process::Child,
    process_group: &mut CredentialProcessGroup,
) {
    process_group.terminate();
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    process_group.disarm();
}

async fn read_auth_response(response: reqwest::Response) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            auth_transport_error(&error).with_output_guard(untrusted_json_output_guard(&bytes))
        })?;
        if bytes.len().saturating_add(chunk.len()) > AUTH_RESPONSE_LIMIT {
            let retained = AUTH_RESPONSE_LIMIT
                .saturating_add(1)
                .saturating_sub(bytes.len())
                .min(chunk.len());
            bytes.extend_from_slice(&chunk[..retained]);
            return Err(ReltioError::auth(
                "auth_response_too_large",
                "authentication response exceeded 1 MB",
            )
            .with_output_guard(untrusted_json_output_guard(&bytes)));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(deserialize_with = "deserialize_secret")]
    access_token: SecretString,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(
        default,
        rename = "refresh_token",
        deserialize_with = "deserialize_optional_secret"
    )]
    refresh_token: Option<SecretString>,
    #[serde(default)]
    _scope: Option<String>,
}

impl TokenResponse {
    fn output_guard(&self) -> OutputGuard {
        response_output_guard(&self.access_token, self.refresh_token.as_ref())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialProcessResponse {
    #[serde(deserialize_with = "deserialize_secret")]
    access_token: SecretString,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    #[serde(rename = "refresh_token")]
    refresh_token: Option<SecretString>,
    #[serde(default)]
    #[serde(rename = "metadata")]
    _metadata: Option<Value>,
}

impl CredentialProcessResponse {
    fn output_guard(&self) -> OutputGuard {
        response_output_guard(&self.access_token, self.refresh_token.as_ref())
    }
}

fn response_output_guard(
    access_token: &SecretString,
    refresh_token: Option<&SecretString>,
) -> OutputGuard {
    let mut secrets = vec![access_token.expose_secret()];
    if let Some(refresh_token) = refresh_token {
        secrets.push(refresh_token.expose_secret());
    }
    OutputGuard::from_known_secrets(&secrets)
}

struct AcquiredToken {
    token: CachedToken,
    output_guard: OutputGuard,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedToken {
    version: u32,
    provider: String,
    #[serde(deserialize_with = "deserialize_secret")]
    access_token: SecretString,
    expires_at: Option<DateTime<Utc>>,
    obtained_at: DateTime<Utc>,
    #[serde(default)]
    reissued_after_rejection: bool,
}

impl CachedToken {
    fn output_guard(&self) -> OutputGuard {
        OutputGuard::from_known_secrets(&[self.access_token.expose_secret()])
    }

    fn is_valid(&self) -> bool {
        self.expires_at.is_some_and(|expires_at| {
            expires_at > Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECONDS)
        })
    }

    fn into_access_token(self, cache_hit: bool) -> AccessToken {
        let output_guard = self.output_guard();
        AccessToken {
            secret: self.access_token,
            output_guard,
            expires_at: self.expires_at,
            provider: self.provider,
            cache_hit,
            obtained_at: Some(self.obtained_at),
        }
    }

    fn replaces_rejected(&self, rejected: &AccessToken) -> bool {
        rejected
            .obtained_at
            .is_some_and(|obtained_at| self.obtained_at > obtained_at)
            || self.access_token.expose_secret() != rejected.expose_secret()
    }
}

#[derive(Serialize)]
struct CachedTokenRef<'a> {
    version: u32,
    provider: &'a str,
    access_token: &'a str,
    expires_at: Option<DateTime<Utc>>,
    obtained_at: DateTime<Utc>,
    reissued_after_rejection: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenRateState {
    request_millis: Vec<i64>,
}

#[derive(Clone, Copy)]
enum AuthLockMode {
    Shared,
    Exclusive,
}

async fn acquire_lock_until(path: PathBuf, deadline: Instant) -> Result<std::fs::File> {
    acquire_file_lock_until(
        path,
        deadline,
        AuthLockMode::Exclusive,
        "failed to lock token cache",
        "token_cache_lock",
    )
    .await
}

async fn acquire_shared_lock_until(path: PathBuf, deadline: Instant) -> Result<std::fs::File> {
    acquire_file_lock_until(
        path,
        deadline,
        AuthLockMode::Shared,
        "failed to lock token cache maintenance",
        "token_cache_maintenance_lock",
    )
    .await
}

async fn acquire_exclusive_lock_until(path: PathBuf, deadline: Instant) -> Result<std::fs::File> {
    acquire_file_lock_until(
        path,
        deadline,
        AuthLockMode::Exclusive,
        "failed to lock token cache maintenance",
        "token_cache_maintenance_lock",
    )
    .await
}

fn acquire_shared_lock_until_sync(path: &Path, deadline: Instant) -> Result<std::fs::File> {
    acquire_file_lock_until_sync(
        path,
        deadline,
        AuthLockMode::Shared,
        "failed to lock token cache maintenance",
        "token_cache_maintenance_lock",
    )
}

fn acquire_exclusive_lock_until_sync(path: &Path, deadline: Instant) -> Result<std::fs::File> {
    acquire_file_lock_until_sync(
        path,
        deadline,
        AuthLockMode::Exclusive,
        "failed to lock token cache maintenance",
        "token_cache_maintenance_lock",
    )
}

fn acquire_exclusive_lock_until_sync_cancellable(
    path: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<std::fs::File> {
    ensure_login_plan_active(deadline, Some(cancellation), "token_cache_maintenance_lock")?;
    let lock = open_private_lock(path)?;
    loop {
        ensure_login_plan_active(deadline, Some(cancellation), "token_cache_maintenance_lock")?;
        match FileExt::try_lock_exclusive(&lock) {
            Ok(()) => return Ok(lock),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = auth_remaining(deadline, "token_cache_maintenance_lock")?;
                thread::sleep(AUTH_LOCK_POLL_INTERVAL.min(remaining));
            }
            Err(error) => {
                return Err(ReltioError::io(
                    "failed to lock token cache maintenance",
                    &error,
                ));
            }
        }
    }
}

async fn acquire_rate_lock_until(path: PathBuf, deadline: Instant) -> Result<std::fs::File> {
    acquire_file_lock_until(
        path,
        deadline,
        AuthLockMode::Exclusive,
        "failed to lock auth rate state",
        "rate_limit_lock",
    )
    .await
}

async fn acquire_file_lock_until(
    path: PathBuf,
    deadline: Instant,
    mode: AuthLockMode,
    io_context: &'static str,
    timeout_stage: &'static str,
) -> Result<std::fs::File> {
    ensure_auth_deadline(deadline, timeout_stage)?;
    let lock = open_private_lock(&path)?;
    loop {
        ensure_auth_deadline(deadline, timeout_stage)?;
        let result = match mode {
            AuthLockMode::Shared => FileExt::try_lock_shared(&lock),
            AuthLockMode::Exclusive => FileExt::try_lock_exclusive(&lock),
        };
        match result {
            Ok(()) => return Ok(lock),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                sleep_with_auth_deadline(AUTH_LOCK_POLL_INTERVAL, deadline, timeout_stage).await?;
            }
            Err(error) => return Err(ReltioError::io(io_context, &error)),
        }
    }
}

fn acquire_file_lock_until_sync(
    path: &Path,
    deadline: Instant,
    mode: AuthLockMode,
    io_context: &'static str,
    timeout_stage: &'static str,
) -> Result<std::fs::File> {
    ensure_auth_deadline(deadline, timeout_stage)?;
    let lock = open_private_lock(path)?;
    loop {
        ensure_auth_deadline(deadline, timeout_stage)?;
        let result = match mode {
            AuthLockMode::Shared => FileExt::try_lock_shared(&lock),
            AuthLockMode::Exclusive => FileExt::try_lock_exclusive(&lock),
        };
        match result {
            Ok(()) => return Ok(lock),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                sleep_with_auth_deadline_sync(AUTH_LOCK_POLL_INTERVAL, deadline, timeout_stage)?;
            }
            Err(error) => return Err(ReltioError::io(io_context, &error)),
        }
    }
}

fn auth_deadline_after(timeout: Duration) -> Result<Instant> {
    if timeout.is_zero() || timeout > MAX_OPERATION_TIMEOUT {
        return Err(ReltioError::usage(
            "invalid_timeout",
            "authentication timeout must be greater than zero and at most 24 hours",
        ));
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ReltioError::usage("invalid_timeout", "authentication timeout is too large"))
}

fn auth_remaining(deadline: Instant, stage: &'static str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(auth_timeout_error(stage))
    } else {
        Ok(remaining)
    }
}

fn ensure_auth_deadline(deadline: Instant, stage: &'static str) -> Result<()> {
    auth_remaining(deadline, stage).map(|_| ())
}

fn ensure_login_plan_active(
    deadline: Instant,
    cancellation: Option<&CancellationToken>,
    stage: &'static str,
) -> Result<()> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Err(auth_canceled_error(stage, false))
    } else {
        ensure_auth_deadline(deadline, stage)
    }
}

async fn sleep_with_auth_deadline(
    delay: Duration,
    deadline: Instant,
    stage: &'static str,
) -> Result<()> {
    let remaining = auth_remaining(deadline, stage)?;
    let bounded = delay.min(remaining);
    tokio::time::sleep(bounded).await;
    if bounded == remaining {
        Err(auth_timeout_error(stage))
    } else {
        ensure_auth_deadline(deadline, stage)
    }
}

fn sleep_with_auth_deadline_sync(
    delay: Duration,
    deadline: Instant,
    stage: &'static str,
) -> Result<()> {
    let remaining = auth_remaining(deadline, stage)?;
    let bounded = delay.min(remaining);
    thread::sleep(bounded);
    if bounded == remaining {
        Err(auth_timeout_error(stage))
    } else {
        ensure_auth_deadline(deadline, stage)
    }
}

fn auth_timeout_error(stage: &'static str) -> ReltioError {
    ReltioError::new(
        "auth_timeout",
        ErrorCategory::Timeout,
        "authentication exceeded the overall timeout",
    )
    .retryable(false)
    .with_details(json!({ "stage": stage }))
}

fn auth_canceled_error(stage: &'static str, local_state_committed: bool) -> ReltioError {
    ReltioError::new(
        "request_canceled",
        ErrorCategory::Canceled,
        "authentication was canceled",
    )
    .with_details(json!({
        "phase": stage,
        "remote_response_received": false,
        "remote_request_completed": Value::Null,
        "remote_operation_completed": Value::Null,
        "remote_operation_state": "authentication_completion_unknown",
        "local_state_committed": local_state_committed,
        "safe_to_replay": false
    }))
}

fn encode_cached_token(token: &CachedToken) -> Result<Zeroizing<Vec<u8>>> {
    validate_token(token.access_token.expose_secret())?;
    let serializable = CachedTokenRef {
        version: token.version,
        provider: &token.provider,
        access_token: token.access_token.expose_secret(),
        expires_at: token.expires_at,
        obtained_at: token.obtained_at,
        reissued_after_rejection: token.reissued_after_rejection,
    };
    let encoded = serde_json::to_vec(&serializable)
        .map_err(|error| ReltioError::internal(format!("failed to encode token cache: {error}")))?;
    validate_cache_image_bound(&encoded)?;
    Ok(Zeroizing::new(encoded))
}

fn decode_cached_token(bytes: &[u8]) -> Result<CachedToken> {
    decode_cached_token_for_provider(bytes, None)
}

fn decode_cached_token_for_provider(
    bytes: &[u8],
    expected_provider: Option<&str>,
) -> Result<CachedToken> {
    validate_cache_image_bound(bytes)?;
    let malformed_guard = malformed_cache_output_guard(bytes);
    let cached: CachedToken = serde_json::from_slice(bytes).map_err(|error| {
        ReltioError::auth("token_cache_invalid", "token cache is invalid")
            .with_details(json_parse_details(&error))
            .with_hint("Run `reltio auth logout`, then authenticate again.")
            .with_output_guard(malformed_guard.clone())
    })?;
    if cached.version != 1 {
        return Err(invalid_cache_integrity_error("unsupported_schema_version")
            .with_output_guard(malformed_guard));
    }
    if !matches!(
        cached.provider.as_str(),
        "bearer" | "client_credentials" | "credential_process"
    ) {
        return Err(invalid_cache_integrity_error("unsupported_provider")
            .with_output_guard(malformed_guard));
    }
    if expected_provider.is_some_and(|expected| cached.provider != expected) {
        return Err(invalid_cache_integrity_error("provider_key_mismatch")
            .with_output_guard(malformed_guard));
    }
    if cached.expires_at.is_none() {
        return Err(
            invalid_cache_integrity_error("missing_expiry").with_output_guard(malformed_guard)
        );
    }
    let output_guard = cached.output_guard();
    validate_token(cached.access_token.expose_secret())
        .map_err(|error| error.with_output_guard(output_guard))?;
    Ok(cached)
}

fn invalid_cache_integrity_error(reason: &'static str) -> ReltioError {
    ReltioError::auth("token_cache_invalid", "token cache is invalid")
        .with_details(json!({"reason": reason}))
        .with_hint("Run `reltio auth logout`, then authenticate again.")
}

fn malformed_cache_output_guard(bytes: &[u8]) -> OutputGuard {
    untrusted_json_output_guard(bytes)
}

fn untrusted_json_output_guard(bytes: &[u8]) -> OutputGuard {
    if bytes.is_empty() {
        return OutputGuard::default();
    }
    let mut strings = Vec::new();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    if (JsonStringCollector {
        strings: &mut strings,
    })
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end())
    .is_err()
    {
        return OutputGuard::deny_all();
    }
    let guard =
        OutputGuard::from_known_secrets(&strings.iter().map(String::as_str).collect::<Vec<_>>());
    strings.zeroize();
    guard
}

struct JsonStringCollector<'a> {
    strings: &'a mut Vec<String>,
}

impl<'de> DeserializeSeed<'de> for JsonStringCollector<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonStringCollector<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        self.strings.push(value.to_owned());
        Ok(())
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        self.strings.push(value);
        Ok(())
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let strings = self.strings;
        while sequence
            .next_element_seed(JsonStringCollector {
                strings: &mut *strings,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let strings = self.strings;
        while map.next_key::<String>()?.is_some() {
            map.next_value_seed(JsonStringCollector {
                strings: &mut *strings,
            })?;
        }
        Ok(())
    }
}

fn merge_cached_token_guard(bytes: &[u8], output_guard: &mut OutputGuard) -> Result<()> {
    let cached = decode_cached_token(bytes)?;
    output_guard.merge(&cached.output_guard());
    Ok(())
}

fn install_cache_image(path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    if let Some(bytes) = bytes {
        validate_cache_image_bound(bytes)?;
        atomic_write_private(path, bytes)
    } else {
        remove_private_file(path).map(|_| ())
    }
}

fn validate_cache_image_bound(bytes: &[u8]) -> Result<()> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > TOKEN_CACHE_LIMIT {
        Err(ReltioError::auth(
            "token_cache_too_large",
            "token cache exceeds the bounded v1 cache-image limit",
        )
        .with_output_guard(OutputGuard::deny_all()))
    } else {
        Ok(())
    }
}

fn cache_plan_commit_error(
    mut error: ReltioError,
    rollback_errors: &[String],
    output_guard: &OutputGuard,
) -> ReltioError {
    if rollback_errors.is_empty() {
        let timeout_stage = error.details.get("stage").cloned();
        let persistence_details = std::mem::take(&mut error.details);
        error.details = json!({
            "persistence": persistence_details,
            "local_cache_restored": true,
            "safe_to_replay": false
        });
        if let Some(stage) = timeout_stage {
            error.details["stage"] = stage;
        }
        return error.with_output_guard(output_guard.clone());
    }
    ReltioError::new(
        "auth_login_cache_rollback_failed",
        ErrorCategory::Internal,
        "authentication cache persistence failed and exact cache rollback did not complete",
    )
    .with_details(json!({
        "persistence_error": error.code,
        "rollback_errors": rollback_errors,
        "local_cache_restored": false,
        "safe_to_replay": false
    }))
    .with_hint(
        "Inspect `reltio auth status`; do not retry login until the reported local cache state is resolved.",
    )
    .with_output_guard(output_guard.clone())
}

fn restore_cache_changes(
    changes_to_restore: &[CacheEntryChange],
    changes_to_verify: &[CacheEntryChange],
) -> Vec<String> {
    let mut errors = changes_to_restore
        .iter()
        .rev()
        .filter_map(|change| {
            let expected = change.before.as_ref().map(|bytes| bytes.as_slice());
            if read_bounded_optional_with_limit(&change.path, true, TOKEN_CACHE_LIMIT)
                .is_ok_and(|actual| actual.as_deref() == expected)
            {
                return None;
            }
            install_cache_image(&change.path, expected)
                .err()
                .map(|error| error.code.clone())
        })
        .collect::<Vec<_>>();
    for change in changes_to_verify {
        let expected = change.before.as_ref().map(|bytes| bytes.as_slice());
        match read_bounded_optional_with_limit(&change.path, true, TOKEN_CACHE_LIMIT) {
            Ok(actual) if actual.as_deref() == expected => {}
            Ok(_) => errors.push("auth_login_cache_restore_mismatch".to_owned()),
            Err(error) => errors.push(error.code.clone()),
        }
    }
    errors
}

fn resolve_client_secret(
    configured: Option<SecretString>,
    secret_file: Option<&Path>,
) -> Result<SecretString> {
    if let Some(secret) = configured {
        validate_client_secret(secret.expose_secret())?;
        return Ok(secret);
    }
    if let Some(path) = secret_file {
        let bytes = Zeroizing::new(read_bounded_with_limit(
            path,
            true,
            u64::try_from(AUTH_RESPONSE_LIMIT).expect("authentication limit fits in u64"),
        )?);
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            ReltioError::auth("client_secret_not_utf8", "client secret file is not UTF-8")
        })?;
        let secret: SecretString = text.trim_end_matches(['\r', '\n']).to_owned().into();
        validate_client_secret(secret.expose_secret())?;
        return Ok(secret);
    }
    Err(ReltioError::auth(
        "client_secret_missing",
        "client credentials authentication needs a client secret",
    )
    .with_hint(
        "Set RELTIO_CLIENT_SECRET, configure an owner-only secret file, or run `reltio auth login`.",
    ))
}

fn validate_client_secret(secret: &str) -> Result<()> {
    if secret.is_empty() || secret.contains(['\r', '\n']) {
        Err(ReltioError::auth(
            "invalid_client_secret",
            "client secret is empty or contains a line break",
        ))
    } else if secret.len() > AUTH_RESPONSE_LIMIT {
        Err(ReltioError::auth(
            "client_secret_too_large",
            "client secret exceeds the 1 MB local safety limit",
        ))
    } else {
        Ok(())
    }
}

fn validate_token(token: &str) -> Result<()> {
    if token.is_empty() || token.contains(['\r', '\n']) {
        Err(ReltioError::auth(
            "invalid_access_token",
            "access token is empty or contains a line break",
        ))
    } else if token.len() > AUTH_RESPONSE_LIMIT {
        Err(ReltioError::auth(
            "access_token_too_large",
            "access token exceeds the 1 MB local safety limit",
        ))
    } else {
        Ok(())
    }
}

fn validate_refresh_token(token: Option<&SecretString>) -> Result<()> {
    let Some(token) = token else {
        return Ok(());
    };
    let token = token.expose_secret();
    if token.is_empty() || token.contains(['\r', '\n']) {
        Err(ReltioError::auth(
            "invalid_refresh_token",
            "refresh token is empty or contains a line break",
        ))
    } else if token.len() > AUTH_RESPONSE_LIMIT {
        Err(ReltioError::auth(
            "refresh_token_too_large",
            "refresh token exceeds the 1 MB local safety limit",
        ))
    } else {
        Ok(())
    }
}

fn checked_expiry(now: DateTime<Utc>, seconds: i64) -> Result<DateTime<Utc>> {
    let duration = TimeDelta::try_seconds(seconds).ok_or_else(|| {
        ReltioError::auth(
            "auth_expiry_invalid",
            "credential provider returned an out-of-range token lifetime",
        )
    })?;
    now.checked_add_signed(duration).ok_or_else(|| {
        ReltioError::auth(
            "auth_expiry_invalid",
            "credential provider returned a token expiry outside the supported date range",
        )
    })
}

fn validate_token_expiry(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Result<()> {
    let Some(expires_at) = expires_at else {
        return Err(ReltioError::auth(
            "auth_token_expiry_missing",
            "persisted access tokens require a declared expiry",
        ));
    };
    if expires_at <= now + TimeDelta::seconds(EXPIRY_SKEW_SECONDS) {
        return Err(ReltioError::auth(
            "auth_token_expiry_too_soon",
            "credential provider returned a token that is already unusable within the local clock-skew window",
        )
        .with_details(json!({
            "expires_at": expires_at,
            "minimum_remaining_seconds": EXPIRY_SKEW_SECONDS
        }))
        .with_hint("Acquire a token with more remaining lifetime before retrying authentication."));
    }
    Ok(())
}

fn validate_process_command(command: &[String]) -> Result<()> {
    if command.is_empty()
        || command
            .iter()
            .any(|argument| argument.is_empty() || argument.contains('\0'))
        || command
            .first()
            .is_some_and(|executable| !Path::new(executable).is_absolute())
        || cfg!(windows)
            && !command.first().is_some_and(|executable| {
                Path::new(executable)
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            })
    {
        Err(ReltioError::auth(
            "credential_process_invalid",
            "credential process requires an absolute private executable path and valid arguments",
        ))
    } else {
        Ok(())
    }
}

fn cache_key(identity: &str) -> String {
    let digest = Sha256::digest(identity.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn cache_identity(identity: &Value) -> String {
    cache_key(&serde_json::to_string(identity).expect("JSON value serialization cannot fail"))
}

fn imported_bearer_key(profile: &str) -> String {
    cache_identity(&json!({
        "version": 2,
        "provider": "bearer",
        "profile": profile
    }))
}

fn merge_all_cached_token_guards(cache_dir: &Path, output_guard: &mut OutputGuard) -> Result<()> {
    let token_dir = cache_dir.join("tokens");
    let entries = match fs::read_dir(&token_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            output_guard.merge(&OutputGuard::deny_all());
            return Err(ReltioError::io("failed to list token cache", &error)
                .with_output_guard(output_guard.clone()));
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                output_guard.merge(&OutputGuard::deny_all());
                return Err(ReltioError::io("failed to inspect token cache", &error)
                    .with_output_guard(output_guard.clone()));
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_private_temporary_name(name) {
            collect_cached_token_guard(&entry.path(), output_guard)?;
            continue;
        }
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if stem.len() != 64 || !stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        collect_cached_token_guard(&entry.path(), output_guard)?;
    }
    Ok(())
}

fn is_private_temporary_name(name: &str) -> bool {
    name.strip_prefix(".reltio-")
        .and_then(|name| name.strip_suffix(".tmp"))
        .is_some_and(|stem| stem.len() == 32 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn clear_token_cache(
    cache_dir: &Path,
    deadline: Instant,
    cancellation: Option<&CancellationToken>,
) -> Result<(usize, OutputGuard)> {
    let token_dir = cache_dir.join("tokens");
    let maintenance_path = token_dir.join("cache-maintenance.lock");
    let mut output_guard = OutputGuard::default();
    let maintenance_result = if let Some(cancellation) = cancellation {
        acquire_exclusive_lock_until_sync_cancellable(&maintenance_path, deadline, cancellation)
    } else {
        acquire_exclusive_lock_until_sync(&maintenance_path, deadline)
    };
    let maintenance = match maintenance_result {
        Ok(maintenance) => maintenance,
        Err(error) => {
            output_guard.merge(&OutputGuard::deny_all());
            return Err(cache_cleanup_error(error, 0, &output_guard));
        }
    };
    let mut removed = 0_usize;
    let entries = match fs::read_dir(&token_dir) {
        Ok(entries) => entries,
        Err(error) => {
            output_guard.merge(&OutputGuard::deny_all());
            return Err(cache_cleanup_error(
                ReltioError::io("failed to list token cache", &error),
                removed,
                &output_guard,
            ));
        }
    };
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                output_guard.merge(&OutputGuard::deny_all());
                return Err(cache_cleanup_error(
                    ReltioError::io("failed to inspect token cache", &error),
                    removed,
                    &output_guard,
                ));
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(".json") {
            if stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                candidates.push(entry.path());
            }
            continue;
        }
        if is_private_temporary_name(name) {
            candidates.push(entry.path());
        }
    }
    if let Err(error) = ensure_login_plan_active(deadline, cancellation, "token_cache_cleanup") {
        output_guard.merge(&OutputGuard::deny_all());
        return Err(cache_cleanup_error(error, removed, &output_guard));
    }
    // Guard every candidate before the first deletion so a partial cleanup
    // failure cannot leave a later cache generation unprotected in diagnostics.
    for path in &candidates {
        if let Err(error) = ensure_login_plan_active(deadline, cancellation, "token_cache_cleanup")
        {
            output_guard.merge(&OutputGuard::deny_all());
            return Err(cache_cleanup_error(error, removed, &output_guard));
        }
        if let Err(error) = collect_cached_token_guard(path, &mut output_guard) {
            return Err(cache_cleanup_error(error, removed, &output_guard));
        }
    }
    if let Err(error) = ensure_login_plan_active(deadline, cancellation, "token_cache_cleanup") {
        return Err(cache_cleanup_error(error, removed, &output_guard));
    }
    for path in &candidates {
        if let Err(error) = ensure_login_plan_active(deadline, cancellation, "token_cache_cleanup")
        {
            return Err(cache_cleanup_error(error, removed, &output_guard));
        }
        match remove_private_file(path) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(error) => {
                return Err(cache_cleanup_error(error, removed, &output_guard));
            }
        }
        if let Err(error) = ensure_login_plan_active(deadline, cancellation, "token_cache_cleanup")
        {
            return Err(cache_cleanup_error(error, removed, &output_guard));
        }
    }
    if let Err(error) = FileExt::unlock(&maintenance) {
        return Err(cache_cleanup_error(
            ReltioError::io("failed to unlock token cache maintenance", &error),
            removed,
            &output_guard,
        ));
    }
    Ok((removed, output_guard))
}

fn cache_cleanup_error(
    mut error: ReltioError,
    removed_before_error: usize,
    output_guard: &OutputGuard,
) -> ReltioError {
    let timeout_stage = error.details.get("stage").cloned();
    let current_removal_committed = error.details["committed"].as_bool() == Some(true)
        && error.details["removed"].as_bool() == Some(true);
    let local_state_committed = removed_before_error > 0 || current_removal_committed;
    let removed = removed_before_error.saturating_add(usize::from(current_removal_committed));
    let cause = std::mem::take(&mut error.details);
    error.details = json!({
        "cleanup": cause,
        "local_cache_entries_removed": removed,
        "local_state_committed": local_state_committed,
        "safe_to_replay": true
    });
    if let Some(stage) = timeout_stage {
        error.details["stage"] = stage;
    }
    error.with_output_guard(output_guard.clone())
}

fn collect_cached_token_guard(path: &Path, output_guard: &mut OutputGuard) -> Result<()> {
    let bytes = match read_bounded_optional_with_limit(path, true, TOKEN_CACHE_LIMIT) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(()),
        Err(error) => {
            output_guard.merge(&OutputGuard::deny_all());
            return Err(error.with_output_guard(output_guard.clone()));
        }
    };
    let bytes = Zeroizing::new(bytes);
    match decode_cached_token(&bytes) {
        Ok(cached) => output_guard.merge(&cached.output_guard()),
        Err(error) => {
            if let Some(guard) = error.output_guard() {
                output_guard.merge(guard);
            } else {
                output_guard.merge(&OutputGuard::deny_all());
            }
        }
    }
    Ok(())
}

fn deserialize_secret<'de, D>(deserializer: D) -> std::result::Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Into::into)
}

fn deserialize_optional_secret<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(Into::into))
}

fn auth_transport_error(error: &reqwest::Error) -> ReltioError {
    ReltioError::new(
        "auth_network_error",
        ErrorCategory::Network,
        format!(
            "authentication request failed: {}",
            redact_text(&error.to_string(), &[])
        ),
    )
    .retryable(false)
    .with_details(json!({
        "attempts": 1,
        "safe_to_replay": true,
        "automatic_retry_permitted": false,
        "practice_id": "AUTH-TOKEN-RETRY-001"
    }))
}

async fn sleep_auth_retry(
    attempts: u32,
    retry_after: Option<Duration>,
    deadline: Instant,
) -> Result<()> {
    let jitter = Duration::from_millis(rand::rng().random_range(0..=250));
    let mut delay = Duration::from_secs(crate::http::backoff_seconds(attempts)) + jitter;
    if let Some(server_delay) = retry_after {
        delay = delay.max(server_delay);
    }
    if delay >= deadline.saturating_duration_since(Instant::now()) {
        return Err(auth_retry_budget_error(attempts));
    }
    tokio::time::sleep(delay).await;
    Ok(())
}

fn auth_retry_budget_error(attempts: u32) -> ReltioError {
    ReltioError::new(
        "auth_retry_budget_exhausted",
        ErrorCategory::Timeout,
        "the next safe token request would exceed the authentication timeout",
    )
    .with_details(json!({
        "attempts": attempts,
        "safe_to_replay": true,
        "practice_id": "AUTH-TOKEN-RETRY-001"
    }))
}

fn unchanged_rejected_token_error() -> ReltioError {
    ReltioError::auth(
        "auth_token_unchanged",
        "the credential provider reissued the access token that Reltio rejected",
    )
    .with_details(json!({
        "safe_to_replay": false,
        "practice_id": "AUTH-TOKEN-CACHE-001"
    }))
    .with_hint(
        "Wait for token rotation or verify the client, tenant access, and identity-provider configuration before retrying.",
    )
}

fn parse_redacted_details(bytes: &[u8], secrets: &[&str]) -> Value {
    let bounded = &bytes[..bytes.len().min(64 * 1024)];
    match serde_json::from_slice::<Value>(bounded) {
        Ok(mut value) => {
            let outcome = redact_json(&mut value, secrets);
            if outcome.is_complete() && sanitize_json_serialization(&mut value, secrets).is_some() {
                value
            } else {
                json!({"body_omitted": true})
            }
        }
        Err(error) => json!({
            "body_omitted": true,
            "reason": "invalid_authentication_json",
            "parser": json_parse_details(&error),
            "truncated": bytes.len() > bounded.len()
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(unix)]
    use std::{fs::Permissions, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::{AuthProfile, ResolvedTarget};

    use super::*;

    fn target(auth_url: &str) -> ResolvedTarget {
        let mut service_urls = BTreeMap::new();
        service_urls.insert(Service::Auth, auth_url.to_owned());
        ResolvedTarget {
            profile: Some("test".to_owned()),
            environment: "http://127.0.0.1".to_owned(),
            tenant: "TestTenant".to_owned(),
            production: false,
            target_overridden: false,
            routing_overridden: false,
            tenant_overridden: false,
            base_url: None,
            service_urls,
            auth: AuthProfile {
                method: Some(AuthMethod::ClientCredentials),
                client_id: Some("client-id".to_owned()),
                ..AuthProfile::default()
            },
            sources: BTreeMap::new(),
        }
    }

    #[cfg(unix)]
    fn copy_private_native_executable(source: &Path, destination: &Path) {
        fs::copy(source, destination).expect("copy native executable");
        #[cfg(target_os = "macos")]
        assert!(
            std::process::Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(destination)
                .status()
                .expect("run ad-hoc code signing")
                .success(),
            "copied macOS executables require a valid ad-hoc signature"
        );
        fs::set_permissions(destination, Permissions::from_mode(0o700))
            .expect("secure native executable");
    }

    #[test]
    fn local_credential_redactor_covers_provider_and_additional_secrets() {
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::from_pairs([(
                "RELTIO_CLIENT_SECRET".to_owned(),
                "configured-client-secret".to_owned(),
            )]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("token manager");
        let mut plan = json!({
            "first": "configured-client-secret",
            "second": "configured-access-token"
        });

        manager
            .redact_local_credentials(&mut plan, &["configured-access-token"])
            .expect("redact local credentials");

        assert_eq!(plan["first"], "[REDACTED]");
        assert_eq!(plan["second"], "[REDACTED]");
    }

    #[test]
    fn prior_profile_guard_covers_basic_and_environment_cache_generations() {
        let directory = tempdir().expect("temporary directory");
        let mut target = target("https://auth.reltio.com");
        target.auth.client_id = Some("zxq".to_owned());
        let basic_environment =
            Environment::from_pairs([("RELTIO_CLIENT_SECRET".to_owned(), "vw".to_owned())]);
        let guard =
            TokenManager::profile_output_guard(&target, &basic_environment, directory.path())
                .expect("profile output guard");
        assert!(!guard.permits(b"enhxOnZ3"));

        let selected_environment = Environment::from_pairs([
            (
                "RELTIO_CLIENT_ID".to_owned(),
                "environment-client".to_owned(),
            ),
            (
                "RELTIO_CLIENT_SECRET".to_owned(),
                "client-secret".to_owned(),
            ),
        ]);
        let manager = TokenManager::from_target(
            &target,
            &selected_environment,
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("environment-selected token manager");
        manager
            .write_cache_until(
                manager.source.cache_key().expect("managed cache key"),
                &CachedToken {
                    version: 1,
                    provider: "client_credentials".to_owned(),
                    access_token: "auth.login".to_owned().into(),
                    expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed environment-selected cache");
        manager
            .write_cache_until(
                &"f".repeat(64),
                &CachedToken {
                    version: 1,
                    provider: "client_credentials".to_owned(),
                    access_token: "stale-generation-token".to_owned().into(),
                    expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed stale cache generation");

        let guard =
            TokenManager::profile_output_guard(&target, &selected_environment, directory.path())
                .expect("profile output guard");
        assert!(!guard.permits(b"auth.login"));
        assert!(!guard.permits(b"stale-generation-token"));
    }

    #[test]
    fn cache_output_guard_covers_orphaned_atomic_token_images() {
        let directory = tempdir().expect("temporary directory");
        let orphan = directory
            .path()
            .join("tokens")
            .join(".reltio-0123456789abcdef0123456789abcdef.tmp");
        let expires_at = Utc::now() + TimeDelta::hours(1);
        let obtained_at = Utc::now();
        atomic_write_private(
            &orphan,
            serde_json::to_string(&json!({
                "version": 1,
                "provider": "bearer",
                "access_token": "orphaned-token-material",
                "expires_at": expires_at,
                "obtained_at": obtained_at,
                "reissued_after_rejection": false
            }))
            .expect("encode orphan")
            .as_bytes(),
        )
        .expect("orphan fixture");

        let guard = TokenManager::cache_output_guard(directory.path()).expect("cache guard");

        assert!(!guard.permits(b"orphaned-token-material"));
    }

    #[test]
    fn cache_output_guard_continues_past_malformed_generations() {
        let directory = tempdir().expect("temporary directory");
        let token_dir = directory.path().join("tokens");
        let expires_at = Utc::now() + TimeDelta::hours(1);
        let obtained_at = Utc::now();
        atomic_write_private(
            &token_dir.join(format!("{}.json", "0".repeat(64))),
            serde_json::to_string(&json!({
                "version": 1,
                "provider": "bearer",
                "access_token": "malformed-generation-secret",
                "expires_at": expires_at,
                "obtained_at": obtained_at,
                "future_secret": "malformed-extension-secret"
            }))
            .expect("encode malformed generation")
            .as_bytes(),
        )
        .expect("malformed generation fixture");
        atomic_write_private(
            &token_dir.join(format!("{}.json", "f".repeat(64))),
            serde_json::to_string(&json!({
                "version": 1,
                "provider": "bearer",
                "access_token": "later-valid-generation-secret",
                "expires_at": expires_at,
                "obtained_at": obtained_at,
                "reissued_after_rejection": false
            }))
            .expect("encode valid generation")
            .as_bytes(),
        )
        .expect("valid generation fixture");

        let guard = TokenManager::cache_output_guard(directory.path())
            .expect("malformed generations are guarded without ending enumeration");

        assert!(!guard.permits(b"malformed-generation-secret"));
        assert!(!guard.permits(b"malformed-extension-secret"));
        assert!(!guard.permits(b"later-valid-generation-secret"));
    }

    #[test]
    fn output_guard_errors_retain_discovered_secret_and_malformed_cache_values() {
        let directory = tempdir().expect("temporary directory");
        let secret_file = directory.path().join("secret");
        atomic_write_private(&secret_file, b"token_cache_invalid").expect("secret file");
        let mut target = target("https://auth.reltio.com");
        target.auth.secret_file = Some(secret_file);
        let manager = TokenManager::from_target(
            &target,
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("token manager");
        let key = manager.source.cache_key().expect("managed cache key");
        atomic_write_private(
            &manager.cache_path(key),
            br#"{"version":1,"provider":"client_credentials","access_token":"auth.login","expires_at":null,"obtained_at":"2026-08-10T00:00:00Z","future_secret":"credential_output_refused"}"#,
        )
        .expect("malformed future cache image");

        let error = manager
            .output_guard()
            .expect_err("unknown cache fields fail closed");

        assert_eq!(error.code, "token_cache_invalid");
        let guard = error.output_guard().expect("error retains output guard");
        assert!(!guard.permits(b"token_cache_invalid"));
        assert!(!guard.permits(b"auth.login"));
        assert!(!guard.permits(b"credential_output_refused"));
    }

    #[test]
    fn malformed_cache_guard_preserves_duplicate_values_and_rejects_unknown_schema() {
        let duplicate = br#"{"version":1,"provider":"bearer","access_token":"token_cache_invalid","access_token":"safe-token","expires_at":"2026-08-11T00:00:00Z","obtained_at":"2026-08-10T00:00:00Z"}"#;
        let Err(error) = decode_cached_token(duplicate) else {
            panic!("duplicate fields must fail closed");
        };
        assert_eq!(error.code, "token_cache_invalid");
        let guard = error.output_guard().expect("malformed cache guard");
        assert!(!guard.permits(b"token_cache_invalid"));
        assert!(!guard.permits(b"safe-token"));

        let unknown_version = br#"{"version":2,"provider":"bearer","access_token":"schema-secret","expires_at":"2026-08-11T00:00:00Z","obtained_at":"2026-08-10T00:00:00Z"}"#;
        let Err(error) = decode_cached_token(unknown_version) else {
            panic!("unknown cache schema versions must fail closed");
        };
        assert_eq!(error.code, "token_cache_invalid");
        assert_eq!(error.details["reason"], "unsupported_schema_version");
        assert!(
            !error
                .output_guard()
                .expect("schema error guard")
                .permits(b"schema-secret")
        );

        let wrong_provider = br#"{"version":1,"provider":"client_credentials","access_token":"provider-secret","expires_at":"2026-08-11T00:00:00Z","obtained_at":"2026-08-10T00:00:00Z"}"#;
        let Err(error) = decode_cached_token_for_provider(wrong_provider, Some("bearer")) else {
            panic!("cache provider must agree with its selected key");
        };
        assert_eq!(error.details["reason"], "provider_key_mismatch");
        assert!(
            !error
                .output_guard()
                .expect("provider error guard")
                .permits(b"provider-secret")
        );
    }

    #[tokio::test]
    async fn managed_login_retains_displaced_bearer_and_restores_exact_preimage() {
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("client-secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(2),
        )
        .expect("token manager");
        TokenManager::import_bearer(
            directory.path(),
            "test",
            "previous-bearer-token".to_owned().into(),
            Some(Utc::now() + TimeDelta::hours(1)),
        )
        .expect("import bearer");
        let managed_key = manager.source.cache_key().expect("managed cache key");
        manager
            .write_cache_until(
                managed_key,
                &CachedToken {
                    version: 1,
                    provider: "client_credentials".to_owned(),
                    access_token: "previous-managed-token".to_owned().into(),
                    expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: true,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed managed cache");
        let managed_path = manager.cache_path(managed_key);
        let managed_before = fs::read(&managed_path).expect("read managed preimage");
        let candidate = AccessToken {
            secret: "candidate-managed-token".to_owned().into(),
            output_guard: OutputGuard::from_known_secrets(&["candidate-managed-token"]),
            expires_at: Some(Utc::now() + TimeDelta::hours(1)),
            provider: "client_credentials".to_owned(),
            cache_hit: false,
            obtained_at: Some(Utc::now()),
        };
        let mut plan = manager
            .prepare_managed_login(&candidate)
            .await
            .expect("prepare cache transaction");
        let bearer_path = manager.cache_path(&imported_bearer_key("test"));

        plan.commit().expect("commit candidate cache");

        assert_eq!(
            decode_cached_token(&fs::read(&bearer_path).expect("read retained bearer"))
                .expect("decode retained bearer")
                .access_token
                .expose_secret(),
            "previous-bearer-token"
        );
        assert_eq!(
            decode_cached_token(&fs::read(&managed_path).expect("read candidate cache"))
                .expect("decode candidate cache")
                .access_token
                .expose_secret(),
            "candidate-managed-token"
        );

        plan.rollback().expect("restore managed preimage");

        assert_eq!(
            fs::read(&managed_path).expect("read restored managed cache"),
            managed_before
        );
        assert_eq!(
            decode_cached_token(&fs::read(&bearer_path).expect("read retained bearer"))
                .expect("decode retained bearer")
                .access_token
                .expose_secret(),
            "previous-bearer-token"
        );
    }

    #[tokio::test]
    async fn managed_login_rollback_is_hidden_from_waiting_token_readers() {
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("client-secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(2),
        )
        .expect("token manager");
        let managed_key = manager.source.cache_key().expect("managed cache key");
        manager
            .write_cache_until(
                managed_key,
                &CachedToken {
                    version: 1,
                    provider: "client_credentials".to_owned(),
                    access_token: "previous-managed-token".to_owned().into(),
                    expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed managed cache");
        let candidate = AccessToken {
            secret: "candidate-managed-token".to_owned().into(),
            output_guard: OutputGuard::from_known_secrets(&["candidate-managed-token"]),
            expires_at: Some(Utc::now() + TimeDelta::hours(1)),
            provider: "client_credentials".to_owned(),
            cache_hit: false,
            obtained_at: Some(Utc::now()),
        };
        let mut plan = manager
            .prepare_managed_login(&candidate)
            .await
            .expect("prepare cache transaction");
        plan.commit().expect("stage candidate cache");
        let waiting_manager = manager.clone();
        let waiting = tokio::spawn(async move { waiting_manager.token(false).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiting.is_finished(),
            "reader must wait for transaction outcome"
        );

        plan.rollback().expect("restore prior generation");
        drop(plan);

        let token = waiting
            .await
            .expect("reader task completes")
            .expect("reader resolves restored cache");
        assert_eq!(token.expose_secret(), "previous-managed-token");
    }

    #[test]
    fn refresh_tokens_reject_empty_line_broken_and_oversized_values() {
        for token in ["", "\r", "\n", "embedded\rline", "embedded\nline"] {
            assert_eq!(
                validate_refresh_token(Some(&SecretString::from(token.to_owned())))
                    .expect_err("invalid refresh token must fail")
                    .code,
                "invalid_refresh_token"
            );
        }
        let maximum = SecretString::from("r".repeat(AUTH_RESPONSE_LIMIT));
        validate_refresh_token(Some(&maximum)).expect("limit-sized refresh token is accepted");
        let oversized = SecretString::from("r".repeat(AUTH_RESPONSE_LIMIT + 1));
        assert_eq!(
            validate_refresh_token(Some(&oversized))
                .expect_err("oversized refresh token must fail")
                .code,
            "refresh_token_too_large"
        );
    }

    #[test]
    fn token_cache_metadata_budget_matches_v1_schema_worst_case() {
        let encoded = serde_json::to_vec(&CachedTokenRef {
            version: u32::MAX,
            provider: "credential_process",
            access_token: "",
            expires_at: Some(DateTime::<Utc>::MAX_UTC),
            obtained_at: DateTime::<Utc>::MAX_UTC,
            reissued_after_rejection: false,
        })
        .expect("encode maximum cache metadata");

        assert_eq!(encoded.len(), TOKEN_CACHE_SCHEMA_METADATA_MAX);
        assert_eq!(TOKEN_CACHE_METADATA_BUDGET, 256);
        assert_eq!(TOKEN_CACHE_LIMIT, 6_291_712);
    }

    #[test]
    fn maximum_plain_token_cache_encoding_round_trips_within_derived_bound() {
        let token = "t".repeat(AUTH_RESPONSE_LIMIT);
        validate_token(&token).expect("a 1 MiB access token remains accepted");
        let cached = CachedToken {
            version: 1,
            provider: "credential_process".to_owned(),
            access_token: token.clone().into(),
            expires_at: Some(Utc::now() + TimeDelta::hours(1)),
            obtained_at: Utc::now(),
            reissued_after_rejection: false,
        };

        let encoded = encode_cached_token(&cached).expect("maximum plain token encodes");

        assert!(
            encoded.len() <= usize::try_from(TOKEN_CACHE_LIMIT).expect("cache limit fits in usize")
        );
        assert!(encoded.len() - AUTH_RESPONSE_LIMIT <= TOKEN_CACHE_METADATA_BUDGET);
        let decoded = decode_cached_token(&encoded).expect("maximum plain token decodes");
        assert!(decoded.access_token.expose_secret() == token);
    }

    #[test]
    fn maximum_json_escaped_token_cache_encoding_round_trips_within_derived_bound() {
        let token = "\0".repeat(AUTH_RESPONSE_LIMIT);
        validate_token(&token).expect("a 1 MiB control-byte token remains accepted");
        let cached = CachedToken {
            version: 1,
            provider: "credential_process".to_owned(),
            access_token: token.clone().into(),
            expires_at: Some(Utc::now() + TimeDelta::hours(1)),
            obtained_at: Utc::now(),
            reissued_after_rejection: true,
        };

        let encoded = encode_cached_token(&cached).expect("maximum escaped token encodes");

        let escaped_token_bytes = AUTH_RESPONSE_LIMIT * MAX_JSON_ESCAPE_BYTES_PER_TOKEN_BYTE;
        assert!(
            encoded.len() <= usize::try_from(TOKEN_CACHE_LIMIT).expect("cache limit fits in usize")
        );
        assert!(encoded.len() - escaped_token_bytes <= TOKEN_CACHE_METADATA_BUDGET);
        let decoded = decode_cached_token(&encoded).expect("maximum escaped token decodes");
        assert!(decoded.access_token.expose_secret() == token);
    }

    #[test]
    fn token_one_byte_over_credential_limit_is_not_cacheable() {
        let cached = CachedToken {
            version: 1,
            provider: "bearer".to_owned(),
            access_token: "t".repeat(AUTH_RESPONSE_LIMIT + 1).into(),
            expires_at: Some(Utc::now() + TimeDelta::hours(1)),
            obtained_at: Utc::now(),
            reissued_after_rejection: false,
        };

        assert_eq!(
            encode_cached_token(&cached)
                .expect_err("a 1 MiB + 1 token must remain rejected")
                .code,
            "access_token_too_large"
        );
    }

    #[tokio::test]
    async fn client_credentials_uses_basic_form_and_cache() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header("authorization", "Basic Y2xpZW50LWlkOnNlY3JldA=="))
            .and(body_string("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": format!("s.{}", "a".repeat(4096)),
                "token_type": "bearer",
                "expires_in": 3600,
                "id_token": "provider-extension-secret"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let first = manager.token(false).await.expect("first token");
        let second = manager.token(false).await.expect("cached token");
        assert_eq!(first.expose_secret(), second.expose_secret());
        assert!(!first.output_guard().permits(b"provider-extension-secret"));
        assert!(!first.cache_hit);
        assert!(second.cache_hit);
    }

    #[tokio::test]
    async fn explicit_login_preserves_reissued_token_lifetime() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "same-opaque-token",
                "token_type": "bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let key = manager.source.cache_key().expect("managed cache key");
        let obtained_at = Utc::now() - TimeDelta::minutes(50);
        let expires_at = obtained_at + TimeDelta::hours(1);
        manager
            .write_cache_until(
                key,
                &CachedToken {
                    version: 1,
                    provider: "client_credentials".to_owned(),
                    access_token: "same-opaque-token".to_owned().into(),
                    expires_at: Some(expires_at),
                    obtained_at,
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed original token generation");

        let token = manager
            .acquire_for_login()
            .await
            .expect("explicit login token");

        assert!(!token.cache_hit);
        assert_eq!(token.obtained_at, Some(obtained_at));
        assert_eq!(token.expires_at, Some(expires_at));

        let mut plan = manager
            .prepare_managed_login(&token)
            .await
            .expect("prepare login cache");
        plan.commit().expect("commit login cache");
        let cached = manager
            .read_cache(key)
            .expect("read committed cache")
            .expect("committed token");
        assert_eq!(cached.obtained_at, obtained_at);
        assert_eq!(cached.expires_at, Some(expires_at));
    }

    #[tokio::test]
    async fn token_deadline_bounds_maintenance_lock_wait() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let held = open_private_lock(&manager.maintenance_lock_path()).expect("maintenance lock");
        FileExt::try_lock_exclusive(&held).expect("hold maintenance lock");
        let started = Instant::now();
        let deadline = started + Duration::from_millis(500);

        let error = manager
            .token_until(false, deadline)
            .await
            .expect_err("maintenance contention must honor the deadline");
        let elapsed = started.elapsed();
        FileExt::unlock(&held).expect("release maintenance lock");

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "token_cache_maintenance_lock");
        assert!(elapsed < Duration::from_secs(2), "elapsed: {elapsed:?}");
    }

    #[tokio::test]
    async fn token_deadline_bounds_per_entry_lock_wait() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let key = manager.source.cache_key().expect("managed cache key");
        let held = open_private_lock(&manager.lock_path(key)).expect("per-entry lock");
        FileExt::try_lock_exclusive(&held).expect("hold per-entry lock");
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);

        let error = acquire_lock_until(manager.lock_path(key), deadline)
            .await
            .expect_err("entry contention must honor the deadline");
        let elapsed = started.elapsed();
        FileExt::unlock(&held).expect("release per-entry lock");

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "token_cache_lock");
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
    }

    #[test]
    fn status_deadline_bounds_synchronous_maintenance_lock_wait() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_millis(50),
        )
        .expect("manager");
        let held = open_private_lock(&manager.maintenance_lock_path()).expect("maintenance lock");
        FileExt::try_lock_exclusive(&held).expect("hold maintenance lock");
        let started = Instant::now();

        let error = manager
            .status()
            .expect_err("status contention must honor the configured timeout");
        let elapsed = started.elapsed();
        FileExt::unlock(&held).expect("release maintenance lock");

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "token_cache_maintenance_lock");
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
    }

    #[test]
    fn imported_bearer_lock_timeout_has_no_late_cache_mutation() {
        let directory = tempdir().expect("temp dir");
        let token_dir = directory.path().join("tokens");
        let maintenance =
            open_private_lock(&token_dir.join("cache-maintenance.lock")).expect("maintenance lock");
        FileExt::try_lock_exclusive(&maintenance).expect("hold maintenance lock");
        let cache_path = token_dir.join(format!("{}.json", imported_bearer_key("test")));
        let started = Instant::now();

        let error = TokenManager::import_bearer_with_timeout(
            directory.path(),
            "test",
            "candidate-bearer-token".to_owned().into(),
            Some(Utc::now() + TimeDelta::hours(1)),
            Duration::from_millis(50),
        )
        .expect_err("import contention must honor the supplied timeout");
        let elapsed = started.elapsed();
        FileExt::unlock(&maintenance).expect("release maintenance lock");
        thread::sleep(Duration::from_millis(100));

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "token_cache_maintenance_lock");
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
        assert!(!cache_path.exists(), "timed-out import mutated cache later");
        assert!(
            !error
                .output_guard()
                .expect("candidate output guard")
                .permits(b"candidate-bearer-token")
        );
    }

    #[test]
    fn cache_cleanup_lock_timeout_preserves_exact_cache_preimage() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::cache_only(directory.path().to_path_buf()).expect("manager");
        let key = "a".repeat(64);
        manager
            .write_cache_until(
                &key,
                &CachedToken {
                    version: 1,
                    provider: "bearer".to_owned(),
                    access_token: "cleanup-preimage-token".to_owned().into(),
                    expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed token cache");
        let cache_path = manager.cache_path(&key);
        let before = fs::read(&cache_path).expect("cache preimage");
        let held = open_private_lock(&manager.maintenance_lock_path()).expect("maintenance lock");
        FileExt::try_lock_shared(&held).expect("hold maintenance lock");
        let started = Instant::now();

        let error = TokenManager::clear_local_cache_with_timeout(
            directory.path(),
            Duration::from_millis(50),
        )
        .expect_err("cleanup contention must honor the supplied timeout");
        let elapsed = started.elapsed();
        FileExt::unlock(&held).expect("release maintenance lock");
        thread::sleep(Duration::from_millis(100));

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "token_cache_maintenance_lock");
        assert_eq!(error.details["local_cache_entries_removed"], 0);
        assert_eq!(error.details["local_state_committed"], false);
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
        assert_eq!(fs::read(cache_path).expect("unchanged cache"), before);
    }

    #[test]
    fn profile_removal_lock_timeout_preserves_exact_cache_preimage() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::cache_only(directory.path().to_path_buf()).expect("manager");
        let key = imported_bearer_key("test");
        manager
            .write_cache_until(
                &key,
                &CachedToken {
                    version: 1,
                    provider: "bearer".to_owned(),
                    access_token: "profile-removal-preimage".to_owned().into(),
                    expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed imported bearer cache");
        let cache_path = manager.cache_path(&key);
        let before = fs::read(&cache_path).expect("cache preimage");
        let held = open_private_lock(&manager.maintenance_lock_path()).expect("maintenance lock");
        FileExt::try_lock_shared(&held).expect("hold maintenance lock");
        let started = Instant::now();

        let error = TokenManager::prepare_imported_bearer_removal_with_timeout(
            directory.path(),
            "test",
            Duration::from_millis(50),
        )
        .expect_err("profile-removal contention must honor the supplied timeout");
        let elapsed = started.elapsed();
        FileExt::unlock(&held).expect("release maintenance lock");
        thread::sleep(Duration::from_millis(100));

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "token_cache_maintenance_lock");
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
        assert_eq!(fs::read(cache_path).expect("unchanged cache"), before);
    }

    #[test]
    fn profile_removal_plan_refuses_deletion_after_its_deadline() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::cache_only(directory.path().to_path_buf()).expect("manager");
        let key = imported_bearer_key("test");
        manager
            .write_cache_until(
                &key,
                &CachedToken {
                    version: 1,
                    provider: "bearer".to_owned(),
                    access_token: "delayed-removal-preimage".to_owned().into(),
                    expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                    obtained_at: Utc::now(),
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed imported bearer cache");
        let cache_path = manager.cache_path(&key);
        let before = fs::read(&cache_path).expect("cache preimage");
        let mut plan = TokenManager::prepare_imported_bearer_removal_with_timeout(
            directory.path(),
            "test",
            Duration::from_secs(2),
        )
        .expect("prepare profile-removal cache plan");
        plan.deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("past deadline");

        let error = plan
            .commit()
            .expect_err("expired plan must not delete cached credentials");

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "token_cache_commit");
        assert_eq!(error.details["local_cache_restored"], true);
        assert_eq!(fs::read(cache_path).expect("unchanged cache"), before);
    }

    #[tokio::test]
    async fn rate_lock_timeout_has_no_late_state_mutation() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let CredentialSource::ClientCredentials { token_url, .. } = &manager.source else {
            panic!("client-credentials source");
        };
        let key = cache_key(&format!(
            "token_rate|{}",
            token_url.origin().ascii_serialization()
        ));
        let token_dir = directory.path().join("tokens");
        let state_path = token_dir.join(format!("rate-{key}.json"));
        let lock_path = token_dir.join(format!("rate-{key}.lock"));
        let held = open_private_lock(&lock_path).expect("rate lock");
        FileExt::try_lock_exclusive(&held).expect("hold rate lock");
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);

        let error = manager
            .wait_for_token_rate_limit(token_url, deadline)
            .await
            .expect_err("rate contention must honor the deadline");
        let elapsed = started.elapsed();
        FileExt::unlock(&held).expect("release rate lock");
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(error.code, "auth_timeout");
        assert_eq!(error.details["stage"], "rate_limit_lock");
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
        assert!(
            !state_path.exists(),
            "a timed-out lock poll must not mutate rate state later"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_managers_singleflight_token_acquisition() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "opaque-token",
                "token_type": "bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let acquisitions = (0..20).map(|_| {
            let manager = manager.clone();
            tokio::spawn(async move { manager.token(false).await })
        });
        for acquisition in futures_util::future::join_all(acquisitions).await {
            assert_eq!(
                acquisition
                    .expect("task completed")
                    .expect("token acquired")
                    .expose_secret(),
                "opaque-token"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_rejections_stop_when_the_provider_reissues_the_same_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "same-opaque-token",
                "token_type": "bearer",
                "expires_in": 3600
            })))
            .expect(2)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let rejected = manager.token(false).await.expect("initial token");
        let refreshes = (0..20).map(|_| {
            let manager = manager.clone();
            let rejected = rejected.clone();
            tokio::spawn(async move { manager.token_after_rejection(&rejected).await })
        });
        for refresh in futures_util::future::join_all(refreshes).await {
            assert_eq!(
                refresh
                    .expect("task completed")
                    .expect_err("an unchanged rejected token must not be replayed")
                    .code,
                "auth_token_unchanged"
            );
        }
        let rejected_again = manager.token(false).await.expect("marked cached token");
        assert_eq!(
            manager
                .token_after_rejection(&rejected_again)
                .await
                .expect_err("the marked generation must not reacquire")
                .code,
            "auth_token_unchanged"
        );
    }

    #[test]
    fn client_credential_status_reports_environment_override() {
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target("https://auth.reltio.com"),
            &Environment::from_pairs([
                (
                    "RELTIO_CLIENT_ID".to_owned(),
                    "environment-client".to_owned(),
                ),
                ("RELTIO_CLIENT_SECRET".to_owned(), "secret".to_owned()),
            ]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(5),
        )
        .expect("manager");

        let status = manager.status().expect("status");

        assert_eq!(status.source, "profile_or_environment");
        assert!(status.environment_override);
    }

    #[tokio::test]
    async fn expired_cache_is_reacquired() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "fresh-token",
                "token_type": "bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let key = manager.source.cache_key().expect("managed cache key");
        manager
            .write_cache_until(
                key,
                &CachedToken {
                    version: 1,
                    provider: "client_credentials".to_owned(),
                    access_token: "expired-token".to_owned().into(),
                    expires_at: Some(Utc::now() - TimeDelta::seconds(1)),
                    obtained_at: Utc::now() - TimeDelta::hours(1),
                    reissued_after_rejection: false,
                },
                Instant::now() + Duration::from_secs(5),
                "test_cache_seed",
            )
            .expect("seed expired cache");

        let first = manager
            .token(false)
            .await
            .expect("expired token reacquired");
        let second = manager.token(false).await.expect("fresh token cached");

        assert_eq!(first.expose_secret(), "fresh-token");
        assert_eq!(second.expose_secret(), "fresh-token");
        assert!(second.cache_hit);
    }

    #[tokio::test]
    async fn provider_token_inside_expiry_skew_is_rejected_without_cache() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "auth_token_expiry_too_soon",
                "token_type": "bearer",
                "expires_in": EXPIRY_SKEW_SECONDS
            })))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");
        let key = manager.source.cache_key().expect("managed cache key");

        let error = manager
            .token(false)
            .await
            .expect_err("unusable provider token must be rejected");

        assert_eq!(error.code, "auth_token_expiry_too_soon");
        assert!(
            !error
                .output_guard()
                .expect("candidate guard")
                .permits(b"auth_token_expiry_too_soon")
        );
        assert!(manager.read_cache(key).expect("read cache").is_none());
    }

    #[tokio::test]
    async fn malformed_token_response_guards_duplicate_candidate_values() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                br#"{"access_token":"auth_response_invalid","access_token":"safe-token","token_type":"bearer","expires_in":3600}"#
                    .as_slice(),
                "application/json",
            ))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let error = manager
            .token(false)
            .await
            .expect_err("duplicate candidate fields must fail closed");

        assert_eq!(error.code, "auth_response_invalid");
        let guard = error.output_guard().expect("raw provider guard");
        assert!(!guard.permits(b"auth_response_invalid"));
        assert!(!guard.permits(b"safe-token"));
    }

    #[tokio::test]
    async fn oversized_auth_response_is_rejected_while_streaming() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; AUTH_RESPONSE_LIMIT + 1]),
            )
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let error = manager
            .token(false)
            .await
            .expect_err("oversized response must fail");

        assert_eq!(error.code, "auth_response_too_large");
    }

    #[tokio::test]
    async fn token_endpoint_does_not_retry_non_rate_limit_failures() {
        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let response_attempts = Arc::clone(&attempts);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                response_attempts.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(503).insert_header("retry-after", "0")
            })
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let error = manager
            .token(false)
            .await
            .expect_err("non-rate-limit token failure must not retry");

        assert_eq!(error.http_status, Some(503));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn token_endpoint_retries_rate_limit_once() {
        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let response_attempts = Arc::clone(&attempts);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                if response_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(429).insert_header("retry-after", "0")
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "access_token": "rate-limit-retry-token",
                        "token_type": "bearer",
                        "expires_in": 3600
                    }))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let token = manager.token(false).await.expect("429 retries once");

        assert_eq!(token.expose_secret(), "rate-limit-retry-token");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn oversized_token_rate_limit_response_does_not_suppress_replay() {
        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let response_attempts = Arc::clone(&attempts);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                if response_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(429)
                        .insert_header("retry-after", "0")
                        .set_body_bytes(vec![b'x'; AUTH_RESPONSE_LIMIT + 1])
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "access_token": "oversized-rate-limit-retry-token",
                        "token_type": "bearer",
                        "expires_in": 3600
                    }))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let token = manager.token(false).await.expect("429 retries once");

        assert_eq!(token.expose_secret(), "oversized-rate-limit-retry-token");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(!token.output_guard().permits(b"originating command output"));
    }

    #[tokio::test]
    async fn repeated_oversized_token_rate_limit_preserves_terminal_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "0")
                    .set_body_bytes(vec![b'x'; AUTH_RESPONSE_LIMIT + 1]),
            )
            .expect(2)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let error = manager
            .token(false)
            .await
            .expect_err("second 429 must remain rate limited");

        assert_eq!(error.code, "auth_rate_limited");
        assert_eq!(error.http_status, Some(429));
        assert_eq!(error.details["attempts"], 2);
        assert_eq!(error.details["response_body_truncated"], true);
        assert_eq!(
            error.details["response"]["reason"],
            "auth_response_too_large"
        );
        assert!(
            !error
                .output_guard()
                .expect("provider response guard")
                .permits(b"originating command output")
        );
    }

    #[tokio::test]
    async fn no_retry_disables_token_rate_limit_replay() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: true,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let error = manager
            .token(false)
            .await
            .expect_err("--no-retry behavior must make one attempt");

        assert_eq!(error.code, "auth_rate_limited");
        assert_eq!(error.details["attempts"], 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn token_rate_limit_is_shared_across_cache_keys() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "rate-limited-token",
                "token_type": "bearer",
                "expires_in": 3600
            })))
            .expect(11)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let started = Instant::now();
        let managers = (0..11)
            .map(|index| {
                let mut distinct = target(&server.uri());
                distinct.auth.client_id = Some(format!("client-{index}"));
                TokenManager::from_target(
                    &distinct,
                    &Environment::default(),
                    directory.path().to_path_buf(),
                    TokenManagerOptions {
                        client_secret: Some("secret".to_owned().into()),
                        no_retry: false,
                    },
                    Duration::from_secs(5),
                )
                .expect("manager")
            })
            .map(|manager| tokio::spawn(async move { manager.token(false).await }));
        for acquisition in futures_util::future::join_all(managers).await {
            acquisition
                .expect("task completed")
                .expect("token acquired");
        }
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "the eleventh request must wait for the shared one-second window"
        );
    }

    #[tokio::test]
    async fn auth_error_redacts_the_complete_basic_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string("proxy echoed Basic Y2xpZW50LWlkOnN1cGVyLXNlY3JldA=="),
            )
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&server.uri()),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("super-secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(5),
        )
        .expect("manager");

        let error = manager.token(false).await.expect_err("request must fail");
        let rendered = serde_json::to_string(&error).expect("error serializes");

        assert!(!rendered.contains("Y2xpZW50LWlkOnN1cGVyLXNlY3JldA"));
        assert!(!rendered.contains("super-secret"));
        assert_eq!(error.details["response"]["body_omitted"], true);
    }

    #[test]
    fn malformed_authentication_json_never_echoes_escaped_credentials() {
        let details = parse_redacted_details(
            br#"{"message":"client\u002dsecret","access_token":"upstream-secret"#,
            &["client-secret"],
        );
        let rendered = details.to_string();
        assert_eq!(details["body_omitted"], true);
        assert!(!rendered.contains("client\\u002dsecret"));
        assert!(!rendered.contains("upstream-secret"));
    }

    #[test]
    fn credential_process_contract_accepts_documented_optional_fields() {
        let parsed: CredentialProcessResponse = serde_json::from_value(json!({
            "access_token": "opaque-token",
            "expires_in": 3600,
            "refresh_token": "ignored-refresh-token",
            "metadata": {"issuer": "broker"}
        }))
        .expect("documented contract parses");
        assert_eq!(parsed.access_token.expose_secret(), "opaque-token");
        let guard = parsed.output_guard();
        assert!(!guard.permits(b"opaque-token"));
        assert!(!guard.permits(b"ignored-refresh-token"));
    }

    #[cfg(windows)]
    #[test]
    fn credential_process_requires_an_explicit_windows_executable_extension() {
        for command in [
            vec![r"C:\private\broker".to_owned()],
            vec![r"C:\private\broker.cmd".to_owned()],
            vec![r"C:\private\broker.bat".to_owned()],
        ] {
            assert_eq!(
                validate_process_command(&command)
                    .expect_err("Windows executable resolution must be unambiguous")
                    .code,
                "credential_process_invalid"
            );
        }
        validate_process_command(&[r"C:\private\broker.EXE".to_owned()])
            .expect("explicit .exe paths are accepted");
    }

    #[test]
    fn credential_process_cache_identity_preserves_argument_boundaries_and_target() {
        let directory = tempdir().expect("temp dir");
        let broker = directory
            .path()
            .join("broker")
            .to_string_lossy()
            .into_owned();
        let mut first_target = target("https://auth.reltio.com");
        first_target.auth = AuthProfile {
            method: Some(AuthMethod::CredentialProcess),
            credential_process: Some(vec![broker.clone(), "x".to_owned(), "y".to_owned()]),
            ..AuthProfile::default()
        };
        let mut second_target = first_target.clone();
        second_target.auth.credential_process = Some(vec![broker, "x\u{1f}y".to_owned()]);
        let first = TokenManager::from_target(
            &first_target,
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(5),
        )
        .expect("first manager");
        let second = TokenManager::from_target(
            &second_target,
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(5),
        )
        .expect("second manager");
        assert_ne!(first.source.cache_key(), second.source.cache_key());

        second_target.tenant = "OtherTenant".to_owned();
        let other_target = TokenManager::from_target(
            &second_target,
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(5),
        )
        .expect("other-target manager");
        assert_ne!(second.source.cache_key(), other_target.source.cache_key());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn credential_process_executes_a_private_absolute_file_and_bounds_failures() {
        let directory = tempdir().expect("temp dir");
        let native_shell = directory.path().join("private-sh");
        copy_private_native_executable(Path::new("/bin/sh"), &native_shell);
        let expected_working_directory = fs::canonicalize(directory.path()).expect("canonical cwd");
        let manager_for = |body: &str, cache: &str, timeout: Duration| {
            let mut broker_target = target("https://auth.reltio.com");
            broker_target.profile = Some(cache.to_owned());
            broker_target.auth = AuthProfile {
                method: Some(AuthMethod::CredentialProcess),
                credential_process: Some(vec![
                    native_shell.to_string_lossy().into_owned(),
                    "-c".to_owned(),
                    body.to_owned(),
                    "private-broker".to_owned(),
                    expected_working_directory.to_string_lossy().into_owned(),
                ]),
                ..AuthProfile::default()
            };
            TokenManager::from_target(
                &broker_target,
                &Environment::default(),
                directory.path().join(cache),
                TokenManagerOptions::default(),
                timeout,
            )
            .expect("credential-process manager")
        };

        let valid = r#"if [ "$(pwd)" != "$1" ]; then printf '%s' '{"access_token":"cwd-invalid","expires_in":3600}'; else printf '%s' '{"access_token":"broker-token","expires_in":3600,"metadata":{"id_token":"broker-extension-secret"}}'; fi"#;
        let token = manager_for(valid, "valid", Duration::from_secs(2))
            .token(false)
            .await
            .expect("broker token");
        assert_eq!(token.expose_secret(), "broker-token");
        assert!(!token.output_guard().permits(b"broker-extension-secret"));
        let malformed_error = manager_for(
            r#"printf '%s' '{"access_token":"secret-parser-fragment"'"#,
            "malformed",
            Duration::from_secs(2),
        )
        .token(false)
        .await
        .expect_err("malformed output");
        assert_eq!(malformed_error.code, "credential_process_output_invalid");
        assert!(
            !serde_json::to_string(&malformed_error)
                .expect("error JSON")
                .contains("secret-parser-fragment")
        );
        assert!(
            !malformed_error
                .output_guard()
                .expect("malformed output fails closed")
                .permits(b"unrelated-output")
        );
        let unknown_field_error = manager_for(
            r#"printf '%s' '{"access_token":"credential_process_output_invalid","unexpected":true}'"#,
            "unknown-field",
            Duration::from_secs(2),
        )
        .token(false)
        .await
        .expect_err("unknown provider fields must fail closed");
        assert_eq!(
            unknown_field_error.code,
            "credential_process_output_invalid"
        );
        assert!(
            !unknown_field_error
                .output_guard()
                .expect("pre-parse provider guard")
                .permits(b"credential_process_output_invalid")
        );
        let expiry_error = manager_for(
            r#"printf '%s' '{"access_token":"broker-token","refresh_token":"range","expires_in":9223372036854775807}'"#,
            "invalid-expiry",
            Duration::from_secs(2),
        )
        .token(false)
        .await
        .expect_err("invalid expiry");
        assert_eq!(expiry_error.code, "auth_expiry_invalid");
        let rendered = serde_json::to_vec(&expiry_error).expect("error JSON");
        assert!(
            rendered
                .windows(b"range".len())
                .any(|bytes| bytes == b"range")
        );
        assert!(
            !expiry_error
                .output_guard()
                .expect("credential-process response guard")
                .permits(&rendered)
        );
        assert_eq!(
            manager_for("exit 23", "failed", Duration::from_secs(2))
                .token(false)
                .await
                .expect_err("failed process")
                .code,
            "credential_process_failed"
        );
        let started = Instant::now();
        let timeout_error = manager_for("exec /bin/sleep 1", "slow", Duration::from_millis(50))
            .token(false)
            .await
            .expect_err("slow process");
        assert_eq!(timeout_error.code, "auth_timeout");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "timed-out credential child was not killed and reaped promptly"
        );

        let descendant_marker = directory.path().join("descendant-survived");
        let descendant_error = manager_for(
            "(sleep 1; printf descendant > descendant-survived) & wait",
            "descendant",
            Duration::from_millis(50),
        )
        .token(false)
        .await
        .expect_err("credential-process descendants must be terminated on timeout");
        assert_eq!(descendant_error.code, "auth_timeout");
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(
            !descendant_marker.exists(),
            "a timed-out credential-process descendant remained alive"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn credential_process_refuses_direct_and_env_shebangs_without_spawning() {
        let directory = tempdir().expect("temp dir");
        for (name, shebang) in [
            ("direct-script", "#!/bin/sh"),
            ("env-script", "#!/usr/bin/env sh"),
        ] {
            let marker = directory.path().join(format!("{name}.spawned"));
            let script = directory.path().join(name);
            fs::write(
                &script,
                format!(
                    "{shebang}\nprintf spawned > \"{}\"\nprintf '%s' '{{\"access_token\":\"unexpected\",\"expires_in\":3600}}'\n",
                    marker.display()
                ),
            )
            .expect("write refused broker script");
            fs::set_permissions(&script, Permissions::from_mode(0o700))
                .expect("secure refused broker script");
            let mut broker_target = target("https://auth.reltio.com");
            broker_target.profile = Some(name.to_owned());
            broker_target.auth = AuthProfile {
                method: Some(AuthMethod::CredentialProcess),
                credential_process: Some(vec![script.to_string_lossy().into_owned()]),
                ..AuthProfile::default()
            };
            let manager = TokenManager::from_target(
                &broker_target,
                &Environment::default(),
                directory.path().join(format!("{name}-cache")),
                TokenManagerOptions::default(),
                Duration::from_secs(2),
            )
            .expect("credential-process manager");

            let error = manager
                .token(false)
                .await
                .expect_err("shebang scripts must be refused before spawn");

            assert_eq!(error.code, "credential_process_script_refused");
            assert!(!marker.exists(), "refused script unexpectedly spawned");
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn credential_process_uses_guarded_directory_without_inherited_path() {
        let directory = tempdir().expect("temporary directory");
        let parent = directory.path().join("broker-directory");
        let broker = parent.join("broker.exe");
        let command_interpreter = PathBuf::from(
            std::env::var_os("SystemRoot").expect("Windows SystemRoot environment variable"),
        )
        .join("System32")
        .join("cmd.exe");
        let bytes = fs::read(command_interpreter).expect("read system command interpreter");
        atomic_write_private(&broker, &bytes).expect("private broker PE");
        let expected_directory = parent.to_string_lossy();
        let contract = format!(
            r#"if defined PATH (echo {{"access_token":"path-present","expires_in":3600}}) else if /I "%CD%"=="{expected_directory}" (echo {{"access_token":"broker-token","expires_in":3600}}) else (echo {{"access_token":"cwd-invalid","expires_in":3600}})"#
        );
        let mut broker_target = target("https://auth.reltio.com");
        broker_target.auth = AuthProfile {
            method: Some(AuthMethod::CredentialProcess),
            credential_process: Some(vec![
                broker.to_string_lossy().into_owned(),
                "/D".to_owned(),
                "/S".to_owned(),
                "/C".to_owned(),
                contract,
            ]),
            ..AuthProfile::default()
        };
        let manager = TokenManager::from_target(
            &broker_target,
            &Environment::default(),
            directory.path().join("cache"),
            TokenManagerOptions::default(),
            Duration::from_secs(5),
        )
        .expect("credential-process manager");

        let token = manager.token(false).await.expect("broker token");
        assert_eq!(token.expose_secret(), "broker-token");
    }

    #[tokio::test]
    async fn token_transport_failure_is_not_advertised_as_retryable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().expect("listener address");
        let resetter = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("local connection");
            drop(connection);
        });
        let directory = tempdir().expect("temp dir");
        let manager = TokenManager::from_target(
            &target(&format!("http://{address}")),
            &Environment::default(),
            directory.path().to_path_buf(),
            TokenManagerOptions {
                client_secret: Some("secret".to_owned().into()),
                no_retry: false,
            },
            Duration::from_secs(2),
        )
        .expect("manager");

        let error = manager
            .token(false)
            .await
            .expect_err("connection must fail");
        resetter.await.expect("reset task");
        assert_eq!(error.code, "auth_network_error");
        assert!(!error.retryable);
        assert_eq!(error.details["automatic_retry_permitted"], false);
    }

    #[test]
    fn logout_removes_verified_orphaned_private_temporaries() {
        let directory = tempdir().expect("temp dir");
        let token_dir = directory.path().join("tokens");
        let orphan = token_dir.join(".reltio-0123456789abcdef0123456789abcdef.tmp");
        atomic_write_private(&orphan, b"orphaned-token-material").expect("orphan fixture");

        assert_eq!(
            TokenManager::clear_local_cache(directory.path()).unwrap().0,
            1
        );
        assert!(!orphan.exists());
    }

    #[test]
    fn cache_cleanup_errors_preserve_partial_and_current_commit_state() {
        let source = std::io::Error::other("injected durability failure");
        let error = ReltioError::io("failed to sync cache cleanup", &source)
            .with_details(json!({ "committed": true, "removed": true }));

        let normalized = cache_cleanup_error(error, 2, &OutputGuard::default());

        assert_eq!(normalized.details["local_cache_entries_removed"], 3);
        assert_eq!(normalized.details["local_state_committed"], true);
        assert_eq!(normalized.details["safe_to_replay"], true);
    }
}
