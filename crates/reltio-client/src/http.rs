use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use futures_util::StreamExt;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode, redirect::Policy};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

use crate::auth::{AccessToken, TokenManager};
use crate::cancellation::CancellationToken;
use crate::error::{ErrorCategory, ReltioError, Result};
use crate::redaction::{
    OutputGuard, contains_known_secret, redact_bytes, redact_json, redact_known_secrets_json,
    redact_response_json, redact_text, sanitize_json_compact_serialization,
    sanitize_json_serialization, sensitive_header,
};
use crate::registry::ReplayPolicy;
use crate::{MAX_OPERATION_TIMEOUT, MAX_POST_BODY_BYTES};

const ERROR_BODY_LIMIT: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_STRUCTURAL_TOKENS: usize = 100_000;

struct ResponseBodyContext<'a> {
    deadline: Instant,
    operation: &'a str,
    attempts: u32,
    replay_safe: bool,
    status: u16,
    request_id: Option<String>,
    cancellation: &'a CancellationToken,
    output_guard: &'a OutputGuard,
}

struct AuthPhaseContext<'a> {
    request: &'a RequestSpec,
    attempts: u32,
    cancellation_state: RemoteCancellationState,
    output_guard: &'a OutputGuard,
}

#[derive(Clone)]
enum RemoteCancellationState {
    RequestNotSent,
    RequestSentCompletionUnknown,
    ResponseReceived {
        status: u16,
        request_id: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub no_retry: bool,
    pub max_response_bytes: usize,
    /// Primarily useful for deterministic contract tests. Production leaves this uncapped.
    pub retry_delay_cap: Option<Duration>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            no_retry: false,
            max_response_bytes: 32 * 1024 * 1024,
            retry_delay_cap: None,
        }
    }
}

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    options: HttpOptions,
    cancellation: CancellationToken,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpClient")
            .field("options", &self.options)
            .field("cancellation", &self.cancellation)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
    pub replay: ReplayPolicy,
    pub operation: String,
    pub practice_ids: Vec<String>,
}

impl RequestSpec {
    pub fn new(method: Method, url: Url, operation: impl Into<String>) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            replay: ReplayPolicy::Unsafe,
            operation: operation.into(),
            practice_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    #[serde(skip)]
    body: Vec<u8>,
    pub content_type: Option<String>,
    #[serde(skip)]
    declared_json: Option<bool>,
    pub request_id: Option<String>,
    pub attempts: u32,
    pub elapsed_ms: u128,
    pub applied_practice_ids: Vec<String>,
    #[serde(skip)]
    redaction_secrets: Vec<SecretString>,
}

impl ApiResponse {
    pub fn output_guard(&self) -> OutputGuard {
        OutputGuard::new(self.redaction_secrets.clone())
    }

    pub fn json(&self) -> Result<Value> {
        let known_secrets = self.known_secrets();
        let mut value = secure_json_value(&self.body).map_err(|error| self.json_error(&error))?;
        if !redact_known_secrets_json(&mut value, &known_secrets).is_complete() {
            return Err(self.redaction_error("redacted_key_collision_limit_exceeded"));
        }
        sanitize_json_serialization(&mut value, &known_secrets)
            .ok_or_else(|| self.redaction_error("serialized_value_could_not_be_sanitized"))?;
        Ok(value)
    }

    pub fn data_value(&self) -> Result<Value> {
        let known_secrets = self.known_secrets();
        if self.body.is_empty() {
            return Ok(Value::Null);
        }
        if self.expects_json() {
            let mut value =
                secure_json_value(&self.body).map_err(|error| self.json_error(&error))?;
            if !redact_response_json(&mut value, &known_secrets).is_complete() {
                return Err(self.redaction_error("redacted_key_collision_limit_exceeded"));
            }
            sanitize_json_serialization(&mut value, &known_secrets)
                .ok_or_else(|| self.redaction_error("serialized_value_could_not_be_sanitized"))?;
            return Ok(value);
        }
        if std::str::from_utf8(&self.body).is_ok() {
            let redacted = redact_bytes(&self.body, &known_secrets);
            Ok(Value::String(String::from_utf8(redacted).unwrap_or_else(
                |_| unreachable!("UTF-8 plus ASCII replacements is UTF-8"),
            )))
        } else {
            Ok(json!({
                "encoding": "base64",
                "data": base64::engine::general_purpose::STANDARD.encode(
                    redact_bytes(&self.body, &known_secrets)
                )
            }))
        }
    }

    pub fn redacted_body(&self) -> Result<Vec<u8>> {
        let known_secrets = self.known_secrets();
        if self.body.is_empty() {
            return Ok(Vec::new());
        }
        if !self.expects_json() {
            return Ok(redact_bytes(&self.body, &known_secrets));
        }
        let mut value = secure_json_value(&self.body).map_err(|error| self.json_error(&error))?;
        let outcome = redact_response_json(&mut value, &known_secrets);
        if !outcome.is_complete() {
            return Err(self.redaction_error("redacted_key_collision_limit_exceeded"));
        }
        if !outcome.was_changed() && !contains_known_secret(&self.body, &known_secrets) {
            return Ok(self.body.clone());
        }
        sanitize_json_compact_serialization(&mut value, &known_secrets)
            .ok_or_else(|| self.redaction_error("serialized_value_could_not_be_sanitized"))?;
        let sanitized = serde_json::to_vec(&value).map_err(|error| {
            ReltioError::internal(format!("failed to serialize a sanitized response: {error}"))
        })?;
        if sanitized.len() > self.body.len() {
            Ok(Vec::new())
        } else {
            Ok(sanitized)
        }
    }

    fn known_secrets(&self) -> Vec<&str> {
        self.redaction_secrets
            .iter()
            .map(ExposeSecret::expose_secret)
            .collect()
    }

    fn expects_json(&self) -> bool {
        self.declared_json
            .unwrap_or_else(|| looks_like_json(&self.body))
    }

    fn json_error(&self, error: &SecureJsonError) -> ReltioError {
        let details = match error {
            SecureJsonError::Structural(reason) => json!({
                "content_type": self.content_type,
                "reason": reason
            }),
            SecureJsonError::Parse(error) => json!({
                "content_type": self.content_type,
                "reason": "invalid_or_unsupported_json",
                "parser_category": format!("{:?}", error.classify()).to_ascii_lowercase(),
                "line": error.line(),
                "column": error.column()
            }),
        };
        ReltioError::new(
            "api_response_invalid_json",
            ErrorCategory::Api,
            "Reltio returned JSON that could not be sanitized safely",
        )
        .with_http_status(self.status)
        .with_request_id(self.request_id.clone())
        .with_details(details)
        .with_output_guard(self.output_guard())
    }

    fn redaction_error(&self, reason: &'static str) -> ReltioError {
        ReltioError::new(
            "api_response_redaction_failed",
            ErrorCategory::Api,
            "Reltio returned data that could not be sanitized safely",
        )
        .with_http_status(self.status)
        .with_request_id(self.request_id.clone())
        .with_details(json!({"reason": reason}))
        .with_output_guard(self.output_guard())
    }
}

fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|content_type| {
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        media_type == "application/json" || media_type.ends_with("+json")
    })
}

fn looks_like_json(body: &[u8]) -> bool {
    body.iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'{' | b'['))
}

#[derive(Debug)]
enum SecureJsonError {
    Structural(&'static str),
    Parse(serde_json::Error),
}

fn secure_json_value(bytes: &[u8]) -> std::result::Result<Value, SecureJsonError> {
    inspect_json_structure(bytes).map_err(SecureJsonError::Structural)?;
    serde_json::from_slice(bytes).map_err(SecureJsonError::Parse)
}

fn inspect_json_structure(bytes: &[u8]) -> std::result::Result<(), &'static str> {
    enum Container {
        Object(BTreeSet<String>),
        Array,
    }

    let mut containers = Vec::<Container>::new();
    let mut offset = 0_usize;
    let mut structural_tokens = 0_usize;
    while offset < bytes.len() {
        match bytes[offset] {
            b'{' => {
                structural_tokens += 1;
                containers.push(Container::Object(BTreeSet::new()));
                if containers.len() > MAX_JSON_DEPTH {
                    return Err("json_nesting_limit_exceeded");
                }
                offset += 1;
            }
            b'[' => {
                structural_tokens += 1;
                containers.push(Container::Array);
                if containers.len() > MAX_JSON_DEPTH {
                    return Err("json_nesting_limit_exceeded");
                }
                offset += 1;
            }
            b'}' | b']' => {
                containers.pop();
                offset += 1;
            }
            b',' | b':' => {
                structural_tokens += 1;
                offset += 1;
            }
            b'"' => {
                let Some(end) = json_string_end(bytes, offset) else {
                    return Ok(());
                };
                let next = bytes[end + 1..]
                    .iter()
                    .find(|byte| !byte.is_ascii_whitespace());
                if next == Some(&b':') {
                    let Some(Container::Object(keys)) = containers.last_mut() else {
                        return Ok(());
                    };
                    let Ok(key) = serde_json::from_slice::<String>(&bytes[offset..=end]) else {
                        return Ok(());
                    };
                    if !keys.insert(key) {
                        return Err("duplicate_json_key_refused");
                    }
                }
                offset = end + 1;
            }
            _ => offset += 1,
        }
        if structural_tokens > MAX_JSON_STRUCTURAL_TOKENS {
            return Err("json_complexity_limit_exceeded");
        }
    }
    Ok(())
}

fn json_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut offset = start + 1;
    while offset < bytes.len() {
        match bytes[offset] {
            b'"' => return Some(offset),
            b'\\' => offset = offset.saturating_add(2),
            _ => offset += 1,
        }
    }
    None
}

impl HttpClient {
    pub fn new(options: HttpOptions) -> Result<Self> {
        Self::new_with_cancellation(options, CancellationToken::default())
    }

    pub fn new_with_cancellation(
        options: HttpOptions,
        cancellation: CancellationToken,
    ) -> Result<Self> {
        if options.timeout.is_zero()
            || options.connect_timeout.is_zero()
            || options.timeout > MAX_OPERATION_TIMEOUT
            || options.connect_timeout > MAX_OPERATION_TIMEOUT
        {
            return Err(ReltioError::usage(
                "invalid_timeout",
                "timeouts must be greater than zero and at most 24 hours",
            ));
        }
        if options.max_response_bytes == 0 {
            return Err(ReltioError::usage(
                "invalid_response_limit",
                "maximum response size must be greater than zero",
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(options.connect_timeout)
            .user_agent(concat!("reltio-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                ReltioError::internal(format!("failed to create HTTP client: {error}"))
            })?;
        Ok(Self {
            client,
            options,
            cancellation,
        })
    }

    pub async fn execute(
        &self,
        token_manager: &TokenManager,
        request: RequestSpec,
    ) -> Result<ApiResponse> {
        let deadline = Instant::now()
            .checked_add(self.options.timeout)
            .ok_or_else(|| ReltioError::usage("invalid_timeout", "request timeout is too large"))?;
        self.execute_until(token_manager, request, deadline).await
    }

    /// Execute within both the client's per-request timeout and a caller-owned deadline.
    pub async fn execute_until(
        &self,
        token_manager: &TokenManager,
        request: RequestSpec,
        caller_deadline: Instant,
    ) -> Result<ApiResponse> {
        if !request.url.username().is_empty() || request.url.password().is_some() {
            return Err(ReltioError::new(
                "url_credentials_refused",
                ErrorCategory::Safety,
                "embedded URL credentials are not allowed",
            ));
        }
        if request.headers.contains_key(reqwest::header::AUTHORIZATION) {
            return Err(ReltioError::new(
                "protected_header_refused",
                ErrorCategory::Safety,
                "Authorization is controlled by the CLI and cannot be overridden",
            ));
        }
        validate_body_size(
            &request.method,
            request.body.as_deref().map_or(0, <[u8]>::len),
        )?;
        let started = Instant::now();
        let client_deadline = started
            .checked_add(self.options.timeout)
            .ok_or_else(|| ReltioError::usage("invalid_timeout", "request timeout is too large"))?;
        let deadline = caller_deadline.min(client_deadline);
        let mut attempts = 0_u32;
        let mut auth_replayed = false;
        let mut cumulative_output_guard = token_manager.output_guard()?;
        self.ensure_not_cancelled(
            &request,
            attempts,
            "before_authentication",
            RemoteCancellationState::RequestNotSent,
            &cumulative_output_guard,
        )?;
        let mut token = self
            .token_before_deadline(
                token_manager,
                deadline,
                &request,
                attempts,
                &cumulative_output_guard,
            )
            .await?;
        let mut used_tokens = Vec::<SecretString>::new();
        cumulative_output_guard.append_secrets_to(&mut used_tokens);

        loop {
            token.output_guard().append_secrets_to(&mut used_tokens);
            cumulative_output_guard.merge(token.output_guard());
            self.ensure_not_cancelled(
                &request,
                attempts,
                "before_send",
                RemoteCancellationState::RequestNotSent,
                &cumulative_output_guard,
            )?;
            let known_tokens = used_tokens
                .iter()
                .map(ExposeSecret::expose_secret)
                .collect::<Vec<_>>();
            attempts += 1;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(
                    timeout_error(&request.operation, attempts, true, "before_send")
                        .with_output_guard(cumulative_output_guard.clone()),
                );
            }
            let mut builder = self
                .client
                .request(request.method.clone(), request.url.clone())
                .headers(request.headers.clone())
                .bearer_auth(token.expose_secret());
            if let Some(body) = &request.body {
                builder = builder.body(body.clone());
            }

            self.ensure_not_cancelled(
                &request,
                attempts,
                "before_send",
                RemoteCancellationState::RequestNotSent,
                &cumulative_output_guard,
            )?;
            let response_future = builder.send();
            tokio::pin!(response_future);
            let send_outcome = tokio::select! {
                biased;
                result = &mut response_future => Some(result),
                () = self.cancellation.cancelled() => None,
                () = tokio::time::sleep(remaining) => {
                    let error = timeout_error(
                        &request.operation,
                        attempts,
                        request.replay != ReplayPolicy::Unsafe,
                        "send",
                    );
                    let error = if request.replay == ReplayPolicy::Unsafe {
                        ambiguous_outcome_error(error, None)
                    } else {
                        error
                    };
                    return Err(error.with_output_guard(cumulative_output_guard.clone()));
                }
            };
            let Some(send_result) = send_outcome else {
                return Err(request_canceled_error(
                    &request.operation,
                    attempts,
                    request.replay != ReplayPolicy::Unsafe,
                    "send",
                    RemoteCancellationState::RequestSentCompletionUnknown,
                )
                .with_output_guard(cumulative_output_guard.clone()));
            };
            let response = match send_result {
                Ok(response) => response,
                Err(error) => {
                    self.ensure_not_cancelled(
                        &request,
                        attempts,
                        "send",
                        RemoteCancellationState::RequestSentCompletionUnknown,
                        &cumulative_output_guard,
                    )?;
                    if self.should_retry_transport(&request, attempts, &error) {
                        self.sleep_before_retry(
                            attempts,
                            None,
                            deadline,
                            &request,
                            RemoteCancellationState::RequestSentCompletionUnknown,
                            &cumulative_output_guard,
                        )
                        .await?;
                        continue;
                    }
                    return Err(transport_error(
                        &request.operation,
                        attempts,
                        request.replay,
                        &error,
                    )
                    .with_output_guard(cumulative_output_guard.clone()));
                }
            };

            let status = response.status();
            let request_id = request_id(response.headers(), &known_tokens);
            let response_state = RemoteCancellationState::ResponseReceived {
                status: status.as_u16(),
                request_id: request_id.clone(),
            };
            self.ensure_not_cancelled(
                &request,
                attempts,
                "response_headers",
                response_state.clone(),
                &cumulative_output_guard,
            )?;
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| redact_text(value, &known_tokens));
                let error = ReltioError::new(
                    "redirect_refused",
                    ErrorCategory::Safety,
                    "Reltio response requested a redirect; authorization was not forwarded",
                )
                .with_http_status(status.as_u16())
                .with_request_id(request_id.clone())
                .with_details(json!({
                    "location": location
                }));
                let error = response_outcome_error(
                    error,
                    status.as_u16(),
                    request_id,
                    request.replay != ReplayPolicy::Unsafe,
                    "redirect_response_received_completion_unknown",
                );
                return Err(error.with_output_guard(cumulative_output_guard.clone()));
            }

            if status == StatusCode::UNAUTHORIZED
                && !auth_replayed
                && !self.options.no_retry
                && request.replay != ReplayPolicy::Unsafe
                && token_manager.can_reacquire()
            {
                auth_replayed = true;
                drop(response);
                token = self
                    .token_after_rejection_before_deadline(
                        token_manager,
                        &token,
                        deadline,
                        AuthPhaseContext {
                            request: &request,
                            attempts,
                            cancellation_state: response_state,
                            output_guard: &cumulative_output_guard,
                        },
                    )
                    .await?;
                continue;
            }

            if !status.is_success() && self.should_retry_status(&request, status, attempts) {
                let retry_after = parse_retry_after(response.headers());
                // Diagnostic body limits must not suppress a status-qualified retry.
                drop(response);
                self.sleep_before_retry(
                    attempts,
                    retry_after,
                    deadline,
                    &request,
                    response_state,
                    &cumulative_output_guard,
                )
                .await?;
                continue;
            }

            self.ensure_not_cancelled(
                &request,
                attempts,
                "response_headers",
                response_state.clone(),
                &cumulative_output_guard,
            )?;
            let headers = sanitized_headers(response.headers(), &known_tokens).map_err(|mut error| {
                let replay_safe = request.replay != ReplayPolicy::Unsafe;
                error.retryable = false;
                if !replay_safe {
                    error.hint = Some(
                        "Do not replay automatically: a remote response was received before output sanitization failed. Verify the operation using the request ID."
                            .to_owned(),
                    );
                }
                response_outcome_error(
                    error,
                    status.as_u16(),
                    request_id.clone(),
                    replay_safe,
                    response_operation_state(status.as_u16()),
                )
                .with_output_guard(cumulative_output_guard.clone())
            })?;
            let original_content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            let content_type = original_content_type
                .as_deref()
                .and_then(|value| sanitized_structured_text(value, &known_tokens));
            let declared_json = original_content_type
                .as_deref()
                .map(|value| is_json_content_type(Some(value)));
            let body_limit = if status.is_success() {
                self.options.max_response_bytes
            } else {
                ERROR_BODY_LIMIT
            };
            let (body, body_truncated) = read_response_body(
                response,
                body_limit,
                !status.is_success(),
                ResponseBodyContext {
                    deadline,
                    operation: &request.operation,
                    attempts,
                    replay_safe: request.replay != ReplayPolicy::Unsafe,
                    status: status.as_u16(),
                    request_id: request_id.clone(),
                    cancellation: &self.cancellation,
                    output_guard: &cumulative_output_guard,
                },
            )
            .await?;
            self.ensure_not_cancelled(
                &request,
                attempts,
                "response_body",
                response_state,
                &cumulative_output_guard,
            )?;
            if !status.is_success() {
                let mut error = api_error(
                    status,
                    request_id,
                    &body,
                    original_content_type.as_deref(),
                    &known_tokens,
                    request.replay != ReplayPolicy::Unsafe,
                    attempts,
                );
                error.details["response_body_truncated"] = Value::Bool(body_truncated);
                if body_truncated {
                    error.details["response"] = json!({
                        "body_omitted": true,
                        "content_type": content_type,
                        "reason": "response_body_too_large"
                    });
                }
                return Err(error.with_output_guard(cumulative_output_guard.clone()));
            }
            return Ok(ApiResponse {
                status: status.as_u16(),
                headers,
                body,
                content_type,
                declared_json,
                request_id,
                attempts,
                elapsed_ms: started.elapsed().as_millis(),
                applied_practice_ids: request.practice_ids,
                redaction_secrets: used_tokens,
            });
        }
    }

    async fn token_before_deadline(
        &self,
        token_manager: &TokenManager,
        deadline: Instant,
        request: &RequestSpec,
        attempts: u32,
        output_guard: &OutputGuard,
    ) -> Result<AccessToken> {
        self.ensure_not_cancelled(
            request,
            attempts,
            "authentication",
            RemoteCancellationState::RequestNotSent,
            output_guard,
        )?;
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Err(
                timeout_error(&request.operation, attempts, true, "authentication")
                    .with_output_guard(output_guard.clone()),
            );
        }
        let acquisition = token_manager.token_until(false, deadline);
        tokio::pin!(acquisition);
        tokio::select! {
            biased;
            result = &mut acquisition => result.map_err(|error| {
                target_auth_error(error, &request.operation, attempts)
                    .with_output_guard(output_guard.clone())
            }),
            () = self.cancellation.cancelled() => {
                let mut cancellation_guard = output_guard.clone();
                if token_manager.can_reacquire() {
                    cancellation_guard.merge(&OutputGuard::deny_all());
                }
                Err(request_canceled_error(
                    &request.operation,
                    attempts,
                    true,
                    "authentication",
                    RemoteCancellationState::RequestNotSent,
                )
                .with_output_guard(cancellation_guard))
            },
        }
    }

    async fn token_after_rejection_before_deadline(
        &self,
        token_manager: &TokenManager,
        rejected: &AccessToken,
        deadline: Instant,
        context: AuthPhaseContext<'_>,
    ) -> Result<AccessToken> {
        self.ensure_not_cancelled(
            context.request,
            context.attempts,
            "authentication",
            context.cancellation_state.clone(),
            context.output_guard,
        )?;
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Err(timeout_error(
                &context.request.operation,
                context.attempts,
                context.request.replay != ReplayPolicy::Unsafe,
                "authentication",
            )
            .with_output_guard(context.output_guard.clone()));
        }
        let acquisition = token_manager.token_after_rejection_until(rejected, deadline);
        tokio::pin!(acquisition);
        tokio::select! {
            biased;
            result = &mut acquisition => result.map_err(|error| {
                target_auth_error(error, &context.request.operation, context.attempts)
                    .with_output_guard(context.output_guard.clone())
            }),
            () = self.cancellation.cancelled() => {
                let mut cancellation_guard = context.output_guard.clone();
                cancellation_guard.merge(&OutputGuard::deny_all());
                Err(request_canceled_error(
                    &context.request.operation,
                    context.attempts,
                    context.request.replay != ReplayPolicy::Unsafe,
                    "authentication",
                    context.cancellation_state,
                )
                .with_output_guard(cancellation_guard))
            },
        }
    }

    fn ensure_not_cancelled(
        &self,
        request: &RequestSpec,
        attempts: u32,
        phase: &'static str,
        state: RemoteCancellationState,
        output_guard: &OutputGuard,
    ) -> Result<()> {
        if self.cancellation.is_cancelled() {
            Err(request_canceled_error(
                &request.operation,
                attempts,
                request.replay != ReplayPolicy::Unsafe,
                phase,
                state,
            )
            .with_output_guard(output_guard.clone()))
        } else {
            Ok(())
        }
    }

    fn should_retry_transport(
        &self,
        request: &RequestSpec,
        attempts: u32,
        error: &reqwest::Error,
    ) -> bool {
        !self.options.no_retry
            && request.replay != ReplayPolicy::Unsafe
            && attempts < 3
            && (error.is_connect() || error.is_timeout())
    }

    fn should_retry_status(
        &self,
        request: &RequestSpec,
        status: StatusCode,
        attempts: u32,
    ) -> bool {
        if self.options.no_retry || request.replay == ReplayPolicy::Unsafe {
            return false;
        }
        retry_attempt_ceiling(status).is_some_and(|ceiling| attempts < ceiling)
    }

    async fn sleep_before_retry(
        &self,
        attempts: u32,
        retry_after: Option<Duration>,
        deadline: Instant,
        request: &RequestSpec,
        cancellation_state: RemoteCancellationState,
        output_guard: &OutputGuard,
    ) -> Result<()> {
        self.ensure_not_cancelled(
            request,
            attempts,
            "retry_backoff",
            cancellation_state.clone(),
            output_guard,
        )?;
        let retry_number = attempts.min(20);
        let seconds = (1_u64 << retry_number) - 1;
        let jitter = Duration::from_millis(rand::rng().random_range(0..=250));
        let mut delay = Duration::from_secs(seconds) + jitter;
        if let Some(server_delay) = retry_after {
            delay = delay.max(server_delay);
        }
        if let Some(cap) = self.options.retry_delay_cap {
            delay = delay.min(cap);
        }
        if delay >= deadline.saturating_duration_since(Instant::now()) {
            return Err(ReltioError::new(
                "retry_budget_exhausted",
                ErrorCategory::Timeout,
                "the next safe retry would exceed the overall timeout",
            )
            .with_details(json!({
                "attempts": attempts,
                "next_delay_ms": u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                "practice_id": "HTTP-RETRY-001"
            }))
            .with_output_guard(output_guard.clone()));
        }
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(request_canceled_error(
                &request.operation,
                attempts,
                request.replay != ReplayPolicy::Unsafe,
                "retry_backoff",
                cancellation_state.clone(),
            )
            .with_output_guard(output_guard.clone())),
            () = tokio::time::sleep(delay) => self.ensure_not_cancelled(
                request,
                attempts,
                "retry_backoff",
                cancellation_state,
                output_guard,
            ),
        }
    }
}

pub fn validate_user_header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue)> {
    let trimmed_name = name.trim();
    if trimmed_name.as_bytes().contains(&b'_') {
        return Err(ReltioError::new(
            "ambiguous_header_name_refused",
            ErrorCategory::Safety,
            format!(
                "header name {trimmed_name:?} contains an underscore, which proxies may normalize to a hyphen and interpret as a different header"
            ),
        ));
    }
    let parsed_name = HeaderName::from_bytes(trimmed_name.as_bytes()).map_err(|_| {
        ReltioError::usage(
            "invalid_header_name",
            format!("invalid header name {name:?}"),
        )
    })?;
    let normalized = parsed_name.as_str();
    if sensitive_header(normalized)
        || matches!(
            normalized,
            "host" | "content-length" | "transfer-encoding" | "connection" | "proxy-connection"
        )
        || normalized.starts_with("x-forwarded-")
        || matches!(
            normalized,
            "forwarded"
                | "x-http-method-override"
                | "x-method-override"
                | "x-original-method"
                | "x-http-method"
                | "x-original-url"
                | "x-rewrite-url"
                | "x-forwarded-uri"
                | "x-forwarded-url"
                | "x-envoy-original-path"
                | "x-original-host"
        )
    {
        return Err(ReltioError::new(
            "protected_header_refused",
            ErrorCategory::Safety,
            format!("header {normalized:?} is controlled by the CLI and cannot be overridden"),
        ));
    }
    let parsed_value = HeaderValue::from_str(value.trim()).map_err(|_| {
        ReltioError::usage(
            "invalid_header_value",
            format!("header {normalized:?} has an invalid value"),
        )
    })?;
    Ok((parsed_name, parsed_value))
}

pub fn retry_attempt_ceiling(status: StatusCode) -> Option<u32> {
    match status.as_u16() {
        429 | 504 => Some(5),
        502 => Some(10),
        503 => Some(12),
        _ => None,
    }
}

pub fn backoff_seconds(retry_number: u32) -> u64 {
    (1_u64 << retry_number.min(20)) - 1
}

fn validate_body_size(method: &Method, size: usize) -> Result<()> {
    if *method == Method::POST && size > MAX_POST_BODY_BYTES {
        Err(ReltioError::usage(
            "post_body_too_large",
            format!(
                "POST body is {size} bytes; Reltio's hard limit is {MAX_POST_BODY_BYTES} bytes"
            ),
        )
        .with_hint("Reduce or split the payload before retrying."))
    } else {
        Ok(())
    }
}

async fn read_response_body(
    response: reqwest::Response,
    limit: usize,
    omit_on_overflow: bool,
    context: ResponseBodyContext<'_>,
) -> Result<(Vec<u8>, bool)> {
    let ResponseBodyContext {
        deadline,
        operation,
        attempts,
        replay_safe,
        status,
        request_id,
        cancellation,
        output_guard,
    } = context;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    loop {
        if cancellation.is_cancelled() {
            return Err(request_canceled_error(
                operation,
                attempts,
                replay_safe,
                "response_body",
                RemoteCancellationState::ResponseReceived { status, request_id },
            )
            .with_output_guard(output_guard.clone()));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(response_body_error(
                timeout_error(operation, attempts, replay_safe, "response_body"),
                status,
                request_id,
                replay_safe,
            )
            .with_output_guard(output_guard.clone()));
        }
        let next = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(request_canceled_error(
                    operation,
                    attempts,
                    replay_safe,
                    "response_body",
                    RemoteCancellationState::ResponseReceived {
                        status,
                        request_id,
                    },
                )
                .with_output_guard(output_guard.clone()));
            }
            next = stream.next() => next,
            () = tokio::time::sleep(remaining) => {
                return Err(response_body_error(
                    timeout_error(operation, attempts, replay_safe, "response_body"),
                    status,
                    request_id.clone(),
                    replay_safe,
                )
                .with_output_guard(output_guard.clone()));
            }
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) if cancellation.is_cancelled() => {
                return Err(request_canceled_error(
                    operation,
                    attempts,
                    replay_safe,
                    "response_body",
                    RemoteCancellationState::ResponseReceived { status, request_id },
                )
                .with_output_guard(output_guard.clone()));
            }
            Err(error) => {
                return Err(response_body_error(
                    ReltioError::new(
                        "response_read_failed",
                        ErrorCategory::Network,
                        format!("failed while reading response: {error}"),
                    )
                    .retryable(replay_safe)
                    .with_details(json!({
                    "attempts": attempts,
                    "safe_to_replay": replay_safe,
                    "phase": "response_body"
                    })),
                    status,
                    request_id.clone(),
                    replay_safe,
                )
                .with_output_guard(output_guard.clone()));
            }
        };
        if body.len().saturating_add(chunk.len()) > limit {
            if cancellation.is_cancelled() {
                return Err(request_canceled_error(
                    operation,
                    attempts,
                    replay_safe,
                    "response_body",
                    RemoteCancellationState::ResponseReceived { status, request_id },
                )
                .with_output_guard(output_guard.clone()));
            }
            if omit_on_overflow {
                return Ok((Vec::new(), true));
            }
            return Err(response_body_error(
                ReltioError::new(
                    "response_too_large",
                    ErrorCategory::Api,
                    format!("response exceeded the configured {limit}-byte limit"),
                )
                .with_hint("Use field selection, pagination, or a larger explicit response limit."),
                status,
                request_id,
                replay_safe,
            )
            .with_output_guard(output_guard.clone()));
        }
        body.extend_from_slice(&chunk);
    }
    if cancellation.is_cancelled() {
        return Err(request_canceled_error(
            operation,
            attempts,
            replay_safe,
            "response_body",
            RemoteCancellationState::ResponseReceived { status, request_id },
        )
        .with_output_guard(output_guard.clone()));
    }
    Ok((body, false))
}

fn target_auth_error(error: ReltioError, operation: &str, attempts: u32) -> ReltioError {
    if error.code != "auth_timeout" {
        return error;
    }
    let output_guard = error.output_guard().cloned();
    let mut error = timeout_error(operation, attempts, true, "authentication");
    if let Some(output_guard) = output_guard {
        error = error.with_output_guard(output_guard);
    }
    error
}

fn request_canceled_error(
    operation: &str,
    attempts: u32,
    replay_safe: bool,
    phase: &str,
    state: RemoteCancellationState,
) -> ReltioError {
    let error = ReltioError::new(
        "request_canceled",
        ErrorCategory::Canceled,
        format!("{operation} was canceled"),
    )
    .retryable(false)
    .with_details(json!({
        "attempts": attempts,
        "phase": phase
    }));
    match state {
        RemoteCancellationState::RequestNotSent => error.with_details(json!({
            "attempts": attempts,
            "phase": phase,
            "remote_response_received": false,
            "remote_request_completed": false,
            "remote_operation_completed": false,
            "remote_operation_state": "request_not_sent",
            "safe_to_replay": true
        })),
        RemoteCancellationState::RequestSentCompletionUnknown => {
            let error = error.with_details(json!({
                "attempts": attempts,
                "phase": phase,
                "remote_response_received": false,
                "remote_request_completed": Value::Null,
                "remote_operation_completed": Value::Null,
                "remote_operation_state": "request_sent_completion_unknown",
                "safe_to_replay": replay_safe
            }));
            if replay_safe {
                error
            } else {
                ambiguous_outcome_error(error, None)
            }
        }
        RemoteCancellationState::ResponseReceived { status, request_id } => response_outcome_error(
            error,
            status,
            request_id,
            replay_safe,
            response_operation_state(status),
        ),
    }
}

fn response_body_error(
    error: ReltioError,
    status: u16,
    request_id: Option<String>,
    replay_safe: bool,
) -> ReltioError {
    response_outcome_error(
        error,
        status,
        request_id,
        replay_safe,
        response_operation_state(status),
    )
}

fn response_outcome_error(
    mut error: ReltioError,
    status: u16,
    request_id: Option<String>,
    replay_safe: bool,
    operation_state: &str,
) -> ReltioError {
    error.http_status = Some(status);
    error.request_id.clone_from(&request_id);
    if !error.details.is_object() {
        let original = std::mem::take(&mut error.details);
        error.details = json!({ "original_details": original });
    }
    let Some(details) = error.details.as_object_mut() else {
        return error;
    };
    details.insert("remote_response_received".to_owned(), Value::Bool(true));
    details.insert("remote_request_completed".to_owned(), Value::Bool(true));
    details.insert("remote_operation_completed".to_owned(), Value::Null);
    details.insert(
        "remote_operation_state".to_owned(),
        Value::String(operation_state.to_owned()),
    );
    details.insert("safe_to_replay".to_owned(), Value::Bool(replay_safe));
    if !replay_safe {
        return ambiguous_outcome_error(error, request_id);
    }
    error
}

fn response_operation_state(status: u16) -> &'static str {
    if (200..300).contains(&status) {
        "success_response_received_completion_unknown"
    } else {
        "error_response_received_completion_unknown"
    }
}

fn ambiguous_outcome_error(mut error: ReltioError, request_id: Option<String>) -> ReltioError {
    if !error.details.is_object() {
        let original = std::mem::take(&mut error.details);
        error.details = json!({ "original_details": original });
    }
    let details = error
        .details
        .as_object_mut()
        .unwrap_or_else(|| unreachable!("details were normalized to an object"));
    details
        .entry("remote_response_received".to_owned())
        .or_insert(Value::Bool(false));
    details
        .entry("remote_request_completed".to_owned())
        .or_insert(Value::Null);
    details
        .entry("remote_operation_completed".to_owned())
        .or_insert(Value::Null);
    details
        .entry("remote_operation_state".to_owned())
        .or_insert(Value::String("request_sent_completion_unknown".to_owned()));
    details
        .entry("safe_to_replay".to_owned())
        .or_insert(Value::Bool(false));
    details.insert("outcome_ambiguous".to_owned(), Value::Bool(true));
    details.insert(
        "verification_hint".to_owned(),
        Value::String(request_id.map_or_else(
            || "Verify the target resource before considering any manual replay.".to_owned(),
            |id| {
                format!(
                    "Verify the target resource before considering any manual replay; use request ID {id} when investigating."
                )
            },
        )),
    );
    error
}

fn request_id(headers: &HeaderMap, known_secrets: &[&str]) -> Option<String> {
    ["x-request-id", "x-correlation-id", "reltio-request-id"]
        .iter()
        .find_map(|name| {
            headers
                .get(*name)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.len() <= 512)
                .and_then(|value| sanitized_structured_text(value, known_secrets))
        })
}

fn sanitized_structured_text(text: &str, known_secrets: &[&str]) -> Option<String> {
    let mut value = Value::String(redact_text(text, known_secrets));
    sanitize_json_serialization(&mut value, known_secrets)?;
    value.as_str().map(ToOwned::to_owned)
}

fn sanitized_headers(
    headers: &HeaderMap,
    known_secrets: &[&str],
) -> Result<BTreeMap<String, String>> {
    let mut sanitized = BTreeMap::new();
    let mut next_suffix = 2_u64;
    for (name, value) in headers {
        if sensitive_header(name.as_str()) {
            continue;
        }
        let Some(value) = value.to_str().ok().filter(|value| value.len() <= 4096) else {
            continue;
        };
        let name = redact_text(name.as_str(), known_secrets);
        let mut candidate = (!sanitized.contains_key(&name)).then(|| name.clone());
        let attempts = sanitized.len().saturating_add(1);
        for _ in 0..attempts {
            if candidate.is_some() {
                break;
            }
            let suffixed = redact_text(&format!("{name}#{next_suffix}"), known_secrets);
            next_suffix = next_suffix
                .checked_add(1)
                .unwrap_or_else(|| unreachable!("a finite header map cannot exhaust key suffixes"));
            if !sanitized.contains_key(&suffixed) {
                candidate = Some(suffixed);
            }
        }
        let candidate = candidate.ok_or_else(|| {
            ReltioError::new(
                "api_response_redaction_failed",
                ErrorCategory::Api,
                "Reltio returned response headers that could not be sanitized safely",
            )
            .with_details(json!({"reason": "redacted_header_collision_limit_exceeded"}))
        })?;
        sanitized.insert(candidate, redact_text(value, known_secrets));
    }
    let mut structured = serde_json::to_value(&sanitized)
        .unwrap_or_else(|_| unreachable!("a string map is always JSON serializable"));
    if sanitize_json_serialization(&mut structured, known_secrets).is_none() {
        return Err(ReltioError::new(
            "api_response_redaction_failed",
            ErrorCategory::Api,
            "Reltio returned response headers that could not be sanitized safely",
        )
        .with_details(json!({"reason": "serialized_headers_could_not_be_sanitized"})));
    }
    serde_json::from_value(structured).map_err(|_| {
        ReltioError::new(
            "api_response_redaction_failed",
            ErrorCategory::Api,
            "Reltio returned response headers that could not be sanitized safely",
        )
        .with_details(json!({"reason": "serialized_headers_could_not_be_sanitized"}))
    })
}

pub(crate) fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let when = httpdate::parse_http_date(value).ok()?;
    when.duration_since(SystemTime::now()).ok()
}

fn api_error(
    status: StatusCode,
    request_id: Option<String>,
    body: &[u8],
    content_type: Option<&str>,
    known_secrets: &[&str],
    replay_safe: bool,
    attempts: u32,
) -> ReltioError {
    let (code, category, message, hint) = match status.as_u16() {
        400 => (
            "api_bad_request",
            ErrorCategory::Api,
            "Reltio rejected the request",
            "Review the filter, fields, options, and endpoint documentation.",
        ),
        401 => (
            "auth_invalid_token",
            ErrorCategory::Authentication,
            "Reltio rejected the access token",
            "Run `reltio auth check` or provide a fresh credential.",
        ),
        403 => (
            "auth_insufficient_permissions",
            ErrorCategory::Authentication,
            "The credential cannot access the selected tenant operation",
            "Check tenant roles, scopes, policy, and IP allowlisting.",
        ),
        404 => (
            "resource_not_found",
            ErrorCategory::NotFound,
            "The requested Reltio resource was not found",
            "Verify the tenant, resource URI, and selected environment.",
        ),
        409 | 412 => (
            "api_conflict",
            ErrorCategory::Conflict,
            "Reltio refused the request because of a conflict or stale precondition",
            "Refresh the resource and reconcile concurrent changes before retrying.",
        ),
        413 => (
            "api_payload_too_large",
            ErrorCategory::Usage,
            "Reltio rejected the request body as too large",
            "Reduce or rechunk the request; do not replay the same body.",
        ),
        429 => (
            "api_rate_limited",
            ErrorCategory::Api,
            "Reltio rate-limited the request",
            "Reduce concurrency and honor Retry-After before trying again.",
        ),
        500 => (
            "api_internal_error",
            ErrorCategory::Api,
            "Reltio returned an internal error; the CLI did not retry it",
            "Check the request and documentation, then contact Reltio Support if it persists.",
        ),
        502..=504 => (
            "api_service_unavailable",
            ErrorCategory::Api,
            "Reltio remained unavailable after the safe retry budget",
            "Retry later or contact Reltio Support with the request ID.",
        ),
        _ => (
            "api_error",
            ErrorCategory::Api,
            "Reltio returned an unsuccessful response",
            "Inspect the bounded response details and request ID.",
        ),
    };
    let declared_json = is_json_content_type(content_type);
    let sanitized_content_type =
        content_type.and_then(|value| sanitized_structured_text(value, known_secrets));
    let details = diagnostic_response_details(
        body,
        declared_json,
        sanitized_content_type.as_deref(),
        known_secrets,
    );
    let retryable = replay_safe && matches!(status.as_u16(), 429 | 502 | 503 | 504);
    ReltioError::new(code, category, message)
        .with_http_status(status.as_u16())
        .with_request_id(request_id)
        .with_details(json!({
            "response": details,
            "attempts": attempts,
            "remote_response_received": true,
            "remote_request_completed": true,
            "remote_operation_completed": Value::Null,
            "remote_operation_state": if replay_safe {
                "error_response_received"
            } else {
                "error_response_received_completion_unknown"
            },
            "safe_to_replay": replay_safe,
            "practice_id": "HTTP-RETRY-001"
        }))
        .with_hint(hint)
        .retryable(retryable)
        .with_output_guard(OutputGuard::from_known_secrets(known_secrets))
}

fn diagnostic_response_details(
    body: &[u8],
    declared_json: bool,
    sanitized_content_type: Option<&str>,
    known_secrets: &[&str],
) -> Value {
    match secure_json_value(body) {
        Ok(mut value) => {
            let outcome = redact_json(&mut value, known_secrets);
            if outcome.is_complete()
                && sanitize_json_serialization(&mut value, known_secrets).is_some()
            {
                value
            } else {
                json!({
                    "body_omitted": true,
                    "reason": "response_redaction_incomplete"
                })
            }
        }
        Err(error) if declared_json || looks_like_json(body) => {
            let reason = match error {
                SecureJsonError::Structural(reason) => reason,
                SecureJsonError::Parse(_) => "invalid_or_unsupported_json",
            };
            json!({
                "body_omitted": true,
                "content_type": sanitized_content_type,
                "reason": reason
            })
        }
        Err(_) => json!({
            "body": redact_text(&String::from_utf8_lossy(body), known_secrets)
        }),
    }
}

fn transport_error(
    operation: &str,
    attempts: u32,
    replay: ReplayPolicy,
    error: &reqwest::Error,
) -> ReltioError {
    let safe_to_replay = replay != ReplayPolicy::Unsafe || error.is_connect();
    let failure = ReltioError::new(
        "network_request_failed",
        ErrorCategory::Network,
        format!(
            "{operation} failed after {attempts} attempt(s): {}",
            redact_text(&error.to_string(), &[])
        ),
    )
    .retryable(safe_to_replay && (error.is_connect() || error.is_timeout()))
    .with_details(json!({
        "attempts": attempts,
        "safe_to_replay": safe_to_replay,
        "phase": if error.is_connect() { "connect" } else { "send" }
    }));
    if safe_to_replay {
        failure
    } else {
        ambiguous_outcome_error(failure, None)
    }
}

fn timeout_error(operation: &str, attempts: u32, safe_to_replay: bool, phase: &str) -> ReltioError {
    ReltioError::new(
        "request_timeout",
        ErrorCategory::Timeout,
        format!("{operation} exceeded the overall timeout"),
    )
    .retryable(safe_to_replay)
    .with_details(json!({
        "attempts": attempts,
        "safe_to_replay": safe_to_replay,
        "phase": phase
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use tempfile::tempdir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::auth::TokenManagerOptions;
    use crate::config::{AuthMethod, AuthProfile, Environment, ResolvedTarget};
    use crate::service::Service;

    use super::*;

    fn auth_target(auth_url: &str) -> ResolvedTarget {
        ResolvedTarget {
            profile: Some("test".to_owned()),
            environment: "test".to_owned(),
            tenant: "TestTenant".to_owned(),
            production: false,
            target_overridden: false,
            routing_overridden: false,
            tenant_overridden: false,
            base_url: None,
            service_urls: BTreeMap::from([(Service::Auth, auth_url.to_owned())]),
            auth: AuthProfile {
                method: Some(AuthMethod::ClientCredentials),
                client_id: Some("client-id".to_owned()),
                ..AuthProfile::default()
            },
            sources: BTreeMap::new(),
        }
    }

    fn bearer_manager(cache_dir: &std::path::Path, token: &str) -> TokenManager {
        TokenManager::from_target(
            &auth_target("https://auth.reltio.com"),
            &Environment::from_pairs([("RELTIO_ACCESS_TOKEN".to_owned(), token.to_owned())]),
            cache_dir.to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(5),
        )
        .expect("token manager")
    }

    async fn wait_for_request_count(server: &MockServer, expected: usize) {
        for _ in 0..500 {
            let requests = server.received_requests().await.expect("received requests");
            if requests.len() >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("server did not receive {expected} request(s)");
    }

    fn response_fixture(body: impl Into<Vec<u8>>, content_type: Option<&str>) -> ApiResponse {
        ApiResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: body.into(),
            content_type: content_type.map(ToOwned::to_owned),
            declared_json: content_type.map(|value| is_json_content_type(Some(value))),
            request_id: Some("response-fixture".to_owned()),
            attempts: 1,
            elapsed_ms: 1,
            applied_practice_ids: Vec::new(),
            redaction_secrets: vec!["secret-token".to_owned().into()],
        }
    }

    #[test]
    fn successful_raw_and_plain_text_responses_preserve_fidelity() {
        let json = b"{\n  \"z\": 1,\n  \"a\": \"password=ordinary\"\n}";
        assert_eq!(
            response_fixture(json.as_slice(), Some("application/json"))
                .redacted_body()
                .expect("raw JSON"),
            json
        );
        assert_eq!(
            response_fixture(b"password=ordinary-upstream".as_slice(), Some("text/plain"))
                .data_value()
                .expect("plain text"),
            Value::String("password=ordinary-upstream".to_owned())
        );
        let json_looking_text = b"{ordinary plain text";
        let response = response_fixture(json_looking_text.as_slice(), Some("text/plain"));
        assert_eq!(
            response.data_value().expect("JSON-looking text"),
            Value::String("{ordinary plain text".to_owned())
        );
        assert_eq!(
            response.redacted_body().expect("raw JSON-looking text"),
            json_looking_text
        );
    }

    #[test]
    fn multi_megabyte_json_with_ordinary_form_syntax_preserves_raw_fidelity() {
        let body = format!(
            r#"{{"ordinary":"+","value":"{}"}}"#,
            "x".repeat(2 * 1024 * 1024)
        )
        .into_bytes();
        let response = response_fixture(body.clone(), Some("application/json"));

        assert_eq!(response.redacted_body().expect("large raw JSON"), body);
    }

    #[test]
    fn non_json_responses_redact_encoded_active_credentials() {
        let response = response_fixture(b"secret%2Dtoken".as_slice(), Some("text/plain"));
        assert_eq!(
            response.data_value().expect("encoded plain-text token"),
            Value::String("[REDACTED]".to_owned())
        );
        assert_eq!(
            response.redacted_body().expect("encoded raw token"),
            b"[REDACTED]"
        );

        let mut response = response_fixture(b"secret+token".as_slice(), Some("text/plain"));
        response.redaction_secrets = vec!["secret token".to_owned().into()];
        assert_eq!(
            response.redacted_body().expect("form-encoded raw token"),
            b"[REDACTED]"
        );

        let mut response = response_fixture(
            [b"\xff".as_slice(), b"secret%2Dtoken"].concat(),
            Some("application/octet-stream"),
        );
        response.redaction_secrets = vec!["secret-token".to_owned().into()];
        let data = response.data_value().expect("binary encoded token");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data["data"].as_str().expect("base64 response data"))
            .expect("decode redacted response data");
        assert_eq!(decoded, b"[REDACTED]");
        assert_eq!(
            response.redacted_body().expect("binary raw token"),
            b"[REDACTED]"
        );

        let mut response = response_fixture(b"secret%252Dtoken", Some("text/plain"));
        response.redaction_secrets = vec!["secret%2Dtoken".to_owned().into()];
        assert_eq!(
            response.redacted_body().expect("encoded token syntax"),
            b"[REDACTED]"
        );

        let response = response_fixture(b"ordinary=%252541", Some("text/plain"));
        assert_eq!(
            response.redacted_body().expect("ordinary encoded data"),
            b"[REDACTED]"
        );
    }

    #[test]
    fn original_content_type_controls_json_sanitization() {
        let mut response = response_fixture(
            br#"{"refresh_token":"upstream-secret"}"#.as_slice(),
            Some("application/json"),
        );
        response.redaction_secrets = vec!["json".to_owned().into()];
        response.content_type = Some(redact_text("application/json", &["json"]));

        assert_eq!(response.content_type.as_deref(), Some("application/"));
        assert_eq!(
            response.data_value().expect("classified JSON")["refresh_token"],
            ""
        );
        let raw = response.redacted_body().expect("classified raw JSON");
        assert!(!String::from_utf8_lossy(&raw).contains("upstream-secret"));
    }

    #[test]
    fn encoded_diagnostic_assignments_are_not_emitted() {
        let details = diagnostic_response_details(
            br#"{"message":"refresh%5Ftoken=upstream-refresh-secret"}"#,
            true,
            Some("application/json"),
            &[],
        );
        assert!(!details.to_string().contains("upstream-refresh-secret"));
    }

    #[test]
    fn numeric_shaped_active_token_is_redacted_as_valid_json() {
        let mut response =
            response_fixture(br#"{"number":12345}"#.as_slice(), Some("application/json"));
        response.redaction_secrets = vec!["123".to_owned().into()];
        assert_eq!(
            response.data_value().expect("structured response")["number"],
            ""
        );
        let raw = response.redacted_body().expect("raw response");
        let parsed: Value = serde_json::from_slice(&raw).expect("redacted raw body is valid JSON");
        assert_eq!(parsed["number"], "");
        assert!(!String::from_utf8_lossy(&raw).contains("123"));
    }

    #[test]
    fn raw_json_lexical_credentials_are_normalized_or_redacted() {
        for (token, body) in [
            ("1E-00", br#"{"value":1E-00}"#.as_slice()),
            (r"\u0061", br#"{"value":"\u0061"}"#.as_slice()),
        ] {
            let mut response = response_fixture(body, Some("application/json"));
            response.redaction_secrets = vec![token.to_owned().into()];
            let raw = response.redacted_body().expect("sanitized raw JSON");
            assert!(!String::from_utf8_lossy(&raw).contains(token));
            serde_json::from_slice::<Value>(&raw).expect("sanitized body remains JSON");
        }

        let mut response = response_fixture(
            br#"{"value":"secret%25252Dtoken"}"#,
            Some("application/json"),
        );
        response.redaction_secrets = vec!["secret-token".to_owned().into()];
        let raw = response.redacted_body().expect("overencoded raw JSON");
        assert!(!String::from_utf8_lossy(&raw).contains("secret"));
    }

    #[test]
    fn structured_json_serialization_cannot_recreate_credentials() {
        let token = r#"longprefix\"longsuffix"#;
        let body = br#"{"value":"longprefix\"longsuffix"}"#;
        let mut response = response_fixture(body, Some("application/json"));
        response.redaction_secrets = vec![token.to_owned().into()];

        for value in [
            response.json().expect("typed JSON"),
            response.data_value().expect("structured JSON"),
            diagnostic_response_details(body, true, Some("application/json"), &[token]),
        ] {
            let compact = serde_json::to_vec(&value).expect("compact JSON");
            let pretty = serde_json::to_vec_pretty(&value).expect("pretty JSON");
            assert!(!contains_known_secret(&compact, &[token]));
            assert!(!contains_known_secret(&pretty, &[token]));
        }
    }

    #[test]
    fn raw_json_redaction_never_amplifies_the_body() {
        let mut response = response_fixture(b"[0,0,0,0]", Some("application/json"));
        response.redaction_secrets = vec!["0".to_owned().into()];
        assert!(
            response
                .redacted_body()
                .expect("bounded raw body")
                .is_empty()
        );

        for token in ["{", ":", "false", "2"] {
            let mut response =
                response_fixture(br#"{"safe":false,"number":2}"#, Some("application/json"));
            response.redaction_secrets = vec![token.to_owned().into()];
            let raw = response.redacted_body().expect("sanitized raw body");
            assert!(!String::from_utf8_lossy(&raw).contains(token));
        }
    }

    #[test]
    fn unsafe_json_shapes_fail_closed_without_echoing_credentials() {
        let nested = format!(
            "{}{{\"refresh\\u005ftoken\":\"secret\\u002dtoken\"}}{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        let response = response_fixture(nested, Some("application/json"));
        for error in [
            response
                .data_value()
                .expect_err("structured output must fail"),
            response.redacted_body().expect_err("raw output must fail"),
        ] {
            assert_eq!(error.code, "api_response_invalid_json");
            assert_eq!(error.details["reason"], "json_nesting_limit_exceeded");
            let rendered = serde_json::to_string(&error).expect("error JSON");
            assert!(!rendered.contains("secret-token"));
            assert!(!rendered.contains("secret\\u002dtoken"));
        }

        let duplicate = response_fixture(
            br#"{"refresh_token":"first-secret","refresh_token":"safe"}"#.as_slice(),
            Some("application/json"),
        );
        assert_eq!(
            duplicate
                .redacted_body()
                .expect_err("duplicate keys must fail")
                .details["reason"],
            "duplicate_json_key_refused"
        );

        let many_values = format!("[{}]", vec!["0"; MAX_JSON_STRUCTURAL_TOKENS + 1].join(","));
        let complex = response_fixture(many_values, Some("application/json"));
        assert_eq!(
            complex
                .redacted_body()
                .expect_err("excessive JSON complexity must fail")
                .details["reason"],
            "json_complexity_limit_exceeded"
        );

        let mut collision = response_fixture(
            br#"{"0a":"left","1a":"middle","2a":"right"}"#,
            Some("application/json"),
        );
        collision.redaction_secrets = (0..=9).map(|digit| digit.to_string().into()).collect();
        let error = collision
            .data_value()
            .expect_err("unrepresentable redacted keys must fail");
        assert_eq!(error.code, "api_response_redaction_failed");
        assert_eq!(
            error.details["reason"],
            "redacted_key_collision_limit_exceeded"
        );
    }

    #[test]
    fn response_json_preserves_arbitrary_precision_numbers() {
        let body = br#"{"integer":123456789012345678901234567890,"decimal":0.123456789012345678901234567890}"#;
        let value = response_fixture(body.as_slice(), Some("application/json"))
            .json()
            .expect("arbitrary precision JSON");
        assert_eq!(
            value["integer"].to_string(),
            "123456789012345678901234567890"
        );
        assert_eq!(
            value["decimal"].to_string(),
            "0.123456789012345678901234567890"
        );
    }

    #[test]
    fn retry_matrix_matches_reviewed_guidance() {
        assert_eq!(
            retry_attempt_ceiling(StatusCode::TOO_MANY_REQUESTS),
            Some(5)
        );
        assert_eq!(retry_attempt_ceiling(StatusCode::BAD_GATEWAY), Some(10));
        assert_eq!(
            retry_attempt_ceiling(StatusCode::SERVICE_UNAVAILABLE),
            Some(12)
        );
        assert_eq!(retry_attempt_ceiling(StatusCode::GATEWAY_TIMEOUT), Some(5));
        assert_eq!(
            retry_attempt_ceiling(StatusCode::INTERNAL_SERVER_ERROR),
            None
        );
        assert_eq!(retry_attempt_ceiling(StatusCode::FORBIDDEN), None);
    }

    #[tokio::test]
    async fn oversized_retryable_errors_do_not_suppress_successful_retry() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let api = MockServer::start().await;
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&attempts);
            Mock::given(method("GET"))
                .and(path("/retry"))
                .respond_with(move |_: &wiremock::Request| {
                    if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                        ResponseTemplate::new(status.as_u16())
                            .set_body_raw(vec![b'x'; ERROR_BODY_LIMIT + 1], "text/plain")
                    } else {
                        ResponseTemplate::new(200).set_body_json(json!({"ok": true}))
                    }
                })
                .expect(2)
                .mount(&api)
                .await;
            let directory = tempdir().expect("temporary directory");
            let manager = TokenManager::from_target(
                &auth_target("https://auth.reltio.com"),
                &Environment::from_pairs([(
                    "RELTIO_ACCESS_TOKEN".to_owned(),
                    "opaque-token".to_owned(),
                )]),
                directory.path().to_path_buf(),
                TokenManagerOptions::default(),
                Duration::from_secs(5),
            )
            .expect("token manager");
            let client = HttpClient::new(HttpOptions {
                timeout: Duration::from_secs(5),
                retry_delay_cap: Some(Duration::ZERO),
                ..HttpOptions::default()
            })
            .expect("HTTP client");
            let mut request = RequestSpec::new(
                Method::GET,
                Url::parse(&format!("{}/retry", api.uri())).expect("URL"),
                "oversized-retry.test",
            );
            request.replay = ReplayPolicy::Safe;

            let response = client.execute(&manager, request).await.expect("safe retry");

            assert_eq!(response.status, 200, "status {status}");
            assert_eq!(response.attempts, 2, "status {status}");
            assert_eq!(attempts.load(Ordering::SeqCst), 2, "status {status}");
        }
    }

    #[tokio::test]
    async fn oversized_retryable_errors_preserve_status_after_attempt_ceiling() {
        for (status, ceiling, expected_code) in [
            (StatusCode::TOO_MANY_REQUESTS, 5, "api_rate_limited"),
            (StatusCode::BAD_GATEWAY, 10, "api_service_unavailable"),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                12,
                "api_service_unavailable",
            ),
            (StatusCode::GATEWAY_TIMEOUT, 5, "api_service_unavailable"),
        ] {
            let api = MockServer::start().await;
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&attempts);
            Mock::given(method("GET"))
                .and(path("/retry"))
                .respond_with(move |_: &wiremock::Request| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(status.as_u16())
                        .set_body_raw(vec![b'x'; ERROR_BODY_LIMIT + 1], "text/plain")
                })
                .mount(&api)
                .await;
            let directory = tempdir().expect("temporary directory");
            let manager = TokenManager::from_target(
                &auth_target("https://auth.reltio.com"),
                &Environment::from_pairs([(
                    "RELTIO_ACCESS_TOKEN".to_owned(),
                    "opaque-token".to_owned(),
                )]),
                directory.path().to_path_buf(),
                TokenManagerOptions::default(),
                Duration::from_secs(5),
            )
            .expect("token manager");
            let client = HttpClient::new(HttpOptions {
                timeout: Duration::from_secs(5),
                retry_delay_cap: Some(Duration::ZERO),
                ..HttpOptions::default()
            })
            .expect("HTTP client");
            let mut request = RequestSpec::new(
                Method::GET,
                Url::parse(&format!("{}/retry", api.uri())).expect("URL"),
                "oversized-retry.test",
            );
            request.replay = ReplayPolicy::Safe;

            let error = client
                .execute(&manager, request)
                .await
                .expect_err("attempt ceiling must fail");

            assert_eq!(error.code, expected_code, "status {status}");
            assert_eq!(error.http_status, Some(status.as_u16()));
            assert_eq!(error.details["attempts"], ceiling);
            assert_eq!(error.details["response_body_truncated"], true);
            assert_eq!(
                error.details["response"]["reason"],
                "response_body_too_large"
            );
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                usize::try_from(ceiling).expect("small ceiling"),
                "status {status}"
            );
        }
    }

    #[test]
    fn backoff_sequence_is_one_three_seven() {
        assert_eq!(
            (1..=5).map(backoff_seconds).collect::<Vec<_>>(),
            [1, 3, 7, 15, 31]
        );
    }

    #[test]
    fn protected_headers_are_refused() {
        let error = validate_user_header("Authorization", "Bearer secret")
            .expect_err("authorization is protected");
        assert_eq!(error.code, "protected_header_refused");
        assert!(validate_user_header("X-HTTP-Method-Override", "DELETE").is_err());
        assert!(validate_user_header("X-Original-URL", "/other-tenant").is_err());
        assert!(validate_user_header("X-Workflow-ID", "123").is_ok());
    }

    #[test]
    fn underscore_header_aliases_are_refused_while_benign_hyphens_are_accepted() {
        for name in [
            "X_Forwarded_For",
            "X_HTTP_Method_Override",
            "X_Original_URL",
            "Proxy_Connection",
            "Content_Length",
            "X_Workflow_ID",
            "  X_Benign  ",
        ] {
            let error = validate_user_header(name, "value")
                .expect_err("every underscore-bearing name must be refused");
            assert_eq!(error.code, "ambiguous_header_name_refused", "{name}");
            assert_eq!(error.category, ErrorCategory::Safety, "{name}");
            assert!(error.message.contains("proxies"), "{name}");
        }
        for name in ["X-Workflow-ID", "X-Benign", "Trace-Context"] {
            assert!(validate_user_header(name, "value").is_ok(), "{name}");
        }
    }

    #[tokio::test]
    async fn already_canceled_request_is_not_sent() {
        let api = MockServer::start().await;
        let directory = tempdir().expect("temporary directory");
        let manager = bearer_manager(directory.path(), "already-canceled-token");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let client = HttpClient::new_with_cancellation(HttpOptions::default(), cancellation)
            .expect("HTTP client");
        let request = RequestSpec::new(
            Method::POST,
            Url::parse(&format!("{}/mutation", api.uri())).expect("URL"),
            "cancellation.before-send",
        );

        let error = client
            .execute(&manager, request)
            .await
            .expect_err("request must be canceled");

        assert_eq!(error.code, "request_canceled");
        assert_eq!(error.category, ErrorCategory::Canceled);
        assert!(!error.retryable);
        assert_eq!(error.details["attempts"], 0);
        assert_eq!(error.details["remote_response_received"], false);
        assert_eq!(error.details["remote_request_completed"], false);
        assert_eq!(error.details["remote_operation_completed"], false);
        assert_eq!(error.details["remote_operation_state"], "request_not_sent");
        assert_eq!(error.details["safe_to_replay"], true);
        assert!(api.received_requests().await.expect("requests").is_empty());
        assert!(
            !error
                .output_guard()
                .expect("cancellation output guard")
                .permits(b"already-canceled-token")
        );
    }

    #[tokio::test]
    async fn unsafe_in_flight_cancellation_is_ambiguous_and_never_retried() {
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/mutation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_json(json!({"ok": true})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = bearer_manager(directory.path(), "unsafe-cancellation-token");
        let cancellation = CancellationToken::new();
        let client = HttpClient::new_with_cancellation(
            HttpOptions {
                timeout: Duration::from_secs(5),
                ..HttpOptions::default()
            },
            cancellation.clone(),
        )
        .expect("HTTP client");
        // The GET method is intentionally classified Unsafe to prove replay policy wins.
        let request = RequestSpec::new(
            Method::GET,
            Url::parse(&format!("{}/mutation", api.uri())).expect("URL"),
            "cancellation.unsafe-send",
        );
        let execution = tokio::spawn(async move { client.execute(&manager, request).await });
        wait_for_request_count(&api, 1).await;

        let started = Instant::now();
        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), execution)
            .await
            .expect("cancellation returns promptly")
            .expect("request task completes")
            .expect_err("request must be canceled");

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(error.code, "request_canceled");
        assert_eq!(error.category, ErrorCategory::Canceled);
        assert!(!error.retryable);
        assert_eq!(error.http_status, None);
        assert_eq!(error.request_id, None);
        assert_eq!(error.details["remote_response_received"], false);
        assert!(error.details["remote_request_completed"].is_null());
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "request_sent_completion_unknown"
        );
        assert_eq!(error.details["safe_to_replay"], false);
        assert_eq!(error.details["outcome_ambiguous"], true);
        assert!(error.details["verification_hint"].is_string());
        assert_eq!(api.received_requests().await.expect("requests").len(), 1);
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("unsafe-cancellation-token")
        );
        assert!(
            !error
                .output_guard()
                .expect("cancellation output guard")
                .permits(b"unsafe-cancellation-token")
        );
    }

    #[tokio::test]
    async fn replay_safe_in_flight_cancellation_remains_safe_without_retrying() {
        let api = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/safe"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_json(json!({"ok": true})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = bearer_manager(directory.path(), "safe-cancellation-token");
        let cancellation = CancellationToken::new();
        let client = HttpClient::new_with_cancellation(
            HttpOptions {
                timeout: Duration::from_secs(5),
                ..HttpOptions::default()
            },
            cancellation.clone(),
        )
        .expect("HTTP client");
        // The POST method is intentionally classified Safe to prove replay policy wins.
        let mut request = RequestSpec::new(
            Method::POST,
            Url::parse(&format!("{}/safe", api.uri())).expect("URL"),
            "cancellation.safe-send",
        );
        request.replay = ReplayPolicy::Safe;
        let execution = tokio::spawn(async move { client.execute(&manager, request).await });
        wait_for_request_count(&api, 1).await;

        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), execution)
            .await
            .expect("cancellation returns promptly")
            .expect("request task completes")
            .expect_err("request must be canceled");

        assert_eq!(error.code, "request_canceled");
        assert!(!error.retryable);
        assert_eq!(error.details["remote_response_received"], false);
        assert!(error.details["remote_request_completed"].is_null());
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "request_sent_completion_unknown"
        );
        assert_eq!(error.details["safe_to_replay"], true);
        assert!(error.details.get("outcome_ambiguous").is_none());
        assert_eq!(api.received_requests().await.expect("requests").len(), 1);
    }

    #[tokio::test]
    async fn cancellation_during_retry_backoff_preserves_the_last_response() {
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/retry"))
            .respond_with(
                ResponseTemplate::new(503)
                    .insert_header("retry-after", "10")
                    .insert_header("x-request-id", "retry-canceled-1")
                    .set_body_json(json!({"message": "wait"})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = bearer_manager(directory.path(), "retry-cancellation-token");
        let cancellation = CancellationToken::new();
        let client = HttpClient::new_with_cancellation(
            HttpOptions {
                timeout: Duration::from_secs(5),
                retry_delay_cap: Some(Duration::from_secs(2)),
                ..HttpOptions::default()
            },
            cancellation.clone(),
        )
        .expect("HTTP client");
        let mut request = RequestSpec::new(
            Method::GET,
            Url::parse(&format!("{}/retry", api.uri())).expect("URL"),
            "cancellation.retry-backoff",
        );
        request.replay = ReplayPolicy::Safe;
        let execution = tokio::spawn(async move { client.execute(&manager, request).await });
        wait_for_request_count(&api, 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), execution)
            .await
            .expect("backoff cancellation returns promptly")
            .expect("request task completes")
            .expect_err("request must be canceled");

        assert_eq!(error.code, "request_canceled");
        assert_eq!(error.http_status, Some(503));
        assert_eq!(error.request_id.as_deref(), Some("retry-canceled-1"));
        assert_eq!(error.details["phase"], "retry_backoff");
        assert_eq!(error.details["remote_response_received"], true);
        assert_eq!(error.details["remote_request_completed"], true);
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "error_response_received_completion_unknown"
        );
        assert_eq!(error.details["safe_to_replay"], true);
        assert!(!error.retryable);
        assert_eq!(api.received_requests().await.expect("requests").len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn response_body_cancellation_preserves_response_status_and_request_id() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("server address");
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = Arc::clone(&requests);
        let (headers_sent, headers_received) = tokio::sync::oneshot::channel();
        let (release_server, released) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            observed_requests.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).expect("read request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-ID: body-canceled-1\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{",
                )
                .expect("write headers and partial body");
            stream.flush().expect("flush response prefix");
            let _ = headers_sent.send(());
            let _ = released.recv_timeout(Duration::from_secs(5));
        });
        let directory = tempdir().expect("temporary directory");
        let manager = bearer_manager(directory.path(), "body-cancellation-token");
        let cancellation = CancellationToken::new();
        let client = HttpClient::new_with_cancellation(
            HttpOptions {
                timeout: Duration::from_secs(5),
                ..HttpOptions::default()
            },
            cancellation.clone(),
        )
        .expect("HTTP client");
        let request = RequestSpec::new(
            Method::POST,
            Url::parse(&format!("http://{address}/mutation")).expect("URL"),
            "cancellation.response-body",
        );
        let execution = tokio::spawn(async move { client.execute(&manager, request).await });
        headers_received.await.expect("response prefix sent");
        tokio::time::sleep(Duration::from_millis(100)).await;

        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), execution)
            .await
            .expect("body cancellation returns promptly")
            .expect("request task completes")
            .expect_err("request must be canceled");
        let _ = release_server.send(());
        server.join().expect("server thread");

        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(error.code, "request_canceled");
        assert_eq!(error.http_status, Some(200));
        assert_eq!(error.request_id.as_deref(), Some("body-canceled-1"));
        assert_eq!(error.details["phase"], "response_body");
        assert_eq!(error.details["remote_response_received"], true);
        assert_eq!(error.details["remote_request_completed"], true);
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "success_response_received_completion_unknown"
        );
        assert_eq!(error.details["safe_to_replay"], false);
        assert_eq!(error.details["outcome_ambiguous"], true);
        assert!(
            error.details["verification_hint"]
                .as_str()
                .is_some_and(|hint| hint.contains("body-canceled-1"))
        );
        assert!(!error.retryable);
    }

    #[test]
    fn post_limit_is_checked_before_allocating_a_request() {
        assert!(validate_body_size(&Method::POST, MAX_POST_BODY_BYTES).is_ok());
        assert!(validate_body_size(&Method::POST, MAX_POST_BODY_BYTES + 1).is_err());
        assert!(validate_body_size(&Method::PUT, MAX_POST_BODY_BYTES + 1).is_ok());
    }

    #[test]
    fn absurd_timeout_is_rejected_without_deadline_arithmetic() {
        let error = HttpClient::new(HttpOptions {
            timeout: Duration::MAX,
            ..HttpOptions::default()
        })
        .expect_err("absurd timeout must fail");
        assert_eq!(error.code, "invalid_timeout");
    }

    #[tokio::test]
    async fn unsafe_request_is_not_replayed_after_unauthorized_response() {
        let auth = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-1",
                "token_type": "bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&auth)
            .await;
        let api = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/mutation"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "no"})))
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target(&auth.uri()),
            &Environment::from_pairs([("RELTIO_CLIENT_SECRET".to_owned(), "secret".to_owned())]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions {
            timeout: Duration::from_secs(2),
            retry_delay_cap: Some(Duration::ZERO),
            ..HttpOptions::default()
        })
        .expect("HTTP client");
        let request = RequestSpec::new(
            Method::DELETE,
            Url::parse(&format!("{}/mutation", api.uri())).expect("URL"),
            "unsafe.test",
        );

        let error = client
            .execute(&manager, request)
            .await
            .expect_err("401 must not be replayed");

        assert_eq!(error.code, "auth_invalid_token");
        assert!(!error.retryable);
        assert_eq!(error.details["safe_to_replay"], false);
    }

    #[tokio::test]
    async fn safe_unauthorized_request_reacquires_once_and_redacts_every_token_generation() {
        let auth = MockServer::start().await;
        let acquisitions = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&acquisitions);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                let token = if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                    "RED"
                } else {
                    "prefixsuffix"
                };
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": token,
                    "token_type": "bearer",
                    "expires_in": 3600
                }))
            })
            .expect(2)
            .mount(&auth)
            .await;
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/entity"))
            .and(header("authorization", "Bearer RED"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&api)
            .await;
        Mock::given(method("GET"))
            .and(path("/entity"))
            .and(header("authorization", "Bearer prefixsuffix"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "RED": "old-token-key",
                "synthesized": "prefixREDsuffix",
                "message": "password=ordinary-upstream-data",
                "refresh_token": "unrecognized-response-credential"
            })))
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target(&auth.uri()),
            &Environment::from_pairs([("RELTIO_CLIENT_SECRET".to_owned(), "secret".to_owned())]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions::default()).expect("HTTP client");
        let mut request = RequestSpec::new(
            Method::GET,
            Url::parse(&format!("{}/entity", api.uri())).expect("URL"),
            "safe.auth-replay",
        );
        request.replay = ReplayPolicy::Safe;

        let response = client.execute(&manager, request).await.expect("request");
        let typed = response.json().expect("typed JSON");
        let rendered = typed.to_string();
        assert!(!rendered.contains("prefixsuffix"));
        assert!(!rendered.contains("RED"));
        assert_eq!(typed[""], "old-token-key");
        assert_eq!(typed["synthesized"], "");
        assert_eq!(typed["message"], "password=ordinary-upstream-data");
        assert_eq!(typed["refresh_token"], "unrecognized-response-credential");

        let raw_structured = response.data_value().expect("raw structured response");
        assert_eq!(raw_structured["refresh_token"], "");
        assert_eq!(raw_structured["synthesized"], "");
        assert_eq!(raw_structured["message"], "password=ordinary-upstream-data");
        assert_eq!(response.attempts, 2);
        assert_eq!(acquisitions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unsafe_redirect_reports_ambiguous_outcome() {
        let api = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mutation"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "/accepted")
                    .insert_header("x-request-id", "mutation-accepted-1"),
            )
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target("https://auth.reltio.com"),
            &Environment::from_pairs([(
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "opaque-token".to_owned(),
            )]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions::default()).expect("HTTP client");
        let request = RequestSpec::new(
            Method::POST,
            Url::parse(&format!("{}/mutation", api.uri())).expect("URL"),
            "unsafe.redirect",
        );

        let error = client
            .execute(&manager, request)
            .await
            .expect_err("redirect must fail");
        assert_eq!(error.code, "redirect_refused");
        assert_eq!(error.request_id.as_deref(), Some("mutation-accepted-1"));
        assert_eq!(error.details["safe_to_replay"], false);
        assert_eq!(error.details["outcome_ambiguous"], true);
        assert_eq!(error.details["remote_response_received"], true);
        assert_eq!(error.details["remote_request_completed"], true);
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "redirect_response_received_completion_unknown"
        );
        assert!(
            !error
                .output_guard()
                .expect("redirect output guard")
                .permits(b"opaque-token")
        );
    }

    #[tokio::test]
    async fn transport_failure_carries_the_active_credential_guard() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve local port");
        let address = listener.local_addr().expect("local address");
        drop(listener);
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target("https://auth.reltio.com"),
            &Environment::from_pairs([(
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "opaque-token".to_owned(),
            )]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(1),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions {
            timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(1),
            no_retry: true,
            ..HttpOptions::default()
        })
        .expect("HTTP client");
        let request = RequestSpec::new(
            Method::GET,
            Url::parse(&format!("http://{address}/entity")).expect("URL"),
            "transport.test",
        );

        let error = client
            .execute(&manager, request)
            .await
            .expect_err("connection must fail");

        assert_eq!(error.code, "network_request_failed");
        assert!(
            !error
                .output_guard()
                .expect("transport output guard")
                .permits(b"opaque-token")
        );
    }

    #[tokio::test]
    async fn ambiguous_unsafe_timeout_is_not_retryable() {
        let api = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mutation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_json(json!({"ok": true})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target("https://auth.reltio.com"),
            &Environment::from_pairs([(
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "opaque-token".to_owned(),
            )]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(1),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions {
            timeout: Duration::from_millis(500),
            ..HttpOptions::default()
        })
        .expect("HTTP client");
        let request = RequestSpec::new(
            Method::POST,
            Url::parse(&format!("{}/mutation", api.uri())).expect("URL"),
            "unsafe.test",
        );

        let error = client
            .execute(&manager, request)
            .await
            .expect_err("request must time out");

        assert_eq!(error.code, "request_timeout");
        assert!(!error.retryable);
        assert_eq!(error.details["safe_to_replay"], false);
        assert_eq!(error.details["phase"], "send");
        assert_eq!(error.details["outcome_ambiguous"], true);
        assert_eq!(error.details["remote_response_received"], false);
        assert!(error.details["remote_request_completed"].is_null());
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "request_sent_completion_unknown"
        );
        assert!(error.details["verification_hint"].is_string());
        assert!(
            !error
                .output_guard()
                .expect("timeout output guard")
                .permits(b"opaque-token")
        );
    }

    #[tokio::test]
    async fn response_body_stall_obeys_deadline_and_unsafe_replay_policy() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("server address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).expect("read request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-ID: mutation-applied-1\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{",
                )
                .expect("write headers and partial body");
            stream.flush().expect("flush response prefix");
            thread::sleep(Duration::from_millis(500));
        });
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target("https://auth.reltio.com"),
            &Environment::from_pairs([(
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "opaque-token".to_owned(),
            )]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(1),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions {
            timeout: Duration::from_millis(150),
            ..HttpOptions::default()
        })
        .expect("HTTP client");
        let request = RequestSpec::new(
            Method::POST,
            Url::parse(&format!("http://{address}/mutation")).expect("URL"),
            "unsafe.body-stall",
        );

        let error = client
            .execute(&manager, request)
            .await
            .expect_err("body must time out");

        assert_eq!(error.code, "request_timeout");
        assert!(!error.retryable);
        assert_eq!(error.details["safe_to_replay"], false);
        assert_eq!(error.details["phase"], "response_body");
        assert_eq!(error.http_status, Some(200));
        assert_eq!(error.request_id.as_deref(), Some("mutation-applied-1"));
        assert_eq!(error.details["outcome_ambiguous"], true);
        assert_eq!(error.details["remote_response_received"], true);
        assert_eq!(error.details["remote_request_completed"], true);
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "success_response_received_completion_unknown"
        );
        assert!(
            !error
                .output_guard()
                .expect("response timeout output guard")
                .permits(b"opaque-token")
        );
        server.join().expect("server thread");
    }

    #[tokio::test]
    async fn included_response_headers_remove_token_and_signature_values() {
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/headers"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("opaque-token", "secret-header-name")
                    .insert_header("refresh-token", "response-refresh-secret")
                    .insert_header("x-amz-security-token", "cloud-session-secret")
                    .insert_header("request-signature", "signature-secret")
                    .insert_header("x-safe-header", "visible")
                    .set_body_json(json!({"ok": true})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target("https://auth.reltio.com"),
            &Environment::from_pairs([(
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "opaque-token".to_owned(),
            )]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions::default()).expect("HTTP client");
        let mut request = RequestSpec::new(
            Method::GET,
            Url::parse(&format!("{}/headers", api.uri())).expect("URL"),
            "headers.test",
        );
        request.replay = ReplayPolicy::Safe;

        let response = client.execute(&manager, request).await.expect("request");

        assert_eq!(
            response.headers.get("x-safe-header").map(String::as_str),
            Some("visible")
        );
        assert!(!response.headers.contains_key("opaque-token"));
        assert!(
            !response
                .headers
                .values()
                .any(|value| value == "secret-header-name")
        );
        assert!(!response.headers.contains_key("refresh-token"));
        assert!(!response.headers.contains_key("x-amz-security-token"));
        assert!(!response.headers.contains_key("request-signature"));
    }

    #[test]
    fn response_header_suffixes_cannot_synthesize_active_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert("first-opaque", HeaderValue::from_static("left"));
        headers.insert("second-value", HeaderValue::from_static("right"));
        let secrets = ["first-opaque", "second-value", "[REDACTED]#2"];
        let sanitized = sanitized_headers(&headers, &secrets).expect("sanitized headers");
        let rendered = serde_json::to_string(&sanitized).expect("header JSON");
        assert!(secrets.iter().all(|secret| !rendered.contains(secret)));
        assert!(sanitized.contains_key("[REDACTED]#3"));

        let digit_secrets = (0..=9).map(|digit| digit.to_string()).collect::<Vec<_>>();
        let digit_secrets = digit_secrets.iter().map(String::as_str).collect::<Vec<_>>();
        let mut exhausted = HeaderMap::new();
        exhausted.insert("0a", HeaderValue::from_static("left"));
        exhausted.insert("1a", HeaderValue::from_static("middle"));
        exhausted.insert("2a", HeaderValue::from_static("right"));
        let error = sanitized_headers(&exhausted, &digit_secrets)
            .expect_err("unrepresentable collisions must fail");
        assert_eq!(error.code, "api_response_redaction_failed");
        assert_eq!(
            error.details["reason"],
            "redacted_header_collision_limit_exceeded"
        );
    }

    #[tokio::test]
    async fn enormous_retry_after_exhausts_budget_without_panicking() {
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rate"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "18446744073709551615")
                    .set_body_json(json!({"message": "wait"})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let directory = tempdir().expect("temporary directory");
        let manager = TokenManager::from_target(
            &auth_target("https://auth.reltio.com"),
            &Environment::from_pairs([(
                "RELTIO_ACCESS_TOKEN".to_owned(),
                "opaque-token".to_owned(),
            )]),
            directory.path().to_path_buf(),
            TokenManagerOptions::default(),
            Duration::from_secs(2),
        )
        .expect("token manager");
        let client = HttpClient::new(HttpOptions {
            timeout: Duration::from_secs(2),
            ..HttpOptions::default()
        })
        .expect("HTTP client");
        let mut request = RequestSpec::new(
            Method::GET,
            Url::parse(&format!("{}/rate", api.uri())).expect("URL"),
            "retry-after.test",
        );
        request.replay = ReplayPolicy::Safe;

        let error = client
            .execute(&manager, request)
            .await
            .expect_err("retry cannot fit");

        assert_eq!(error.code, "retry_budget_exhausted");
    }

    #[test]
    fn malformed_error_json_is_omitted_without_echoing_escaped_secrets() {
        let error = api_error(
            StatusCode::BAD_REQUEST,
            None,
            br#"{"refresh_token":"upstream-refresh-secret","message":"access\u002dsecret"#,
            Some("application/json"),
            &["access-secret"],
            true,
            1,
        );
        let rendered = serde_json::to_string(&error).expect("error serializes");
        assert!(!rendered.contains("upstream-refresh-secret"));
        assert!(!rendered.contains("access\\u002dsecret"));
        assert_eq!(error.details["response"]["body_omitted"], true);
    }
}
