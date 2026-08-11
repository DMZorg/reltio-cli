use std::collections::BTreeSet;
use std::io::{self, Read};
use std::time::Instant;

use is_terminal::IsTerminal;
use reltio_client::MAX_POST_BODY_BYTES;
use reltio_client::auth::TokenManagerOptions;
use reltio_client::entities::{
    EntityGetOptions, EntityScanRequest, EntitySearchRequest, SEARCH_BOUNDARY_WARNING,
    SEARCH_RESULT_BOUNDARY, validate_get, validate_query_filter, validate_scan, validate_search,
};
use reltio_client::error::{ErrorCategory, ReltioError, Result, json_parse_details};
use reltio_client::fs::read_bounded;
use reltio_client::http::{RequestSpec, validate_user_header};
use reltio_client::redaction::{redact_bytes, redact_text, redact_url, sensitive_query_key};
use reltio_client::registry::{PracticeCoverage, Registry, ReplayPolicy, Safety};
use reltio_client::service::{Service, ServiceResolver, canonical_url_path};
use reqwest::Method;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::cli::{ApiPracticesSubcommand, ApiRequestArgs, ApiSubcommand, OutputFormat};
use crate::commands::{Runtime, sha256_hex};
use crate::output::{Meta, write_raw_guarded, write_success_guarded, write_warning_guarded};

pub async fn run(runtime: &Runtime, command: ApiSubcommand) -> Result<()> {
    match command {
        ApiSubcommand::Request(arguments) => request(runtime, arguments).await,
        ApiSubcommand::Practices(command) => practices(runtime, command.command),
    }
}

async fn request(runtime: &Runtime, arguments: ApiRequestArgs) -> Result<()> {
    let started = Instant::now();
    let method = parse_method(&arguments.method)?;
    if arguments.service == Service::Auth {
        return Err(ReltioError::new(
            "raw_auth_service_refused",
            ErrorCategory::Safety,
            "raw requests to the authentication service are disabled because they require provider-specific secret handling",
        )
        .with_hint("Use the typed `reltio auth` commands."));
    }
    if runtime.render.format == OutputFormat::Raw && arguments.include_headers {
        return Err(ReltioError::usage(
            "raw_headers_ambiguous",
            "--include-headers cannot be combined with --output raw",
        ));
    }
    if runtime.render.format == OutputFormat::Raw && io::stdout().is_terminal() {
        return Err(ReltioError::new(
            "raw_output_tty_refused",
            ErrorCategory::Safety,
            "refusing to write an unwrapped upstream response to terminal stdout",
        )
        .with_hint("Redirect raw output to a deliberate file or process."));
    }
    if matches!(method, Method::GET | Method::HEAD) && arguments.data.is_some() {
        return Err(ReltioError::usage(
            "read_method_body_refused",
            "GET and HEAD raw requests cannot include --data",
        ));
    }
    let query = parse_query(&arguments.query)?;
    let headers = parse_headers(&arguments.header, arguments.data.is_some())?;
    let body = arguments.data.as_deref().map(read_input).transpose()?;

    let (_, target) = runtime.config_and_target()?;
    let resolver = ServiceResolver::new(target.clone());
    let base = resolver.base_url(arguments.service)?;
    let mut url = resolver.request_url(arguments.service, &arguments.path)?;
    let endpoint_path = endpoint_relative_path(&base, &url)?;
    if !query.is_empty() {
        let mut serializer = url.query_pairs_mut();
        for (key, value) in &query {
            serializer.append_pair(key, value);
        }
    }
    let registry = Registry::embedded()?;
    let endpoint = registry.match_endpoint(arguments.service, method.as_str(), &endpoint_path);
    let matched_practices =
        registry.match_practices(arguments.service, method.as_str(), &endpoint_path);
    let mut coverage = registry.request_coverage(endpoint, &matched_practices);
    for practice in &matched_practices {
        apply_practice_preflight(&practice.id, &query)?;
    }
    if let Some(endpoint) = endpoint {
        if !apply_endpoint_preflight(endpoint.id.as_str(), &query, &headers, body.as_deref())? {
            coverage = PracticeCoverage::Partial;
        }
    }
    let search_window = reviewed_entity_search_window(endpoint, &query, body.as_deref())?;
    let read_semantic = endpoint.is_some_and(|entry| entry.safety == Safety::Read)
        || matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    if arguments.service == Service::Mcp && !read_semantic {
        return Err(ReltioError::new(
            "raw_mcp_mutation_refused",
            ErrorCategory::Safety,
            "generic raw MCP mutations are disabled until a reviewed tool-specific tenant adapter exists",
        ));
    }
    let unreviewed_mutation = !read_semantic && endpoint.is_none();
    if unreviewed_mutation {
        coverage = PracticeCoverage::Unknown;
    }
    if !resolver.request_is_tenant_bound(arguments.service, &url, body.as_deref())? {
        return Err(ReltioError::new(
            "request_tenant_unbound",
            ErrorCategory::Safety,
            "raw request URL is not provably bound to the selected tenant",
        )
        .with_hint("Use the documented tenant position for this service, or add a reviewed typed endpoint adapter."));
    }
    if !read_semantic {
        require_mutation_confirmation(
            runtime,
            &target,
            unreviewed_mutation,
            arguments.allow_unreviewed_endpoint,
        )?;
    }
    let replay = if coverage == PracticeCoverage::Reviewed {
        endpoint.map_or(ReplayPolicy::Unsafe, |entry| entry.replay)
    } else {
        ReplayPolicy::Unsafe
    };
    let mut practice_ids = endpoint.map_or_else(Vec::new, |entry| entry.practice_ids.clone());
    for practice in matched_practices {
        if !practice_ids.contains(&practice.id) {
            practice_ids.push(practice.id.clone());
        }
    }
    if runtime.globals.dry_run {
        let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
        let auth_status = manager.status()?;
        let known_secrets = dry_run_known_secrets(runtime);
        let mut meta =
            Meta::new("api.request").with_target(&target, Some(&arguments.service.to_string()));
        meta.elapsed_ms = started.elapsed().as_millis();
        meta.practice_coverage = Some(coverage);
        meta.practice_ids.clone_from(&practice_ids);
        meta.consistency = endpoint.map(|entry| entry.consistency);
        meta.auth_source = Some(auth_status.source);
        append_request_warnings(&mut meta, coverage, endpoint, &query);
        let mut plan = json!({
            "dry_run": true,
            "method": method.as_str(),
            "url": sanitized_plan_url(&url, &known_secrets),
            "query": query.iter().map(|(key, value)| json!({
                "name": redact_text(key, &known_secrets),
                "value": if sensitive_query_key(key) {
                    "[REDACTED]".to_owned()
                } else {
                    redact_text(value, &known_secrets)
                }
            })).collect::<Vec<_>>(),
            "body_bytes": body.as_ref().map_or(0, Vec::len),
            "body_sha256": body.as_deref().map(sha256_hex),
            "endpoint_id": endpoint.map(|entry| entry.id.as_str()),
            "safety": if read_semantic { "read" } else { "mutation" },
            "safe_to_replay": replay != ReplayPolicy::Unsafe,
            "retry_policy": {
                "classification": replay,
                "automatic_retries_enabled": !runtime.globals.no_retry
                    && replay != ReplayPolicy::Unsafe,
                "no_retry": runtime.globals.no_retry
            },
            "practice_coverage": coverage,
            "network_request_sent": false
        });
        let output_guard = manager.redact_local_credentials(&mut plan, &known_secrets)?;
        return write_success_guarded(&plan, &meta, runtime.render, &output_guard);
    }

    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let local_guard = manager.output_guard()?;
    let auth_status = manager
        .status()
        .map_err(|error| error.with_output_guard(local_guard.clone()))?;
    if matches!(
        runtime.render.format,
        OutputFormat::Raw | OutputFormat::Table
    ) {
        for warning in [
            coverage_warning(coverage),
            endpoint_warning(endpoint),
            query_warning(endpoint, &query),
        ]
        .into_iter()
        .flatten()
        {
            write_warning_guarded(warning, runtime.globals.quiet, &local_guard)?;
        }
    }
    if runtime.render.format == OutputFormat::Raw
        && coverage == PracticeCoverage::Reviewed
        && runtime.globals.verbose > 0
    {
        write_warning_guarded(
            "practice_coverage=reviewed",
            runtime.globals.quiet,
            &local_guard,
        )?;
    }
    let mut spec = RequestSpec::new(method, url, "api.request");
    spec.headers = headers;
    spec.body = body;
    spec.replay = replay;
    spec.practice_ids.clone_from(&practice_ids);
    let mut response = runtime
        .http_client()
        .map_err(|error| error.with_output_guard(local_guard.clone()))?
        .execute(&manager, spec)
        .await
        .map_err(|error| error.with_output_guard(local_guard.clone()))?;
    let mut output_guard = response.output_guard();
    let refreshed_local_guard = manager.output_guard().map_err(|error| {
        response_output_error(
            error,
            response.status,
            response.request_id.clone(),
            !read_semantic,
        )
    })?;
    output_guard.merge(&refreshed_local_guard);

    if runtime.render.format == OutputFormat::Raw {
        let boundary_reached = if search_window.is_some() {
            let data = response.data_value().map_err(|error| {
                response_output_error(
                    error,
                    response.status,
                    response.request_id.clone(),
                    !read_semantic,
                )
            })?;
            entity_search_boundary_reached(search_window, &data)
        } else {
            false
        };
        let body = response.redacted_body().map_err(|error| {
            response_output_error(
                error,
                response.status,
                response.request_id.clone(),
                !read_semantic,
            )
        })?;
        let status = response.status;
        let request_id = response.request_id.clone();
        if boundary_reached {
            write_warning_guarded(
                SEARCH_BOUNDARY_WARNING,
                runtime.globals.quiet,
                &output_guard,
            )
            .map_err(|error| {
                response_output_error(error, status, request_id.clone(), !read_semantic)
            })?;
        }
        drop(response);
        return write_raw_guarded(&body, false, &output_guard)
            .map_err(|error| response_output_error(error, status, request_id, !read_semantic));
    }
    let response_data = response.data_value().map_err(|error| {
        response_output_error(
            error,
            response.status,
            response.request_id.clone(),
            !read_semantic,
        )
    })?;
    let boundary_reached = entity_search_boundary_reached(search_window, &response_data);
    let data = if arguments.include_headers {
        json!({
            "body": response_data,
            "headers": std::mem::take(&mut response.headers)
        })
    } else {
        response_data
    };
    let mut meta =
        Meta::new("api.request").with_target(&target, Some(&arguments.service.to_string()));
    meta.elapsed_ms = started.elapsed().as_millis();
    meta.request_id.clone_from(&response.request_id);
    meta.http_status = Some(response.status);
    meta.attempts = Some(response.attempts);
    meta.practice_coverage = Some(coverage);
    meta.practice_ids = std::mem::take(&mut response.applied_practice_ids);
    meta.consistency = endpoint.map(|entry| entry.consistency);
    meta.auth_source = Some(auth_status.source);
    append_request_warnings(&mut meta, coverage, endpoint, &query);
    if boundary_reached {
        meta.warnings.push(SEARCH_BOUNDARY_WARNING.to_owned());
        if runtime.render.format == OutputFormat::Table {
            write_warning_guarded(
                SEARCH_BOUNDARY_WARNING,
                runtime.globals.quiet,
                &output_guard,
            )
            .map_err(|error| {
                response_output_error(
                    error,
                    response.status,
                    response.request_id.clone(),
                    !read_semantic,
                )
            })?;
        }
    }
    let status = response.status;
    let request_id = response.request_id.clone();
    drop(response);
    write_success_guarded(&data, &meta, runtime.render, &output_guard)
        .map_err(|error| response_output_error(error, status, request_id, !read_semantic))
}

fn response_output_error(
    mut error: ReltioError,
    status: u16,
    request_id: Option<String>,
    mutation: bool,
) -> ReltioError {
    error.http_status = Some(status);
    error.request_id.clone_from(&request_id);
    let output_error_details = std::mem::replace(&mut error.details, Value::Null);
    let mut details = serde_json::Map::new();
    details.insert("remote_response_received".to_owned(), Value::Bool(true));
    details.insert("output_error".to_owned(), output_error_details);
    if mutation {
        details.insert("remote_request_completed".to_owned(), Value::Bool(true));
        details.insert("remote_operation_completed".to_owned(), Value::Null);
        details.insert(
            "remote_operation_state".to_owned(),
            Value::String(if status == 202 {
                "accepted_async_completion_unknown".to_owned()
            } else {
                "success_response_received_completion_unknown".to_owned()
            }),
        );
        details.insert("safe_to_replay".to_owned(), Value::Bool(false));
        let verification_hint = request_id.map_or_else(
            || {
                "Do not replay: a successful remote response was received, but operation completion could not be represented safely."
                    .to_owned()
            },
            |id| {
                format!(
                    "Do not replay: a successful remote response was received, but operation completion could not be represented safely; retain request ID {id}."
                )
            },
        );
        details.insert(
            "verification_hint".to_owned(),
            Value::String(verification_hint.clone()),
        );
        error.hint = Some(verification_hint);
    }
    error.details = Value::Object(details);
    error.retryable = false;
    error
}

fn append_request_warnings(
    meta: &mut Meta,
    coverage: PracticeCoverage,
    endpoint: Option<&reltio_client::registry::Endpoint>,
    query: &[(String, String)],
) {
    if let Some(warning) = coverage_warning(coverage) {
        meta.warnings.push(warning.to_owned());
    }
    if let Some(warning) = endpoint_warning(endpoint) {
        meta.warnings.push(warning.to_owned());
    }
    if let Some(warning) = query_warning(endpoint, query) {
        meta.warnings.push(warning.to_owned());
    }
}

fn coverage_warning(coverage: PracticeCoverage) -> Option<&'static str> {
    match coverage {
        PracticeCoverage::Unknown => Some(
            "this raw endpoint has unknown API-practice coverage and receives conservative no-retry behavior",
        ),
        PracticeCoverage::Partial => Some(
            "this raw endpoint has only partial API-practice coverage; matched guards are enforced and retries remain conservative",
        ),
        PracticeCoverage::Reviewed => None,
    }
}

fn endpoint_warning(endpoint: Option<&reltio_client::registry::Endpoint>) -> Option<&'static str> {
    endpoint
        .is_some_and(|endpoint| {
            matches!(
                endpoint.id.as_str(),
                "entity.search.get" | "entity.search.get_alias"
            )
        })
        .then_some("Reltio recommends POST /entities/_search with parameters in the request body")
}

fn query_warning(
    endpoint: Option<&reltio_client::registry::Endpoint>,
    query: &[(String, String)],
) -> Option<&'static str> {
    (endpoint.is_some_and(|endpoint| endpoint.id == "entity.get")
        && query
            .iter()
            .any(|(key, _)| key == "reverseTranscodeLookups"))
    .then_some(
        "reverseTranscodeLookups was introduced by Reltio as Preview; verify tenant availability and destination-system mappings before relying on the result",
    )
}

fn dry_run_known_secrets(runtime: &Runtime) -> Vec<&str> {
    ["RELTIO_ACCESS_TOKEN", "RELTIO_CLIENT_SECRET"]
        .into_iter()
        .filter_map(|name| runtime.environment.get(name))
        .collect()
}

fn sanitized_plan_url(url: &url::Url, known_secrets: &[&str]) -> String {
    let mut sanitized = redact_url(url);
    let pairs = sanitized
        .query_pairs()
        .map(|(key, value)| {
            let value = if sensitive_query_key(&key) {
                "[REDACTED]".to_owned()
            } else {
                redact_text(&value, known_secrets)
            };
            (key.into_owned(), value)
        })
        .collect::<Vec<_>>();
    if sanitized.query().is_some() {
        sanitized.set_query(None);
        let mut query = sanitized.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(&key, &value);
        }
    }
    String::from_utf8(redact_bytes(
        sanitized.to_string().as_bytes(),
        known_secrets,
    ))
    .unwrap_or_else(|_| unreachable!("a URL plus ASCII redaction markers remains UTF-8"))
}

fn practices(runtime: &Runtime, command: ApiPracticesSubcommand) -> Result<()> {
    let started = Instant::now();
    let registry = Registry::embedded()?;
    let (command_name, data) = match command {
        ApiPracticesSubcommand::List => (
            "api.practices.list",
            Value::Array(
                registry
                    .practices()
                    .iter()
                    .map(|practice| {
                        json!({
                            "id": practice.id,
                            "title": practice.title,
                            "classification": practice.classification,
                            "enforcement": practice.enforcement,
                            "commands": practice.commands,
                            "reviewed_at": practice.reviewed_at
                        })
                    })
                    .collect(),
            ),
        ),
        ApiPracticesSubcommand::Show { id } => {
            let practice = registry.practice(&id).ok_or_else(|| {
                ReltioError::usage(
                    "practice_not_found",
                    format!("API practice {id:?} is not registered"),
                )
            })?;
            (
                "api.practices.show",
                serde_json::to_value(practice).map_err(|error| {
                    ReltioError::internal(format!("failed to encode API practice: {error}"))
                })?,
            )
        }
        ApiPracticesSubcommand::Check { strict } => {
            let age = registry.review_age_days()?;
            if strict && age > 14 {
                return Err(ReltioError::new(
                    "practice_review_stale",
                    ErrorCategory::Conflict,
                    format!("API-practice review is {age} days old; release maximum is 14"),
                )
                .with_hint("Review the current corpus, release notes, and deprecation notices before release."));
            }
            let all_reviewed = registry
                .endpoints()
                .iter()
                .all(|endpoint| registry.coverage(Some(endpoint)) == PracticeCoverage::Reviewed);
            if strict && !all_reviewed {
                return Err(ReltioError::new(
                    "practice_coverage_incomplete",
                    ErrorCategory::Conflict,
                    "one or more typed endpoints have incomplete API-practice coverage",
                ));
            }
            let endpoint_coverage = registry
                .endpoints()
                .iter()
                .map(|endpoint| {
                    json!({
                        "id": endpoint.id,
                        "service": endpoint.service,
                        "method": endpoint.method,
                        "path_pattern": endpoint.path_pattern,
                        "commands": endpoint.commands,
                        "practice_ids": endpoint.practice_ids,
                        "test_ids": endpoint.test_ids,
                        "coverage": registry.coverage(Some(endpoint))
                    })
                })
                .collect::<Vec<_>>();
            (
                "api.practices.check",
                json!({
                    "valid": all_reviewed,
                    "schema_version": 1,
                    "endpoint_count": registry.endpoints().len(),
                    "practice_count": registry.practices().len(),
                    "reviewed_at": registry.metadata().reviewed_at,
                    "review_age_days": age,
                    "release_freshness_max_days": 14,
                    "release_fresh": age <= 14,
                    "corpus_commit": registry.metadata().corpus_commit,
                    "release_notes_through": registry.metadata().release_notes_through,
                    "endpoints": endpoint_coverage
                }),
            )
        }
    };
    let mut meta = Meta::new(command_name);
    meta.elapsed_ms = started.elapsed().as_millis();
    write_success_guarded(&data, &meta, runtime.render, &runtime.local_output_guard())
}

fn parse_method(value: &str) -> Result<Method> {
    let upper = value.to_ascii_uppercase();
    let method = Method::from_bytes(upper.as_bytes()).map_err(|_| {
        ReltioError::usage(
            "invalid_http_method",
            format!("invalid HTTP method {value:?}"),
        )
    })?;
    if matches!(method, Method::CONNECT | Method::TRACE) {
        return Err(ReltioError::new(
            "unsafe_http_method_refused",
            ErrorCategory::Safety,
            "CONNECT and TRACE are not supported by the raw request command",
        ));
    }
    Ok(method)
}

fn parse_query(values: &[String]) -> Result<Vec<(String, String)>> {
    let mut parsed = Vec::with_capacity(values.len());
    let mut keys = BTreeSet::new();
    for pair in values {
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            ReltioError::usage("invalid_query", "query values must use KEY=VALUE")
        })?;
        if key.is_empty() || key.contains(['\r', '\n', '\0']) || value.contains(['\r', '\n', '\0'])
        {
            return Err(ReltioError::usage(
                "invalid_query",
                "query key or value is empty or contains a control character",
            ));
        }
        if sensitive_query_key(key) {
            return Err(ReltioError::new(
                "query_secret_refused",
                ErrorCategory::Safety,
                format!("sensitive query key {key:?} is not allowed"),
            ));
        }
        if key.eq_ignore_ascii_case("_method") || key.eq_ignore_ascii_case("x-http-method-override")
        {
            return Err(ReltioError::new(
                "method_override_refused",
                ErrorCategory::Safety,
                "query-based HTTP method overrides are not allowed",
            ));
        }
        if !keys.insert(key.to_ascii_lowercase()) {
            return Err(ReltioError::usage(
                "duplicate_query_parameter",
                format!("query parameter {key:?} was provided more than once"),
            ));
        }
        parsed.push((key.to_owned(), value.to_owned()));
    }
    Ok(parsed)
}

fn parse_headers(values: &[String], has_body: bool) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for value in values {
        let (name, value) = value
            .split_once(':')
            .ok_or_else(|| ReltioError::usage("invalid_header", "headers must use NAME: VALUE"))?;
        let (name, value) = validate_user_header(name, value)?;
        if headers.insert(name.clone(), value).is_some() {
            return Err(ReltioError::usage(
                "duplicate_header",
                format!("header {:?} was provided more than once", name.as_str()),
            ));
        }
    }
    if !headers.contains_key(ACCEPT) {
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    }
    if has_body && !headers.contains_key(CONTENT_TYPE) {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    Ok(headers)
}

fn read_input(value: &str) -> Result<Vec<u8>> {
    let bytes = if value == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .take(u64::try_from(MAX_POST_BODY_BYTES).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ReltioError::io("failed to read request body from stdin", &error))?;
        bytes
    } else if let Some(path) = value.strip_prefix('@') {
        read_bounded(path.as_ref(), false).map_err(|error| {
            if error.code == "local_io_error" {
                ReltioError::usage("local_input_unreadable", error.message.clone())
                    .with_details(error.details.clone())
            } else {
                error
            }
        })?
    } else {
        value.as_bytes().to_vec()
    };
    if bytes.len() > MAX_POST_BODY_BYTES {
        return Err(ReltioError::usage(
            "post_body_too_large",
            format!(
                "request body is {} bytes; Reltio's POST limit is {} bytes",
                bytes.len(),
                MAX_POST_BODY_BYTES
            ),
        ));
    }
    Ok(bytes)
}

fn endpoint_relative_path(base: &url::Url, request: &url::Url) -> Result<String> {
    let base_path = canonical_url_path(base)?;
    let request_path = canonical_url_path(request)?;
    let relative = request_path.strip_prefix(&base_path).ok_or_else(|| {
        ReltioError::new(
            "request_path_escape",
            ErrorCategory::Safety,
            "request URL is outside the selected service base",
        )
    })?;
    Ok(format!("/{}", relative.trim_start_matches('/')))
}

fn apply_endpoint_preflight(
    endpoint_id: &str,
    query: &[(String, String)],
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<bool> {
    match endpoint_id {
        "entity.get" => {
            if body.is_some() {
                return Err(ReltioError::usage(
                    "entity_get_body_refused",
                    "entity.get does not accept a request body",
                ));
            }
            let options = EntityGetOptions {
                select: query_value(query, "select").map(ToOwned::to_owned),
                time: query_entity_get_u64(query, "time")?,
                options: query_value(query, "options")
                    .map(|value| value.split(',').map(ToOwned::to_owned).collect())
                    .unwrap_or_default(),
                merge_duplicate_crosswalks: query_entity_get_bool(
                    query,
                    "mergeDuplicateCrosswalks",
                )?
                .unwrap_or(false),
                default_max_values: query_entity_get_u32(query, "defaultMaxValues")?,
                explicit_survivorship_group: query_value(query, "explicitSurvivorshipGroup")
                    .map(ToOwned::to_owned),
                reverse_transcode_lookups: query_value(query, "reverseTranscodeLookups")
                    .map(ToOwned::to_owned),
                send_masked: query_entity_get_bool(query, "sendMasked")?.unwrap_or(false),
            };
            validate_get("entities/reviewed", &options)?;
            Ok(query.iter().all(|(key, _)| {
                matches!(
                    key.as_str(),
                    "select"
                        | "time"
                        | "options"
                        | "mergeDuplicateCrosswalks"
                        | "defaultMaxValues"
                        | "explicitSurvivorshipGroup"
                        | "reverseTranscodeLookups"
                        | "sendMasked"
                )
            }))
        }
        "entity.search" => {
            require_json_content_type(headers)?;
            let body = body.ok_or_else(|| {
                ReltioError::usage(
                    "entity_search_body_required",
                    "reviewed POST entity search requires a JSON body",
                )
            })?;
            if query.iter().any(|(key, _)| {
                matches!(
                    key.as_str(),
                    "filter"
                        | "select"
                        | "max"
                        | "offset"
                        | "sort"
                        | "order"
                        | "options"
                        | "defaultMaxValues"
                        | "activeness"
                        | "scoreEnabled"
                )
            }) {
                return Err(ReltioError::usage(
                    "entity_search_query_override_refused",
                    "search parameters must be in the POST body; query values would override them",
                ));
            }
            let request: EntitySearchRequest = serde_json::from_slice(body).map_err(|error| {
                ReltioError::usage(
                    "entity_search_body_invalid",
                    "entity search body is invalid JSON or does not match the reviewed schema",
                )
                .with_details(json_parse_details(&error))
            })?;
            validate_search(&request)?;
            Ok(query.is_empty())
        }
        "entity.search.get" | "entity.search.get_alias" => {
            if body.is_some() {
                return Err(ReltioError::usage(
                    "entity_search_get_body_refused",
                    "reviewed GET entity search does not accept a request body",
                ));
            }
            let request = EntitySearchRequest {
                filter: query_value(query, "filter").map(ToOwned::to_owned),
                select: query_value(query, "select").map(ToOwned::to_owned),
                max: query_u32(query, "max")?.unwrap_or(50),
                offset: query_u32(query, "offset")?.unwrap_or(0),
                sort: query_value(query, "sort").map(ToOwned::to_owned),
                order: query_value(query, "order").map(ToOwned::to_owned),
                options: query_value(query, "options")
                    .map(|value| value.split(',').map(ToOwned::to_owned).collect())
                    .unwrap_or_default(),
                default_max_values: query_u32(query, "defaultMaxValues")?,
                activeness: query_value(query, "activeness").map(ToOwned::to_owned),
                score_enabled: query_bool(query, "scoreEnabled")?,
            };
            validate_search(&request)?;
            Ok(query.iter().all(|(key, _)| {
                matches!(
                    key.as_str(),
                    "filter"
                        | "select"
                        | "max"
                        | "offset"
                        | "sort"
                        | "order"
                        | "options"
                        | "defaultMaxValues"
                        | "activeness"
                        | "scoreEnabled"
                )
            }))
        }
        "entity.scan" => {
            if body.is_some() {
                require_json_content_type(headers)?;
            }
            let cursor = body.map(parse_scan_cursor).transpose()?;
            let request = EntityScanRequest {
                filter: query_value(query, "filter").map(ToOwned::to_owned),
                cursor,
                max: query_value(query, "max")
                    .map(|value| {
                        value.parse::<u32>().map_err(|_| {
                            ReltioError::usage(
                                "invalid_page_size",
                                "entity scan max must be an unsigned integer",
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(100),
                select: query_value(query, "select").map(ToOwned::to_owned),
                options: query_value(query, "options")
                    .map(|value| value.split(',').map(ToOwned::to_owned).collect())
                    .unwrap_or_default(),
                activeness: query_value(query, "activeness").map(ToOwned::to_owned),
            };
            validate_scan(&request)?;
            Ok(query.iter().all(|(key, _)| {
                matches!(
                    key.as_str(),
                    "filter" | "max" | "select" | "options" | "activeness"
                )
            }))
        }
        _ => Ok(true),
    }
}

fn reviewed_entity_search_window(
    endpoint: Option<&reltio_client::registry::Endpoint>,
    query: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<Option<(u32, u32)>> {
    let Some(endpoint) = endpoint else {
        return Ok(None);
    };
    match endpoint.id.as_str() {
        "entity.search" => {
            let body = body.ok_or_else(|| {
                ReltioError::usage(
                    "entity_search_body_required",
                    "reviewed POST entity search requires a JSON body",
                )
            })?;
            let request: EntitySearchRequest = serde_json::from_slice(body).map_err(|error| {
                ReltioError::usage(
                    "entity_search_body_invalid",
                    "entity search body is invalid JSON or does not match the reviewed schema",
                )
                .with_details(json_parse_details(&error))
            })?;
            Ok(Some((request.offset, request.max)))
        }
        "entity.search.get" | "entity.search.get_alias" => Ok(Some((
            query_u32(query, "offset")?.unwrap_or(0),
            query_u32(query, "max")?.unwrap_or(50),
        ))),
        _ => Ok(None),
    }
}

fn entity_search_boundary_reached(search_window: Option<(u32, u32)>, data: &Value) -> bool {
    let Some((offset, maximum)) = search_window else {
        return false;
    };
    let Some(entities) = data.as_array() else {
        return false;
    };
    let returned = u32::try_from(entities.len()).unwrap_or(u32::MAX);
    returned == maximum && offset.saturating_add(returned) >= SEARCH_RESULT_BOUNDARY
}

fn apply_practice_preflight(practice_id: &str, query: &[(String, String)]) -> Result<()> {
    if practice_id == "ENTITY-FILTER-QUERY-001" {
        if let Some(filter) = query_value(query, "filter") {
            validate_query_filter(filter)?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScanContinuation {
    cursor: RawScanCursor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScanCursor {
    value: String,
}

fn parse_scan_cursor(body: &[u8]) -> Result<String> {
    let continuation: RawScanContinuation = serde_json::from_slice(body).map_err(|error| {
        ReltioError::usage(
            "scan_cursor_body_invalid",
            "entity scan cursor body is invalid JSON or does not match the reviewed schema",
        )
        .with_details(json_parse_details(&error))
    })?;
    Ok(continuation.cursor.value)
}

fn query_value<'a>(query: &'a [(String, String)], expected: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(key, _)| key == expected)
        .map(|(_, value)| value.as_str())
}

fn query_u32(query: &[(String, String)], name: &str) -> Result<Option<u32>> {
    query_value(query, name)
        .map(|value| {
            value.parse::<u32>().map_err(|_| {
                ReltioError::usage(
                    "invalid_entity_search_query",
                    format!("entity search {name} must be an unsigned integer"),
                )
            })
        })
        .transpose()
}

fn query_bool(query: &[(String, String)], name: &str) -> Result<Option<bool>> {
    query_value(query, name)
        .map(|value| match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(ReltioError::usage(
                "invalid_entity_search_query",
                format!("entity search {name} must be true or false"),
            )),
        })
        .transpose()
}

fn query_entity_get_u64(query: &[(String, String)], name: &str) -> Result<Option<u64>> {
    query_value(query, name)
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                ReltioError::usage(
                    "invalid_entity_get_query",
                    format!("entity get {name} must be an unsigned integer"),
                )
            })
        })
        .transpose()
}

fn query_entity_get_u32(query: &[(String, String)], name: &str) -> Result<Option<u32>> {
    query_value(query, name)
        .map(|value| {
            value.parse::<u32>().map_err(|_| {
                ReltioError::usage(
                    "invalid_entity_get_query",
                    format!("entity get {name} must be an unsigned integer"),
                )
            })
        })
        .transpose()
}

fn query_entity_get_bool(query: &[(String, String)], name: &str) -> Result<Option<bool>> {
    query_value(query, name)
        .map(|value| {
            if value.eq_ignore_ascii_case("true") {
                Ok(true)
            } else if value.eq_ignore_ascii_case("false") {
                Ok(false)
            } else {
                Err(ReltioError::usage(
                    "invalid_entity_get_query",
                    format!("entity get {name} must be true or false"),
                ))
            }
        })
        .transpose()
}

fn require_json_content_type(headers: &HeaderMap) -> Result<()> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if content_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(ReltioError::usage(
            "reviewed_endpoint_content_type_invalid",
            "reviewed entity POST endpoints require Content-Type: application/json",
        ))
    }
}

fn require_mutation_confirmation(
    runtime: &Runtime,
    target: &reltio_client::config::ResolvedTarget,
    unreviewed: bool,
    allow_unreviewed: bool,
) -> Result<()> {
    if unreviewed && !allow_unreviewed {
        return Err(ReltioError::new(
            "unreviewed_mutation_refused",
            ErrorCategory::Safety,
            "raw mutation endpoint has not been reviewed against current Reltio practices",
        )
        .with_hint("Review the endpoint, then add --allow-unreviewed-endpoint and normal confirmations deliberately."));
    }
    if !runtime.globals.yes {
        return Err(ReltioError::new(
            "mutation_confirmation_required",
            ErrorCategory::Safety,
            "raw mutation requires --yes in non-interactive mode",
        ));
    }
    if (target.production || target.target_overridden || target.profile.is_none())
        && runtime.globals.confirm_tenant.as_deref() != Some(target.tenant.as_str())
    {
        return Err(ReltioError::new(
            "tenant_confirmation_required",
            ErrorCategory::Safety,
            format!(
                "mutation against this production, unnamed, or overridden target requires --confirm-tenant {}",
                target.tenant
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_failure_after_mutation_success_is_never_replayable() {
        let error = response_output_error(
            ReltioError::new(
                "output_write_failed",
                ErrorCategory::Internal,
                "injected output failure",
            ),
            200,
            Some("mutation-request-1".to_owned()),
            true,
        );

        assert!(!error.retryable);
        assert_eq!(error.http_status, Some(200));
        assert_eq!(error.request_id.as_deref(), Some("mutation-request-1"));
        assert_eq!(error.details["remote_request_completed"], true);
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "success_response_received_completion_unknown"
        );
        assert_eq!(error.details["safe_to_replay"], false);
        assert!(error.details["verification_hint"].is_string());
        assert!(
            error
                .hint
                .as_deref()
                .is_some_and(|hint| hint.contains("Do not replay"))
        );
    }

    #[test]
    fn accepted_mutation_output_failure_does_not_claim_async_completion() {
        let error = response_output_error(
            ReltioError::new(
                "api_response_invalid_json",
                ErrorCategory::Api,
                "injected sanitization failure",
            )
            .with_details(json!({"reason": "duplicate_json_key_refused"})),
            202,
            None,
            true,
        );
        assert!(error.details["remote_operation_completed"].is_null());
        assert_eq!(
            error.details["remote_operation_state"],
            "accepted_async_completion_unknown"
        );
        assert_eq!(
            error.details["output_error"]["reason"],
            "duplicate_json_key_refused"
        );
        assert_eq!(error.details["safe_to_replay"], false);
    }
}
