use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use is_terminal::IsTerminal;
use reltio_client::MAX_POST_BODY_BYTES;
use reltio_client::auth::TokenManagerOptions;
use reltio_client::cancellation::{CancellationToken, EventStamp};
use reltio_client::entities::{
    CROSSWALK_ID_FALLBACK_WARNING, ENTITY_MATCH_TYPES, ENTITY_SCAN_OPTIONS_PROVISIONAL_WARNING,
    EntityByCrosswalkRequest, EntityGetOptions, EntityHistoryRequest, EntityMatchesRequest,
    EntityScanRequest, EntitySearchRequest, HISTORY_BOUNDARY_WARNING,
    HISTORY_CANONICAL_VALUES_WARNING, HISTORY_RESULT_BOUNDARY, POTENTIAL_MATCHES_FRESHNESS_WARNING,
    SEARCH_BOUNDARY_WARNING, SEARCH_RESULT_BOUNDARY, entity_by_crosswalk_id_fallback_detected,
    validate_by_crosswalk, validate_get, validate_history, validate_matches, validate_query_filter,
    validate_scan, validate_scan_option_acknowledgement, validate_search,
};
use reltio_client::error::{ErrorCategory, ReltioError, Result, json_parse_details};
use reltio_client::fs::read_bounded;
use reltio_client::http::{ApiResponse, RequestSpec, validate_user_header};
use reltio_client::redaction::{redact_bytes, redact_text, redact_url, sensitive_query_key};
use reltio_client::registry::{PracticeCoverage, Registry, ReplayPolicy, Safety};
use reltio_client::service::{
    Service, ServiceResolver, canonical_url_path, validate_request_path_argument,
};
use reqwest::Method;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit;
use crate::cli::{ApiPracticesSubcommand, ApiRequestArgs, ApiSubcommand, OutputFormat};
use crate::commands::{Runtime, sha256_hex};
use crate::output::Meta;
use crate::release;

const HISTORY_SELECTION_WARNING: &str = "Reltio recommends showAll=true when no history filter is used and offers skipReferenceAttributesProcessing when lower latency is more important than complete reference-attribute deltas";

pub async fn run(runtime: &Runtime, command: ApiSubcommand) -> Result<()> {
    match command {
        ApiSubcommand::Request(arguments) => request(runtime, arguments).await,
        ApiSubcommand::Practices(command) => practices(runtime, command.command).await,
    }
}

async fn request(runtime: &Runtime, arguments: ApiRequestArgs) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
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
    let absolute_path_argument = url::Url::parse(&arguments.path).is_ok();
    if !absolute_path_argument
        && arguments.service == Service::Data
        && method == Method::POST
        && is_unverified_scan_route_argument(&arguments.path)
    {
        return Err(unverified_scan_route_error());
    }
    validate_request_path_argument(&arguments.path)?;
    if !absolute_path_argument
        && arguments.service == Service::Data
        && method == Method::POST
        && is_reviewed_scan_route_argument(&arguments.path)
    {
        validate_scan_query_before_body(&query, arguments.allow_unverified_scan_options)?;
    } else if !absolute_path_argument && arguments.allow_unverified_scan_options {
        validate_scan_option_acknowledgement(&[], true)?;
    }
    let resolved_absolute = if absolute_path_argument {
        let (_, target) = runtime.config_and_target()?;
        let resolver = ServiceResolver::new(target.clone());
        let base = resolver.base_url(arguments.service)?;
        let url = resolver.request_url(arguments.service, &arguments.path)?;
        let endpoint_path = endpoint_relative_path(&base, &url)?;
        validate_scan_route_before_body(
            arguments.service,
            &method,
            &endpoint_path,
            &query,
            arguments.allow_unverified_scan_options,
        )?;
        Some((target, resolver, url, endpoint_path))
    } else {
        None
    };
    let body = match arguments.data.as_deref() {
        Some(value) => Some(read_input(value, deadline, &runtime.cancellation).await?),
        None => None,
    };
    let (target, resolver, mut url, endpoint_path) = if let Some(resolved) = resolved_absolute {
        resolved
    } else {
        let (_, target) = runtime.config_and_target()?;
        let resolver = ServiceResolver::new(target.clone());
        let base = resolver.base_url(arguments.service)?;
        let url = resolver.request_url(arguments.service, &arguments.path)?;
        let endpoint_path = endpoint_relative_path(&base, &url)?;
        validate_scan_route_before_body(
            arguments.service,
            &method,
            &endpoint_path,
            &query,
            arguments.allow_unverified_scan_options,
        )?;
        (target, resolver, url, endpoint_path)
    };
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
        if !apply_endpoint_preflight(
            endpoint.id.as_str(),
            &endpoint_path,
            &query,
            &headers,
            body.as_deref(),
        )? {
            coverage = PracticeCoverage::Partial;
        }
    }
    let crosswalk_lookup = endpoint
        .filter(|endpoint| endpoint.id == "entity.by-crosswalk")
        .map(|_| entity_crosswalk_request(&endpoint_path, &query))
        .transpose()?;
    let scan_continuation =
        endpoint.is_some_and(|endpoint| endpoint.id == "entity.scan") && body.is_some();
    let search_window = reviewed_entity_search_window(endpoint, &query, body.as_deref())?;
    let history_window = reviewed_entity_history_window(endpoint, &query)?;
    let read_semantic = request_is_read_semantic(endpoint.map(|entry| entry.safety), &method);
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
        if !runtime.globals.dry_run && !audit::mutation_audit_available(registry) {
            return Err(ReltioError::new(
                "mutation_audit_unavailable",
                ErrorCategory::Safety,
                "raw mutations are disabled until mutation_audit_v1 has implementation evidence",
            )
            .with_details(json!({
                "required_contract": audit::MUTATION_AUDIT_CONTRACT_ID,
                "body_sha256": body.as_deref().map(sha256_hex),
                "remote_response_received": false,
                "remote_request_completed": false,
                "remote_operation_completed": false,
                "remote_operation_state": "request_not_sent",
                "local_state_committed": false,
                "safe_to_replay": true
            }))
            .with_hint("Use --dry-run to inspect the plan. Add a reviewed typed mutation and complete the audit-result contract before sending it."));
        }
    }
    let replay = request_replay_policy(
        coverage,
        endpoint.map(|entry| entry.replay),
        scan_continuation,
    );
    let mut practice_ids = endpoint.map_or_else(Vec::new, |entry| entry.practice_ids.clone());
    for practice in matched_practices {
        if !practice_ids.contains(&practice.id) {
            practice_ids.push(practice.id.clone());
        }
    }
    if runtime.globals.dry_run {
        let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
        let auth_status = runtime.token_manager_status(&manager, deadline).await?;
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
        runtime
            .ensure_not_cancelled("before_dry_run_output", false)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        if Instant::now() >= deadline {
            return Err(ReltioError::new(
                "request_timeout",
                ErrorCategory::Timeout,
                "the command exceeded its overall timeout during local preflight",
            )
            .with_details(json!({
                "phase": "dry_run",
                "remote_response_received": false,
                "remote_request_completed": false,
                "remote_operation_completed": false,
                "remote_operation_state": "request_not_sent",
                "local_state_committed": false,
                "safe_to_replay": true
            }))
            .with_output_guard(output_guard));
        }
        return runtime
            .emit_success(&plan, &meta, deadline, &output_guard)
            .await;
    }

    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let local_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let auth_status = runtime
        .token_manager_status(&manager, deadline)
        .await
        .map_err(|error| error.with_output_guard(local_guard.clone()))?;
    if matches!(
        runtime.render.format,
        OutputFormat::Raw | OutputFormat::Table
    ) {
        for warning in request_warnings(coverage, endpoint, &query) {
            runtime
                .emit_warning(warning, deadline, &local_guard)
                .await?;
        }
    }
    if runtime.render.format == OutputFormat::Raw
        && coverage == PracticeCoverage::Reviewed
        && runtime.globals.verbose > 0
    {
        runtime
            .emit_warning("practice_coverage=reviewed", deadline, &local_guard)
            .await?;
    }
    let mut spec = RequestSpec::new(method, url, "api.request");
    spec.headers = headers;
    spec.body = body;
    spec.replay = replay;
    spec.practice_ids.clone_from(&practice_ids);
    let mut response = runtime
        .http_client_until(deadline)
        .map_err(|error| error.with_output_guard(local_guard.clone()))?
        .execute_until(&manager, spec, deadline)
        .await
        .map_err(|error| error.with_output_guard(local_guard.clone()))?;
    let mut output_guard = response.output_guard();
    let refreshed_local_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await
        .map_err(|error| {
            response_output_error(
                error,
                response.status,
                response.request_id.clone(),
                read_semantic,
                replay,
            )
        })?;
    output_guard.merge(&refreshed_local_guard);
    ensure_api_response_active(
        runtime,
        deadline,
        &response,
        read_semantic,
        replay,
        &output_guard,
    )?;

    if runtime.render.format == OutputFormat::Raw {
        let (search_boundary_reached, history_boundary_reached, crosswalk_fallback_detected) =
            if search_window.is_some() || history_window.is_some() || crosswalk_lookup.is_some() {
                let data = response.data_value().map_err(|error| {
                    response_output_error(
                        error,
                        response.status,
                        response.request_id.clone(),
                        read_semantic,
                        replay,
                    )
                })?;
                (
                    entity_search_boundary_reached(search_window, &data),
                    entity_history_boundary_reached(history_window, &data),
                    crosswalk_lookup.as_ref().is_some_and(|lookup| {
                        data.as_array().is_some_and(|entries| {
                            entity_by_crosswalk_id_fallback_detected(entries, lookup)
                        })
                    }),
                )
            } else {
                (false, false, false)
            };
        let body = response.redacted_body().map_err(|error| {
            response_output_error(
                error,
                response.status,
                response.request_id.clone(),
                read_semantic,
                replay,
            )
        })?;
        let status = response.status;
        let request_id = response.request_id.clone();
        for warning in [
            search_boundary_reached.then_some(SEARCH_BOUNDARY_WARNING),
            history_boundary_reached.then_some(HISTORY_BOUNDARY_WARNING),
            crosswalk_fallback_detected.then_some(CROSSWALK_ID_FALLBACK_WARNING),
        ]
        .into_iter()
        .flatten()
        {
            runtime
                .emit_warning(warning, deadline, &output_guard)
                .await
                .map_err(|error| {
                    response_output_error(error, status, request_id.clone(), read_semantic, replay)
                })?;
        }
        ensure_api_response_active(
            runtime,
            deadline,
            &response,
            read_semantic,
            replay,
            &output_guard,
        )?;
        drop(response);
        return runtime
            .emit_raw(&body, false, deadline, &output_guard)
            .await
            .map_err(|error| {
                response_output_error(error, status, request_id, read_semantic, replay)
            });
    }
    let response_data = response.data_value().map_err(|error| {
        response_output_error(
            error,
            response.status,
            response.request_id.clone(),
            read_semantic,
            replay,
        )
    })?;
    let search_boundary_reached = entity_search_boundary_reached(search_window, &response_data);
    let history_boundary_reached = entity_history_boundary_reached(history_window, &response_data);
    let crosswalk_fallback_detected = crosswalk_lookup.as_ref().is_some_and(|lookup| {
        response_data
            .as_array()
            .is_some_and(|entries| entity_by_crosswalk_id_fallback_detected(entries, lookup))
    });
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
    for warning in [
        search_boundary_reached.then_some(SEARCH_BOUNDARY_WARNING),
        history_boundary_reached.then_some(HISTORY_BOUNDARY_WARNING),
        crosswalk_fallback_detected.then_some(CROSSWALK_ID_FALLBACK_WARNING),
    ]
    .into_iter()
    .flatten()
    {
        meta.warnings.push(warning.to_owned());
        if runtime.render.format == OutputFormat::Table {
            runtime
                .emit_warning(warning, deadline, &output_guard)
                .await
                .map_err(|error| {
                    response_output_error(
                        error,
                        response.status,
                        response.request_id.clone(),
                        read_semantic,
                        replay,
                    )
                })?;
        }
    }
    let status = response.status;
    let request_id = response.request_id.clone();
    ensure_api_response_active(
        runtime,
        deadline,
        &response,
        read_semantic,
        replay,
        &output_guard,
    )?;
    drop(response);
    runtime
        .emit_success(&data, &meta, deadline, &output_guard)
        .await
        .map_err(|error| response_output_error(error, status, request_id, read_semantic, replay))
}

fn ensure_api_response_active(
    runtime: &Runtime,
    deadline: Instant,
    response: &ApiResponse,
    read_semantic: bool,
    replay: ReplayPolicy,
    output_guard: &reltio_client::redaction::OutputGuard,
) -> Result<()> {
    let (code, category, message) = if runtime.cancellation.is_cancelled() {
        (
            "request_canceled",
            ErrorCategory::Canceled,
            "the command was canceled after a successful response was received",
        )
    } else if Instant::now() >= deadline {
        (
            "request_timeout",
            ErrorCategory::Timeout,
            "the command exceeded its overall timeout after a successful response was received",
        )
    } else {
        return Ok(());
    };
    let replay_safe = read_semantic && replay != ReplayPolicy::Unsafe;
    let mut error = ReltioError::new(code, category, message)
        .with_http_status(response.status)
        .with_request_id(response.request_id.clone())
        .with_details(json!({
            "phase": "response_processing",
            "remote_response_received": true,
            "remote_request_completed": true,
            "remote_operation_completed": read_semantic.then_some(true),
            "remote_operation_state": if read_semantic {
                "success_response_received"
            } else {
                "success_response_received_completion_unknown"
            },
            "local_state_committed": false,
            "safe_to_replay": replay_safe
        }))
        .with_output_guard(output_guard.clone());
    if read_semantic && !replay_safe {
        error.hint = Some(
            "Do not replay: the successful response consumed a one-shot request such as a scan cursor continuation. Resume from the last durable checkpoint instead."
                .to_owned(),
        );
    }
    Err(error)
}

fn response_output_error(
    mut error: ReltioError,
    status: u16,
    request_id: Option<String>,
    read_semantic: bool,
    replay: ReplayPolicy,
) -> ReltioError {
    error.http_status = Some(status);
    error.request_id.clone_from(&request_id);
    let output_error_details = std::mem::replace(&mut error.details, Value::Null);
    let mut details = serde_json::Map::new();
    details.insert("remote_response_received".to_owned(), Value::Bool(true));
    details.insert("remote_request_completed".to_owned(), Value::Bool(true));
    details.insert("local_state_committed".to_owned(), Value::Bool(false));
    details.insert("output_error".to_owned(), output_error_details);
    if read_semantic {
        let replay_safe = replay != ReplayPolicy::Unsafe;
        details.insert("remote_operation_completed".to_owned(), Value::Bool(true));
        details.insert(
            "remote_operation_state".to_owned(),
            Value::String("success_response_received".to_owned()),
        );
        details.insert("safe_to_replay".to_owned(), Value::Bool(replay_safe));
        if !replay_safe {
            let verification_hint = request_id.map_or_else(
                || {
                    "Do not replay: the successful response consumed a one-shot request such as a scan cursor continuation. Resume from the last durable checkpoint instead."
                        .to_owned()
                },
                |id| {
                    format!(
                        "Do not replay request {id}: its successful response consumed a one-shot request such as a scan cursor continuation. Resume from the last durable checkpoint instead."
                    )
                },
            );
            details.insert(
                "verification_hint".to_owned(),
                Value::String(verification_hint.clone()),
            );
            error.hint = Some(verification_hint);
        }
    } else {
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
    for warning in request_warnings(coverage, endpoint, query) {
        meta.warnings.push(warning.to_owned());
    }
}

fn request_warnings(
    coverage: PracticeCoverage,
    endpoint: Option<&reltio_client::registry::Endpoint>,
    query: &[(String, String)],
) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    warnings.extend(coverage_warning(coverage));
    warnings.extend(endpoint_warning(endpoint));
    warnings.extend(query_warnings(endpoint, query));
    warnings
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
    match endpoint.map(|endpoint| endpoint.id.as_str()) {
        Some("entity.search.get" | "entity.search.get_alias") => {
            Some("Reltio recommends POST /entities/_search with parameters in the request body")
        }
        Some("entity.history") => Some(HISTORY_CANONICAL_VALUES_WARNING),
        _ => None,
    }
}

fn query_warnings(
    endpoint: Option<&reltio_client::registry::Endpoint>,
    query: &[(String, String)],
) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    match endpoint.map(|endpoint| endpoint.id.as_str()) {
        Some("entity.get")
            if query
                .iter()
                .any(|(key, _)| key == "reverseTranscodeLookups") =>
        {
            warnings.push(
                "reverseTranscodeLookups was introduced by Reltio as Preview; verify tenant availability and destination-system mappings before relying on the result",
            );
        }
        Some("entity.matches") => warnings.push(POTENTIAL_MATCHES_FRESHNESS_WARNING),
        Some("entity.scan")
            if query_value(query, "options").is_some_and(|value| !value.is_empty()) =>
        {
            warnings.push(ENTITY_SCAN_OPTIONS_PROVISIONAL_WARNING);
        }
        Some("entity.history")
            if query_value(query, "filter").is_none()
                && query_value(query, "showAll") != Some("true") =>
        {
            warnings.push(HISTORY_SELECTION_WARNING);
        }
        _ => {}
    }
    warnings
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

async fn practices(runtime: &Runtime, command: ApiPracticesSubcommand) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
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
        ApiPracticesSubcommand::Check {
            strict,
            release_ready,
            expected_release,
        } => {
            if let Some(expected_release) = expected_release {
                let expected_release = normalized_stable_release(&expected_release)?;
                let manifest_release = registry.requirements().target_release.as_str();
                let cli_release = env!("CARGO_PKG_VERSION");
                if !release_versions_match(&expected_release, manifest_release, cli_release) {
                    return Err(ReltioError::new(
                        "release_version_mismatch",
                        ErrorCategory::Conflict,
                        "the release tag, product contract, and built package version do not match",
                    )
                    .with_details(json!({
                        "expected_release": expected_release,
                        "manifest_release": manifest_release,
                        "cli_version": cli_release
                    }))
                    .with_hint("Update the package and PRD-bound release manifest together before creating the stable tag."));
                }
            }
            let age = registry.review_age_days()?;
            if (strict || release_ready) && age > 14 {
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
            if (strict || release_ready) && !all_reviewed {
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
                        "commands": endpoint.commands().collect::<Vec<_>>(),
                        "command_links": endpoint.command_links,
                        "practice_ids": endpoint.practice_ids,
                        "test_ids": endpoint.test_ids,
                        "coverage": registry.coverage(Some(endpoint))
                    })
                })
                .collect::<Vec<_>>();
            let release_readiness = release::readiness(registry)?;
            if release_ready && release_readiness["release_ready"] != true {
                return Err(ReltioError::new(
                    "release_operations_incomplete",
                    ErrorCategory::Conflict,
                    "the v0.1.0 product MVP still has missing operations, operation evidence, approved endpoint bindings, capabilities, acceptance scenarios, or contract evidence/runtime support",
                )
                .with_details(release_readiness)
                .with_hint("Resolve every blocker reported by `reltio api practices check` before a stable v0.1.0 release."));
            }
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
                    "release_requirements": release_readiness,
                    "corpus_commit": registry.metadata().corpus_commit,
                    "release_notes_through": registry.metadata().release_notes_through,
                    "endpoints": endpoint_coverage
                }),
            )
        }
    };
    let mut meta = Meta::new(command_name);
    meta.elapsed_ms = started.elapsed().as_millis();
    runtime
        .emit_success(&data, &meta, deadline, &runtime.environment_output_guard())
        .await
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

fn normalized_stable_release(value: &str) -> Result<String> {
    let normalized = value.strip_prefix('v').unwrap_or(value);
    let segments = normalized.split('.').collect::<Vec<_>>();
    let valid_segment = |segment: &&str| {
        !segment.is_empty()
            && segment.bytes().all(|byte| byte.is_ascii_digit())
            && (segment.len() == 1 || !segment.starts_with('0'))
    };
    if segments.len() != 3 || !segments.iter().all(valid_segment) {
        return Err(ReltioError::usage(
            "invalid_expected_release",
            format!("expected stable release version MAJOR.MINOR.PATCH, received {value:?}"),
        ));
    }
    Ok(normalized.to_owned())
}

fn release_versions_match(expected: &str, manifest: &str, cli: &str) -> bool {
    expected == manifest && expected == cli
}

fn request_is_read_semantic(endpoint_safety: Option<Safety>, method: &Method) -> bool {
    endpoint_safety.map_or_else(
        || matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS),
        |safety| safety == Safety::Read,
    )
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

async fn read_input(
    value: &str,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    let bytes = if value == "-" {
        read_request_body_stdin(deadline, cancellation).await?
    } else if let Some(path) = value.strip_prefix('@') {
        read_request_body_file(PathBuf::from(path), deadline, cancellation).await?
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

async fn read_request_body_stdin(
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    if let Some(control) = active_input_control(cancellation, deadline) {
        return Err(request_body_control_error(control));
    }
    let timeline = Arc::new(Mutex::new(InputReaderState::Pending));
    let thread_timeline = Arc::clone(&timeline);
    let thread_cancellation = cancellation.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("reltio-request-body".to_owned())
        .spawn(move || {
            let control = begin_input_read(&thread_timeline, &thread_cancellation, deadline);
            let result = control.map_or_else(
                || {
                    let mut bytes = Vec::new();
                    io::stdin()
                        .take(u64::try_from(MAX_POST_BODY_BYTES).unwrap_or(u64::MAX) + 1)
                        .read_to_end(&mut bytes)
                        .map(|_| bytes)
                        .map_err(|error| {
                            ReltioError::io("failed to read request body from stdin", &error)
                        })
                },
                |control| Err(request_body_control_error(control)),
            );
            let completed_at = publish_input_completion(&thread_timeline, &thread_cancellation);
            let _ = sender.send((completed_at, result));
        })
        .map_err(|error| ReltioError::io("failed to start the request-body reader", &error))?;

    await_input_reader(receiver, timeline, deadline, cancellation).await
}

async fn read_request_body_file(
    path: PathBuf,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    if let Some(control) = active_input_control(cancellation, deadline) {
        return Err(request_body_control_error(control));
    }
    let timeline = Arc::new(Mutex::new(InputReaderState::Pending));
    let thread_timeline = Arc::clone(&timeline);
    let thread_cancellation = cancellation.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("reltio-request-file".to_owned())
        .spawn(move || {
            let control = begin_input_read(&thread_timeline, &thread_cancellation, deadline);
            let result = control.map_or_else(
                || {
                    read_bounded(&path, false).map_err(|error| {
                        if error.code == "local_io_error" {
                            ReltioError::usage("local_input_unreadable", error.message.clone())
                                .with_details(error.details.clone())
                        } else {
                            error
                        }
                    })
                },
                |control| Err(request_body_control_error(control)),
            );
            let completed_at = publish_input_completion(&thread_timeline, &thread_cancellation);
            let _ = sender.send((completed_at, result));
        })
        .map_err(|error| ReltioError::io("failed to start the request-file reader", &error))?;

    await_input_reader(receiver, timeline, deadline, cancellation).await
}

async fn await_input_reader(
    mut receiver: tokio::sync::oneshot::Receiver<(EventStamp, Result<Vec<u8>>)>,
    timeline: Arc<Mutex<InputReaderState>>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timeout);
    tokio::select! {
        biased;
        result = &mut receiver => resolve_input_result(result, cancellation, deadline),
        () = cancellation.cancelled() => {
            resolve_input_control(
                &mut receiver,
                &timeline,
                cancellation,
                deadline,
                InputControl::Canceled,
            ).await
        }
        () = &mut timeout => {
            resolve_input_control(
                &mut receiver,
                &timeline,
                cancellation,
                deadline,
                InputControl::TimedOut,
            ).await
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputReaderState {
    Pending,
    Reading,
    Completing,
    Completed(EventStamp),
}

fn begin_input_read(
    timeline: &Mutex<InputReaderState>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Option<InputControl> {
    let mut state = timeline
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let control = active_input_control(cancellation, deadline);
    if control.is_none() {
        *state = InputReaderState::Reading;
    }
    control
}

fn publish_input_completion(
    timeline: &Mutex<InputReaderState>,
    cancellation: &CancellationToken,
) -> EventStamp {
    let mut state = timeline
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *state = InputReaderState::Completing;
    let completed_at = cancellation.event_stamp();
    *state = InputReaderState::Completed(completed_at);
    completed_at
}

async fn resolve_input_control(
    receiver: &mut tokio::sync::oneshot::Receiver<(EventStamp, Result<Vec<u8>>)>,
    timeline: &Mutex<InputReaderState>,
    cancellation: &CancellationToken,
    deadline: Instant,
    fallback: InputControl,
) -> Result<Vec<u8>> {
    let state = *timeline
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if matches!(
        state,
        InputReaderState::Completing | InputReaderState::Completed(_)
    ) {
        resolve_input_result(receiver.await, cancellation, deadline)
    } else {
        Err(request_body_control_error(
            active_input_control(cancellation, deadline).unwrap_or(fallback),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputControl {
    Canceled,
    TimedOut,
}

fn active_input_control(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Option<InputControl> {
    let canceled_at = cancellation.cancelled_at();
    if Instant::now() < deadline {
        return canceled_at.map(|_| InputControl::Canceled);
    }
    Some(
        if canceled_at.is_some_and(|stamp| stamp.occurred_at_or_before(deadline)) {
            InputControl::Canceled
        } else {
            InputControl::TimedOut
        },
    )
}

fn input_control_after(
    completed_at: EventStamp,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Option<InputControl> {
    let canceled_at = cancellation.cancelled_at();
    let canceled_first = canceled_at.is_some_and(|stamp| !completed_at.precedes(stamp));
    let timed_out_first = !completed_at.occurred_before(deadline);
    match (canceled_first, timed_out_first) {
        (false, false) => None,
        (true, false) => Some(InputControl::Canceled),
        (false, true) => Some(InputControl::TimedOut),
        (true, true) => Some(
            if canceled_at.is_some_and(|stamp| stamp.occurred_at_or_before(deadline)) {
                InputControl::Canceled
            } else {
                InputControl::TimedOut
            },
        ),
    }
}

fn resolve_input_result(
    result: std::result::Result<
        (EventStamp, Result<Vec<u8>>),
        tokio::sync::oneshot::error::RecvError,
    >,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>> {
    match result {
        Ok((completed_at, result)) => input_control_after(completed_at, cancellation, deadline)
            .map_or(result, |control| Err(request_body_control_error(control))),
        Err(_) => active_input_control(cancellation, deadline).map_or_else(
            || {
                Err(ReltioError::internal(
                    "the request-body reader terminated without a result",
                ))
            },
            |control| Err(request_body_control_error(control)),
        ),
    }
}

fn request_body_control_error(control: InputControl) -> ReltioError {
    let (code, category, message) = match control {
        InputControl::Canceled => (
            "request_canceled",
            ErrorCategory::Canceled,
            "request-body input was canceled",
        ),
        InputControl::TimedOut => (
            "request_timeout",
            ErrorCategory::Timeout,
            "request-body input exceeded the overall timeout",
        ),
    };
    ReltioError::new(code, category, message).with_details(json!({
        "phase": "request_body_input",
        "remote_response_received": false,
        "remote_request_completed": false,
        "remote_operation_completed": false,
        "remote_operation_state": "request_not_sent",
        "network_request_sent": false,
        "local_state_committed": false,
        "safe_to_replay": true
    }))
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

fn is_unverified_scan_route(endpoint_path: &str) -> bool {
    endpoint_path == "/entities/_scan/"
        || endpoint_path.trim_end_matches('/') == "/entities/v2/_scan"
}

fn is_unverified_scan_route_argument(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let path = path.trim_start_matches('/');
    matches!(
        path,
        "entities/_scan/" | "entities/v2/_scan" | "entities/v2/_scan/"
    )
}

fn is_reviewed_scan_route_argument(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.trim_start_matches('/') == "entities/_scan"
}

fn validate_scan_route_before_body(
    service: Service,
    method: &Method,
    endpoint_path: &str,
    query: &[(String, String)],
    allow_unverified_options: bool,
) -> Result<()> {
    if service != Service::Data || method != Method::POST {
        if allow_unverified_options {
            validate_scan_option_acknowledgement(&[], true)?;
        }
        return Ok(());
    }
    if is_unverified_scan_route(endpoint_path) {
        return Err(unverified_scan_route_error());
    }
    if endpoint_path == "/entities/_scan" {
        validate_scan_query_before_body(query, allow_unverified_options)?;
    } else if allow_unverified_options {
        validate_scan_option_acknowledgement(&[], true)?;
    }
    Ok(())
}

fn validate_scan_query_before_body(
    query: &[(String, String)],
    allow_unverified_options: bool,
) -> Result<()> {
    let request = EntityScanRequest {
        filter: Some(
            query_value(query, "filter")
                .unwrap_or("prebody-scan-validation")
                .to_owned(),
        ),
        cursor: None,
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
    validate_scan_option_acknowledgement(&request.options, allow_unverified_options)
}

fn unverified_scan_route_error() -> ReltioError {
    ReltioError::new(
        "unverified_scan_route_refused",
        ErrorCategory::Safety,
        "the legacy OpenAPI scan route is not enabled because it conflicts with current English Reltio documentation",
    )
    .with_details(json!({
        "documented_route": "/entities/_scan",
        "unverified_route": "/entities/v2/_scan",
        "unverified_aliases": ["/entities/_scan/", "/entities/v2/_scan/"],
        "network_request_sent": false,
        "local_state_committed": false,
        "safe_to_replay": true
    }))
    .with_hint(
        "Use /entities/_scan or the typed `entity scan` command; verify the v2 route against a live tenant before registering it.",
    )
}

fn apply_endpoint_preflight(
    endpoint_id: &str,
    endpoint_path: &str,
    query: &[(String, String)],
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<bool> {
    match endpoint_id {
        "entity.by-crosswalk" => {
            if body.is_some() {
                return Err(ReltioError::usage(
                    "entity_crosswalk_body_refused",
                    "reviewed GET entity by-crosswalk does not accept a request body",
                ));
            }
            let lookup = entity_crosswalk_request(endpoint_path, query)?;
            validate_by_crosswalk(&lookup)?;
            Ok(query
                .iter()
                .all(|(key, _)| matches!(key.as_str(), "type" | "sourceTable" | "options")))
        }
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
            Ok(request.options.is_empty()
                && query.iter().all(|(key, _)| {
                    matches!(
                        key.as_str(),
                        "filter" | "max" | "select" | "options" | "activeness"
                    )
                }))
        }
        "entity.history" => {
            let explicit_order = query_value(query, "order").is_some();
            let options = query_value(query, "options")
                .map(|value| value.split(',').collect::<Vec<_>>())
                .unwrap_or_default();
            if options
                .iter()
                .any(|option| *option != "skipReferenceAttributesProcessing")
            {
                return Err(ReltioError::usage(
                    "invalid_history_option",
                    "the reviewed entity history option is skipReferenceAttributesProcessing",
                ));
            }
            let history = EntityHistoryRequest {
                max: query_operation_u32(query, "max", "entity_history")?.unwrap_or(50),
                offset: query_operation_u32(query, "offset", "entity_history")?.unwrap_or(0),
                order: query_value(query, "order").unwrap_or("desc").to_owned(),
                filter: query_value(query, "filter").map(ToOwned::to_owned),
                show_all: query_operation_bool(query, "showAll", "entity_history")?
                    .unwrap_or(false),
                show_major_events_only: query_operation_bool(
                    query,
                    "showMajorEventsOnly",
                    "entity_history",
                )?,
                skip_reference_attributes_processing: !options.is_empty(),
            };
            validate_history("entities/reviewed", &history)?;
            Ok(explicit_order
                && query.iter().all(|(key, _)| {
                    matches!(
                        key.as_str(),
                        "max"
                            | "offset"
                            | "order"
                            | "filter"
                            | "showAll"
                            | "showMajorEventsOnly"
                            | "options"
                    )
                }))
        }
        "entity.matches" => {
            let transitive =
                query_operation_bool(query, "transitive", "entity_matches")?.unwrap_or(false);
            let force_match =
                query_operation_bool(query, "forceMatch", "entity_matches")?.unwrap_or(false);
            if force_match {
                return Err(ReltioError::new(
                    "raw_force_match_refused",
                    ErrorCategory::Safety,
                    "forceMatch=true is disabled until forced recalculation has a reviewed cost, state-change, and replay-safety contract",
                )
                .with_details(json!({
                    "network_request_sent": false,
                    "local_state_committed": false,
                    "safe_to_replay": true
                }))
                .with_hint("Use forceMatch=false to retrieve stored direct matches."));
            }
            let deep = query_operation_u32(query, "deep", "entity_matches")?;
            if deep == Some(0) {
                return Err(ReltioError::usage(
                    "invalid_matches_depth",
                    "entity matches deep must be greater than zero",
                ));
            }
            let match_type = query_value(query, "type");
            if match_type.is_some_and(|match_type| {
                match_type.is_empty() || match_type.contains(['\r', '\n', '\0'])
            }) {
                return Err(ReltioError::usage(
                    "invalid_match_type",
                    "entity matches type must be non-empty and contain no controls",
                ));
            }
            let reviewed_match_type =
                match_type.is_none_or(|match_type| ENTITY_MATCH_TYPES.contains(&match_type));
            let matches = EntityMatchesRequest {
                max: query_operation_u32(query, "max", "entity_matches")?.unwrap_or(200),
                offset: query_operation_u32(query, "offset", "entity_matches")?.unwrap_or(0),
                match_type: None,
            };
            validate_matches("entities/reviewed", &matches)?;
            let narrowed_direct_read = !transitive && deep == Some(1);
            Ok(narrowed_direct_read
                && reviewed_match_type
                && query.iter().all(|(key, _)| {
                    matches!(
                        key.as_str(),
                        "transitive" | "forceMatch" | "deep" | "max" | "offset" | "type"
                    )
                }))
        }
        _ => Ok(true),
    }
}

fn entity_crosswalk_request(
    endpoint_path: &str,
    query: &[(String, String)],
) -> Result<EntityByCrosswalkRequest> {
    let value = endpoint_path
        .rsplit('/')
        .next()
        .ok_or_else(|| ReltioError::internal("matched entity by-crosswalk path has no value"))?;
    Ok(EntityByCrosswalkRequest {
        value: value.to_owned(),
        source_type: query_value(query, "type")
            .ok_or_else(|| {
                ReltioError::usage(
                    "crosswalk_type_required",
                    "reviewed entity by-crosswalk requires query parameter type",
                )
            })?
            .to_owned(),
        source_table: query_value(query, "sourceTable").map(ToOwned::to_owned),
        options: query_value(query, "options")
            .map(|value| value.split(',').map(ToOwned::to_owned).collect())
            .unwrap_or_default(),
    })
}

fn request_replay_policy(
    coverage: PracticeCoverage,
    endpoint_replay: Option<ReplayPolicy>,
    scan_continuation: bool,
) -> ReplayPolicy {
    if coverage != PracticeCoverage::Reviewed || scan_continuation {
        ReplayPolicy::Unsafe
    } else {
        endpoint_replay.unwrap_or(ReplayPolicy::Unsafe)
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

fn reviewed_entity_history_window(
    endpoint: Option<&reltio_client::registry::Endpoint>,
    query: &[(String, String)],
) -> Result<Option<(u32, u32)>> {
    if endpoint.is_none_or(|endpoint| endpoint.id != "entity.history") {
        return Ok(None);
    }
    Ok(Some((
        query_operation_u32(query, "offset", "entity_history")?.unwrap_or(0),
        query_operation_u32(query, "max", "entity_history")?.unwrap_or(50),
    )))
}

fn entity_history_boundary_reached(history_window: Option<(u32, u32)>, data: &Value) -> bool {
    let Some((offset, maximum)) = history_window else {
        return false;
    };
    let Some(changes) = data.as_array() else {
        return false;
    };
    let returned = u32::try_from(changes.len()).unwrap_or(u32::MAX);
    returned == maximum && offset.saturating_add(returned) >= HISTORY_RESULT_BOUNDARY
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

fn query_operation_u32(
    query: &[(String, String)],
    name: &str,
    operation: &str,
) -> Result<Option<u32>> {
    query_value(query, name)
        .map(|value| {
            value.parse::<u32>().map_err(|_| {
                ReltioError::usage(
                    format!("invalid_{operation}_query"),
                    format!(
                        "{} {name} must be an unsigned integer",
                        operation.replace('_', " ")
                    ),
                )
            })
        })
        .transpose()
}

fn query_operation_bool(
    query: &[(String, String)],
    name: &str,
    operation: &str,
) -> Result<Option<bool>> {
    query_value(query, name)
        .map(|value| {
            if value.eq_ignore_ascii_case("true") {
                Ok(true)
            } else if value.eq_ignore_ascii_case("false") {
                Ok(false)
            } else {
                Err(ReltioError::usage(
                    format!("invalid_{operation}_query"),
                    format!(
                        "{} {name} must be true or false",
                        operation.replace('_', " ")
                    ),
                ))
            }
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

    #[::std::prelude::v1::test]
    fn registered_safety_overrides_http_method_defaults_fail_closed() {
        assert!(!request_is_read_semantic(
            Some(Safety::HighImpact),
            &Method::GET
        ));
        assert!(request_is_read_semantic(Some(Safety::Read), &Method::POST));
        assert!(request_is_read_semantic(None, &Method::GET));
        assert!(!request_is_read_semantic(None, &Method::POST));
    }

    #[test]
    fn raw_scan_continuations_are_never_replayed_automatically() {
        assert_eq!(
            request_replay_policy(
                PracticeCoverage::Reviewed,
                Some(ReplayPolicy::Conditional),
                false,
            ),
            ReplayPolicy::Conditional
        );
        assert_eq!(
            request_replay_policy(
                PracticeCoverage::Reviewed,
                Some(ReplayPolicy::Conditional),
                true,
            ),
            ReplayPolicy::Unsafe
        );
    }

    #[test]
    fn unverified_scan_route_matcher_includes_the_trailing_slash_alias() {
        assert!(is_unverified_scan_route("/entities/v2/_scan"));
        assert!(is_unverified_scan_route("/entities/v2/_scan/"));
        assert!(is_unverified_scan_route("/entities/_scan/"));
        assert!(!is_unverified_scan_route("/entities/_scan"));
        assert!(!is_unverified_scan_route("/entities/v2/_scan/child"));
        assert!(is_unverified_scan_route_argument("entities/v2/_scan/"));
        assert!(is_unverified_scan_route_argument("entities/_scan/"));
        assert!(!is_reviewed_scan_route_argument("entities/_scan/"));
        assert!(is_reviewed_scan_route_argument("entities/_scan"));
        assert!(!is_reviewed_scan_route_argument("entities/v2/_scan"));

        let oversized = vec![("max".to_owned(), "201".to_owned())];
        assert_eq!(
            validate_scan_route_before_body(
                Service::Data,
                &Method::POST,
                "/entities/_scan",
                &oversized,
                false,
            )
            .expect_err("reviewed route applies scan preflight")
            .code,
            "scan_page_size_too_large"
        );
        validate_scan_route_before_body(
            Service::Data,
            &Method::POST,
            "/archive/entities/_scan",
            &oversized,
            false,
        )
        .expect("unrelated suffix is not classified as the reviewed scan route");
    }

    #[::std::prelude::v1::test]
    fn release_version_binding_requires_one_stable_exact_version() {
        assert_eq!(normalized_stable_release("v0.1.0").unwrap(), "0.1.0");
        assert!(normalized_stable_release("0.1.0-alpha.1").is_err());
        assert!(normalized_stable_release("v01.1.0").is_err());
        assert!(release_versions_match("0.1.0", "0.1.0", "0.1.0"));
        assert!(!release_versions_match("0.1.1", "0.1.0", "0.1.0"));
        assert!(!release_versions_match("0.1.0", "0.1.0", "0.1.0-alpha.1"));
    }

    #[tokio::test]
    async fn request_file_input_checks_control_before_opening() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = read_request_body_file(
            PathBuf::from("missing-request-body"),
            Instant::now() + std::time::Duration::from_secs(1),
            &cancellation,
        )
        .await
        .expect_err("cancellation wins before file access");

        assert_eq!(error.code, "request_canceled");
        assert_eq!(error.details["phase"], "request_body_input");
        assert_eq!(error.details["network_request_sent"], false);
        assert_eq!(error.details["safe_to_replay"], true);
    }

    #[tokio::test]
    async fn request_file_input_control_does_not_wait_for_a_blocked_reader() {
        for (control, expected_code) in [
            (InputControl::Canceled, "request_canceled"),
            (InputControl::TimedOut, "request_timeout"),
        ] {
            let cancellation = CancellationToken::new();
            let timeline = Arc::new(Mutex::new(InputReaderState::Pending));
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let deadline = if control == InputControl::TimedOut {
                Instant::now() + std::time::Duration::from_millis(10)
            } else {
                Instant::now() + std::time::Duration::from_secs(30)
            };
            if control == InputControl::Canceled {
                cancellation.cancel();
            }

            let error = await_input_reader(receiver, timeline, deadline, &cancellation)
                .await
                .expect_err("control must win while the reader remains blocked");

            assert_eq!(error.code, expected_code);
            assert_eq!(error.details["phase"], "request_body_input");
            assert_eq!(error.details["network_request_sent"], false);
            assert_eq!(error.details["safe_to_replay"], true);
            drop(sender);
        }
    }

    #[tokio::test]
    async fn request_file_input_completion_publication_preserves_event_order() {
        let cancellation = CancellationToken::new();
        let completed_at = cancellation.event_stamp();
        cancellation.cancel();
        let timeline = Arc::new(Mutex::new(InputReaderState::Completing));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let _ = sender.send((completed_at, Ok(b"completed-first".to_vec())));
        });

        let result = await_input_reader(
            receiver,
            timeline,
            Instant::now() + std::time::Duration::from_secs(1),
            &cancellation,
        )
        .await
        .expect("completion that precedes cancellation remains authoritative");

        assert_eq!(result, b"completed-first");
    }

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
            false,
            ReplayPolicy::Unsafe,
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
            false,
            ReplayPolicy::Unsafe,
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

    #[test]
    fn output_failure_after_one_shot_read_success_is_never_replayable() {
        let error = response_output_error(
            ReltioError::new(
                "api_response_invalid_json",
                ErrorCategory::Api,
                "injected scan response failure",
            ),
            200,
            Some("scan-request-1".to_owned()),
            true,
            ReplayPolicy::Unsafe,
        );

        assert!(!error.retryable);
        assert_eq!(error.details["remote_operation_completed"], true);
        assert_eq!(
            error.details["remote_operation_state"],
            "success_response_received"
        );
        assert_eq!(error.details["safe_to_replay"], false);
        assert!(
            error
                .hint
                .as_deref()
                .is_some_and(|hint| hint.contains("Do not replay"))
        );
    }
}
