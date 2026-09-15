use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};
use fs2::FileExt;
use is_terminal::IsTerminal;
use reltio_client::auth::TokenManagerOptions;
use reltio_client::cancellation::{CancellationToken, EventStamp};
use reltio_client::entities::{
    CROSSWALK_ID_FALLBACK_WARNING, ENTITY_SCAN_OPTIONS_PROVISIONAL_WARNING,
    EntityByCrosswalkRequest, EntityGetOptions, EntityHistoryRequest, EntityMatchesRequest,
    EntityScanRequest, EntitySearchRequest, HISTORY_BOUNDARY_WARNING,
    HISTORY_CANONICAL_VALUES_WARNING, POTENTIAL_MATCHES_FRESHNESS_WARNING, SEARCH_BOUNDARY_WARNING,
    validate_by_crosswalk, validate_get, validate_history, validate_matches, validate_scan,
    validate_scan_option_acknowledgement, validate_search,
};
use reltio_client::error::{ErrorCategory, ReltioError, Result, json_parse_details};
use reltio_client::fs::{
    atomic_write_private, is_lock_contended, open_private_lock, read_bounded_optional,
};
use reltio_client::http::ApiResponse;
use reltio_client::registry::{PracticeCoverage, Registry};
use reltio_client::service::{Service, ServiceResolver};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cli::{
    EntityByCrosswalkArgs, EntityGetArgs, EntityHistoryArgs, EntityMatchesArgs, EntityScanArgs,
    EntitySearchArgs, EntitySubcommand, OutputFormat,
};
use crate::commands::{Runtime, sha256_hex};
use crate::output::{Meta, OutputContext, prepare_raw_guarded, write_jsonl_event_guarded};

const REVERSE_TRANSCODE_WARNING: &str = "reverseTranscodeLookups was introduced by Reltio as Preview; verify tenant availability and destination-system mappings before relying on the result";

pub async fn run(runtime: &Runtime, command: EntitySubcommand) -> Result<()> {
    if runtime.render.format == OutputFormat::Raw && io::stdout().is_terminal() {
        return Err(ReltioError::new(
            "raw_output_tty_refused",
            ErrorCategory::Safety,
            "refusing to write an upstream raw entity body to terminal stdout",
        )
        .with_hint("Redirect stdout to a file or pipe for deliberate raw response handling."));
    }
    match command {
        EntitySubcommand::Get(arguments) => get(runtime, arguments).await,
        EntitySubcommand::ByCrosswalk(arguments) => by_crosswalk(runtime, arguments).await,
        EntitySubcommand::Search(arguments) => search(runtime, arguments).await,
        EntitySubcommand::Scan(arguments) => scan(runtime, arguments).await,
        EntitySubcommand::History(arguments) => history(runtime, arguments).await,
        EntitySubcommand::Matches(arguments) => matches(runtime, arguments).await,
    }
}

async fn get(runtime: &Runtime, arguments: EntityGetArgs) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let options = EntityGetOptions {
        select: runtime.globals.fields.clone(),
        time: arguments.time,
        options: arguments.options,
        merge_duplicate_crosswalks: arguments.merge_duplicate_crosswalks,
        default_max_values: arguments.default_max_values,
        explicit_survivorship_group: arguments.explicit_survivorship_group,
        reverse_transcode_lookups: arguments.reverse_transcode_lookups,
        send_masked: arguments.send_masked,
    };
    validate_get(&arguments.entity, &options)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let auth_status = runtime
        .token_manager_status(&manager, deadline)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let client = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let result = client
        .get(&arguments.entity, &options)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(&result.response.output_guard());
    ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
    if options.reverse_transcode_lookups.is_some()
        && matches!(
            runtime.render.format,
            OutputFormat::Raw | OutputFormat::Table
        )
    {
        runtime
            .emit_warning(REVERSE_TRANSCODE_WARNING, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &result.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(result.entity);
        let body = result
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
        return runtime
            .emit_raw(&body, false, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &result.response));
    }
    let mut meta = response_meta(
        "entity.get",
        &target,
        &result.response,
        started,
        Some(result.consistency),
    );
    meta.auth_source = Some(auth_status.source);
    meta.practice_coverage = Some(PracticeCoverage::Reviewed);
    if options.reverse_transcode_lookups.is_some() {
        meta.warnings.push(REVERSE_TRANSCODE_WARNING.to_owned());
    }
    let entity = result.entity;
    ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
    runtime
        .emit_success(&entity, &meta, deadline, &output_guard)
        .await
        .map_err(|error| read_response_output_error(error, &result.response))
}

async fn by_crosswalk(runtime: &Runtime, arguments: EntityByCrosswalkArgs) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let request = EntityByCrosswalkRequest {
        value: arguments.value,
        source_type: arguments.source_type,
        source_table: arguments.source_table,
        options: arguments.options,
    };
    validate_by_crosswalk(&request)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let auth_status = runtime
        .token_manager_status(&manager, deadline)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let client = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let result = client
        .by_crosswalk(&request)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(&result.response.output_guard());
    ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
    if result.id_fallback_detected
        && matches!(
            runtime.render.format,
            OutputFormat::Raw | OutputFormat::Table
        )
    {
        runtime
            .emit_warning(CROSSWALK_ID_FALLBACK_WARNING, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &result.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(result.entries);
        let body = result
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
        return runtime
            .emit_raw(&body, false, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &result.response));
    }
    let mut meta = response_meta(
        "entity.by-crosswalk",
        &target,
        &result.response,
        started,
        Some(result.consistency),
    );
    meta.auth_source = Some(auth_status.source);
    meta.practice_coverage = Some(PracticeCoverage::Reviewed);
    if result.id_fallback_detected {
        meta.warnings.push(CROSSWALK_ID_FALLBACK_WARNING.to_owned());
    }
    let entries = Value::Array(result.entries);
    ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
    runtime
        .emit_success(&entries, &meta, deadline, &output_guard)
        .await
        .map_err(|error| read_response_output_error(error, &result.response))
}

async fn search(runtime: &Runtime, arguments: EntitySearchArgs) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let request = EntitySearchRequest {
        filter: arguments.filter,
        select: runtime.globals.fields.clone(),
        max: arguments.max_items,
        offset: arguments.offset,
        sort: arguments.sort,
        order: arguments.order,
        options: arguments.options,
        default_max_values: arguments.default_max_values,
        activeness: arguments.activeness,
        score_enabled: arguments.score_enabled.then_some(true),
    };
    validate_search(&request)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let auth_status = runtime
        .token_manager_status(&manager, deadline)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let client = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let page = client
        .search(&request)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(&page.response.output_guard());
    ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
    if page.boundary_reached
        && matches!(
            runtime.render.format,
            OutputFormat::Raw | OutputFormat::Table
        )
    {
        runtime
            .emit_warning(SEARCH_BOUNDARY_WARNING, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(page.entities);
        let body = page
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
        return runtime
            .emit_raw(&body, false, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &page.response));
    }
    let returned = page.entities.len();
    let mut meta = response_meta(
        "entity.search",
        &target,
        &page.response,
        started,
        Some(page.consistency),
    );
    meta.auth_source = Some(auth_status.source);
    meta.practice_coverage = Some(PracticeCoverage::Reviewed);
    if page.boundary_reached {
        meta.warnings.push(SEARCH_BOUNDARY_WARNING.to_owned());
    }
    meta.pagination = Some(json!({
        "kind": "offset",
        "offset": page.offset,
        "max": page.max,
        "returned": returned,
        "next_offset": page.next_offset,
        "result_boundary": 10000,
        "boundary_reached": page.boundary_reached,
        "continuation": page.next_offset.map(|offset| json!({
            "command": "entity.search",
            "arguments": {
                "filter": request.filter,
                "fields": request.select,
                "max_items": request.max,
                "offset": offset,
                "sort": request.sort,
                "order": request.order,
                "options": request.options,
                "default_max_values": request.default_max_values,
                "activeness": request.activeness,
                "score_enabled": request.score_enabled.unwrap_or(false)
            }
        }))
    }));
    let entities = Value::Array(page.entities);
    ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
    runtime
        .emit_success(&entities, &meta, deadline, &output_guard)
        .await
        .map_err(|error| read_response_output_error(error, &page.response))
}

async fn history(runtime: &Runtime, arguments: EntityHistoryArgs) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let request = EntityHistoryRequest {
        max: arguments.max_items,
        offset: arguments.offset,
        order: arguments.order,
        filter: arguments.filter,
        show_all: arguments.show_all,
        show_major_events_only: arguments.show_major_events_only,
        skip_reference_attributes_processing: arguments.skip_reference_attributes_processing,
    };
    validate_history(&arguments.entity, &request)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let auth_status = runtime
        .token_manager_status(&manager, deadline)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let client = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let page = client
        .history(&arguments.entity, &request)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(&page.response.output_guard());
    ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
    if matches!(
        runtime.render.format,
        OutputFormat::Raw | OutputFormat::Table
    ) {
        runtime
            .emit_warning(HISTORY_CANONICAL_VALUES_WARNING, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if page.boundary_reached
        && matches!(
            runtime.render.format,
            OutputFormat::Raw | OutputFormat::Table
        )
    {
        runtime
            .emit_warning(HISTORY_BOUNDARY_WARNING, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(page.changes);
        let body = page
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
        return runtime
            .emit_raw(&body, false, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &page.response));
    }
    let returned = page.changes.len();
    let mut meta = response_meta(
        "entity.history",
        &target,
        &page.response,
        started,
        Some(page.consistency),
    );
    meta.auth_source = Some(auth_status.source);
    meta.practice_coverage = Some(PracticeCoverage::Reviewed);
    meta.warnings
        .push(HISTORY_CANONICAL_VALUES_WARNING.to_owned());
    if page.boundary_reached {
        meta.warnings.push(HISTORY_BOUNDARY_WARNING.to_owned());
    }
    meta.pagination = Some(json!({
        "kind": "offset",
        "offset": page.offset,
        "max": page.max,
        "returned": returned,
        "next_offset": page.next_offset,
        "result_boundary": 1000,
        "boundary_reached": page.boundary_reached,
        "continuation": page.next_offset.map(|offset| json!({
            "command": "entity.history",
            "arguments": {
                "entity": arguments.entity,
                "max_items": request.max,
                "offset": offset,
                "order": request.order,
                "filter": request.filter,
                "show_all": request.show_all,
                "show_major_events_only": request.show_major_events_only,
                "skip_reference_attributes_processing": request.skip_reference_attributes_processing
            }
        }))
    }));
    let changes = Value::Array(page.changes);
    ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
    runtime
        .emit_success(&changes, &meta, deadline, &output_guard)
        .await
        .map_err(|error| read_response_output_error(error, &page.response))
}

async fn matches(runtime: &Runtime, arguments: EntityMatchesArgs) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let request = EntityMatchesRequest {
        max: arguments.max_items,
        offset: arguments.offset,
        match_type: arguments.match_type,
    };
    validate_matches(&arguments.entity, &request)?;
    let (_, target) = runtime.config_and_target()?;
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let auth_status = runtime
        .token_manager_status(&manager, deadline)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let client = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let page = client
        .matches(&arguments.entity, &request)
        .await
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    output_guard.merge(&page.response.output_guard());
    ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
    if matches!(
        runtime.render.format,
        OutputFormat::Raw | OutputFormat::Table
    ) {
        runtime
            .emit_warning(POTENTIAL_MATCHES_FRESHNESS_WARNING, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(page.matches);
        let body = page
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
        return runtime
            .emit_raw(&body, false, deadline, &output_guard)
            .await
            .map_err(|error| read_response_output_error(error, &page.response));
    }
    let mut meta = response_meta(
        "entity.matches",
        &target,
        &page.response,
        started,
        Some(page.consistency),
    );
    meta.auth_source = Some(auth_status.source);
    meta.practice_coverage = Some(PracticeCoverage::Reviewed);
    meta.warnings
        .push(POTENTIAL_MATCHES_FRESHNESS_WARNING.to_owned());
    meta.pagination = Some(json!({
        "kind": "offset",
        "offset": page.offset,
        "max": page.max,
        "returned": Value::Null,
        "next_offset": Value::Null,
        "continuation_known": false
    }));
    let matches = page.matches;
    ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
    runtime
        .emit_success(&matches, &meta, deadline, &output_guard)
        .await
        .map_err(|error| read_response_output_error(error, &page.response))
}

async fn scan(runtime: &Runtime, arguments: EntityScanArgs) -> Result<()> {
    if runtime.render.format != OutputFormat::Jsonl {
        return Err(ReltioError::usage(
            "scan_requires_jsonl",
            "entity scan streams only JSONL item, checkpoint, and summary events",
        )
        .with_hint("Use --output jsonl or omit --output for the scan default."));
    }
    if arguments.page_size == 0 || arguments.checkpoint_every == 0 {
        return Err(ReltioError::usage(
            "invalid_scan_bound",
            "page-size and checkpoint-every must be greater than zero",
        ));
    }
    if arguments.max_items == Some(0) || arguments.max_pages == Some(0) {
        return Err(ReltioError::usage(
            "invalid_scan_bound",
            "max-items and max-pages must be greater than zero when supplied",
        ));
    }
    let resume_file_output = resume_file_text(arguments.resume_file.as_deref())?;
    validate_scan(&EntityScanRequest {
        filter: Some(arguments.filter.clone()),
        cursor: None,
        max: arguments.page_size,
        select: runtime.globals.fields.clone(),
        options: arguments.options.clone(),
        activeness: arguments.activeness.clone(),
    })?;
    validate_scan_option_acknowledgement(
        &arguments.options,
        arguments.allow_unverified_scan_options,
    )?;
    let scan_endpoint = Registry::embedded()?
        .endpoint("entity.scan")
        .ok_or_else(|| ReltioError::internal("entity scan endpoint is absent from the registry"))?;
    let scan_consistency = scan_endpoint.consistency;
    let cursor_ttl_seconds = scan_endpoint.cursor_ttl_seconds.ok_or_else(|| {
        ReltioError::internal("entity scan endpoint has no cursor TTL in the registry")
    })?;
    let cursor_ttl = i64::try_from(cursor_ttl_seconds)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .ok_or_else(|| ReltioError::internal("entity scan cursor TTL is out of range"))?;

    let started = Instant::now();
    let timeout = runtime.timeout()?;
    let deadline = runtime.deadline_from(started)?;
    let (_, target) = runtime.config_and_target()?;
    let data_service_url = ServiceResolver::new(target.clone())
        .base_url(Service::Data)?
        .to_string();
    let manager = runtime.token_manager(&target, TokenManagerOptions::default())?;
    let mut output_guard = runtime
        .token_manager_output_guard(&manager, deadline)
        .await?;
    let client = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let resume_lock = match arguments.resume_file.as_deref() {
        Some(path) => Some(Arc::new(
            acquire_resume_lock_until(path, deadline, &runtime.cancellation)
                .await
                .map_err(|error| {
                    scan_resume_setup_error(error, resume_file_output, &output_guard, "resume_lock")
                })?,
        )),
        None => None,
    };
    let query_hash = scan_query_hash(runtime, &arguments);
    let filter_hash = sha256_hex(arguments.filter.trim().as_bytes());
    let resume_bytes = read_resume_optional_until(
        arguments.resume_file.as_deref(),
        resume_lock.clone(),
        deadline,
        &runtime.cancellation,
    )
    .await
    .map_err(|error| {
        scan_resume_setup_error(error, resume_file_output, &output_guard, "resume_read")
    })?;
    let resumed_from_artifact = resume_bytes.is_some();
    let mut state = load_or_create_resume(
        arguments
            .resume_file
            .as_deref()
            .zip(resume_bytes.as_deref()),
        &target,
        &arguments,
        &filter_hash,
        &query_hash,
        &data_service_url,
        cursor_ttl,
    )
    .map_err(|error| {
        scan_resume_setup_error(
            error,
            resume_file_output,
            &output_guard,
            "resume_validation",
        )
    })?;
    let mut pages = 0_u64;
    let mut returned = state.sequence;
    let mut exhausted = state.exhausted;
    let initial_sequence = state.initial_sequence;
    let fresh_scan = !resumed_from_artifact;
    let mut current_progress_committed = resumed_from_artifact || state.exhausted;
    let mut local_checkpoint_committed = Some(resumed_from_artifact);
    let mut persisted_sequence = resumed_from_artifact.then_some(state.sequence);
    let mut checkpoint_commit_unknown = false;
    let mut output_emitted = false;
    let mut output_emission_attempted = false;
    let mut uncheckpointed_output = false;
    let mut last_response = ScanResponseOutcome::default();
    let output_context = OutputContext::default();
    macro_rules! progress_error {
        ($error:expr, $phase:expr) => {
            scan_progress_error(
                $error,
                ScanProgress {
                    last_response: &last_response,
                    phase: $phase,
                    local_checkpoint_committed,
                    checkpoint_commit_unknown,
                    output_emitted,
                    output_emission_attempted,
                    uncheckpointed_output,
                    fresh_scan,
                    initial_sequence,
                    persisted_sequence,
                    resume_file: resume_file_output,
                    returned,
                    pages,
                },
                &output_guard,
            )
        };
    }
    while !exhausted {
        runtime
            .ensure_not_cancelled("before_scan_page", false)
            .map_err(|error| progress_error!(error, ScanFailurePhase::BeforeResponse))?;
        if started.elapsed() >= timeout {
            return Err(progress_error!(
                ReltioError::new(
                    "scan_timeout",
                    ErrorCategory::Timeout,
                    "entity scan reached its overall timeout; the checkpoint remains resumable",
                )
                .with_details(json!({
                    "returned": returned,
                    "pages": pages,
                    "resume_file": resume_file_output
                })),
                ScanFailurePhase::BeforeResponse
            ));
        }
        let returned_this_run = returned.saturating_sub(initial_sequence);
        if arguments.max_pages.is_some_and(|maximum| pages >= maximum)
            || arguments
                .max_items
                .is_some_and(|maximum| returned_this_run >= maximum)
        {
            break;
        }
        let request_deadline = scan_request_deadline(&state, deadline)
            .map_err(|error| progress_error!(error, ScanFailurePhase::BeforeResponse))?;
        let remaining = arguments
            .max_items
            .map_or(u64::from(arguments.page_size), |maximum| {
                maximum.saturating_sub(returned_this_run)
            });
        let request_max =
            u32::try_from(remaining.min(u64::from(arguments.page_size))).map_err(|_| {
                progress_error!(
                    ReltioError::internal("scan page size conversion failed"),
                    ScanFailurePhase::BeforeResponse
                )
            })?;
        let request_started_at = Utc::now();
        let page = client
            .scan_page_until(
                &EntityScanRequest {
                    filter: state.cursor.is_none().then(|| arguments.filter.clone()),
                    cursor: state.cursor.clone(),
                    max: request_max,
                    select: state
                        .cursor
                        .is_none()
                        .then(|| runtime.globals.fields.clone())
                        .flatten(),
                    options: if state.cursor.is_none() {
                        arguments.options.clone()
                    } else {
                        Vec::new()
                    },
                    activeness: state
                        .cursor
                        .is_none()
                        .then(|| arguments.activeness.clone())
                        .flatten(),
                },
                request_deadline,
            )
            .await;
        let page = match page {
            Ok(page) => page,
            Err(error) => {
                if let Some(guard) = error.output_guard() {
                    output_guard.merge(guard);
                }
                let phase = scan_request_failure_phase(&error);
                return Err(progress_error!(error, phase));
            }
        };
        output_guard.merge(&page.response.output_guard());
        pages += 1;
        last_response.0 = Some((page.response.status, page.response.request_id.clone()));
        if page.objects.len() > usize::try_from(request_max).unwrap_or(usize::MAX) {
            return Err(progress_error!(
                ReltioError::new(
                    "scan_page_limit_violated",
                    ErrorCategory::Api,
                    "Reltio returned more scan objects than requested; refusing to create an unsafe checkpoint",
                )
                .with_request_id(page.response.request_id),
                ScanFailurePhase::AfterResponse
            ));
        }
        let objects = page.objects;
        let cursor = page.cursor;
        drop(page.response);
        runtime
            .ensure_not_cancelled("before_scan_page_output", false)
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
        let object_count = u64::try_from(objects.len()).map_err(|_| {
            progress_error!(
                ReltioError::internal("scan page object count cannot be represented"),
                ScanFailurePhase::AfterResponse
            )
        })?;
        let page_returned = returned.checked_add(object_count).ok_or_else(|| {
            progress_error!(
                ReltioError::usage(
                    "resume_file_invalid",
                    "scan page would exhaust the persisted sequence capacity",
                )
                .with_details(json!({ "reason": "sequence_out_of_range" })),
                ScanFailurePhase::AfterResponse
            )
        })?;
        if page_returned == u64::MAX {
            return Err(progress_error!(
                ReltioError::usage(
                    "resume_file_invalid",
                    "scan page would exhaust the persisted sequence capacity",
                )
                .with_details(json!({ "reason": "sequence_out_of_range" })),
                ScanFailurePhase::AfterResponse
            ));
        }
        let mut page_output = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            let sequence = returned
                .checked_add(u64::try_from(index).unwrap_or(u64::MAX))
                .and_then(|sequence| sequence.checked_add(1))
                .ok_or_else(|| {
                    progress_error!(
                        ReltioError::usage(
                            "resume_file_invalid",
                            "scan sequence cannot be incremented safely",
                        ),
                        ScanFailurePhase::AfterResponse
                    )
                })?;
            write_jsonl_event_guarded(
                &json!({
                    "schema_version": reltio_client::SCHEMA_VERSION,
                    "type": "item",
                    "data": object,
                    "meta": {
                        "sequence": sequence,
                        "cursor": null,
                        "consistency": scan_consistency
                    }
                }),
                &mut page_output,
                &output_guard,
            )
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
        }

        let mut next_state = state.clone();
        next_state.cursor = Some(cursor);
        next_state.sequence = page_returned;
        next_state.last_read_at = request_started_at;
        // Tenant preserveCursor capability is not discoverable here, so use the
        // shorter reviewed TTL to fail safely rather than resume a stale cursor.
        next_state.expires_at = request_started_at + cursor_ttl;
        next_state.exhausted = objects.is_empty();
        let next_exhausted = next_state.exhausted;

        let next_progress_committed = pages % arguments.checkpoint_every == 0 || next_exhausted;
        if next_progress_committed {
            write_checkpoint_event(
                &mut page_output,
                &next_state,
                pages,
                resume_file_output,
                &output_guard,
            )
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
        }
        let prepared = prepare_raw_guarded(&page_output, false, &output_guard)
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?
            .with_context(&output_context);
        output_emission_attempted = true;
        runtime
            .emit_prepared(prepared, deadline)
            .await
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
        returned = page_returned;
        state = next_state;
        exhausted = next_exhausted;
        current_progress_committed = next_progress_committed;
        output_emitted = true;
        uncheckpointed_output = true;
        local_checkpoint_committed = Some(false);
        checkpoint_commit_unknown = false;
        if current_progress_committed {
            if let Some(path) = arguments.resume_file.as_deref() {
                if let Err(error) = commit_scan_progress_until(
                    path,
                    &state,
                    Arc::clone(
                        resume_lock
                            .as_ref()
                            .expect("a resume path always has a held lock"),
                    ),
                    deadline,
                    &runtime.cancellation,
                )
                .await
                {
                    match checkpoint_commit_outcome(&error) {
                        CheckpointCommitOutcome::Committed => {
                            local_checkpoint_committed = Some(true);
                            persisted_sequence = Some(state.sequence);
                            uncheckpointed_output = false;
                        }
                        CheckpointCommitOutcome::NotCommitted => {
                            local_checkpoint_committed = Some(false);
                        }
                        CheckpointCommitOutcome::Unknown => {
                            local_checkpoint_committed = None;
                            checkpoint_commit_unknown = true;
                        }
                    }
                    return Err(progress_error!(error, ScanFailurePhase::AfterResponse));
                }
                local_checkpoint_committed = Some(true);
                persisted_sequence = Some(state.sequence);
                uncheckpointed_output = false;
            }
        }
        if exhausted {
            break;
        }
    }

    if pages > 0 && !current_progress_committed {
        runtime
            .ensure_not_cancelled("before_scan_checkpoint_output", false)
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
        let mut checkpoint_output = Vec::new();
        write_checkpoint_event(
            &mut checkpoint_output,
            &state,
            pages,
            resume_file_output,
            &output_guard,
        )
        .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
        let prepared = prepare_raw_guarded(&checkpoint_output, false, &output_guard)
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?
            .with_context(&output_context);
        output_emission_attempted = true;
        runtime
            .emit_prepared(prepared, deadline)
            .await
            .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
        output_emitted = true;
        local_checkpoint_committed = Some(false);
        checkpoint_commit_unknown = false;
        if let Some(path) = arguments.resume_file.as_deref() {
            if let Err(error) = commit_scan_progress_until(
                path,
                &state,
                Arc::clone(
                    resume_lock
                        .as_ref()
                        .expect("a resume path always has a held lock"),
                ),
                deadline,
                &runtime.cancellation,
            )
            .await
            {
                match checkpoint_commit_outcome(&error) {
                    CheckpointCommitOutcome::Committed => {
                        local_checkpoint_committed = Some(true);
                        persisted_sequence = Some(state.sequence);
                        uncheckpointed_output = false;
                    }
                    CheckpointCommitOutcome::NotCommitted => {
                        local_checkpoint_committed = Some(false);
                    }
                    CheckpointCommitOutcome::Unknown => {
                        local_checkpoint_committed = None;
                        checkpoint_commit_unknown = true;
                    }
                }
                return Err(progress_error!(error, ScanFailurePhase::AfterResponse));
            }
            local_checkpoint_committed = Some(true);
            persisted_sequence = Some(state.sequence);
            uncheckpointed_output = false;
        }
    }
    runtime
        .ensure_not_cancelled("before_scan_summary", false)
        .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
    if Instant::now() >= deadline {
        return Err(progress_error!(
            ReltioError::new(
                "scan_timeout",
                ErrorCategory::Timeout,
                "entity scan reached its overall timeout before summary output",
            )
            .with_details(json!({
                "returned": returned,
                "pages": pages,
                "resume_file": resume_file_output
            })),
            ScanFailurePhase::AfterResponse
        ));
    }
    let mut summary_output = Vec::new();
    write_jsonl_event_guarded(
        &json!({
            "schema_version": reltio_client::SCHEMA_VERSION,
            "type": "summary",
            "data": null,
            "meta": {
                "returned": returned,
                "returned_this_run": returned.saturating_sub(state.initial_sequence),
                "pages": pages,
                "exhausted": exhausted,
                "elapsed_ms": started.elapsed().as_millis(),
                "consistency": scan_consistency,
                "warnings": if arguments.options.is_empty() {
                    vec![format!(
                        "cursor resume expiry uses the conservative documented {cursor_ttl_seconds}-second preserved-cursor TTL"
                    )]
                } else {
                    vec![
                        format!(
                            "cursor resume expiry uses the conservative documented {cursor_ttl_seconds}-second preserved-cursor TTL"
                        ),
                        ENTITY_SCAN_OPTIONS_PROVISIONAL_WARNING.to_owned(),
                    ]
                }
            }
        }),
        &mut summary_output,
        &output_guard,
    )
    .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?;
    let prepared = prepare_raw_guarded(&summary_output, false, &output_guard)
        .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))?
        .with_context(&output_context);
    output_emission_attempted = true;
    runtime
        .emit_prepared(prepared, deadline)
        .await
        .map_err(|error| progress_error!(error, ScanFailurePhase::AfterResponse))
}

#[derive(Default)]
struct ScanResponseOutcome(Option<(u16, Option<String>)>);

#[derive(Clone, Copy)]
enum ScanFailurePhase {
    BeforeResponse,
    AfterResponse,
}

#[derive(Clone, Copy)]
struct ScanProgress<'a> {
    last_response: &'a ScanResponseOutcome,
    phase: ScanFailurePhase,
    local_checkpoint_committed: Option<bool>,
    checkpoint_commit_unknown: bool,
    output_emitted: bool,
    output_emission_attempted: bool,
    uncheckpointed_output: bool,
    fresh_scan: bool,
    initial_sequence: u64,
    persisted_sequence: Option<u64>,
    resume_file: Option<&'a str>,
    returned: u64,
    pages: u64,
}

fn scan_request_failure_phase(error: &ReltioError) -> ScanFailurePhase {
    if error.http_status.is_some()
        || error.request_id.is_some()
        || error.details["remote_response_received"].as_bool() == Some(true)
    {
        ScanFailurePhase::AfterResponse
    } else {
        ScanFailurePhase::BeforeResponse
    }
}

fn scan_progress_error(
    mut error: ReltioError,
    progress: ScanProgress<'_>,
    output_guard: &reltio_client::redaction::OutputGuard,
) -> ReltioError {
    let mut details = match std::mem::take(&mut error.details) {
        Value::Object(details) => details,
        cause => serde_json::Map::from_iter([("cause".to_owned(), cause)]),
    };
    let response_received = matches!(progress.phase, ScanFailurePhase::AfterResponse)
        && (details
            .get("remote_response_received")
            .and_then(Value::as_bool)
            == Some(true)
            || error.http_status.is_some()
            || error.request_id.is_some()
            || progress.last_response.0.is_some());
    details
        .entry("remote_response_received".to_owned())
        .or_insert(Value::Bool(response_received));
    details
        .entry("remote_request_completed".to_owned())
        .or_insert(Value::Bool(response_received));
    details
        .entry("remote_operation_completed".to_owned())
        .or_insert(Value::Bool(false));
    details
        .entry("remote_operation_state".to_owned())
        .or_insert_with(|| {
            Value::String(if response_received {
                "scan_page_response_received".to_owned()
            } else {
                "scan_request_not_completed".to_owned()
            })
        });
    details.insert(
        "local_state_committed".to_owned(),
        progress
            .local_checkpoint_committed
            .map_or(Value::Null, Value::Bool),
    );
    details.insert(
        "checkpoint_commit_unknown".to_owned(),
        Value::Bool(progress.checkpoint_commit_unknown),
    );
    let output_proven_omitted =
        details.get("output_omitted").and_then(Value::as_bool) == Some(true);
    let output_may_exist =
        progress.output_emitted || progress.output_emission_attempted && !output_proven_omitted;
    let artifact_safe_to_replay = progress.fresh_scan
        && progress.initial_sequence == 0
        && progress.returned == 0
        && !output_may_exist;
    let local_output_refusal = error.code == "credential_output_refused" && output_proven_omitted;
    let underlying_safe_to_replay = details.get("safe_to_replay").and_then(Value::as_bool);
    let safe_to_replay = artifact_safe_to_replay
        && (underlying_safe_to_replay != Some(false) || local_output_refusal);
    if let Some(underlying_safe_to_replay) =
        details.insert("safe_to_replay".to_owned(), Value::Bool(safe_to_replay))
    {
        details.insert(
            "underlying_safe_to_replay".to_owned(),
            underlying_safe_to_replay,
        );
    }
    details.insert(
        "scan_artifact_safe_to_replay".to_owned(),
        Value::Bool(artifact_safe_to_replay),
    );
    details.insert(
        "output_emitted".to_owned(),
        Value::Bool(progress.output_emitted),
    );
    details.insert(
        "output_emission_attempted".to_owned(),
        Value::Bool(progress.output_emission_attempted),
    );
    details.insert(
        "uncheckpointed_output".to_owned(),
        Value::Bool(progress.uncheckpointed_output),
    );
    details.insert("returned".to_owned(), Value::from(progress.returned));
    details.insert("pages".to_owned(), Value::from(progress.pages));
    if !artifact_safe_to_replay {
        let checkpoint_state = if progress.checkpoint_commit_unknown {
            "unknown"
        } else {
            match progress.local_checkpoint_committed {
                Some(true) => "committed",
                Some(false) => "not_committed",
                None => "unknown",
            }
        };
        let action = if progress.resume_file.is_some() {
            "Compare the last complete JSONL item sequence in the output artifact with the resume file sequence, then truncate or de-duplicate output before continuing from the persisted cursor."
        } else {
            "Inspect the output artifact for complete JSONL records and de-duplicate item meta.sequence values before starting another scan."
        };
        details.insert(
            "artifact_reconciliation".to_owned(),
            json!({
                "required": true,
                "resume_file": progress.resume_file,
                "initial_sequence": progress.initial_sequence,
                "last_confirmed_sequence": progress.returned,
                "confirmed_items_this_run": progress.returned.saturating_sub(progress.initial_sequence),
                "last_known_checkpoint_sequence": progress.persisted_sequence,
                "checkpoint_commit_state": checkpoint_state,
                "action": action
            }),
        );
        if error.hint.is_none() {
            error.hint = Some(action.to_owned());
        }
    }
    if let Some((status, request_id)) = &progress.last_response.0 {
        details.insert(
            "last_successful_http_status".to_owned(),
            Value::from(*status),
        );
        details.insert(
            "last_successful_request_id".to_owned(),
            request_id.clone().map_or(Value::Null, Value::String),
        );
        if matches!(progress.phase, ScanFailurePhase::AfterResponse) {
            error.http_status.get_or_insert(*status);
            if error.request_id.is_none() {
                error.request_id.clone_from(request_id);
            }
        }
    }
    error.details = Value::Object(details);
    error.with_output_guard(output_guard.clone())
}

fn scan_resume_setup_error(
    mut error: ReltioError,
    resume_file: Option<&str>,
    output_guard: &reltio_client::redaction::OutputGuard,
    phase: &'static str,
) -> ReltioError {
    let mut details = match std::mem::take(&mut error.details) {
        Value::Object(details) => details,
        cause => serde_json::Map::from_iter([("cause".to_owned(), cause)]),
    };
    if let Some(operation_safe_to_replay) =
        details.insert("safe_to_replay".to_owned(), Value::Bool(false))
    {
        details.insert(
            "resume_operation_safe_to_replay".to_owned(),
            operation_safe_to_replay,
        );
    }
    details.insert("phase".to_owned(), Value::String(phase.to_owned()));
    details.insert(
        "artifact_reconciliation".to_owned(),
        json!({
            "required": true,
            "resume_file": resume_file,
            "checkpoint_commit_state": "not_started",
            "action": "Inspect the resume artifact before retrying; continue only after confirming its cursor and sequence match the intended output artifact."
        }),
    );
    error.details = Value::Object(details);
    error.retryable = false;
    error.with_output_guard(output_guard.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointCommitOutcome {
    Committed,
    NotCommitted,
    Unknown,
}

fn checkpoint_commit_outcome(error: &ReltioError) -> CheckpointCommitOutcome {
    if error.details["committed"].as_bool() == Some(true) {
        CheckpointCommitOutcome::Committed
    } else if error.details["checkpoint_commit_unknown"].as_bool() == Some(true) {
        CheckpointCommitOutcome::Unknown
    } else {
        CheckpointCommitOutcome::NotCommitted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumeState {
    schema_version: u32,
    endpoint_id: String,
    profile: Option<String>,
    environment: String,
    tenant: String,
    filter_hash: String,
    query_hash: String,
    page_size: u32,
    data_service_url: String,
    cursor: Option<String>,
    sequence: u64,
    #[serde(skip)]
    initial_sequence: u64,
    acquired_at: DateTime<Utc>,
    last_read_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    exhausted: bool,
    cli_version: String,
}

fn load_or_create_resume(
    existing: Option<(&Path, &[u8])>,
    target: &reltio_client::config::ResolvedTarget,
    arguments: &EntityScanArgs,
    filter_hash: &str,
    query_hash: &str,
    data_service_url: &str,
    cursor_ttl: TimeDelta,
) -> Result<ResumeState> {
    if let Some((path, bytes)) = existing {
        let mut state = parse_resume_state(bytes, path)?;
        let identity_matches = state.schema_version == 2
            && state.endpoint_id == "entity.scan"
            && state.profile == target.profile
            && state.environment == target.environment
            && state.tenant == target.tenant
            && state.filter_hash == filter_hash
            && state.query_hash == query_hash
            && state.page_size == arguments.page_size
            && state.data_service_url == data_service_url
            && state.cli_version == env!("CARGO_PKG_VERSION");
        if !identity_matches {
            return Err(ReltioError::new(
                    "resume_context_mismatch",
                    ErrorCategory::Conflict,
                    "resume file does not match the selected CLI version, profile, tenant, service route, or normalized scan query",
                )
                .with_hint(
                    "Use the CLI version and original arguments that created the file, or choose a new resume file.",
                ));
        }
        validate_resume_progress(&state)?;
        let now = Utc::now();
        if state.last_read_at < state.acquired_at || state.last_read_at > now {
            return Err(ReltioError::usage(
                "resume_file_invalid",
                "resume file acquisition and last-read times are not chronologically valid",
            ));
        }
        let declared_expires_at = state.expires_at;
        state.expires_at = state
                .last_read_at
                .checked_add_signed(cursor_ttl)
                .ok_or_else(|| {
                    ReltioError::usage(
                        "resume_file_invalid",
                        "resume file last-read time cannot be combined with the reviewed cursor lifetime",
                    )
                })?;
        ensure_cursor_fresh(&state, now)?;
        if declared_expires_at != state.expires_at {
            return Err(ReltioError::usage(
                    "resume_file_invalid",
                    "resume file expiry does not match its last-read time and the reviewed cursor lifetime",
                )
                .with_details(json!({ "reason": "cursor_expiry_mismatch" })));
        }
        state.initial_sequence = state.sequence;
        return Ok(state);
    }
    let now = Utc::now();
    Ok(ResumeState {
        schema_version: 2,
        endpoint_id: "entity.scan".to_owned(),
        profile: target.profile.clone(),
        environment: target.environment.clone(),
        tenant: target.tenant.clone(),
        filter_hash: filter_hash.to_owned(),
        query_hash: query_hash.to_owned(),
        page_size: arguments.page_size,
        data_service_url: data_service_url.to_owned(),
        cursor: None,
        sequence: 0,
        initial_sequence: 0,
        acquired_at: now,
        last_read_at: now,
        expires_at: now + cursor_ttl,
        exhausted: false,
        cli_version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

async fn acquire_resume_lock_until(
    path: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<std::fs::File> {
    let path = path.to_path_buf();
    run_resume_io_until(
        "reltio-resume-lock",
        "resume_lock",
        deadline,
        cancellation,
        move || acquire_resume_lock(&path),
    )
    .await
}

async fn read_resume_optional_until(
    path: Option<&Path>,
    lock_owner: Option<Arc<std::fs::File>>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let path = path.to_path_buf();
    run_resume_io_until(
        "reltio-resume-read",
        "resume_read",
        deadline,
        cancellation,
        move || {
            let result = read_bounded_optional(&path, true);
            drop(lock_owner);
            result
        },
    )
    .await
}

async fn commit_scan_progress_until(
    path: &Path,
    state: &ResumeState,
    lock_owner: Arc<std::fs::File>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(state).map_err(|error| {
        ReltioError::internal(format!("failed to encode scan checkpoint: {error}"))
    })?;
    let path = path.to_path_buf();
    run_resume_write_until(deadline, cancellation, move || {
        let result = atomic_write_private(&path, &encoded);
        drop(lock_owner);
        result
    })
    .await
}

async fn run_resume_io_until<T, Operation>(
    thread_name: &'static str,
    phase: &'static str,
    deadline: Instant,
    cancellation: &CancellationToken,
    operation: Operation,
) -> Result<T>
where
    T: Send + 'static,
    Operation: FnOnce() -> Result<T> + Send + 'static,
{
    if let Some(control) = active_resume_control(cancellation, deadline) {
        return Err(resume_io_control_error(control, phase));
    }
    let timeline = ResumeIoTimeline::default();
    let thread_timeline = timeline.clone();
    let thread_cancellation = cancellation.clone();
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            let result = active_resume_control(&thread_cancellation, deadline)
                .map_or_else(operation, |control| {
                    Err(resume_io_control_error(control, phase))
                });
            let completed_at = thread_cancellation.event_stamp();
            thread_timeline.record_completed(completed_at);
            let _ = sender.send((completed_at, result));
        })
        .map_err(|error| {
            ReltioError::io(
                &format!("failed to start the bounded scan {phase} operation"),
                &error,
            )
        })?;
    wait_for_resume_io(&mut receiver, &timeline, phase, deadline, cancellation).await
}

async fn wait_for_resume_io<T>(
    receiver: &mut tokio::sync::oneshot::Receiver<(EventStamp, Result<T>)>,
    timeline: &ResumeIoTimeline,
    phase: &'static str,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T> {
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timeout);
    tokio::select! {
        biased;
        result = &mut *receiver => resolve_resume_io_result(
            result,
            cancellation,
            deadline,
            phase,
        ),
        () = cancellation.cancelled() => {
            if timeline.completed_at().is_some_and(|completed_at| {
                resume_control_after(completed_at, cancellation, deadline).is_none()
            }) {
                return resolve_resume_io_result(
                    receiver.await,
                    cancellation,
                    deadline,
                    phase,
                );
            }
            Err(resume_io_control_error(
                active_resume_control(cancellation, deadline).unwrap_or(ResumeControl::Canceled),
                phase,
            ))
        },
        () = &mut timeout => {
            if timeline.completed_at().is_some_and(|completed_at| {
                resume_control_after(completed_at, cancellation, deadline).is_none()
            }) {
                return resolve_resume_io_result(
                    receiver.await,
                    cancellation,
                    deadline,
                    phase,
                );
            }
            Err(resume_io_control_error(
                active_resume_control(cancellation, deadline).unwrap_or(ResumeControl::TimedOut),
                phase,
            ))
        },
    }
}

fn resolve_resume_io_result<T>(
    result: std::result::Result<(EventStamp, Result<T>), tokio::sync::oneshot::error::RecvError>,
    cancellation: &CancellationToken,
    deadline: Instant,
    phase: &'static str,
) -> Result<T> {
    match result {
        Ok((completed_at, result)) => resume_control_after(completed_at, cancellation, deadline)
            .map_or(result, |control| {
                Err(resume_io_control_error(control, phase))
            }),
        Err(_) => active_resume_control(cancellation, deadline).map_or_else(
            || {
                Err(ReltioError::internal(format!(
                    "the bounded scan {phase} operation terminated without a result"
                )))
            },
            |control| Err(resume_io_control_error(control, phase)),
        ),
    }
}

async fn run_resume_write_until<Operation>(
    deadline: Instant,
    cancellation: &CancellationToken,
    operation: Operation,
) -> Result<()>
where
    Operation: FnOnce() -> Result<()> + Send + 'static,
{
    if let Some(control) = active_resume_control(cancellation, deadline) {
        return Err(resume_write_control_error(control, false));
    }
    let timeline = ResumeIoTimeline::default();
    let thread_timeline = timeline.clone();
    let thread_cancellation = cancellation.clone();
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("reltio-resume-write".to_owned())
        .spawn(move || {
            let mut launched = false;
            let result =
                match thread_timeline.mark_launched_if_active(&thread_cancellation, deadline) {
                    Ok(()) => {
                        launched = true;
                        operation()
                    }
                    Err(control) => Err(resume_write_control_error(control, false)),
                };
            let completed_at = thread_cancellation.event_stamp();
            thread_timeline.record_completed(completed_at);
            let _ = sender.send((completed_at, launched, result));
        })
        .map_err(|error| {
            ReltioError::io("failed to start the bounded scan checkpoint writer", &error)
        })?;

    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timeout);
    tokio::select! {
        biased;
        result = &mut receiver => resolve_resume_write_result(
            result,
            cancellation,
            deadline,
        ),
        () = cancellation.cancelled() => {
            if timeline.completed_at().is_some_and(|completed_at| {
                resume_control_after(completed_at, cancellation, deadline).is_none()
            }) {
                return resolve_resume_write_result(
                    (&mut receiver).await,
                    cancellation,
                    deadline,
                );
            }
            Err(resume_write_control_error(
                active_resume_control(cancellation, deadline).unwrap_or(ResumeControl::Canceled),
                timeline.launched_at().is_some(),
            ))
        },
        () = &mut timeout => {
            if timeline.completed_at().is_some_and(|completed_at| {
                resume_control_after(completed_at, cancellation, deadline).is_none()
            }) {
                return resolve_resume_write_result(
                    (&mut receiver).await,
                    cancellation,
                    deadline,
                );
            }
            Err(resume_write_control_error(
                active_resume_control(cancellation, deadline).unwrap_or(ResumeControl::TimedOut),
                timeline.launched_at().is_some(),
            ))
        },
    }
}

fn resolve_resume_write_result(
    result: std::result::Result<
        (EventStamp, bool, Result<()>),
        tokio::sync::oneshot::error::RecvError,
    >,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<()> {
    match result {
        Ok((completed_at, launched, result)) => {
            resume_control_after(completed_at, cancellation, deadline).map_or(result, |control| {
                Err(resume_write_control_error(control, launched))
            })
        }
        Err(_) => active_resume_control(cancellation, deadline).map_or_else(
            || {
                Err(ReltioError::internal(
                    "the bounded scan checkpoint writer terminated without a result",
                ))
            },
            |control| Err(resume_write_control_error(control, true)),
        ),
    }
}

#[derive(Debug, Clone, Default)]
struct ResumeIoTimeline {
    launched_at: Arc<Mutex<Option<EventStamp>>>,
    completed_at: Arc<Mutex<Option<EventStamp>>>,
}

impl ResumeIoTimeline {
    fn mark_launched_if_active(
        &self,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> std::result::Result<(), ResumeControl> {
        let mut launched_at = self
            .launched_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(control) = active_resume_control(cancellation, deadline) {
            return Err(control);
        }
        *launched_at = Some(cancellation.event_stamp());
        Ok(())
    }

    fn launched_at(&self) -> Option<EventStamp> {
        *self
            .launched_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record_completed(&self, stamp: EventStamp) {
        *self
            .completed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stamp);
    }

    fn completed_at(&self) -> Option<EventStamp> {
        *self
            .completed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeControl {
    Canceled,
    TimedOut,
}

fn active_resume_control(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Option<ResumeControl> {
    let canceled_at = cancellation.cancelled_at();
    if Instant::now() < deadline {
        return canceled_at.map(|_| ResumeControl::Canceled);
    }
    Some(
        if canceled_at.is_some_and(|stamp| stamp.occurred_at_or_before(deadline)) {
            ResumeControl::Canceled
        } else {
            ResumeControl::TimedOut
        },
    )
}

fn resume_control_after(
    completed_at: EventStamp,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Option<ResumeControl> {
    let canceled_at = cancellation.cancelled_at();
    let canceled_first = canceled_at.is_some_and(|stamp| !completed_at.precedes(stamp));
    let timed_out_first = !completed_at.occurred_before(deadline);
    match (canceled_first, timed_out_first) {
        (false, false) => None,
        (true, false) => Some(ResumeControl::Canceled),
        (false, true) => Some(ResumeControl::TimedOut),
        (true, true) => Some(
            if canceled_at.is_some_and(|stamp| stamp.occurred_at_or_before(deadline)) {
                ResumeControl::Canceled
            } else {
                ResumeControl::TimedOut
            },
        ),
    }
}

fn resume_io_control_error(control: ResumeControl, phase: &'static str) -> ReltioError {
    let (code, category, message) = match control {
        ResumeControl::Canceled => (
            "request_canceled",
            ErrorCategory::Canceled,
            "scan resume-file I/O was canceled",
        ),
        ResumeControl::TimedOut => (
            "request_timeout",
            ErrorCategory::Timeout,
            "scan resume-file I/O exceeded the overall timeout",
        ),
    };
    ReltioError::new(code, category, message).with_details(json!({
        "phase": phase,
        "remote_response_received": false,
        "remote_request_completed": false,
        "remote_operation_completed": false,
        "remote_operation_state": "request_not_sent",
        "local_state_committed": false,
        "safe_to_replay": true
    }))
}

fn resume_write_control_error(control: ResumeControl, commit_unknown: bool) -> ReltioError {
    let (code, category, message) = match control {
        ResumeControl::Canceled => (
            "request_canceled",
            ErrorCategory::Canceled,
            "scan checkpoint persistence was canceled",
        ),
        ResumeControl::TimedOut => (
            "request_timeout",
            ErrorCategory::Timeout,
            "scan checkpoint persistence exceeded the overall timeout",
        ),
    };
    let committed = if commit_unknown {
        Value::Null
    } else {
        Value::Bool(false)
    };
    ReltioError::new(code, category, message)
        .with_details(json!({
            "phase": "resume_write",
            "committed": committed.clone(),
            "checkpoint_commit_unknown": commit_unknown,
            "local_state_committed": committed,
            "safe_to_replay": !commit_unknown
        }))
        .with_hint(if commit_unknown {
            "The checkpoint write may have committed after control fired; inspect the resume file and reconcile it with complete JSONL item sequences before continuing."
        } else {
            "The checkpoint write did not start before control fired."
        })
}

fn acquire_resume_lock(path: &Path) -> Result<std::fs::File> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock = open_private_lock(Path::new(&lock_path))?;
    FileExt::try_lock_exclusive(&lock).map_err(|error| {
        if is_lock_contended(&error) {
            ReltioError::new(
                "resume_file_in_use",
                ErrorCategory::Conflict,
                format!("another scan is using resume file {}", path.display()),
            )
        } else {
            ReltioError::io("failed to lock scan resume file", &error)
        }
    })?;
    Ok(lock)
}

fn resume_file_text(path: Option<&Path>) -> Result<Option<&str>> {
    path.map(|path| {
        path.to_str().ok_or_else(|| {
            ReltioError::usage(
                "invalid_resume_file_path",
                "resume-file must be a valid UTF-8 path so checkpoint metadata remains structured",
            )
        })
    })
    .transpose()
}

fn ensure_cursor_fresh(state: &ResumeState, now: DateTime<Utc>) -> Result<()> {
    if state.cursor.is_some() && !state.exhausted && state.expires_at <= now {
        Err(cursor_expired_error())
    } else {
        Ok(())
    }
}

fn scan_request_deadline(state: &ResumeState, overall_deadline: Instant) -> Result<Instant> {
    if state.cursor.is_none() || state.exhausted {
        return Ok(overall_deadline);
    }
    let now_instant = Instant::now();
    let now = Utc::now();
    ensure_cursor_fresh(state, now)?;
    let remaining = (state.expires_at - now)
        .to_std()
        .map_err(|_| cursor_expired_error())?;
    let cursor_deadline = now_instant.checked_add(remaining).ok_or_else(|| {
        ReltioError::internal("cursor lifetime cannot be represented as a request deadline")
    })?;
    Ok(overall_deadline.min(cursor_deadline))
}

fn validate_resume_progress(state: &ResumeState) -> Result<()> {
    if state.cursor.is_none() {
        return Err(ReltioError::usage(
            "resume_file_invalid",
            "persisted scan progress requires a cursor",
        )
        .with_details(json!({ "reason": "missing_cursor" })));
    }
    if state.sequence == u64::MAX {
        return Err(ReltioError::usage(
            "resume_file_invalid",
            "persisted scan sequence is out of range",
        )
        .with_details(json!({ "reason": "sequence_out_of_range" })));
    }
    Ok(())
}

fn cursor_expired_error() -> ReltioError {
    ReltioError::new(
        "resume_cursor_expired",
        ErrorCategory::Conflict,
        "the saved cursor is past its conservative documented lifetime",
    )
    .with_hint("Start a new scan; Reltio cursors cannot be safely reconstructed.")
}

fn parse_resume_state(bytes: &[u8], path: &Path) -> Result<ResumeState> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        ReltioError::usage(
            "resume_file_invalid",
            format!("failed to parse resume file {}", path.display()),
        )
        .with_details(json_parse_details(&error))
    })?;
    let state = if value.get("type").and_then(Value::as_str) == Some("checkpoint") {
        value.pointer("/meta/resume").cloned().ok_or_else(|| {
            ReltioError::usage(
                "resume_file_invalid",
                format!("checkpoint event {} has no resume data", path.display()),
            )
        })?
    } else {
        value
    };
    serde_json::from_value(state).map_err(|error| {
        ReltioError::usage(
            "resume_file_invalid",
            format!("resume file {} has an invalid state shape", path.display()),
        )
        .with_details(json_parse_details(&error))
    })
}

fn write_checkpoint_event(
    writer: &mut impl Write,
    state: &ResumeState,
    pages: u64,
    resume_file: Option<&str>,
    output_guard: &reltio_client::redaction::OutputGuard,
) -> Result<()> {
    write_jsonl_event_guarded(
        &json!({
            "schema_version": reltio_client::SCHEMA_VERSION,
            "type": "checkpoint",
            "data": null,
            "meta": {
                "sequence": state.sequence,
                "cursor": state.cursor,
                "returned": state.sequence,
                "pages": pages,
                "expires_at": state.expires_at,
                "resume_file": resume_file,
                "resume": state
            }
        }),
        writer,
        output_guard,
    )
}

fn scan_query_hash(runtime: &Runtime, arguments: &EntityScanArgs) -> String {
    let normalized = json!({
        "filter": arguments.filter.trim(),
        "select": runtime.globals.fields,
        "options": arguments.options,
        "activeness": arguments.activeness
    });
    sha256_hex(normalized.to_string().as_bytes())
}

fn ensure_finite_response_active(
    runtime: &Runtime,
    deadline: Instant,
    response: &ApiResponse,
    output_guard: &reltio_client::redaction::OutputGuard,
) -> Result<()> {
    let (code, category, message) = if runtime.cancellation.is_cancelled() {
        (
            "request_canceled",
            ErrorCategory::Canceled,
            "the command was canceled after a successful read response was received",
        )
    } else if Instant::now() >= deadline {
        (
            "request_timeout",
            ErrorCategory::Timeout,
            "the command exceeded its overall timeout after a successful read response was received",
        )
    } else {
        return Ok(());
    };
    Err(ReltioError::new(code, category, message)
        .with_http_status(response.status)
        .with_request_id(response.request_id.clone())
        .with_details(json!({
            "phase": "response_processing",
            "remote_response_received": true,
            "remote_request_completed": true,
            "remote_operation_completed": true,
            "remote_operation_state": "success_response_received",
            "local_state_committed": false,
            "safe_to_replay": true
        }))
        .with_output_guard(output_guard.clone()))
}

fn read_response_output_error(mut error: ReltioError, response: &ApiResponse) -> ReltioError {
    error.http_status = Some(response.status);
    error.request_id.clone_from(&response.request_id);
    let output_error = std::mem::replace(&mut error.details, Value::Null);
    error.details = json!({
        "output_error": output_error,
        "remote_response_received": true,
        "remote_request_completed": true,
        "remote_operation_completed": true,
        "remote_operation_state": "success_response_received",
        "local_state_committed": false,
        "safe_to_replay": true
    });
    error.retryable = false;
    error
}

fn response_meta(
    command: &str,
    target: &reltio_client::config::ResolvedTarget,
    response: &reltio_client::http::ApiResponse,
    started: Instant,
    consistency: Option<reltio_client::registry::Consistency>,
) -> Meta {
    let mut meta = Meta::new(command).with_target(target, Some("data"));
    meta.elapsed_ms = started.elapsed().as_millis();
    meta.request_id.clone_from(&response.request_id);
    meta.http_status = Some(response.status);
    meta.attempts = Some(response.attempts);
    meta.practice_ids.clone_from(&response.applied_practice_ids);
    meta.consistency = consistency;
    meta
}

#[allow(dead_code)]
fn endpoint_is_reviewed(id: &str) -> Result<bool> {
    let registry = Registry::embedded()?;
    Ok(registry
        .endpoint(id)
        .is_some_and(|endpoint| registry.coverage(Some(endpoint)) == PracticeCoverage::Reviewed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resume_state() -> ResumeState {
        let now = Utc::now();
        ResumeState {
            schema_version: 2,
            endpoint_id: "entity.scan".to_owned(),
            profile: Some("test".to_owned()),
            environment: "test".to_owned(),
            tenant: "TestTenant".to_owned(),
            filter_hash: "filter".to_owned(),
            query_hash: "query".to_owned(),
            page_size: 100,
            data_service_url: "https://test.reltio.com/reltio/api/TestTenant/".to_owned(),
            cursor: Some("cursor-1".to_owned()),
            sequence: 10,
            initial_sequence: 0,
            acquired_at: now,
            last_read_at: now,
            expires_at: now + TimeDelta::hours(1),
            exhausted: false,
            cli_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    #[test]
    fn checkpoint_event_round_trips_as_resume_state() {
        let state = resume_state();
        let mut bytes = Vec::new();
        write_checkpoint_event(
            &mut bytes,
            &state,
            1,
            None,
            &reltio_client::redaction::OutputGuard::default(),
        )
        .expect("checkpoint event");

        let decoded = parse_resume_state(&bytes, Path::new("checkpoint.jsonl"))
            .expect("event is a resume artifact");

        assert_eq!(decoded.cursor.as_deref(), Some("cursor-1"));
        assert_eq!(decoded.sequence, 10);
        assert_eq!(decoded.tenant, "TestTenant");
        assert_eq!(decoded.cli_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn active_scan_refuses_an_expired_cursor_before_the_next_request() {
        let mut state = resume_state();
        state.expires_at = Utc::now() - TimeDelta::seconds(1);

        let error = ensure_cursor_fresh(&state, Utc::now())
            .expect_err("expired active cursor must not be sent");

        assert_eq!(error.code, "resume_cursor_expired");
    }

    #[test]
    fn continuation_deadline_never_outlives_the_cursor() {
        let state = resume_state();
        let overall_deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(7_200))
            .expect("overall deadline");

        let request_deadline =
            scan_request_deadline(&state, overall_deadline).expect("cursor deadline");

        assert!(request_deadline < overall_deadline);
    }

    #[test]
    fn persisted_progress_requires_a_cursor_and_incrementable_sequence() {
        let mut state = resume_state();
        state.cursor = None;
        assert_eq!(
            validate_resume_progress(&state)
                .expect_err("missing cursor must fail")
                .details["reason"],
            "missing_cursor"
        );

        state.cursor = Some("cursor-1".to_owned());
        state.sequence = u64::MAX;
        assert_eq!(
            validate_resume_progress(&state)
                .expect_err("maximum sequence must fail")
                .details["reason"],
            "sequence_out_of_range"
        );
    }

    #[test]
    fn scan_failure_preserves_current_response_metadata_over_prior_success() {
        let error = ReltioError::new(
            "service_unavailable",
            ErrorCategory::Api,
            "the continuation request failed",
        )
        .with_http_status(503)
        .with_details(json!({
            "remote_response_received": true,
            "remote_request_completed": true,
            "remote_operation_completed": false,
            "remote_operation_state": "request_failed",
            "safe_to_replay": true
        }));
        let normalized = scan_progress_error(
            error,
            ScanProgress {
                last_response: &ScanResponseOutcome(Some((200, Some("prior-request".to_owned())))),
                phase: ScanFailurePhase::BeforeResponse,
                local_checkpoint_committed: Some(true),
                checkpoint_commit_unknown: false,
                output_emitted: true,
                output_emission_attempted: true,
                uncheckpointed_output: true,
                fresh_scan: false,
                initial_sequence: 10,
                persisted_sequence: Some(10),
                resume_file: Some("scan.resume.json"),
                returned: 25,
                pages: 2,
            },
            &reltio_client::redaction::OutputGuard::default(),
        );

        assert_eq!(normalized.http_status, Some(503));
        assert_eq!(normalized.details["last_successful_http_status"], 200);
        assert_eq!(
            normalized.details["remote_operation_state"],
            "request_failed"
        );
        assert_eq!(normalized.details["safe_to_replay"], false);
        assert_eq!(normalized.details["underlying_safe_to_replay"], true);
    }

    #[test]
    fn stale_checkpoint_does_not_make_later_output_safe_to_replay() {
        let normalized = scan_progress_error(
            ReltioError::io(
                "failed to write scan output",
                &io::Error::new(io::ErrorKind::BrokenPipe, "closed"),
            ),
            ScanProgress {
                last_response: &ScanResponseOutcome(Some((200, None))),
                phase: ScanFailurePhase::AfterResponse,
                local_checkpoint_committed: Some(true),
                checkpoint_commit_unknown: false,
                output_emitted: true,
                output_emission_attempted: true,
                uncheckpointed_output: true,
                fresh_scan: false,
                initial_sequence: 10,
                persisted_sequence: Some(10),
                resume_file: Some("scan.resume.json"),
                returned: 25,
                pages: 2,
            },
            &reltio_client::redaction::OutputGuard::default(),
        );

        assert_eq!(normalized.details["local_state_committed"], true);
        assert_eq!(normalized.details["uncheckpointed_output"], true);
        assert_eq!(normalized.details["safe_to_replay"], false);
    }

    #[test]
    fn fresh_scan_guard_refusal_before_output_remains_safe_to_replay() {
        let normalized = scan_progress_error(
            ReltioError::new(
                "credential_output_refused",
                ErrorCategory::Safety,
                "the first page was refused before output",
            )
            .with_details(json!({ "output_omitted": true, "safe_to_replay": false })),
            ScanProgress {
                last_response: &ScanResponseOutcome(Some((200, None))),
                phase: ScanFailurePhase::AfterResponse,
                local_checkpoint_committed: Some(false),
                checkpoint_commit_unknown: false,
                output_emitted: false,
                output_emission_attempted: true,
                uncheckpointed_output: false,
                fresh_scan: true,
                initial_sequence: 0,
                persisted_sequence: None,
                resume_file: Some("scan.resume.json"),
                returned: 0,
                pages: 1,
            },
            &reltio_client::redaction::OutputGuard::default(),
        );

        assert_eq!(normalized.details["output_omitted"], true);
        assert_eq!(normalized.details["underlying_safe_to_replay"], false);
        assert_eq!(normalized.details["scan_artifact_safe_to_replay"], true);
        assert_eq!(normalized.details["safe_to_replay"], true);
        assert!(normalized.details.get("artifact_reconciliation").is_none());
    }

    #[test]
    fn provider_replay_veto_survives_a_fresh_scan_without_output() {
        let normalized = scan_progress_error(
            ReltioError::new(
                "request_canceled",
                ErrorCategory::Canceled,
                "credential acquisition was canceled",
            )
            .with_details(json!({
                "credential_process_started": Value::Null,
                "credential_process_side_effects": "unknown",
                "safe_to_replay": false
            })),
            ScanProgress {
                last_response: &ScanResponseOutcome::default(),
                phase: ScanFailurePhase::BeforeResponse,
                local_checkpoint_committed: Some(false),
                checkpoint_commit_unknown: false,
                output_emitted: false,
                output_emission_attempted: false,
                uncheckpointed_output: false,
                fresh_scan: true,
                initial_sequence: 0,
                persisted_sequence: None,
                resume_file: Some("scan.resume.json"),
                returned: 0,
                pages: 0,
            },
            &reltio_client::redaction::OutputGuard::deny_all(),
        );

        assert_eq!(normalized.details["underlying_safe_to_replay"], false);
        assert_eq!(normalized.details["scan_artifact_safe_to_replay"], true);
        assert_eq!(normalized.details["safe_to_replay"], false);
        assert!(normalized.details.get("artifact_reconciliation").is_none());
    }

    #[test]
    fn a_resumed_scan_without_new_output_is_not_safe_to_replay() {
        let normalized = scan_progress_error(
            ReltioError::new(
                "request_canceled",
                ErrorCategory::Canceled,
                "the continuation was canceled",
            ),
            ScanProgress {
                last_response: &ScanResponseOutcome::default(),
                phase: ScanFailurePhase::BeforeResponse,
                local_checkpoint_committed: Some(true),
                checkpoint_commit_unknown: false,
                output_emitted: false,
                output_emission_attempted: false,
                uncheckpointed_output: false,
                fresh_scan: false,
                initial_sequence: 10,
                persisted_sequence: Some(10),
                resume_file: Some("scan.resume.json"),
                returned: 10,
                pages: 0,
            },
            &reltio_client::redaction::OutputGuard::default(),
        );

        assert_eq!(normalized.details["safe_to_replay"], false);
        assert_eq!(
            normalized.details["artifact_reconciliation"]["required"],
            true
        );
        assert_eq!(
            normalized.details["artifact_reconciliation"]["last_known_checkpoint_sequence"],
            10
        );
    }

    #[test]
    fn a_fresh_scan_before_output_remains_safe_to_replay() {
        let error = ReltioError::new(
            "api_response_invalid_json",
            ErrorCategory::Api,
            "the first page was malformed",
        )
        .with_http_status(200)
        .with_request_id(Some("malformed-page".to_owned()))
        .with_output_guard(reltio_client::redaction::OutputGuard::from_known_secrets(
            &["response-secret"],
        ));
        assert!(matches!(
            scan_request_failure_phase(&error),
            ScanFailurePhase::AfterResponse
        ));
        let normalized = scan_progress_error(
            error,
            ScanProgress {
                last_response: &ScanResponseOutcome::default(),
                phase: ScanFailurePhase::AfterResponse,
                local_checkpoint_committed: Some(false),
                checkpoint_commit_unknown: false,
                output_emitted: false,
                output_emission_attempted: false,
                uncheckpointed_output: false,
                fresh_scan: true,
                initial_sequence: 0,
                persisted_sequence: None,
                resume_file: None,
                returned: 0,
                pages: 0,
            },
            &reltio_client::redaction::OutputGuard::default(),
        );

        assert_eq!(normalized.http_status, Some(200));
        assert_eq!(normalized.request_id.as_deref(), Some("malformed-page"));
        assert_eq!(normalized.details["remote_response_received"], true);
        assert_eq!(normalized.details["safe_to_replay"], true);
        assert!(normalized.details.get("artifact_reconciliation").is_none());
    }

    #[test]
    fn committed_checkpoint_errors_preserve_durability_metadata() {
        let error = ReltioError::io(
            "failed to sync committed checkpoint",
            &io::Error::other("injected directory sync failure"),
        )
        .with_details(json!({
            "committed": true,
            "durability": "uncertain"
        }));
        assert_eq!(
            checkpoint_commit_outcome(&error),
            CheckpointCommitOutcome::Committed
        );
        let normalized = scan_progress_error(
            error,
            ScanProgress {
                last_response: &ScanResponseOutcome(Some((200, None))),
                phase: ScanFailurePhase::AfterResponse,
                local_checkpoint_committed: Some(true),
                checkpoint_commit_unknown: false,
                output_emitted: true,
                output_emission_attempted: true,
                uncheckpointed_output: false,
                fresh_scan: true,
                initial_sequence: 0,
                persisted_sequence: Some(1),
                resume_file: Some("scan.resume.json"),
                returned: 1,
                pages: 1,
            },
            &reltio_client::redaction::OutputGuard::default(),
        );

        assert_eq!(normalized.details["committed"], true);
        assert_eq!(normalized.details["durability"], "uncertain");
        assert_eq!(normalized.details["local_state_committed"], true);
        assert_eq!(normalized.details["uncheckpointed_output"], false);
        assert_eq!(
            normalized.details["artifact_reconciliation"]["checkpoint_commit_state"],
            "committed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn launched_resume_write_reports_unknown_commit_when_control_wins() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let cancellation = CancellationToken::new();
        let writer_cancellation = cancellation.clone();
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let thread_started = Arc::clone(&started);
        let thread_release = Arc::clone(&release);
        let writer = tokio::spawn(async move {
            run_resume_write_until(
                Instant::now() + std::time::Duration::from_secs(30),
                &writer_cancellation,
                move || {
                    assert_eq!(std::thread::current().name(), Some("reltio-resume-write"));
                    thread_started.store(true, Ordering::Release);
                    while !thread_release.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Ok(())
                },
            )
            .await
        });
        while !started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), writer)
            .await
            .expect("control bounds the launched write")
            .expect("writer task completes")
            .expect_err("launched write cannot become success after cancellation");
        release.store(true, Ordering::Release);

        assert_eq!(error.code, "request_canceled");
        assert!(error.details["committed"].is_null());
        assert_eq!(error.details["checkpoint_commit_unknown"], true);
        assert_eq!(error.details["safe_to_replay"], false);
    }

    #[tokio::test]
    async fn resume_write_checks_control_before_launch() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let launched = Arc::new(AtomicBool::new(false));
        let thread_launched = Arc::clone(&launched);

        let error = run_resume_write_until(
            Instant::now() + std::time::Duration::from_secs(30),
            &cancellation,
            move || {
                thread_launched.store(true, Ordering::Release);
                Ok(())
            },
        )
        .await
        .expect_err("preexisting control must prevent a checkpoint write");

        assert!(!launched.load(Ordering::Acquire));
        assert_eq!(error.details["committed"], false);
        assert_eq!(error.details["checkpoint_commit_unknown"], false);
    }

    #[test]
    fn completed_resume_write_wins_over_later_control() {
        let cancellation = CancellationToken::new();
        let completed_at = cancellation.event_stamp();
        cancellation.cancel();

        resolve_resume_write_result(
            Ok((completed_at, true, Ok(()))),
            &cancellation,
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .expect("completion before cancellation remains authoritative");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_read_returns_on_control_without_waiting_for_blocked_io() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let cancellation = CancellationToken::new();
        let reader_cancellation = cancellation.clone();
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let thread_started = Arc::clone(&started);
        let thread_release = Arc::clone(&release);
        let reader = tokio::spawn(async move {
            run_resume_io_until(
                "reltio-resume-read",
                "resume_read",
                Instant::now() + std::time::Duration::from_secs(30),
                &reader_cancellation,
                move || {
                    assert_eq!(std::thread::current().name(), Some("reltio-resume-read"));
                    thread_started.store(true, Ordering::Release);
                    while !thread_release.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Ok(())
                },
            )
            .await
        });
        while !started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), reader)
            .await
            .expect("control bounds the read")
            .expect("reader task completes")
            .expect_err("blocked read must observe cancellation");
        release.store(true, Ordering::Release);

        assert_eq!(error.code, "request_canceled");
        assert_eq!(error.details["phase"], "resume_read");
    }

    #[test]
    fn resume_file_has_one_active_owner() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("resume.json");
        let first = acquire_resume_lock(&path).expect("first owner acquires lock");

        let error = acquire_resume_lock(&path).expect_err("second owner must fail");
        assert_eq!(error.code, "resume_file_in_use");

        drop(first);
        acquire_resume_lock(&path).expect("lock is released on drop");
    }
}
