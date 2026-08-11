use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};
use fs2::FileExt;
use is_terminal::IsTerminal;
use reltio_client::auth::TokenManagerOptions;
use reltio_client::entities::{
    CROSSWALK_ID_FALLBACK_WARNING, EntityByCrosswalkRequest, EntityGetOptions,
    EntityHistoryRequest, EntityMatchesRequest, EntityScanRequest, EntitySearchRequest,
    HISTORY_BOUNDARY_WARNING, HISTORY_CANONICAL_VALUES_WARNING,
    POTENTIAL_MATCHES_FRESHNESS_WARNING, SEARCH_BOUNDARY_WARNING, validate_by_crosswalk,
    validate_get, validate_history, validate_matches, validate_scan, validate_search,
};
use reltio_client::error::{ErrorCategory, ReltioError, Result, json_parse_details};
use reltio_client::fs::{atomic_write_private, open_private_lock, read_bounded_optional};
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
use crate::output::{
    Meta, output_error, write_jsonl_event_guarded, write_raw_guarded, write_success_guarded,
    write_warning_guarded,
};

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
    let mut output_guard = manager.output_guard()?;
    let auth_status = manager
        .status_until(deadline)
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
        write_warning_guarded(
            REVERSE_TRANSCODE_WARNING,
            runtime.globals.quiet,
            &output_guard,
        )
        .map_err(|error| read_response_output_error(error, &result.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(result.entity);
        let body = result
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
        return write_raw_guarded(&body, false, &output_guard)
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
    write_success_guarded(&entity, &meta, runtime.render, &output_guard)
        .map_err(|error| read_response_output_error(error, &result.response))
}

async fn by_crosswalk(runtime: &Runtime, arguments: EntityByCrosswalkArgs) -> Result<()> {
    reject_fields(runtime, "entity by-crosswalk")?;
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
    let mut output_guard = manager.output_guard()?;
    let auth_status = manager
        .status_until(deadline)
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
        write_warning_guarded(
            CROSSWALK_ID_FALLBACK_WARNING,
            runtime.globals.quiet,
            &output_guard,
        )
        .map_err(|error| read_response_output_error(error, &result.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(result.entries);
        let body = result
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &result.response, &output_guard)?;
        return write_raw_guarded(&body, false, &output_guard)
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
    write_success_guarded(&entries, &meta, runtime.render, &output_guard)
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
    let mut output_guard = manager.output_guard()?;
    let auth_status = manager
        .status_until(deadline)
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
        write_warning_guarded(
            SEARCH_BOUNDARY_WARNING,
            runtime.globals.quiet,
            &output_guard,
        )
        .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(page.entities);
        let body = page
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
        return write_raw_guarded(&body, false, &output_guard)
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
    write_success_guarded(&entities, &meta, runtime.render, &output_guard)
        .map_err(|error| read_response_output_error(error, &page.response))
}

async fn history(runtime: &Runtime, arguments: EntityHistoryArgs) -> Result<()> {
    reject_fields(runtime, "entity history")?;
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
    let mut output_guard = manager.output_guard()?;
    let auth_status = manager
        .status_until(deadline)
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
        write_warning_guarded(
            HISTORY_CANONICAL_VALUES_WARNING,
            runtime.globals.quiet,
            &output_guard,
        )
        .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if page.boundary_reached
        && matches!(
            runtime.render.format,
            OutputFormat::Raw | OutputFormat::Table
        )
    {
        write_warning_guarded(
            HISTORY_BOUNDARY_WARNING,
            runtime.globals.quiet,
            &output_guard,
        )
        .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(page.changes);
        let body = page
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
        return write_raw_guarded(&body, false, &output_guard)
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
    write_success_guarded(&changes, &meta, runtime.render, &output_guard)
        .map_err(|error| read_response_output_error(error, &page.response))
}

async fn matches(runtime: &Runtime, arguments: EntityMatchesArgs) -> Result<()> {
    reject_fields(runtime, "entity matches")?;
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
    let mut output_guard = manager.output_guard()?;
    let auth_status = manager
        .status_until(deadline)
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
        write_warning_guarded(
            POTENTIAL_MATCHES_FRESHNESS_WARNING,
            runtime.globals.quiet,
            &output_guard,
        )
        .map_err(|error| read_response_output_error(error, &page.response))?;
    }
    if runtime.render.format == OutputFormat::Raw {
        drop(page.matches);
        let body = page
            .response
            .redacted_body()
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        ensure_finite_response_active(runtime, deadline, &page.response, &output_guard)?;
        return write_raw_guarded(&body, false, &output_guard)
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
    write_success_guarded(&matches, &meta, runtime.render, &output_guard)
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
    let mut output_guard = manager.output_guard()?;
    let client = runtime
        .entities_client_until(&target, manager, deadline)
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let _resume_lock = arguments
        .resume_file
        .as_deref()
        .map(acquire_resume_lock)
        .transpose()
        .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let query_hash = scan_query_hash(runtime, &arguments);
    let filter_hash = sha256_hex(arguments.filter.trim().as_bytes());
    let mut state = load_or_create_resume(
        arguments.resume_file.as_deref(),
        &target,
        &arguments,
        &filter_hash,
        &query_hash,
        &data_service_url,
        cursor_ttl,
    )
    .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    let mut writer = io::BufWriter::new(io::stdout().lock());
    let mut pages = 0_u64;
    let mut returned = state.sequence;
    let mut exhausted = state.exhausted;
    let mut current_progress_committed = state.exhausted;
    while !exhausted {
        if started.elapsed() >= timeout {
            return Err(ReltioError::new(
                "scan_timeout",
                ErrorCategory::Timeout,
                "entity scan reached its overall timeout; the checkpoint remains resumable",
            )
            .with_details(json!({
                "returned": returned,
                "pages": pages,
                "resume_file": resume_file_output
            }))
            .with_output_guard(output_guard));
        }
        if arguments.max_pages.is_some_and(|maximum| pages >= maximum)
            || arguments
                .max_items
                .is_some_and(|maximum| returned >= maximum)
        {
            break;
        }
        let request_deadline = scan_request_deadline(&state, deadline)
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let remaining = arguments
            .max_items
            .map_or(u64::from(arguments.page_size), |maximum| {
                maximum.saturating_sub(returned)
            });
        let request_max =
            u32::try_from(remaining.min(u64::from(arguments.page_size))).map_err(|_| {
                ReltioError::internal("scan page size conversion failed")
                    .with_output_guard(output_guard.clone())
            })?;
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
            .await
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
        let page_read_at = Utc::now();
        output_guard.merge(&page.response.output_guard());
        pages += 1;
        if page.objects.len() > usize::try_from(request_max).unwrap_or(usize::MAX) {
            return Err(ReltioError::new(
                "scan_page_limit_violated",
                ErrorCategory::Api,
                "Reltio returned more scan objects than requested; refusing to create an unsafe checkpoint",
            )
            .with_request_id(page.response.request_id)
            .with_output_guard(output_guard.clone()));
        }
        let objects = page.objects;
        let cursor = page.cursor;
        drop(page.response);
        let object_count = u64::try_from(objects.len()).map_err(|_| {
            ReltioError::internal("scan page object count cannot be represented")
                .with_output_guard(output_guard.clone())
        })?;
        let sequence_fits = returned
            .checked_add(object_count)
            .is_some_and(|sequence| sequence < u64::MAX);
        if !sequence_fits {
            return Err(ReltioError::usage(
                "resume_file_invalid",
                "scan page would exhaust the persisted sequence capacity",
            )
            .with_details(json!({ "reason": "sequence_out_of_range" }))
            .with_output_guard(output_guard.clone()));
        }
        for object in &objects {
            returned = returned.checked_add(1).ok_or_else(|| {
                ReltioError::usage(
                    "resume_file_invalid",
                    "scan sequence cannot be incremented safely",
                )
                .with_output_guard(output_guard.clone())
            })?;
            write_jsonl_event_guarded(
                &json!({
                    "schema_version": reltio_client::SCHEMA_VERSION,
                    "type": "item",
                    "data": object,
                    "meta": {
                        "sequence": returned,
                        "cursor": null,
                        "consistency": scan_consistency
                    }
                }),
                &mut writer,
                &output_guard,
            )?;
        }

        state.cursor = Some(cursor);
        state.sequence = returned;
        state.last_read_at = page_read_at;
        // Tenant preserveCursor capability is not discoverable here, so use the
        // shorter reviewed TTL to fail safely rather than resume a stale cursor.
        state.expires_at = page_read_at + cursor_ttl;
        state.exhausted = objects.is_empty();
        if objects.is_empty() {
            exhausted = true;
        }

        if pages % arguments.checkpoint_every == 0 || exhausted {
            write_checkpoint_event(
                &mut writer,
                &state,
                pages,
                resume_file_output,
                &output_guard,
            )?;
            commit_scan_progress(&mut writer, arguments.resume_file.as_deref(), Some(&state))
                .map_err(|error| error.with_output_guard(output_guard.clone()))?;
            current_progress_committed = true;
        } else {
            commit_scan_progress(&mut writer, None, None)
                .map_err(|error| error.with_output_guard(output_guard.clone()))?;
            current_progress_committed = false;
        }
        if exhausted {
            break;
        }
    }

    if pages > 0 && !current_progress_committed {
        write_checkpoint_event(
            &mut writer,
            &state,
            pages,
            resume_file_output,
            &output_guard,
        )?;
        commit_scan_progress(&mut writer, arguments.resume_file.as_deref(), Some(&state))
            .map_err(|error| error.with_output_guard(output_guard.clone()))?;
    }
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
                "warnings": [
                    format!(
                        "cursor resume expiry uses the conservative documented {cursor_ttl_seconds}-second preserved-cursor TTL"
                    )
                ]
            }
        }),
        &mut writer,
        &output_guard,
    )?;
    writer
        .flush()
        .map_err(|error| output_error(&error).with_output_guard(output_guard))
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
    path: Option<&Path>,
    target: &reltio_client::config::ResolvedTarget,
    arguments: &EntityScanArgs,
    filter_hash: &str,
    query_hash: &str,
    data_service_url: &str,
    cursor_ttl: TimeDelta,
) -> Result<ResumeState> {
    if let Some(path) = path {
        if let Some(bytes) = read_bounded_optional(path, true)? {
            let mut state = parse_resume_state(&bytes, path)?;
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

fn save_resume(path: &Path, state: &ResumeState) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(state).map_err(|error| {
        ReltioError::internal(format!("failed to encode scan checkpoint: {error}"))
    })?;
    atomic_write_private(path, &encoded)
}

fn acquire_resume_lock(path: &Path) -> Result<std::fs::File> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock = open_private_lock(Path::new(&lock_path))?;
    FileExt::try_lock_exclusive(&lock).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
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

fn commit_scan_progress(
    writer: &mut impl Write,
    resume_file: Option<&Path>,
    state: Option<&ResumeState>,
) -> Result<()> {
    writer.flush().map_err(|error| output_error(&error))?;
    if let (Some(path), Some(state)) = (resume_file, state) {
        save_resume(path, state)?;
    }
    Ok(())
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

fn reject_fields(runtime: &Runtime, command: &str) -> Result<()> {
    if runtime.globals.fields.is_some() {
        Err(ReltioError::usage(
            "fields_unsupported",
            format!("--fields is not part of the reviewed {command} contract"),
        ))
    } else {
        Ok(())
    }
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
    use std::io;

    use super::*;

    struct FlushFailure(Vec<u8>);

    impl Write for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected"))
        }
    }

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
    fn failed_output_flush_never_advances_resume_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("resume.json");
        let mut writer = FlushFailure(Vec::new());

        let error = commit_scan_progress(&mut writer, Some(&path), Some(&resume_state()))
            .expect_err("flush failure must abort commit");

        assert_eq!(error.code, "output_write_failed");
        assert!(!path.exists());
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
