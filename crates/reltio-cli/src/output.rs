use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use reltio_client::cancellation::{CancellationToken, EventStamp};
use reltio_client::config::ResolvedTarget;
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::redaction::{MAX_OUTPUT_GUARD_CONTEXT_BYTES, OutputGuard};
use reltio_client::registry::{Consistency, PracticeCoverage};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::OutputFormat;

const MAX_TABLE_COLUMNS: usize = 256;
const MAX_TABLE_CELLS: usize = 100_000;
const MAX_TABLE_CELL_BYTES: usize = 80;
const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    pub format: OutputFormat,
    pub compact: bool,
}

pub struct PreparedOutput {
    bytes: Vec<u8>,
    newline: bool,
    guard: OutputGuard,
    context: Option<OutputContext>,
}

impl PreparedOutput {
    pub fn with_additional_guard(mut self, guard: &OutputGuard) -> Result<Self> {
        self.guard.merge(guard);
        ensure_guarded_output_sequence(&self.bytes, self.newline, &self.guard)?;
        Ok(self)
    }

    pub fn with_context(mut self, context: &OutputContext) -> Self {
        self.context = Some(context.clone());
        self
    }

    pub async fn write_stdout_with_owner<Owner>(
        self,
        owner: Owner,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<()>
    where
        Owner: Send + 'static,
    {
        let failure_guard = self.guard.clone();
        self.write_controlled(
            OutputStream::Stdout,
            owner,
            deadline,
            cancellation,
            failure_guard,
        )
        .await
    }

    pub async fn write_stdout_disclosing_with_owner<Owner>(
        self,
        owner: Owner,
        deadline: Instant,
        cancellation: &CancellationToken,
        failure_guard: OutputGuard,
    ) -> Result<()>
    where
        Owner: Send + 'static,
    {
        self.write_controlled(
            OutputStream::Stdout,
            owner,
            deadline,
            cancellation,
            failure_guard,
        )
        .await
    }

    pub async fn write_stderr_with_owner<Owner>(
        self,
        owner: Owner,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<()>
    where
        Owner: Send + 'static,
    {
        let failure_guard = self.guard.clone();
        self.write_controlled(
            OutputStream::Stderr,
            owner,
            deadline,
            cancellation,
            failure_guard,
        )
        .await
    }

    async fn write_controlled<Owner>(
        self,
        stream: OutputStream,
        owner: Owner,
        deadline: Instant,
        cancellation: &CancellationToken,
        failure_guard: OutputGuard,
    ) -> Result<()>
    where
        Owner: Send + 'static,
    {
        if let Some(control) = active_output_control(cancellation, deadline) {
            return Err(output_control_failure(control, true, &failure_guard));
        }

        let thread_cancellation = cancellation.clone();
        let writer_guard = failure_guard.clone();
        let timeline = OutputTimeline::default();
        let thread_timeline = timeline.clone();
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("reltio-output".to_owned())
            .spawn(move || {
                let result = write_stream_with_context(
                    stream,
                    &self.bytes,
                    self.newline,
                    deadline,
                    &thread_cancellation,
                    &self.guard,
                    self.context.as_ref(),
                )
                .map_err(|error| error.with_output_guard(writer_guard));
                let completed_at = thread_cancellation.event_stamp();
                thread_timeline.record(completed_at);
                // The cache/output owner is released only after the last physical
                // write and flush attempt has completed.
                drop(owner);
                let _ = sender.send((completed_at, result));
            })
            .map_err(|error| {
                ReltioError::io("failed to start the bounded output writer", &error)
                    .with_output_guard(failure_guard.clone())
            })?;

        let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(timeout);
        tokio::select! {
            biased;
            result = &mut receiver => resolve_output_result(
                result,
                cancellation,
                deadline,
                &failure_guard,
            ),
            () = cancellation.cancelled() => {
                if timeline
                    .completed_at()
                    .is_some_and(|completed_at| {
                        output_control_after(completed_at, cancellation, deadline).is_none()
                    })
                {
                    return resolve_output_result(
                        (&mut receiver).await,
                        cancellation,
                        deadline,
                        &failure_guard,
                    );
                }
                Err(output_control_failure(
                    active_output_control(cancellation, deadline)
                        .unwrap_or(OutputControl::Canceled),
                    false,
                    &failure_guard,
                ))
            },
            () = &mut timeout => {
                if timeline
                    .completed_at()
                    .is_some_and(|completed_at| {
                        output_control_after(completed_at, cancellation, deadline).is_none()
                    })
                {
                    return resolve_output_result(
                        (&mut receiver).await,
                        cancellation,
                        deadline,
                        &failure_guard,
                    );
                }
                Err(output_control_failure(
                    active_output_control(cancellation, deadline)
                        .unwrap_or(OutputControl::TimedOut),
                    false,
                    &failure_guard,
                ))
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutputContext {
    state: Arc<Mutex<OutputContextState>>,
}

impl Default for OutputContext {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(OutputContextState {
                tail: Vec::new(),
                retention_limit: MAX_OUTPUT_GUARD_CONTEXT_BYTES,
                total_emitted: 0,
                uncertain: false,
            })),
        }
    }
}

#[derive(Debug)]
struct OutputContextState {
    tail: Vec<u8>,
    retention_limit: usize,
    total_emitted: usize,
    uncertain: bool,
}

impl OutputContextState {
    fn admit(&mut self, bytes: &[u8], newline: bool, guard: &OutputGuard) -> Result<()> {
        if self.uncertain {
            return Err(guarded_output_refusal(
                guard,
                Some("prior_output_state_uncertain"),
            ));
        }
        let required = guard.required_stream_context_bytes();
        if required > self.retention_limit && self.total_emitted > self.tail.len() {
            return Err(guarded_output_refusal(
                guard,
                Some("prior_output_context_insufficient"),
            ));
        }
        self.retention_limit = self.retention_limit.max(required);
        if guard.permits_with_prefix(&self.tail, bytes, output_suffix(bytes, newline)) {
            Ok(())
        } else {
            Err(guarded_output_refusal(guard, Some("cross_emission_match")))
        }
    }

    fn record(&mut self, bytes: &[u8], newline: bool) {
        let suffix = output_suffix(bytes, newline);
        let appended = bytes.len().saturating_add(suffix.len());
        self.total_emitted = self.total_emitted.saturating_add(appended);
        if self.retention_limit == 0 {
            self.tail.clear();
            return;
        }
        if appended >= self.retention_limit {
            self.tail.clear();
            let suffix_bytes = suffix.len().min(self.retention_limit);
            let body_bytes = self.retention_limit.saturating_sub(suffix_bytes);
            self.tail
                .extend_from_slice(&bytes[bytes.len().saturating_sub(body_bytes)..]);
            self.tail
                .extend_from_slice(&suffix[suffix.len().saturating_sub(suffix_bytes)..]);
            return;
        }
        let retained = self.retention_limit - appended;
        if self.tail.len() > retained {
            let start = self.tail.len() - retained;
            self.tail.copy_within(start.., 0);
            self.tail.truncate(retained);
        }
        self.tail.extend_from_slice(bytes);
        self.tail.extend_from_slice(suffix);
    }

    fn mark_uncertain(&mut self) {
        self.uncertain = true;
    }
}

#[derive(Clone, Copy)]
enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Default)]
struct OutputTimeline {
    completed_at: Arc<Mutex<Option<EventStamp>>>,
}

impl OutputTimeline {
    fn record(&self, completed_at: EventStamp) {
        *self
            .completed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(completed_at);
    }

    fn completed_at(&self) -> Option<EventStamp> {
        *self
            .completed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputControl {
    Canceled,
    TimedOut,
}

fn active_output_control(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Option<OutputControl> {
    let canceled_at = cancellation.cancelled_at();
    if Instant::now() < deadline {
        return canceled_at.map(|_| OutputControl::Canceled);
    }
    Some(
        if canceled_at.is_some_and(|stamp| stamp.occurred_at_or_before(deadline)) {
            OutputControl::Canceled
        } else {
            OutputControl::TimedOut
        },
    )
}

fn output_control_after(
    completed_at: EventStamp,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Option<OutputControl> {
    let canceled_at = cancellation.cancelled_at();
    let canceled_first = canceled_at.is_some_and(|stamp| !completed_at.precedes(stamp));
    let timed_out_first = !completed_at.occurred_before(deadline);
    match (canceled_first, timed_out_first) {
        (false, false) => None,
        (true, false) => Some(OutputControl::Canceled),
        (false, true) => Some(OutputControl::TimedOut),
        (true, true) => Some(
            if canceled_at.is_some_and(|stamp| stamp.occurred_at_or_before(deadline)) {
                OutputControl::Canceled
            } else {
                OutputControl::TimedOut
            },
        ),
    }
}

fn resolve_output_result(
    result: std::result::Result<(EventStamp, Result<()>), tokio::sync::oneshot::error::RecvError>,
    cancellation: &CancellationToken,
    deadline: Instant,
    failure_guard: &OutputGuard,
) -> Result<()> {
    match result {
        Ok((completed_at, result)) => output_control_after(completed_at, cancellation, deadline)
            .map_or(result, |control| {
                Err(output_control_failure(control, false, failure_guard))
            }),
        Err(_) => active_output_control(cancellation, deadline).map_or_else(
            || {
                Err(
                    ReltioError::internal("the bounded output writer terminated without a result")
                        .with_output_guard(failure_guard.clone()),
                )
            },
            |control| Err(output_control_failure(control, false, failure_guard)),
        ),
    }
}

fn output_control_failure(
    control: OutputControl,
    before_emission: bool,
    guard: &OutputGuard,
) -> ReltioError {
    match control {
        OutputControl::Canceled => output_control_error(
            "request_canceled",
            ErrorCategory::Canceled,
            if before_emission {
                "output was canceled before emission"
            } else {
                "output was canceled during emission"
            },
            guard,
        ),
        OutputControl::TimedOut => output_control_error(
            "request_timeout",
            ErrorCategory::Timeout,
            if before_emission {
                "the command exceeded its overall timeout before output"
            } else {
                "the command exceeded its overall timeout during output"
            },
            guard,
        ),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Meta {
    pub command: String,
    pub cli_version: &'static str,
    pub profile: Option<String>,
    pub environment: Option<String>,
    pub tenant: Option<String>,
    pub service: Option<String>,
    pub request_id: Option<String>,
    pub elapsed_ms: u128,
    pub pagination: Option<Value>,
    pub warnings: Vec<String>,
    pub practice_coverage: Option<PracticeCoverage>,
    pub practice_ids: Vec<String>,
    pub consistency: Option<Consistency>,
    pub http_status: Option<u16>,
    pub attempts: Option<u32>,
    pub auth_source: Option<String>,
}

impl Meta {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            cli_version: env!("CARGO_PKG_VERSION"),
            profile: None,
            environment: None,
            tenant: None,
            service: None,
            request_id: None,
            elapsed_ms: 0,
            pagination: None,
            warnings: Vec::new(),
            practice_coverage: None,
            practice_ids: Vec::new(),
            consistency: None,
            http_status: None,
            attempts: None,
            auth_source: None,
        }
    }

    pub fn with_target(mut self, target: &ResolvedTarget, service: Option<&str>) -> Self {
        self.profile.clone_from(&target.profile);
        self.environment = Some(target.environment.clone());
        self.tenant = Some(target.tenant.clone());
        self.service = service.map(ToOwned::to_owned);
        self
    }
}

#[derive(Serialize)]
struct SuccessEnvelope<'a> {
    schema_version: u32,
    ok: bool,
    data: &'a Value,
    meta: &'a Meta,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    schema_version: u32,
    ok: bool,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    #[serde(flatten)]
    error: &'a ReltioError,
    docs_url: &'static str,
}

pub fn prepare_success_guarded(
    data: &Value,
    meta: &Meta,
    options: RenderOptions,
    guard: &OutputGuard,
) -> Result<PreparedOutput> {
    let rendered = || -> Result<(Vec<u8>, bool)> {
        Ok(match options.format {
            OutputFormat::Json => {
                let envelope = SuccessEnvelope {
                    schema_version: reltio_client::SCHEMA_VERSION,
                    ok: true,
                    data,
                    meta,
                };
                let bytes = if options.compact {
                    serde_json::to_vec(&envelope)
                } else {
                    serde_json::to_vec_pretty(&envelope)
                }
                .map_err(|error| serialization_error(&error))?;
                (bytes, true)
            }
            OutputFormat::Jsonl => {
                let envelope = SuccessEnvelope {
                    schema_version: reltio_client::SCHEMA_VERSION,
                    ok: true,
                    data,
                    meta,
                };
                (
                    serde_json::to_vec(&envelope).map_err(|error| serialization_error(&error))?,
                    true,
                )
            }
            OutputFormat::Yaml => {
                let envelope = SuccessEnvelope {
                    schema_version: reltio_client::SCHEMA_VERSION,
                    ok: true,
                    data,
                    meta,
                };
                (yaml_document(&envelope)?, true)
            }
            OutputFormat::Table => (render_table(data)?.into_bytes(), false),
            OutputFormat::Raw => {
                let bytes = match data {
                    Value::String(text) => Ok(text.as_bytes().to_vec()),
                    _ if options.compact => serde_json::to_vec(data),
                    _ => serde_json::to_vec_pretty(data),
                }
                .map_err(|error| serialization_error(&error))?;
                (bytes, true)
            }
        })
    };
    let (bytes, newline) = rendered().map_err(|error| error.with_output_guard(guard.clone()))?;
    ensure_guarded_output_sequence(&bytes, newline, guard)?;
    Ok(PreparedOutput {
        bytes,
        newline,
        guard: guard.clone(),
        context: None,
    })
}

fn yaml_document(value: &impl Serialize) -> Result<Vec<u8>> {
    // JSON flow syntax is valid YAML 1.2 and preserves serde_json's
    // arbitrary-precision number representation without private tags.
    let mut bytes = b"---\n".to_vec();
    bytes.extend(serde_json::to_vec_pretty(value).map_err(|error| serialization_error(&error))?);
    Ok(bytes)
}

pub fn prepare_raw_guarded(
    bytes: &[u8],
    newline: bool,
    guard: &OutputGuard,
) -> Result<PreparedOutput> {
    ensure_guarded_output_sequence(bytes, newline, guard)?;
    Ok(PreparedOutput {
        bytes: bytes.to_vec(),
        newline,
        guard: guard.clone(),
        context: None,
    })
}

pub fn write_jsonl_event_guarded(
    value: &Value,
    writer: &mut impl Write,
    guard: &OutputGuard,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|error| serialization_error(&error))?;
    ensure_guarded_output_sequence(&bytes, true, guard)?;
    writer
        .write_all(&bytes)
        .map_err(|error| output_error(&error).with_output_guard(guard.clone()))?;
    writer
        .write_all(b"\n")
        .map_err(|error| output_error(&error).with_output_guard(guard.clone()))
}

pub fn prepare_error_guarded(
    error: &ReltioError,
    format: OutputFormat,
    final_guard: &OutputGuard,
) -> Result<Option<PreparedOutput>> {
    let mut guard = final_guard.clone();
    if let Some(error_guard) = error.output_guard() {
        guard.merge(error_guard);
    }
    let envelope = ErrorEnvelope {
        schema_version: reltio_client::SCHEMA_VERSION,
        ok: false,
        error: ErrorBody {
            error,
            docs_url: "https://github.com/aiadjacent/reltio-cli/blob/main/docs/errors.md",
        },
    };
    let mut bytes = if format == OutputFormat::Table {
        let mut text = String::new();
        let _ = writeln!(
            text,
            "error[{}]: {}",
            terminal_safe(&error.code),
            terminal_safe(&error.message)
        );
        if let Some(hint) = &error.hint {
            let _ = writeln!(text, "hint: {}", terminal_safe(hint));
        }
        text.into_bytes()
    } else {
        serde_json::to_vec(&envelope).unwrap_or_default()
    };
    if !guard.permits_with_suffix(&bytes, output_suffix(&bytes, true)) {
        bytes = guarded_error_fallback(error, &guard);
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    ensure_guarded_output_sequence(&bytes, true, &guard)?;
    Ok(Some(PreparedOutput {
        bytes,
        newline: true,
        guard,
        context: None,
    }))
}

pub fn prepare_error_context_fallback_guarded(
    error: &ReltioError,
    final_guard: &OutputGuard,
    context: &OutputContext,
) -> Option<PreparedOutput> {
    let mut guard = final_guard.clone();
    if let Some(error_guard) = error.output_guard() {
        guard.merge(error_guard);
    }
    let mut state = context
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.uncertain {
        return None;
    }
    let positional = guarded_error_fallback(error, &guard);
    let bytes = std::iter::once(positional)
        .chain((0_u64..=1_024).map(|number| number.to_string().into_bytes()))
        .find(|candidate| {
            !candidate.is_empty()
                && guard.permits_with_suffix(candidate, b"\n")
                && state.admit(candidate, true, &guard).is_ok()
        });
    let bytes = bytes?;
    Some(PreparedOutput {
        bytes,
        newline: true,
        guard,
        context: None,
    })
}

fn ensure_guarded_output(bytes: &[u8], guard: &OutputGuard) -> Result<()> {
    ensure_guarded_output_sequence(bytes, false, guard)
}

fn ensure_guarded_output_sequence(bytes: &[u8], newline: bool, guard: &OutputGuard) -> Result<()> {
    if guard.permits_with_suffix(bytes, output_suffix(bytes, newline)) {
        return Ok(());
    }
    Err(guarded_output_refusal(guard, None))
}

fn guarded_output_refusal(guard: &OutputGuard, reason: Option<&'static str>) -> ReltioError {
    ReltioError::new(
        "credential_output_refused",
        ErrorCategory::Safety,
        "refusing to emit output that would reproduce an active credential",
    )
    .with_details(json!({
        "output_omitted": true,
        "safe_to_replay": false,
        "reason": reason
    }))
    .with_output_guard(guard.clone())
}

fn guarded_error_fallback(error: &ReltioError, guard: &OutputGuard) -> Vec<u8> {
    if let Some(bytes) = guarded_error_context(error, guard) {
        return bytes;
    }
    guard.safe_json_fallback_with_suffix(b"\n")
}

fn guarded_error_context(error: &ReltioError, guard: &OutputGuard) -> Option<Vec<u8>> {
    let details = error.details.as_object();
    // Positional emergency schema: marker, code, category, retryable, HTTP
    // status, request ID, response-received, replay-safe, request-completed,
    // operation-completed, operation-state, local-state-committed. Boolean
    // state uses 1=yes, 0=no, -1=unknown.
    let positional = Value::Array(vec![
        Value::String("reltio_guarded_failure".to_owned()),
        guarded_scalar(Value::String(error.code.clone()), guard),
        guarded_scalar(
            serde_json::to_value(error.category).unwrap_or(Value::Null),
            guard,
        ),
        Value::from(i32::from(error.retryable)),
        guarded_scalar(error.http_status.map_or(Value::Null, Value::from), guard),
        guarded_scalar(
            error
                .request_id
                .as_ref()
                .map_or(Value::Null, |value| Value::String(value.clone())),
            guard,
        ),
        Value::from(context_code(details, "remote_response_received")),
        Value::from(context_code(details, "safe_to_replay")),
        Value::from(context_code(details, "remote_request_completed")),
        Value::from(context_code(details, "remote_operation_completed")),
        guarded_scalar(context_string(details, "remote_operation_state"), guard),
        Value::from(context_code(details, "local_state_committed")),
    ]);
    let bytes = serde_json::to_vec(&positional).ok()?;
    guard.permits_with_suffix(&bytes, b"\n").then_some(bytes)
}

fn context_string(details: Option<&serde_json::Map<String, Value>>, key: &str) -> Value {
    details
        .and_then(|details| details.get(key))
        .and_then(Value::as_str)
        .map_or(Value::Null, |value| Value::String(value.to_owned()))
}

fn context_code(details: Option<&serde_json::Map<String, Value>>, key: &str) -> i8 {
    match details
        .and_then(|details| details.get(key))
        .and_then(Value::as_bool)
    {
        Some(true) => 1,
        Some(false) => 0,
        None => -1,
    }
}

fn guarded_scalar(value: Value, guard: &OutputGuard) -> Value {
    serde_json::to_vec(&value)
        .ok()
        .filter(|bytes| guard.permits(bytes))
        .map_or(Value::Null, |_| value)
}

pub fn prepare_warning_guarded(
    message: &str,
    quiet: bool,
    guard: &OutputGuard,
) -> Result<Option<PreparedOutput>> {
    if quiet {
        return Ok(None);
    }
    let bytes = format!("warning: {}\n", terminal_safe(message)).into_bytes();
    ensure_guarded_output(&bytes, guard)?;
    Ok(Some(PreparedOutput {
        bytes,
        newline: false,
        guard: guard.clone(),
        context: None,
    }))
}

fn write_stream_with_context(
    stream: OutputStream,
    bytes: &[u8],
    newline: bool,
    deadline: Instant,
    cancellation: &CancellationToken,
    guard: &OutputGuard,
    context: Option<&OutputContext>,
) -> Result<()> {
    let mut context = context.map(|context| {
        context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    });
    if let Some(context) = &mut context {
        context.admit(bytes, newline, guard)?;
    }
    write_stream_controlled(
        stream,
        bytes,
        newline,
        deadline,
        cancellation,
        context.as_deref_mut(),
    )
}

fn write_stream_controlled(
    stream: OutputStream,
    bytes: &[u8],
    newline: bool,
    deadline: Instant,
    cancellation: &CancellationToken,
    context: Option<&mut OutputContextState>,
) -> Result<()> {
    match stream {
        OutputStream::Stdout => {
            let mut writer = io::stdout().lock();
            write_to_writer(&mut writer, bytes, newline, deadline, cancellation, context)
        }
        OutputStream::Stderr => {
            let mut writer = io::stderr().lock();
            write_to_writer(&mut writer, bytes, newline, deadline, cancellation, context)
        }
    }
}

fn write_to_writer(
    writer: &mut impl Write,
    bytes: &[u8],
    newline: bool,
    deadline: Instant,
    cancellation: &CancellationToken,
    mut context: Option<&mut OutputContextState>,
) -> Result<()> {
    let result = (|| {
        write_chunks(
            writer,
            bytes,
            deadline,
            cancellation,
            context.as_deref_mut(),
        )?;
        if newline && !bytes.ends_with(b"\n") {
            write_chunks(
                writer,
                b"\n",
                deadline,
                cancellation,
                context.as_deref_mut(),
            )?;
        }
        writer.flush().map_err(|error| output_error(&error))
    })();
    if result.is_err() {
        if let Some(context) = context {
            context.mark_uncertain();
        }
    }
    result
}

fn write_chunks(
    writer: &mut impl Write,
    bytes: &[u8],
    deadline: Instant,
    cancellation: &CancellationToken,
    mut context: Option<&mut OutputContextState>,
) -> Result<()> {
    for chunk in bytes.chunks(OUTPUT_CHUNK_BYTES) {
        let mut remaining = chunk;
        while !remaining.is_empty() {
            ensure_output_active(deadline, cancellation)?;
            let written = writer
                .write(remaining)
                .map_err(|error| output_error(&error))?;
            if written == 0 {
                return Err(output_error(&io::Error::new(
                    io::ErrorKind::WriteZero,
                    "output sink accepted zero bytes",
                )));
            }
            if let Some(context) = context.as_deref_mut() {
                context.record(&remaining[..written], false);
            }
            remaining = &remaining[written..];
        }
    }
    Ok(())
}

fn ensure_output_active(deadline: Instant, cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        return Err(output_control_error(
            "request_canceled",
            ErrorCategory::Canceled,
            "output was canceled during emission",
            &OutputGuard::default(),
        ));
    }
    if Instant::now() >= deadline {
        return Err(output_control_error(
            "request_timeout",
            ErrorCategory::Timeout,
            "the command exceeded its overall timeout during output",
            &OutputGuard::default(),
        ));
    }
    Ok(())
}

fn output_control_error(
    code: &'static str,
    category: ErrorCategory,
    message: &'static str,
    guard: &OutputGuard,
) -> ReltioError {
    ReltioError::new(code, category, message)
        .with_details(json!({
            "phase": "output",
            "remote_response_received": Value::Null,
            "remote_request_completed": Value::Null,
            "remote_operation_completed": Value::Null,
            "remote_operation_state": "unknown",
            "local_state_committed": Value::Null,
            "safe_to_replay": false
        }))
        .with_output_guard(guard.clone())
}

fn output_suffix(bytes: &[u8], newline: bool) -> &'static [u8] {
    if newline && !bytes.ends_with(b"\n") {
        b"\n"
    } else {
        &[]
    }
}

fn serialization_error(error: &serde_json::Error) -> ReltioError {
    ReltioError::internal(format!("failed to serialize output: {error}"))
}

pub(crate) fn output_error(error: &io::Error) -> ReltioError {
    ReltioError::new(
        "output_write_failed",
        ErrorCategory::Internal,
        format!("failed to write output: {error}"),
    )
}

fn render_table(value: &Value) -> Result<String> {
    match value {
        Value::Array(rows) if rows.iter().all(Value::is_object) && !rows.is_empty() => {
            render_object_rows(rows)
        }
        Value::Object(object) => {
            enforce_table_shape(object.len(), 2)?;
            let rows: Vec<Value> = object
                .iter()
                .map(|(key, value)| json!({ "field": key, "value": cell(value) }))
                .collect();
            render_object_rows(&rows)
        }
        _ => Ok(format!("{}\n", cell(value))),
    }
}

fn render_object_rows(rows: &[Value]) -> Result<String> {
    let mut column_indices = HashMap::<&str, usize>::new();
    let mut columns = Vec::<(&str, String)>::new();
    for row in rows {
        if let Some(object) = row.as_object() {
            for key in object.keys() {
                if !column_indices.contains_key(key.as_str()) {
                    if columns.len() == MAX_TABLE_COLUMNS {
                        return Err(table_shape_error(rows.len(), columns.len() + 1));
                    }
                    column_indices.insert(key, columns.len());
                    columns.push((key, truncate(&terminal_safe(key), MAX_TABLE_CELL_BYTES)));
                }
            }
        }
    }
    enforce_table_shape(rows.len(), columns.len())?;
    let mut widths: Vec<usize> = columns.iter().map(|(_, rendered)| rendered.len()).collect();
    for row in rows {
        let object = row.as_object().expect("rows checked above");
        for (key, value) in object {
            let index = column_indices[key.as_str()];
            widths[index] = widths[index]
                .max(cell(value).len())
                .min(MAX_TABLE_CELL_BYTES);
        }
    }
    let separator = format!(
        "+{}+\n",
        widths
            .iter()
            .map(|width| "-".repeat(width + 2))
            .collect::<Vec<_>>()
            .join("+")
    );
    let mut output = separator.clone();
    output.push('|');
    for ((_, column), width) in columns.iter().zip(&widths) {
        write!(&mut output, " {column:width$} |", width = *width)
            .expect("writing to a String cannot fail");
    }
    output.push('\n');
    output.push_str(&separator);
    for row in rows {
        let object = row.as_object().expect("rows checked above");
        output.push('|');
        for ((key, _), width) in columns.iter().zip(&widths) {
            let text = object.get(*key).map_or_else(String::new, |value| {
                truncate(&cell(value), MAX_TABLE_CELL_BYTES)
            });
            write!(&mut output, " {text:width$} |", width = *width)
                .expect("writing to a String cannot fail");
        }
        output.push('\n');
    }
    output.push_str(&separator);
    Ok(output)
}

fn enforce_table_shape(rows: usize, columns: usize) -> Result<()> {
    if rows
        .checked_mul(columns)
        .is_none_or(|cells| cells > MAX_TABLE_CELLS)
    {
        return Err(table_shape_error(rows, columns));
    }
    Ok(())
}

fn table_shape_error(rows: usize, columns: usize) -> ReltioError {
    ReltioError::new(
        "table_shape_too_large",
        ErrorCategory::Safety,
        "response shape is too sparse or wide for bounded table rendering",
    )
    .with_details(json!({
        "rows": rows,
        "columns": columns,
        "maximum_columns": MAX_TABLE_COLUMNS,
        "maximum_cells": MAX_TABLE_CELLS
    }))
    .with_hint("Use JSON, JSONL, or YAML output to preserve the full response shape.")
}

fn cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => terminal_safe(text),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

fn truncate(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        value.to_owned()
    } else {
        let mut result = value
            .chars()
            .take(maximum.saturating_sub(3))
            .collect::<String>();
        result.push_str("...");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_control_uses_chronological_event_order() {
        let late_cancellation = CancellationToken::new();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let completed = late_cancellation.event_stamp();
        late_cancellation.cancel();
        assert_eq!(
            output_control_after(completed, &late_cancellation, deadline),
            None,
            "physical completion before cancellation remains authoritative"
        );

        let early_cancellation = CancellationToken::new();
        early_cancellation.cancel();
        let completed = early_cancellation.event_stamp();
        assert_eq!(
            output_control_after(completed, &early_cancellation, deadline),
            Some(OutputControl::Canceled)
        );

        let timeout = CancellationToken::new();
        let expired = Instant::now();
        let completed = timeout.event_stamp();
        assert_eq!(
            output_control_after(completed, &timeout, expired),
            Some(OutputControl::TimedOut)
        );
    }

    #[test]
    fn table_output_escapes_terminal_control_sequences() {
        let rendered = render_table(&json!([{
            "na\u{1b}]0;title\u{7}": "value\u{1b}]52;c;Y29weQ==\u{7}"
        }]))
        .expect("bounded table");
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(rendered.contains(r"\u{1b}"));
        assert!(rendered.contains(r"\u{7}"));
    }

    #[test]
    fn human_diagnostics_escape_terminal_control_sequences() {
        let message = terminal_safe("failure\u{1b}]52;c;Y29weQ==\u{7}");
        assert!(!message.contains('\u{1b}'));
        assert!(!message.contains('\u{7}'));
        assert!(message.contains(r"\u{1b}"));
        assert!(message.contains(r"\u{7}"));
    }

    #[test]
    fn yaml_uses_lossless_json_flow_numbers_instead_of_private_tags() {
        let value: Value = serde_json::from_str(
            r#"{"integer":123456789012345678901234567890,"decimal":0.123456789012345678901234567890}"#,
        )
        .expect("arbitrary precision fixture");
        let meta = Meta::new("yaml.test");
        let envelope = SuccessEnvelope {
            schema_version: reltio_client::SCHEMA_VERSION,
            ok: true,
            data: &value,
            meta: &meta,
        };
        let rendered = String::from_utf8(yaml_document(&envelope).expect("YAML renderer"))
            .expect("UTF-8 YAML");
        assert!(rendered.starts_with("---\n{"));
        assert!(rendered.contains("123456789012345678901234567890"));
        assert!(rendered.contains("0.123456789012345678901234567890"));
        assert!(!rendered.contains("$serde_json::private"));
        serde_yaml::from_str::<serde_yaml::Value>(r#"{"ordinary": 6}"#)
            .expect("JSON flow syntax is valid YAML");
    }

    #[test]
    fn final_render_guard_covers_generated_envelope_and_table_bytes() {
        let guard = OutputGuard::from_known_secrets(&["data"]);
        let data = json!({"safe": "visible"});
        let meta = Meta::new("api.request");
        let envelope = SuccessEnvelope {
            schema_version: reltio_client::SCHEMA_VERSION,
            ok: true,
            data: &data,
            meta: &meta,
        };
        let rendered = serde_json::to_vec(&envelope).expect("success envelope");
        let error = ensure_guarded_output(&rendered, &guard).expect_err("token must be refused");
        assert_eq!(error.code, "credential_output_refused");
        assert!(error.output_guard().is_some());

        let guard = OutputGuard::from_known_secrets(&[r"\u{1b}"]);
        let rendered = render_table(&json!({"value": "\u{1b}"})).expect("bounded table");
        assert!(ensure_guarded_output(rendered.as_bytes(), &guard).is_err());

        let guard = OutputGuard::from_known_secrets(&[r#"a ","b"#]);
        assert!(!guard.permits(br#"["a+","b"]"#));
    }

    #[test]
    fn final_render_guard_covers_appended_newline_boundaries() {
        let guard = OutputGuard::from_known_secrets(&["raw-visible\n"]);
        assert!(guard.permits(b"raw-visible"));
        assert!(ensure_guarded_output_sequence(b"raw-visible", true, &guard).is_err());

        let guard = OutputGuard::from_known_secrets(&["a\n"]);
        assert!(guard.permits(b"%61"));
        assert!(ensure_guarded_output_sequence(b"%61", true, &guard).is_err());
    }

    #[test]
    fn stream_context_catches_credentials_split_across_successful_emissions() {
        let context = OutputContext::default();
        let mut state = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.record(b"split-", false);

        let guard = OutputGuard::from_known_secrets(&["split-secret"]);
        let error = state
            .admit(b"secret", false, &guard)
            .expect_err("a raw cross-emission credential must be refused");

        assert_eq!(error.code, "credential_output_refused");
        assert_eq!(error.details["reason"], "cross_emission_match");
    }

    #[test]
    fn stream_context_catches_two_layer_credentials_from_a_later_final_guard() {
        let context = OutputContext::default();
        let mut state = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.record(b"%2573%2570%256c%2569%2574%252", false);

        let guard = OutputGuard::from_known_secrets(&["split-secret"]);
        assert!(guard.permits(b"d%2573%2565%2563%2572%2565%2574"));
        let error = state
            .admit(b"d%2573%2565%2563%2572%2565%2574", false, &guard)
            .expect_err("a canonical cross-emission credential must be refused");

        assert_eq!(error.code, "credential_output_refused");
        assert_eq!(error.details["reason"], "cross_emission_match");
    }

    #[test]
    fn stream_context_tracks_partial_writes_and_fails_closed_after_sink_errors() {
        #[derive(Default)]
        struct PartialThenError {
            writes: usize,
        }

        impl Write for PartialThenError {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                if self.writes == 1 {
                    Ok(bytes.len().min(6))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "injected partial write failure",
                    ))
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let context = OutputContext::default();
        let mut state = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .admit(b"split-more", false, &OutputGuard::default())
            .expect("the emission is safe before touching the sink");
        let error = write_to_writer(
            &mut PartialThenError::default(),
            b"split-more",
            false,
            Instant::now() + std::time::Duration::from_secs(1),
            &CancellationToken::new(),
            Some(&mut state),
        )
        .expect_err("the second physical write fails");
        assert_eq!(error.code, "output_write_failed");
        assert_eq!(state.tail, b"split-");

        let guard = OutputGuard::from_known_secrets(&["split-secret"]);
        let error = state
            .admit(b"secret", false, &guard)
            .expect_err("uncertain physical output must poison later emissions");
        assert_eq!(error.details["reason"], "prior_output_state_uncertain");
    }

    #[test]
    fn stream_context_fails_closed_after_flush_errors() {
        #[derive(Default)]
        struct FlushError;

        impl Write for FlushError {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected flush failure",
                ))
            }
        }

        let context = OutputContext::default();
        let mut state = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let error = write_to_writer(
            &mut FlushError,
            b"flushed-prefix",
            false,
            Instant::now() + std::time::Duration::from_secs(1),
            &CancellationToken::new(),
            Some(&mut state),
        )
        .expect_err("flush failure is reported");
        assert_eq!(error.code, "output_write_failed");
        assert_eq!(state.tail, b"flushed-prefix");
        let error = state
            .admit(b"later", false, &OutputGuard::default())
            .expect_err("flush uncertainty suppresses later records");
        assert_eq!(error.details["reason"], "prior_output_state_uncertain");
    }

    #[test]
    fn sparse_table_shapes_are_refused_before_dense_allocation() {
        let rows = (0..2_000)
            .map(|index| json!({format!("column-{index}"): index}))
            .collect::<Vec<_>>();

        let error = render_table(&Value::Array(rows)).expect_err("sparse table must be bounded");

        assert_eq!(error.code, "table_shape_too_large");
        assert_eq!(error.details["maximum_columns"], MAX_TABLE_COLUMNS);
        assert_eq!(error.details["maximum_cells"], MAX_TABLE_CELLS);
    }

    #[test]
    fn guarded_error_fallback_preserves_remote_outcome_when_labels_or_bools_conflict() {
        for token in ["error", "true", "false", "request", "status"] {
            let guard = OutputGuard::from_known_secrets(&[token]);
            let error = ReltioError::new(
                "credential_output_refused",
                ErrorCategory::Safety,
                "unsafe output",
            )
            .with_http_status(200)
            .with_request_id(Some("mutation-success-3".to_owned()))
            .with_details(json!({
                "remote_response_received": true,
                "remote_request_completed": true,
                "remote_operation_completed": null,
                "remote_operation_state": "success_response_received_completion_unknown",
                "safe_to_replay": false
            }))
            .with_output_guard(guard.clone());
            let bytes = guarded_error_fallback(&error, &guard);
            assert!(guard.permits_with_suffix(&bytes, b"\n"), "token {token:?}");
            let value: Value = serde_json::from_slice(&bytes).expect("guarded error JSON");
            let fields = value.as_array().expect("positional guarded failure");
            assert_eq!(fields.len(), 12);
            assert_eq!(fields[0], "reltio_guarded_failure");
            assert_eq!(fields[1], "credential_output_refused");
            assert_eq!(fields[2], "safety");
            assert_eq!(fields[3], 0);
            assert_eq!(fields[4], 200);
            assert_eq!(fields[5], "mutation-success-3");
            assert_eq!(fields[6], 1);
            assert_eq!(fields[7], 0);
            assert_eq!(fields[8], 1);
            assert_eq!(fields[9], -1);
            assert_eq!(fields[11], -1);
        }
    }

    #[test]
    fn guarded_error_fallback_preserves_local_commit_state_without_its_label() {
        let guard = OutputGuard::from_known_secrets(&["local_state_committed"]);
        let error = ReltioError::new(
            "output_write_failed",
            ErrorCategory::Internal,
            "injected output failure",
        )
        .with_details(json!({
            "local_state_committed": true,
            "safe_to_replay": false
        }))
        .with_output_guard(guard.clone());

        let bytes = guarded_error_fallback(&error, &guard);

        assert!(guard.permits_with_suffix(&bytes, b"\n"));
        let fields: Value = serde_json::from_slice(&bytes).expect("guarded error JSON");
        assert_eq!(fields.as_array().unwrap().len(), 12);
        assert_eq!(fields[0], "reltio_guarded_failure");
        assert_eq!(fields[7], 0);
        assert_eq!(fields[11], 1);
    }

    #[test]
    fn guarded_local_errors_use_a_stable_positional_schema() {
        for token in ["error", "false"] {
            let guard = OutputGuard::from_known_secrets(&[token]);
            let error = ReltioError::usage("invalid_cli_usage", "invalid command")
                .with_output_guard(guard.clone());

            let bytes = guarded_error_fallback(&error, &guard);
            assert!(guard.permits_with_suffix(&bytes, b"\n"), "token {token:?}");
            let fields: Value = serde_json::from_slice(&bytes).expect("guarded error JSON");
            assert_eq!(fields.as_array().unwrap().len(), 12);
            assert_eq!(fields[0], "reltio_guarded_failure");
            assert_eq!(fields[1], "invalid_cli_usage");
            assert_eq!(fields[2], "usage");
            assert_eq!(fields[3], 0);
            assert_eq!(fields[4], Value::Null);
            assert_eq!(fields[5], Value::Null);
            assert_eq!(fields[6], -1);
            assert_eq!(fields[7], -1);
            assert_eq!(fields[11], -1);
        }
    }

    #[test]
    fn contextual_error_fallback_advances_from_positional_json_to_a_safe_scalar() {
        let context = OutputContext::default();
        context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(b"prefix", false);
        let guard =
            OutputGuard::from_known_secrets(&["error", "prefix[\"reltio_guarded_failure\""]);
        let error = ReltioError::new(
            "request_timeout",
            ErrorCategory::Timeout,
            "the request timed out",
        )
        .with_output_guard(guard.clone());
        let ordinary = prepare_error_guarded(&error, OutputFormat::Json, &guard)
            .expect("ordinary fallback prepares")
            .expect("ordinary fallback exists");
        assert!(ordinary.bytes.starts_with(b"[\"reltio_guarded_failure\""));

        let contextual = prepare_error_context_fallback_guarded(&error, &guard, &context)
            .expect("a scalar remains representable");

        assert_eq!(contextual.bytes, b"0");
    }
}
