use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, Write};

use reltio_client::config::ResolvedTarget;
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::redaction::OutputGuard;
use reltio_client::registry::{Consistency, PracticeCoverage};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::OutputFormat;

const MAX_TABLE_COLUMNS: usize = 256;
const MAX_TABLE_CELLS: usize = 100_000;
const MAX_TABLE_CELL_BYTES: usize = 80;

#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    pub format: OutputFormat,
    pub compact: bool,
}

pub struct PreparedOutput {
    bytes: Vec<u8>,
    newline: bool,
    guard: OutputGuard,
}

impl PreparedOutput {
    pub fn write_stdout(self) -> Result<()> {
        write_stdout(&self.bytes, self.newline).map_err(|error| error.with_output_guard(self.guard))
    }

    pub fn write_stderr(self) -> Result<()> {
        io::stderr()
            .lock()
            .write_all(&self.bytes)
            .map_err(|error| output_error(&error).with_output_guard(self.guard))
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

pub fn write_success_guarded(
    data: &Value,
    meta: &Meta,
    options: RenderOptions,
    guard: &OutputGuard,
) -> Result<()> {
    prepare_success_guarded(data, meta, options, guard)?.write_stdout()
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
    })
}

fn yaml_document(value: &impl Serialize) -> Result<Vec<u8>> {
    // JSON flow syntax is valid YAML 1.2 and preserves serde_json's
    // arbitrary-precision number representation without private tags.
    let mut bytes = b"---\n".to_vec();
    bytes.extend(serde_json::to_vec_pretty(value).map_err(|error| serialization_error(&error))?);
    Ok(bytes)
}

pub fn write_raw_guarded(bytes: &[u8], newline: bool, guard: &OutputGuard) -> Result<()> {
    ensure_guarded_output_sequence(bytes, newline, guard)?;
    write_stdout(bytes, newline).map_err(|error| error.with_output_guard(guard.clone()))
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

pub fn write_error(error: &ReltioError, format: OutputFormat) {
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
    if let Some(guard) = error.output_guard() {
        if !guard.permits_with_suffix(&bytes, output_suffix(&bytes, true)) {
            bytes = guarded_error_fallback(error, guard);
        }
    }
    let mut stderr = io::stderr().lock();
    if !bytes.is_empty() {
        let _ = stderr.write_all(&bytes);
        if !bytes.ends_with(b"\n") {
            let _ = stderr.write_all(b"\n");
        }
    }
}

fn ensure_guarded_output(bytes: &[u8], guard: &OutputGuard) -> Result<()> {
    ensure_guarded_output_sequence(bytes, false, guard)
}

fn ensure_guarded_output_sequence(bytes: &[u8], newline: bool, guard: &OutputGuard) -> Result<()> {
    if guard.permits_with_suffix(bytes, output_suffix(bytes, newline)) {
        return Ok(());
    }
    Err(ReltioError::new(
        "credential_output_refused",
        ErrorCategory::Safety,
        "refusing to emit output that would reproduce an active credential",
    )
    .with_details(json!({"output_omitted": true, "safe_to_replay": false}))
    .with_output_guard(guard.clone()))
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

pub fn write_warning_guarded(message: &str, quiet: bool, guard: &OutputGuard) -> Result<()> {
    if let Some(output) = prepare_warning_guarded(message, quiet, guard)? {
        output.write_stderr()?;
    }
    Ok(())
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
    }))
}

fn write_stdout(bytes: &[u8], newline: bool) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .map_err(|error| output_error(&error))?;
    if newline && !bytes.ends_with(b"\n") {
        stdout
            .write_all(b"\n")
            .map_err(|error| output_error(&error))?;
    }
    stdout.flush().map_err(|error| output_error(&error))
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
}
