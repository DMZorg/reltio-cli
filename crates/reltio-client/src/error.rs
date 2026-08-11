use std::fmt;

use serde::Serialize;
use serde_json::{Value, json};

use crate::redaction::OutputGuard;

/// Stable error categories exposed by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Usage,
    Profile,
    Authentication,
    Network,
    Api,
    NotFound,
    Conflict,
    Safety,
    Timeout,
    Canceled,
    Internal,
}

/// A structured, redaction-safe failure.
///
/// The payload is boxed so the error side of every client `Result` remains a
/// single pointer even though the stable automation contract carries rich
/// recovery metadata.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
#[must_use]
pub struct ReltioError(Box<ReltioErrorData>);

#[derive(Debug, Clone, Serialize)]
pub struct ReltioErrorData {
    pub code: String,
    pub category: ErrorCategory,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default = "empty_object")]
    pub details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggested_commands: Vec<String>,
    #[serde(skip)]
    output_guard: Option<OutputGuard>,
}

pub type Result<T> = std::result::Result<T, ReltioError>;

/// Returns parser diagnostics that never include source JSON or parser prose.
pub fn json_parse_details(error: &serde_json::Error) -> Value {
    json!({
        "parser_category": format!("{:?}", error.classify()).to_ascii_lowercase(),
        "line": error.line(),
        "column": error.column()
    })
}

impl ReltioError {
    pub fn new(
        code: impl Into<String>,
        category: ErrorCategory,
        message: impl Into<String>,
    ) -> Self {
        Self(Box::new(ReltioErrorData {
            code: code.into(),
            category,
            message: message.into(),
            retryable: false,
            http_status: None,
            request_id: None,
            details: empty_object(),
            hint: None,
            suggested_commands: Vec::new(),
            output_guard: None,
        }))
    }

    pub fn usage(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, ErrorCategory::Usage, message)
    }

    pub fn profile(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, ErrorCategory::Profile, message)
    }

    pub fn auth(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, ErrorCategory::Authentication, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal_error", ErrorCategory::Internal, message)
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.0.hint = Some(hint.into());
        self
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.0.details = details;
        self
    }

    pub fn with_http_status(mut self, status: u16) -> Self {
        self.0.http_status = Some(status);
        self
    }

    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.0.request_id = request_id;
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.0.retryable = retryable;
        self
    }

    pub fn with_suggested_command(mut self, command: impl Into<String>) -> Self {
        self.0.suggested_commands.push(command.into());
        self
    }

    pub fn with_output_guard(mut self, guard: OutputGuard) -> Self {
        if let Some(current) = &mut self.0.output_guard {
            current.merge(&guard);
        } else {
            self.0.output_guard = Some(guard);
        }
        self
    }

    pub fn output_guard(&self) -> Option<&OutputGuard> {
        self.0.output_guard.as_ref()
    }

    /// Stable process exit code defined by the product contract.
    pub fn exit_code(&self) -> i32 {
        match self.category {
            ErrorCategory::Usage => 2,
            ErrorCategory::Profile | ErrorCategory::Authentication => 3,
            ErrorCategory::NotFound => 4,
            ErrorCategory::Conflict | ErrorCategory::Safety => 5,
            ErrorCategory::Timeout => 7,
            ErrorCategory::Canceled => 8,
            ErrorCategory::Network | ErrorCategory::Api | ErrorCategory::Internal => 1,
        }
    }

    pub fn io(context: &str, error: &std::io::Error) -> Self {
        Self::new(
            "local_io_error",
            ErrorCategory::Internal,
            format!("{context}: {error}"),
        )
        .with_details(json!({ "kind": format!("{:?}", error.kind()) }))
    }
}

impl fmt::Display for ReltioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::ops::Deref for ReltioError {
    type Target = ReltioErrorData;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ReltioError {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::error::Error for ReltioError {}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_error_categories_map_to_documented_exit_codes() {
        for (category, expected) in [
            (ErrorCategory::Usage, 2),
            (ErrorCategory::Profile, 3),
            (ErrorCategory::Authentication, 3),
            (ErrorCategory::Network, 1),
            (ErrorCategory::Api, 1),
            (ErrorCategory::NotFound, 4),
            (ErrorCategory::Conflict, 5),
            (ErrorCategory::Safety, 5),
            (ErrorCategory::Timeout, 7),
            (ErrorCategory::Canceled, 8),
            (ErrorCategory::Internal, 1),
        ] {
            assert_eq!(
                ReltioError::new("test_error", category, "test error").exit_code(),
                expected,
                "{category:?}"
            );
        }
    }
}
