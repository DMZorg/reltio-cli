mod audit;
mod cli;
mod commands;
mod metadata;
mod output;
mod release;

use std::future::Future;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use std::{env, ffi::OsStr};

use clap::Parser;
use reltio_client::cancellation::{CancellationReason, CancellationToken};
use reltio_client::config::{ConfigPaths, Environment};
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::redaction::OutputGuard;

use crate::cli::{Cli, OutputFormat};
use crate::commands::{Runtime, acquire_final_output_guard_lease};
use crate::output::{
    OutputContext, RenderOptions, prepare_error_context_fallback_guarded, prepare_error_guarded,
    prepare_raw_guarded,
};

#[tokio::main]
async fn main() -> ExitCode {
    let started = Instant::now();
    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    let forced_cancellation = CancellationToken::new();
    let signal_forced_cancellation = forced_cancellation.clone();
    #[cfg(unix)]
    let Ok(mut interrupts) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    else {
        return ExitCode::from(1);
    };
    #[cfg(windows)]
    let Ok(mut interrupts) = tokio::signal::windows::ctrl_c() else {
        return ExitCode::from(1);
    };
    #[cfg(any(unix, windows))]
    let signal = tokio::spawn(async move {
        let mut signal_observed = false;
        while interrupts.recv().await.is_some() {
            record_interrupt(
                &mut signal_observed,
                &signal_cancellation,
                &signal_forced_cancellation,
            );
        }
    });
    #[cfg(not(any(unix, windows)))]
    let signal = tokio::spawn(async move {
        let mut signal_observed = false;
        while tokio::signal::ctrl_c().await.is_ok() {
            record_interrupt(
                &mut signal_observed,
                &signal_cancellation,
                &signal_forced_cancellation,
            );
        }
    });
    let environment = Environment::capture();
    let stderr_context = OutputContext::default();
    let invocation_deadline = preparse_deadline(started, &environment);
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            use clap::error::ErrorKind;
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let result = emit_preparse_output(
                    error.to_string().into_bytes(),
                    &environment,
                    invocation_deadline,
                    &cancellation,
                )
                .await;
                let exit = match result {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        emit_process_error(
                            &error,
                            preparse_output_format(&environment),
                            &environment,
                            invocation_deadline,
                            &cancellation,
                            &stderr_context,
                        )
                        .await;
                        error_exit_code(
                            &error,
                            signal_preceded_deadline(&cancellation, invocation_deadline),
                        )
                    }
                };
                signal.abort();
                return exit;
            }
            let mut failure = ReltioError::usage("invalid_cli_usage", error.to_string());
            emit_process_error(
                &failure,
                preparse_output_format(&environment),
                &environment,
                invocation_deadline,
                &cancellation,
                &stderr_context,
            )
            .await;
            if Instant::now() >= invocation_deadline {
                failure = command_timeout_error(failure);
            }
            signal.abort();
            return error_exit_code(
                &failure,
                signal_preceded_deadline(&cancellation, invocation_deadline),
            );
        }
    };
    let format = match resolved_output_format(&cli, &environment) {
        Ok(format) => format,
        Err(mut error) => {
            emit_process_error(
                &error,
                preparse_output_format(&environment),
                &environment,
                invocation_deadline,
                &cancellation,
                &stderr_context,
            )
            .await;
            if Instant::now() >= invocation_deadline {
                error = command_timeout_error(error);
            }
            signal.abort();
            return error_exit_code(
                &error,
                signal_preceded_deadline(&cancellation, invocation_deadline),
            );
        }
    };
    let render = RenderOptions {
        format,
        compact: cli.compact,
    };
    let (result, interrupted) = Box::pin(run_with_sigint(
        cli,
        environment.clone(),
        render,
        cancellation.clone(),
        forced_cancellation,
        invocation_deadline,
        stderr_context.clone(),
    ))
    .await;
    let exit = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit_process_error(
                &error,
                render.format,
                &environment,
                invocation_deadline,
                &cancellation,
                &stderr_context,
            )
            .await;
            error_exit_code(&error, interrupted)
        }
    };
    signal.abort();
    exit
}

fn environment_output_guard(environment: &Environment) -> OutputGuard {
    reltio_client::auth::environment_credential_output_guard(environment)
}

async fn run_with_sigint(
    cli: Cli,
    environment: Environment,
    render: RenderOptions,
    cancellation: CancellationToken,
    forced_cancellation: CancellationToken,
    deadline: Instant,
    stderr_context: OutputContext,
) -> (Result<()>, bool) {
    let command = Box::pin(run(
        cli,
        environment,
        render,
        cancellation.clone(),
        deadline,
        stderr_context,
    ));
    run_command_with_control(command, cancellation, forced_cancellation, deadline).await
}

async fn run_command_with_control<F>(
    command: F,
    cancellation: CancellationToken,
    forced_cancellation: CancellationToken,
    deadline: Instant,
) -> (Result<()>, bool)
where
    F: Future<Output = Result<()>>,
{
    if Instant::now() >= deadline {
        if signal_preceded_deadline(&cancellation, deadline) {
            return forced_control_result(&cancellation, deadline);
        }
        cancellation.cancel_with_reason(CancellationReason::Deadline);
        return (Err(command_timeout_error(command_canceled_error())), false);
    }
    tokio::pin!(command);
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timeout);

    tokio::select! {
        biased;
        () = forced_cancellation.cancelled() => {
            forced_control_result(&cancellation, deadline)
        },
        result = &mut command => {
            let result = result.map_err(|error| {
                normalize_late_cancellation(error, &cancellation, deadline)
            });
            let interrupted = result.is_err() && signal_preceded_deadline(&cancellation, deadline);
            (result, interrupted)
        },
        () = cancellation.cancelled() => {
            let result = tokio::select! {
                biased;
                () = forced_cancellation.cancelled() => {
                    return forced_control_result(&cancellation, deadline);
                },
                result = &mut command => result.map_err(|error| {
                    normalize_late_cancellation(error, &cancellation, deadline)
                }),
            };
            if result.is_ok() {
                return (result, false);
            }
            let interrupted = signal_preceded_deadline(&cancellation, deadline);
            (Err(result.unwrap_err_or_else(command_canceled_error)), interrupted)
        }
        () = &mut timeout => {
            cancellation.cancel_with_reason(CancellationReason::Deadline);
            let result = tokio::select! {
                biased;
                () = forced_cancellation.cancelled() => {
                    return forced_control_result(&cancellation, deadline);
                },
                result = &mut command => result,
            };
            if result.is_ok() {
                return (result, false);
            }
            if signal_preceded_deadline(&cancellation, deadline) {
                (Err(result.unwrap_err_or_else(command_canceled_error)), true)
            } else {
                (Err(result.map_or_else(command_timeout_error, |()| {
                    command_timeout_error(command_canceled_error())
                })), false)
            }
        }
    }
}

fn record_interrupt(
    signal_observed: &mut bool,
    cancellation: &CancellationToken,
    forced_cancellation: &CancellationToken,
) {
    if *signal_observed {
        forced_cancellation.cancel_with_reason(CancellationReason::Signal);
    } else {
        *signal_observed = true;
        cancellation.cancel_with_reason(CancellationReason::Signal);
    }
}

fn forced_control_result(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> (Result<()>, bool) {
    let interrupted = signal_preceded_deadline(cancellation, deadline);
    let error = normalize_late_cancellation(command_canceled_error(), cancellation, deadline);
    (Err(error), interrupted)
}

fn normalize_late_cancellation(
    error: ReltioError,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> ReltioError {
    if error.category == ErrorCategory::Canceled
        && Instant::now() >= deadline
        && cancellation
            .cancelled_at()
            .is_none_or(|stamp| !stamp.occurred_at_or_before(deadline))
    {
        command_timeout_error(error)
    } else {
        error
    }
}

fn signal_preceded_deadline(cancellation: &CancellationToken, deadline: Instant) -> bool {
    cancellation.cancellation_reason() == Some(CancellationReason::Signal)
        && cancellation
            .cancelled_at()
            .is_some_and(|stamp| stamp.occurred_at_or_before(deadline))
}

trait ResultControlExt {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> ReltioError) -> ReltioError;
}

impl ResultControlExt for Result<()> {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> ReltioError) -> ReltioError {
        match self {
            Ok(()) => fallback(),
            Err(error) => error,
        }
    }
}

fn command_canceled_error() -> ReltioError {
    ReltioError::new(
        "request_canceled",
        ErrorCategory::Canceled,
        "the command was canceled",
    )
    .with_details(serde_json::json!({
        "phase": "command_completion",
        "remote_response_received": null,
        "remote_request_completed": null,
        "remote_operation_completed": null,
        "remote_operation_state": "completion_race",
        "local_state_committed": null,
        "safe_to_replay": false
    }))
}

async fn emit_preparse_output(
    bytes: Vec<u8>,
    environment: &Environment,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<()> {
    let paths = ConfigPaths::discover(environment)
        .map_err(|error| error.with_output_guard(OutputGuard::deny_all()))?;
    let lease =
        acquire_final_output_guard_lease(&paths, environment, deadline, cancellation).await?;
    let prepared = prepare_raw_guarded(&bytes, false, &environment_output_guard(environment))?
        .with_additional_guard(lease.output_guard())?;
    prepared
        .write_stdout_with_owner(lease, deadline, cancellation)
        .await
}

async fn emit_process_error(
    error: &ReltioError,
    format: OutputFormat,
    environment: &Environment,
    deadline: Instant,
    cancellation: &CancellationToken,
    stderr_context: &OutputContext,
) {
    let Ok(paths) = ConfigPaths::discover(environment) else {
        return;
    };
    if cancellation.is_cancelled() || Instant::now() >= deadline {
        return;
    }
    let Ok(lease) =
        acquire_final_output_guard_lease(&paths, environment, deadline, cancellation).await
    else {
        return;
    };
    let mut final_guard = environment_output_guard(environment);
    final_guard.merge(lease.output_guard());
    let Ok(Some(prepared)) = prepare_error_guarded(error, format, &final_guard) else {
        return;
    };
    let result = prepared
        .with_context(stderr_context)
        .write_stderr_with_owner(lease, deadline, cancellation)
        .await;
    let Err(write_error) = result else {
        return;
    };
    if write_error.code != "credential_output_refused"
        || write_error.details["reason"] != "cross_emission_match"
        || cancellation.is_cancelled()
        || Instant::now() >= deadline
    {
        return;
    }

    let Ok(lease) =
        acquire_final_output_guard_lease(&paths, environment, deadline, cancellation).await
    else {
        return;
    };
    let mut final_guard = environment_output_guard(environment);
    final_guard.merge(lease.output_guard());
    let Some(prepared) =
        prepare_error_context_fallback_guarded(error, &final_guard, stderr_context)
    else {
        return;
    };
    let _ = prepared
        .with_context(stderr_context)
        .write_stderr_with_owner(lease, deadline, cancellation)
        .await;
}

fn preparse_deadline(started: Instant, environment: &Environment) -> Instant {
    let timeout = preparse_timeout()
        .or_else(|| {
            environment
                .get("RELTIO_TIMEOUT")
                .and_then(|value| humantime::parse_duration(value).ok())
        })
        .filter(|duration| !duration.is_zero() && *duration <= reltio_client::MAX_OPERATION_TIMEOUT)
        .unwrap_or(Duration::from_secs(30));
    started.checked_add(timeout).unwrap_or(started)
}

fn preparse_timeout() -> Option<Duration> {
    preparse_timeout_from(env::args_os().skip(1))
}

fn preparse_timeout_from<I, S>(arguments: I) -> Option<Duration>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    while let Some(argument) = arguments.next() {
        if argument == OsStr::new("--") {
            break;
        }
        if argument == OsStr::new("--timeout") {
            return arguments
                .next()
                .as_deref()
                .and_then(OsStr::to_str)
                .and_then(|value| humantime::parse_duration(value).ok());
        }
        if argument == OsStr::new("--credential-process-arg") {
            let _ = arguments.next();
            continue;
        }
        if let Some(argument) = argument.to_str() {
            if let Some(value) = argument.strip_prefix("--timeout=") {
                return humantime::parse_duration(value).ok();
            }
        }
    }
    None
}

fn error_exit_code(error: &ReltioError, interrupted: bool) -> ExitCode {
    if interrupted {
        ExitCode::from(130)
    } else {
        ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(1))
    }
}

fn command_timeout_error(mut error: ReltioError) -> ReltioError {
    if error.category == ErrorCategory::Timeout {
        return error;
    }
    let original_code = error.code.clone();
    "request_timeout".clone_into(&mut error.code);
    error.category = ErrorCategory::Timeout;
    "the command exceeded its overall timeout".clone_into(&mut error.message);
    error.retryable = false;
    if let Some(details) = error.details.as_object_mut() {
        details.insert("cause_code".to_owned(), original_code.into());
        details.insert("deadline_exceeded".to_owned(), true.into());
    }
    error
}

async fn run(
    cli: Cli,
    environment: Environment,
    render: RenderOptions,
    cancellation: CancellationToken,
    invocation_deadline: Instant,
    stderr_context: OutputContext,
) -> Result<()> {
    Runtime::new(
        &cli,
        environment,
        render,
        cancellation,
        invocation_deadline,
        stderr_context,
    )?
    .dispatch(cli.command)
    .await
}

fn resolved_output_format(cli: &Cli, environment: &Environment) -> Result<OutputFormat> {
    let default = if matches!(
        cli.command,
        cli::Command::Entity(cli::EntityCommand {
            command: cli::EntitySubcommand::Scan(_)
        })
    ) {
        OutputFormat::Jsonl
    } else {
        OutputFormat::Json
    };
    if let Some(output) = cli.output {
        return Ok(output);
    }
    if let Some(value) = environment.get("RELTIO_OUTPUT") {
        return parse_output_format(value).ok_or_else(|| {
            ReltioError::usage(
                "invalid_output_format",
                format!(
                    "RELTIO_OUTPUT must be one of json, jsonl, table, yaml, or raw; received {value:?}"
                ),
            )
        });
    }
    Ok(default)
}

fn parse_output_format(value: &str) -> Option<OutputFormat> {
    match value {
        "json" => Some(OutputFormat::Json),
        "jsonl" => Some(OutputFormat::Jsonl),
        "table" => Some(OutputFormat::Table),
        "yaml" => Some(OutputFormat::Yaml),
        "raw" => Some(OutputFormat::Raw),
        _ => None,
    }
}

fn preparse_output_format(environment: &Environment) -> OutputFormat {
    preparse_output_format_from(env::args_os().skip(1))
        .or_else(|| {
            environment
                .get("RELTIO_OUTPUT")
                .and_then(parse_output_format)
        })
        .unwrap_or(OutputFormat::Json)
}

fn preparse_output_format_from<I, S>(arguments: I) -> Option<OutputFormat>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    while let Some(argument) = arguments.next() {
        if argument == OsStr::new("--") {
            break;
        }
        if argument == OsStr::new("--credential-process-arg") {
            let _ = arguments.next();
            continue;
        }
        if argument == OsStr::new("--output") {
            return Some(
                arguments
                    .next()
                    .as_deref()
                    .and_then(OsStr::to_str)
                    .and_then(parse_output_format)
                    .unwrap_or(OutputFormat::Json),
            );
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--output="))
        {
            return Some(parse_output_format(value).unwrap_or(OutputFormat::Json));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn credential_process_arguments_do_not_become_the_preparse_timeout() {
        assert_eq!(
            preparse_timeout_from(["auth", "login", "--credential-process-arg", "--timeout=5ms",]),
            None
        );
        assert_eq!(
            preparse_timeout_from([
                "--timeout=2s",
                "auth",
                "login",
                "--credential-process-arg",
                "--timeout=5ms",
            ]),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn credential_process_arguments_do_not_become_the_preparse_output_format() {
        assert_eq!(
            preparse_output_format_from([
                "auth",
                "login",
                "--credential-process-arg",
                "--output=table",
            ]),
            None
        );
        assert_eq!(
            preparse_output_format_from([
                "--output=yaml",
                "auth",
                "login",
                "--credential-process-arg",
                "--output=table",
            ]),
            Some(OutputFormat::Yaml)
        );
    }

    #[test]
    fn signal_exit_status_uses_the_first_control_event() {
        let signal = CancellationToken::new();
        let future_deadline = Instant::now() + Duration::from_secs(1);
        signal.cancel_with_reason(CancellationReason::Signal);
        assert!(signal_preceded_deadline(&signal, future_deadline));

        let deadline = CancellationToken::new();
        deadline.cancel_with_reason(CancellationReason::Deadline);
        deadline.cancel_with_reason(CancellationReason::Signal);
        assert!(!signal_preceded_deadline(&deadline, future_deadline));

        let late_signal = CancellationToken::new();
        let elapsed_deadline = Instant::now();
        std::thread::sleep(Duration::from_millis(1));
        late_signal.cancel_with_reason(CancellationReason::Signal);
        assert!(!signal_preceded_deadline(&late_signal, elapsed_deadline));

        let canceled = ReltioError::new("request_canceled", ErrorCategory::Canceled, "late signal");
        let normalized = normalize_late_cancellation(canceled, &late_signal, elapsed_deadline);
        assert_eq!(normalized.code, "request_timeout");
        assert_eq!(normalized.category, ErrorCategory::Timeout);
    }

    #[test]
    fn repeated_interrupt_requests_forced_command_drop() {
        let cancellation = CancellationToken::new();
        let forced_cancellation = CancellationToken::new();
        let mut signal_observed = false;

        record_interrupt(&mut signal_observed, &cancellation, &forced_cancellation);
        assert_eq!(
            cancellation.cancellation_reason(),
            Some(CancellationReason::Signal)
        );
        assert!(!forced_cancellation.is_cancelled());

        record_interrupt(&mut signal_observed, &cancellation, &forced_cancellation);
        assert_eq!(
            forced_cancellation.cancellation_reason(),
            Some(CancellationReason::Signal)
        );
    }

    #[tokio::test]
    async fn elapsed_deadline_precedes_an_immediately_ready_command_error() {
        let cancellation = CancellationToken::new();
        let command_error = ReltioError::new(
            "invalid_arguments",
            ErrorCategory::Usage,
            "the command arguments are invalid",
        );
        let deadline = Instant::now();
        tokio::task::yield_now().await;

        let (result, interrupted) = run_command_with_control(
            async { Err(command_error) },
            cancellation,
            CancellationToken::new(),
            deadline,
        )
        .await;

        let error = result.unwrap_err();
        assert_eq!(error.code, "request_timeout");
        assert_eq!(error.category, ErrorCategory::Timeout);
        assert!(!interrupted);
    }

    #[tokio::test]
    async fn forced_interrupt_drops_a_command_stalled_during_graceful_cleanup() {
        let cancellation = CancellationToken::new();
        let forced_cancellation = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let command_drop = DropFlag(Arc::clone(&dropped));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let command = async move {
            let _command_drop = command_drop;
            let _ = started_tx.send(());
            std::future::pending::<Result<()>>().await
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        let task = tokio::spawn(run_command_with_control(
            command,
            cancellation.clone(),
            forced_cancellation.clone(),
            deadline,
        ));
        started_rx.await.expect("pending command starts");
        let mut signal_observed = false;

        record_interrupt(&mut signal_observed, &cancellation, &forced_cancellation);
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "the first interrupt remains graceful");

        record_interrupt(&mut signal_observed, &cancellation, &forced_cancellation);
        let (result, interrupted) = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("forced cancellation is bounded")
            .expect("controlled command task completes");

        assert_eq!(result.unwrap_err().code, "request_canceled");
        assert!(interrupted);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
