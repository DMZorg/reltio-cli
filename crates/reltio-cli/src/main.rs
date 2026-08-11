mod audit;
mod cli;
mod commands;
mod metadata;
mod output;
mod release;

use std::process::ExitCode;
use std::{env, ffi::OsStr};

use clap::Parser;
use reltio_client::auth::TokenManager;
use reltio_client::cancellation::CancellationToken;
use reltio_client::config::{ConfigPaths, Environment};
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::redaction::OutputGuard;
use serde_json::Value;

use crate::cli::{Cli, OutputFormat};
use crate::commands::Runtime;
use crate::output::{RenderOptions, write_error, write_raw_guarded};

#[tokio::main]
async fn main() -> ExitCode {
    let environment = Environment::capture();
    let environment_guard = process_output_guard(&environment);
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            use clap::error::ErrorKind;
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                return match write_raw_guarded(
                    error.to_string().as_bytes(),
                    false,
                    &environment_guard,
                ) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        write_error(&error, preparse_output_format(&environment));
                        ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(1))
                    }
                };
            }
            let failure = ReltioError::usage("invalid_cli_usage", error.to_string())
                .with_output_guard(environment_guard.clone());
            write_error(&failure, preparse_output_format(&environment));
            return ExitCode::from(u8::try_from(failure.exit_code()).unwrap_or(1));
        }
    };
    let format = match resolved_output_format(&cli, &environment) {
        Ok(format) => format,
        Err(error) => {
            let error = error.with_output_guard(environment_guard.clone());
            write_error(&error, preparse_output_format(&environment));
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(1));
        }
    };
    let render = RenderOptions {
        format,
        compact: cli.compact,
    };
    let cancellation = CancellationToken::new();
    let (result, interrupted) = run_with_sigint(cli, environment, render, cancellation).await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let error = error.with_output_guard(environment_guard);
            write_error(&error, render.format);
            if interrupted {
                ExitCode::from(130)
            } else {
                ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(1))
            }
        }
    }
}

fn environment_output_guard(environment: &Environment) -> OutputGuard {
    OutputGuard::from_known_secrets(
        &["RELTIO_ACCESS_TOKEN", "RELTIO_CLIENT_SECRET"]
            .into_iter()
            .filter_map(|name| environment.get(name))
            .collect::<Vec<_>>(),
    )
}

fn process_output_guard(environment: &Environment) -> OutputGuard {
    let mut guard = environment_output_guard(environment);
    let Ok(paths) = ConfigPaths::discover(environment) else {
        return guard;
    };
    match TokenManager::cache_output_guard(&paths.cache_dir) {
        Ok(cache_guard) => guard.merge(&cache_guard),
        Err(error) => match error.output_guard() {
            Some(cache_guard) => guard.merge(cache_guard),
            None => guard.merge(&OutputGuard::deny_all()),
        },
    }
    guard
}

async fn run_with_sigint(
    cli: Cli,
    environment: Environment,
    render: RenderOptions,
    cancellation: CancellationToken,
) -> (Result<()>, bool) {
    let signal_cancellation = cancellation.clone();
    let mut signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
            true
        } else {
            false
        }
    });
    let command = run(cli, environment, render, cancellation.clone());
    tokio::pin!(command);

    tokio::select! {
        biased;
        signal_result = &mut signal => {
            let interrupted = signal_result.unwrap_or(false);
            let result = command.await;
            if interrupted && result.is_ok() {
                (Err(interrupted_command_error()), true)
            } else {
                (result, interrupted)
            }
        }
        result = &mut command => {
            signal.abort();
            (result, false)
        },
    }
}

fn interrupted_command_error() -> ReltioError {
    ReltioError::new(
        "request_canceled",
        ErrorCategory::Canceled,
        "the command was canceled",
    )
    .with_details(serde_json::json!({
        "phase": "command_completion",
        "remote_response_received": Value::Null,
        "remote_request_completed": Value::Null,
        "remote_operation_completed": Value::Null,
        "remote_operation_state": "unknown",
        "local_state_committed": Value::Null,
        "safe_to_replay": false
    }))
}

async fn run(
    cli: Cli,
    environment: Environment,
    render: RenderOptions,
    cancellation: CancellationToken,
) -> Result<()> {
    Runtime::new(&cli, environment, render, cancellation)?
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
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == OsStr::new("--") {
            break;
        }
        if argument == OsStr::new("--output") {
            return arguments
                .next()
                .as_deref()
                .and_then(OsStr::to_str)
                .and_then(parse_output_format)
                .unwrap_or(OutputFormat::Json);
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--output="))
        {
            return parse_output_format(value).unwrap_or(OutputFormat::Json);
        }
    }
    environment
        .get("RELTIO_OUTPUT")
        .and_then(parse_output_format)
        .unwrap_or(OutputFormat::Json)
}
