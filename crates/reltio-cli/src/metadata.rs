use std::collections::BTreeSet;

use clap::{ArgAction, CommandFactory};
use reltio_client::error::{ReltioError, Result};
use serde::Serialize;
use serde_json::{Value, json, to_value};

use crate::cli::Cli;

const OUTPUT_ENVIRONMENT: &[&str] = &["RELTIO_OUTPUT"];
const PROFILE_ENVIRONMENT: &[&str] = &["RELTIO_CONFIG", "RELTIO_PROFILE", "RELTIO_OUTPUT"];
const AUTH_ENVIRONMENT: &[&str] = &[
    "RELTIO_CONFIG",
    "RELTIO_PROFILE",
    "RELTIO_ENVIRONMENT",
    "RELTIO_BASE_URL",
    "RELTIO_TENANT",
    "RELTIO_AUTH_URL",
    "RELTIO_ACCESS_TOKEN",
    "RELTIO_CLIENT_ID",
    "RELTIO_CLIENT_SECRET",
    "RELTIO_OUTPUT",
    "RELTIO_TIMEOUT",
];
const RAW_ENVIRONMENT: &[&str] = &[
    "RELTIO_CONFIG",
    "RELTIO_PROFILE",
    "RELTIO_ENVIRONMENT",
    "RELTIO_BASE_URL",
    "RELTIO_TENANT",
    "RELTIO_AUTH_URL",
    "RELTIO_ACCESS_TOKEN",
    "RELTIO_CLIENT_ID",
    "RELTIO_CLIENT_SECRET",
    "RELTIO_OUTPUT",
    "RELTIO_TIMEOUT",
    "RELTIO_CONFIRM_TENANT",
];

const AUTH_PRACTICES: &[&str] = &[
    "AUTH-CENTRALIZED-001",
    "AUTH-CLIENT-CREDENTIALS-001",
    "AUTH-TOKEN-CACHE-001",
    "AUTH-TOKEN-REISSUE-001",
    "AUTH-OPAQUE-TOKEN-001",
    "AUTH-TOKEN-RETRY-001",
];
const AUTH_CHECK_PRACTICES: &[&str] = &[
    "AUTH-CENTRALIZED-001",
    "AUTH-CLIENT-CREDENTIALS-001",
    "AUTH-TOKEN-CACHE-001",
    "AUTH-TOKEN-REISSUE-001",
    "AUTH-OPAQUE-TOKEN-001",
    "AUTH-TOKEN-RETRY-001",
    "AUTH-BEARER-001",
    "HTTP-RETRY-001",
    "HTTP-POST-SIZE-001",
    "ENTITY-SEARCH-POST-001",
    "ENTITY-SEARCH-BOUNDARY-001",
    "ENTITY-SEARCH-CONSISTENCY-001",
    "ENTITY-FILTER-QUERY-001",
    "ENTITY-LOSSLESS-001",
];
const ENTITY_GET_PRACTICES: &[&str] = &[
    "AUTH-CENTRALIZED-001",
    "AUTH-CLIENT-CREDENTIALS-001",
    "AUTH-TOKEN-CACHE-001",
    "AUTH-TOKEN-REISSUE-001",
    "AUTH-OPAQUE-TOKEN-001",
    "AUTH-TOKEN-RETRY-001",
    "AUTH-BEARER-001",
    "HTTP-RETRY-001",
    "ENTITY-GET-CONSISTENCY-001",
    "ENTITY-GET-PARAMETERS-001",
    "ENTITY-GET-REVERSE-TRANSCODE-001",
    "ENTITY-LOSSLESS-001",
];
const ENTITY_SEARCH_PRACTICES: &[&str] = &[
    "AUTH-CENTRALIZED-001",
    "AUTH-CLIENT-CREDENTIALS-001",
    "AUTH-TOKEN-CACHE-001",
    "AUTH-TOKEN-REISSUE-001",
    "AUTH-OPAQUE-TOKEN-001",
    "AUTH-TOKEN-RETRY-001",
    "AUTH-BEARER-001",
    "HTTP-RETRY-001",
    "HTTP-POST-SIZE-001",
    "ENTITY-SEARCH-POST-001",
    "ENTITY-SEARCH-BOUNDARY-001",
    "ENTITY-SEARCH-CONSISTENCY-001",
    "ENTITY-FILTER-QUERY-001",
    "ENTITY-LOSSLESS-001",
];
const ENTITY_SCAN_PRACTICES: &[&str] = &[
    "AUTH-CENTRALIZED-001",
    "AUTH-CLIENT-CREDENTIALS-001",
    "AUTH-TOKEN-CACHE-001",
    "AUTH-TOKEN-REISSUE-001",
    "AUTH-OPAQUE-TOKEN-001",
    "AUTH-TOKEN-RETRY-001",
    "AUTH-BEARER-001",
    "HTTP-RETRY-001",
    "HTTP-POST-SIZE-001",
    "ENTITY-SCAN-CURSOR-001",
    "ENTITY-FILTER-QUERY-001",
    "ENTITY-SEARCH-CONSISTENCY-001",
    "ENTITY-LOSSLESS-001",
];
const RAW_PRACTICES: &[&str] = &[
    "AUTH-CENTRALIZED-001",
    "AUTH-CLIENT-CREDENTIALS-001",
    "AUTH-TOKEN-CACHE-001",
    "AUTH-TOKEN-REISSUE-001",
    "AUTH-OPAQUE-TOKEN-001",
    "AUTH-TOKEN-RETRY-001",
    "AUTH-BEARER-001",
    "HTTP-RETRY-001",
    "HTTP-POST-SIZE-001",
    "ENTITY-GET-CONSISTENCY-001",
    "ENTITY-GET-PARAMETERS-001",
    "ENTITY-GET-REVERSE-TRANSCODE-001",
    "ENTITY-SEARCH-GET-001",
    "ENTITY-SEARCH-POST-001",
    "ENTITY-SEARCH-BOUNDARY-001",
    "ENTITY-SEARCH-CONSISTENCY-001",
    "ENTITY-SCAN-CURSOR-001",
    "ENTITY-FILTER-QUERY-001",
    "ENTITY-LOSSLESS-001",
];
#[cfg(test)]
const NETWORK_COMMANDS: &[&str] = &[
    "auth.login",
    "auth.check",
    "auth.token",
    "entity.get",
    "entity.search",
    "entity.scan",
    "api.request",
    "doctor",
];

#[derive(Debug, Clone, Serialize)]
pub struct CommandMetadata {
    pub name: &'static str,
    pub summary: &'static str,
    pub safety: &'static str,
    pub input_formats: &'static [&'static str],
    pub output: &'static str,
    pub practice_ids: &'static [&'static str],
    pub environment: &'static [&'static str],
    pub examples: &'static [&'static str],
}

#[derive(Debug, Serialize)]
struct ArgumentMetadata {
    name: String,
    long: Option<String>,
    positional: Option<usize>,
    value_type: &'static str,
    required: bool,
    multiple: bool,
    global: bool,
    default: Vec<String>,
    possible_values: Vec<String>,
    environment: Option<String>,
    description: Option<String>,
}

pub fn all() -> &'static [CommandMetadata] {
    &[
        CommandMetadata {
            name: "profile.list",
            summary: "List configured profiles without resolving credentials.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: PROFILE_ENVIRONMENT,
            examples: &["reltio profile list"],
        },
        CommandMetadata {
            name: "profile.show",
            summary: "Show one profile without exposing credential material.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: PROFILE_ENVIRONMENT,
            examples: &["reltio profile show dev"],
        },
        CommandMetadata {
            name: "profile.add",
            summary: "Create a non-secret routing and authentication profile.",
            safety: "local_write",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: PROFILE_ENVIRONMENT,
            examples: &["reltio profile add dev --environment dev --tenant ExampleTenant"],
        },
        CommandMetadata {
            name: "profile.update",
            summary: "Update non-secret settings for one profile.",
            safety: "local_write",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: PROFILE_ENVIRONMENT,
            examples: &["reltio profile update dev --tenant ExampleTenant"],
        },
        CommandMetadata {
            name: "profile.use",
            summary: "Select the default profile for later invocations.",
            safety: "local_write",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: PROFILE_ENVIRONMENT,
            examples: &["reltio profile use dev"],
        },
        CommandMetadata {
            name: "profile.remove",
            summary: "Transactionally remove one profile, its selection, and imported bearer cache.",
            safety: "local_write",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: PROFILE_ENVIRONMENT,
            examples: &["reltio profile remove dev"],
        },
        CommandMetadata {
            name: "auth.login",
            summary: "Configure a credential provider and cache only a currently usable token.",
            safety: "authentication",
            input_formats: &["hidden_tty", "stdin", "environment", "credential_process"],
            output: "finite envelope",
            practice_ids: AUTH_PRACTICES,
            environment: AUTH_ENVIRONMENT,
            examples: &[
                "reltio --profile dev auth login --method client-credentials --client-id example-client",
            ],
        },
        CommandMetadata {
            name: "auth.status",
            summary: "Inspect auth provider and cache state without a network request.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[
                "AUTH-TOKEN-CACHE-001",
                "AUTH-TOKEN-REISSUE-001",
                "AUTH-OPAQUE-TOKEN-001",
            ],
            environment: AUTH_ENVIRONMENT,
            examples: &["reltio --profile dev auth status"],
        },
        CommandMetadata {
            name: "auth.check",
            summary: "Validate token and tenant access with a minimal reviewed entity search.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: AUTH_CHECK_PRACTICES,
            environment: AUTH_ENVIRONMENT,
            examples: &["reltio --profile dev auth check"],
        },
        CommandMetadata {
            name: "auth.token",
            summary: "Deliberately reveal the selected access token after explicit acknowledgement.",
            safety: "secret_disclosure",
            input_formats: &[],
            output: "finite envelope or raw secret",
            practice_ids: &[
                "AUTH-CENTRALIZED-001",
                "AUTH-CLIENT-CREDENTIALS-001",
                "AUTH-TOKEN-CACHE-001",
                "AUTH-TOKEN-REISSUE-001",
                "AUTH-OPAQUE-TOKEN-001",
                "AUTH-TOKEN-RETRY-001",
            ],
            environment: AUTH_ENVIRONMENT,
            examples: &["reltio --profile dev --output raw auth token --show"],
        },
        CommandMetadata {
            name: "auth.logout",
            summary: "Clear all local cached token material.",
            safety: "local_write",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[
                "AUTH-TOKEN-CACHE-001",
                "AUTH-TOKEN-REISSUE-001",
                "AUTH-OPAQUE-TOKEN-001",
            ],
            environment: AUTH_ENVIRONMENT,
            examples: &["reltio --profile dev auth logout"],
        },
        CommandMetadata {
            name: "entity.get",
            summary: "Retrieve one entity by ID or URI with consistent-read metadata.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope or raw upstream body",
            practice_ids: ENTITY_GET_PRACTICES,
            environment: AUTH_ENVIRONMENT,
            examples: &["reltio --profile dev entity get entities/00009qz"],
        },
        CommandMetadata {
            name: "entity.search",
            summary: "Run a POST-body indexed search within the 10,000-result boundary.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope or raw upstream body",
            practice_ids: ENTITY_SEARCH_PRACTICES,
            environment: AUTH_ENVIRONMENT,
            examples: &[
                "reltio --profile dev entity search --filter equals(type,'configuration/entityTypes/Organization') --max-items 25",
            ],
        },
        CommandMetadata {
            name: "entity.scan",
            summary: "Stream cursor pages as JSONL with target-, query-, route-, and CLI-version-bound resume state.",
            safety: "read",
            input_formats: &[],
            output: "JSONL item/checkpoint/summary events",
            practice_ids: ENTITY_SCAN_PRACTICES,
            environment: AUTH_ENVIRONMENT,
            examples: &[
                "reltio --profile dev entity scan --filter equals(type,'configuration/entityTypes/Organization') --max-items 1000",
            ],
        },
        CommandMetadata {
            name: "api.request",
            summary: "Issue a controlled raw request with host, header, practice, retry, and mutation safeguards.",
            safety: "dynamic",
            input_formats: &["inline", "@file", "stdin"],
            output: "finite envelope or raw body",
            practice_ids: RAW_PRACTICES,
            environment: RAW_ENVIRONMENT,
            examples: &["reltio --profile dev api request GET /entities/00009qz --service data"],
        },
        CommandMetadata {
            name: "api.practices.list",
            summary: "List reviewed upstream API practices and their enforcement modes.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio api practices list"],
        },
        CommandMetadata {
            name: "api.practices.show",
            summary: "Show one source-linked API practice.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio api practices show AUTH-TOKEN-CACHE-001"],
        },
        CommandMetadata {
            name: "api.practices.check",
            summary: "Validate registry joins and optionally enforce release freshness.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio api practices check --strict"],
        },
        CommandMetadata {
            name: "skills.list",
            summary: "List embedded version-matched agent skills.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio skills list"],
        },
        CommandMetadata {
            name: "skills.get",
            summary: "Print one embedded agent skill.",
            safety: "read",
            input_formats: &[],
            output: "Markdown",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio skills get reltio-data"],
        },
        CommandMetadata {
            name: "skills.path",
            summary: "Print the stable embedded URI for one agent skill.",
            safety: "read",
            input_formats: &[],
            output: "raw text",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio skills path reltio-data"],
        },
        CommandMetadata {
            name: "agent.guide",
            summary: "Print version-matched autonomous-use guidance.",
            safety: "read",
            input_formats: &[],
            output: "Markdown",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio agent guide"],
        },
        CommandMetadata {
            name: "command.schema",
            summary: "Emit stable metadata and typed arguments for implemented commands.",
            safety: "read",
            input_formats: &[],
            output: "finite envelope",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio command schema entity.get"],
        },
        CommandMetadata {
            name: "completion.generate",
            summary: "Generate a shell completion script for the installed binary.",
            safety: "read",
            input_formats: &[],
            output: "shell script",
            practice_ids: &[],
            environment: OUTPUT_ENVIRONMENT,
            examples: &["reltio completion generate bash"],
        },
        CommandMetadata {
            name: "doctor",
            summary: "Diagnose configuration, routing, auth cache, and practices; warnings or failures exit nonzero.",
            safety: "read",
            input_formats: &[],
            output: "finite success envelope or structured diagnostic error",
            practice_ids: ENTITY_SEARCH_PRACTICES,
            environment: AUTH_ENVIRONMENT,
            examples: &["reltio --profile dev doctor"],
        },
    ]
}

pub fn schema(name: Option<&str>) -> Result<Value> {
    match name {
        Some(name) => {
            let metadata = all()
                .iter()
                .find(|metadata| metadata.name == name)
                .ok_or_else(|| {
                    ReltioError::usage(
                        "command_schema_not_found",
                        format!("no command schema exists for {name:?}"),
                    )
                })?;
            schema_value(metadata)
        }
        None => all()
            .iter()
            .map(schema_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

fn schema_value(metadata: &CommandMetadata) -> Result<Value> {
    let mut value = to_value(metadata).map_err(|error| {
        ReltioError::internal(format!("failed to encode command schema: {error}"))
    })?;
    let arguments = to_value(arguments(metadata.name)?).map_err(|error| {
        ReltioError::internal(format!("failed to encode command arguments: {error}"))
    })?;
    value
        .as_object_mut()
        .unwrap_or_else(|| unreachable!("command metadata serializes as an object"))
        .insert("arguments".to_owned(), arguments);
    let consistency = match metadata.name {
        "entity.get" => Value::String("consistent".to_owned()),
        "auth.check" | "entity.search" | "entity.scan" => Value::String("eventual".to_owned()),
        "api.request" | "doctor" => Value::String("dynamic".to_owned()),
        _ => Value::Null,
    };
    value
        .as_object_mut()
        .unwrap_or_else(|| unreachable!("command metadata serializes as an object"))
        .insert("consistency".to_owned(), consistency);
    if metadata.name == "entity.scan" {
        value
            .as_object_mut()
            .unwrap_or_else(|| unreachable!("command metadata serializes as an object"))
            .insert(
                "resume_identity_fields".to_owned(),
                json!([
                    "schema_version",
                    "endpoint_id",
                    "profile",
                    "environment",
                    "tenant",
                    "filter_hash",
                    "query_hash",
                    "page_size",
                    "data_service_url",
                    "cli_version"
                ]),
            );
    }
    Ok(value)
}

fn arguments(name: &str) -> Result<Vec<ArgumentMetadata>> {
    let mut root = Cli::command();
    root.build();
    let root_globals = root
        .get_arguments()
        .filter(|argument| argument.is_global_set())
        .map(|argument| argument.get_id().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let mut command = &root;
    for segment in name.split('.') {
        command = command.find_subcommand(segment).ok_or_else(|| {
            ReltioError::internal(format!(
                "command metadata {name:?} does not map to the Clap command tree"
            ))
        })?;
    }

    Ok(command
        .get_arguments()
        .filter(|argument| !matches!(argument.get_id().as_str(), "help" | "version"))
        .map(|argument| argument_metadata(name, argument, &root_globals))
        .collect())
}

fn argument_metadata(
    command: &str,
    argument: &clap::Arg,
    root_globals: &BTreeSet<String>,
) -> ArgumentMetadata {
    let action = argument.get_action();
    let possible_values = argument_possible_values(command, argument, action);
    ArgumentMetadata {
        name: argument.get_id().as_str().to_owned(),
        long: argument.get_long().map(ToOwned::to_owned),
        positional: argument.get_index(),
        value_type: argument_type(
            command,
            argument.get_id().as_str(),
            action,
            &possible_values,
        ),
        required: argument.is_required_set(),
        multiple: matches!(action, ArgAction::Append | ArgAction::Count),
        global: argument.is_global_set() || root_globals.contains(argument.get_id().as_str()),
        default: argument
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect(),
        possible_values,
        environment: argument
            .get_env()
            .map(|value| value.to_string_lossy().into_owned())
            .or_else(|| {
                (argument.get_id().as_str() == "output").then(|| "RELTIO_OUTPUT".to_owned())
            }),
        description: argument.get_help().map(ToString::to_string),
    }
}

fn argument_possible_values(
    command: &str,
    argument: &clap::Arg,
    action: &ArgAction,
) -> Vec<String> {
    if matches!(
        action,
        ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count
    ) {
        return Vec::new();
    }
    let mut values: Vec<String> = argument
        .get_value_parser()
        .possible_values()
        .map(|values| values.map(|value| value.get_name().to_owned()).collect())
        .unwrap_or_default();
    if values.is_empty() {
        values = match (command, argument.get_id().as_str()) {
            ("auth.login", "method") => ["bearer", "client-credentials", "credential-process"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            ("profile.add" | "profile.update", "auth_method") => ["bearer", "client-credentials"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            ("api.request", "service") => [
                "data",
                "tasks",
                "physical-config",
                "jobs",
                "workflow",
                "rdm",
                "dtss",
                "mcp",
                "auth",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            ("entity.get", "options") => [
                "sendHidden",
                "ovOnly",
                "nonOvOnly",
                "serializeInitialSourcesInCrosswalks",
                "cleanEntity",
                "showAppliedSurvivorshipRules",
                "showEndDatedReferenceAttributes",
                "explainOv",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            _ => Vec::new(),
        };
    }
    values
}

fn argument_type(
    command: &str,
    name: &str,
    action: &ArgAction,
    possible_values: &[String],
) -> &'static str {
    match action {
        ArgAction::SetTrue | ArgAction::SetFalse => return "boolean",
        ArgAction::Count => return "count",
        ArgAction::Append => return "string_array",
        _ => {}
    }
    if command == "profile.update" && name == "production" {
        return "boolean";
    }
    if !possible_values.is_empty() {
        return "enum";
    }
    match (command, name) {
        (_, "timeout" | "connect_timeout" | "expires_in") => "duration",
        (
            _,
            "max_response_bytes" | "default_max_values" | "max_items" | "offset" | "page_size"
            | "max_pages" | "checkpoint_every",
        )
        | ("entity.get", "time") => "unsigned_integer",
        (_, "secret_file" | "resume_file") => "path",
        ("api.request", "method") => "http_method",
        (_, "data") => "inline_or_file_input",
        _ => "string",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::{Command, Parser};
    use reltio_client::registry::Registry;

    use super::*;

    #[test]
    fn metadata_exactly_covers_executable_command_leaves() {
        let mut actual = BTreeSet::new();
        collect_leaves(&Cli::command(), "", &mut actual);
        let expected: BTreeSet<_> = all()
            .iter()
            .map(|metadata| metadata.name.to_owned())
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn metadata_examples_parse_with_this_binary() {
        for metadata in all() {
            for example in metadata.examples {
                Cli::try_parse_from(example.split_ascii_whitespace()).unwrap_or_else(|error| {
                    panic!(
                        "example for {} does not parse: {example}: {error}",
                        metadata.name
                    )
                });
            }
        }
    }

    #[test]
    fn endpoint_practices_are_present_in_affected_command_schemas() {
        let registry = Registry::embedded().expect("registry parses");
        for endpoint in registry.endpoints() {
            for command in &endpoint.commands {
                let metadata = all()
                    .iter()
                    .find(|metadata| metadata.name == command)
                    .unwrap_or_else(|| panic!("endpoint {} references {command}", endpoint.id));
                for practice_id in &endpoint.practice_ids {
                    assert!(
                        metadata.practice_ids.contains(&practice_id.as_str()),
                        "{} omits {practice_id} from endpoint {}",
                        metadata.name,
                        endpoint.id
                    );
                }
            }
        }
    }

    #[test]
    fn practice_command_links_are_present_in_command_schemas() {
        let registry = Registry::embedded().expect("registry parses");
        for practice in registry.practices() {
            for command in &practice.commands {
                let metadata = all()
                    .iter()
                    .find(|metadata| metadata.name == command)
                    .unwrap_or_else(|| panic!("practice {} references {command}", practice.id));
                assert!(
                    metadata.practice_ids.contains(&practice.id.as_str()),
                    "{} omits practice {}",
                    metadata.name,
                    practice.id
                );
            }
        }
    }

    #[test]
    fn every_network_command_has_declared_endpoint_coverage() {
        let registry = Registry::embedded().expect("registry parses");
        for command in NETWORK_COMMANDS {
            assert!(
                registry
                    .endpoints()
                    .iter()
                    .any(|endpoint| endpoint.commands.iter().any(|linked| linked == command)),
                "network command {command} has no endpoint declaration"
            );
        }
    }

    #[test]
    fn every_schema_exposes_typed_arguments() {
        for metadata in all() {
            let value = schema(Some(metadata.name)).expect("schema encodes");
            let arguments = value["arguments"].as_array().expect("arguments array");
            assert!(!arguments.is_empty(), "{}", metadata.name);
            assert!(
                arguments.iter().all(|argument| argument["value_type"]
                    .as_str()
                    .is_some_and(|kind| !kind.is_empty())),
                "{}",
                metadata.name
            );
        }
    }

    #[test]
    fn schemas_report_semantic_enums_globals_and_environment() {
        let login = schema(Some("auth.login")).expect("login schema");
        let method = schema_argument(&login, "method");
        assert_eq!(method["value_type"], "enum");
        assert_eq!(
            method["possible_values"],
            serde_json::json!(["bearer", "client-credentials", "credential-process"])
        );

        let request = schema(Some("api.request")).expect("request schema");
        let service = schema_argument(&request, "service");
        assert_eq!(service["value_type"], "enum");
        assert!(
            service["possible_values"]
                .as_array()
                .expect("service values")
                .contains(&Value::String("physical-config".to_owned()))
        );
        assert_eq!(
            schema_argument(&request, "method")["value_type"],
            "http_method"
        );
        assert!(
            request["environment"]
                .as_array()
                .expect("request environment")
                .contains(&Value::String("RELTIO_CONFIRM_TENANT".to_owned()))
        );

        let entity_get = schema(Some("entity.get")).expect("entity get schema");
        assert_eq!(
            schema_argument(&entity_get, "time")["value_type"],
            "unsigned_integer"
        );

        let entity_scan = schema(Some("entity.scan")).expect("entity scan schema");
        assert_eq!(
            entity_scan["resume_identity_fields"],
            serde_json::json!([
                "schema_version",
                "endpoint_id",
                "profile",
                "environment",
                "tenant",
                "filter_hash",
                "query_hash",
                "page_size",
                "data_service_url",
                "cli_version"
            ])
        );

        let doctor = schema(Some("doctor")).expect("doctor schema");
        assert_eq!(doctor["consistency"], "dynamic");

        let profile = schema(Some("profile.add")).expect("profile schema");
        assert_eq!(schema_argument(&profile, "environment")["global"], true);
        assert_eq!(schema_argument(&profile, "tenant")["global"], true);
        assert_eq!(
            schema_argument(&profile, "production")["value_type"],
            "boolean"
        );
        assert_eq!(
            schema_argument(&profile, "auth_method")["possible_values"],
            serde_json::json!(["bearer", "client-credentials"])
        );
        assert!(
            schema_argument(&profile, "production")["possible_values"]
                .as_array()
                .expect("boolean values")
                .is_empty()
        );

        for metadata in all() {
            let value = schema(Some(metadata.name)).expect("schema");
            assert!(
                value["environment"]
                    .as_array()
                    .expect("command environment")
                    .contains(&Value::String("RELTIO_OUTPUT".to_owned())),
                "{}",
                metadata.name
            );
            assert_eq!(
                schema_argument(&value, "output")["environment"],
                "RELTIO_OUTPUT",
                "{}",
                metadata.name
            );
        }
    }

    fn schema_argument<'a>(schema: &'a Value, name: &str) -> &'a Value {
        schema["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|argument| argument["name"] == name)
            .unwrap_or_else(|| panic!("{} has no {name} argument", schema["name"]))
    }

    fn collect_leaves(command: &Command, prefix: &str, leaves: &mut BTreeSet<String>) {
        for child in command.get_subcommands() {
            let name = if prefix.is_empty() {
                child.get_name().to_owned()
            } else {
                format!("{prefix}.{}", child.get_name())
            };
            if child.get_subcommands().next().is_none() {
                leaves.insert(name);
            } else {
                collect_leaves(child, &name, leaves);
            }
        }
    }
}
