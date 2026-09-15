use std::time::Instant;

use clap::CommandFactory;
use reltio_client::error::{ReltioError, Result};
use serde_json::{Value, json};

use crate::cli::{
    AgentSubcommand, Cli, CommandMetadataSubcommand, CompletionShell, CompletionSubcommand,
    SkillsSubcommand,
};
use crate::commands::Runtime;
use crate::metadata;
use crate::output::Meta;

const SKILLS: &[(&str, &str, &str)] = &[
    (
        "reltio-usage",
        "Core command selection, output, safety, and recovery contract",
        include_str!("../../../../skills/reltio-usage.md"),
    ),
    (
        "reltio-auth",
        "Authentication provider and secret-handling guidance",
        include_str!("../../../../skills/reltio-auth.md"),
    ),
    (
        "reltio-data",
        "Consistent entity reads, indexed search, and cursor scans",
        include_str!("../../../../skills/reltio-data.md"),
    ),
    (
        "reltio-operations",
        "Raw requests, API practices, production checks, and diagnostics",
        include_str!("../../../../skills/reltio-operations.md"),
    ),
];

pub async fn run_skills(runtime: &Runtime, command: SkillsSubcommand) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    let output_guard = runtime.environment_output_guard();
    match command {
        SkillsSubcommand::List => {
            let data = Value::Array(
                SKILLS
                    .iter()
                    .map(|(name, description, _)| {
                        json!({
                            "name": name,
                            "description": description,
                            "path": format!("embedded://skills/{name}.md")
                        })
                    })
                    .collect(),
            );
            let mut meta = Meta::new("skills.list");
            meta.elapsed_ms = started.elapsed().as_millis();
            runtime
                .emit_success(&data, &meta, deadline, &output_guard)
                .await
        }
        SkillsSubcommand::Get { name } => {
            let (_, _, contents) = skill(&name)?;
            runtime
                .emit_raw(contents.as_bytes(), false, deadline, &output_guard)
                .await
        }
        SkillsSubcommand::Path { name } => {
            skill(&name)?;
            runtime
                .emit_raw(
                    format!("embedded://skills/{name}.md\n").as_bytes(),
                    false,
                    deadline,
                    &output_guard,
                )
                .await
        }
    }
}

pub async fn run_agent(runtime: &Runtime, command: AgentSubcommand) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    match command {
        AgentSubcommand::Guide => {
            let (_, _, guide) = skill("reltio-usage")?;
            runtime
                .emit_raw(
                    guide.as_bytes(),
                    false,
                    deadline,
                    &runtime.environment_output_guard(),
                )
                .await
        }
    }
}

pub async fn run_command_metadata(
    runtime: &Runtime,
    command: CommandMetadataSubcommand,
) -> Result<()> {
    match command {
        CommandMetadataSubcommand::Schema { command } => {
            let started = Instant::now();
            let deadline = runtime.deadline_from(started)?;
            let data = metadata::schema(command.as_deref())?;
            let mut meta = Meta::new("command.schema");
            meta.elapsed_ms = started.elapsed().as_millis();
            runtime
                .emit_success(&data, &meta, deadline, &runtime.environment_output_guard())
                .await
        }
    }
}

pub async fn run_completion(runtime: &Runtime, command: CompletionSubcommand) -> Result<()> {
    let started = Instant::now();
    let deadline = runtime.deadline_from(started)?;
    match command {
        CompletionSubcommand::Generate { shell } => {
            let mut command = Cli::command();
            let mut output = Vec::new();
            match shell {
                CompletionShell::Bash => clap_complete::generate(
                    clap_complete::shells::Bash,
                    &mut command,
                    "reltio",
                    &mut output,
                ),
                CompletionShell::Elvish => clap_complete::generate(
                    clap_complete::shells::Elvish,
                    &mut command,
                    "reltio",
                    &mut output,
                ),
                CompletionShell::Fish => clap_complete::generate(
                    clap_complete::shells::Fish,
                    &mut command,
                    "reltio",
                    &mut output,
                ),
                CompletionShell::PowerShell => clap_complete::generate(
                    clap_complete::shells::PowerShell,
                    &mut command,
                    "reltio",
                    &mut output,
                ),
                CompletionShell::Zsh => clap_complete::generate(
                    clap_complete::shells::Zsh,
                    &mut command,
                    "reltio",
                    &mut output,
                ),
            }
            runtime
                .emit_raw(
                    &output,
                    false,
                    deadline,
                    &runtime.environment_output_guard(),
                )
                .await
        }
    }
}

fn skill(name: &str) -> Result<(&'static str, &'static str, &'static str)> {
    SKILLS
        .iter()
        .copied()
        .find(|(candidate, _, _)| *candidate == name)
        .ok_or_else(|| {
            ReltioError::usage(
                "skill_not_found",
                format!("embedded skill {name:?} does not exist"),
            )
        })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn shipped_reltio_examples_parse_with_the_current_command_tree() {
        let documents = [
            include_str!("../../../../README.md"),
            include_str!("../../../../docs/quickstart.md"),
            include_str!("../../../../docs/authentication.md"),
            include_str!("../../../../docs/output-contract.md"),
            SKILLS[0].2,
            SKILLS[1].2,
            SKILLS[2].2,
            SKILLS[3].2,
        ];
        for document in documents {
            for command in bash_reltio_commands(document) {
                let arguments = shell_words(&command);
                if let Err(error) = Cli::try_parse_from(arguments) {
                    if !matches!(
                        error.kind(),
                        clap::error::ErrorKind::DisplayHelp
                            | clap::error::ErrorKind::DisplayVersion
                    ) {
                        panic!("example does not parse: {command}: {error}");
                    }
                }
            }
        }
    }

    fn bash_reltio_commands(document: &str) -> Vec<String> {
        let mut commands = Vec::new();
        let mut in_bash = false;
        let mut logical_line = String::new();
        for line in document.lines() {
            let trimmed = line.trim();
            if trimmed == "```bash" {
                in_bash = true;
                continue;
            }
            if in_bash && trimmed == "```" {
                in_bash = false;
                logical_line.clear();
                continue;
            }
            if !in_bash || trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !logical_line.is_empty() {
                logical_line.push(' ');
            }
            logical_line.push_str(trimmed.trim_end_matches('\\').trim_end());
            if trimmed.ends_with('\\') {
                continue;
            }
            if let Some(offset) = logical_line.find("reltio ") {
                let mut command = logical_line[offset..].to_owned();
                if let Some(redirect) = command.find(" > ") {
                    command.truncate(redirect);
                }
                commands.push(command);
            }
            logical_line.clear();
        }
        commands
    }

    fn shell_words(command: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut current = String::new();
        let mut quote = None;
        let mut escaped = false;
        for character in command.chars() {
            if escaped {
                current.push(character);
                escaped = false;
                continue;
            }
            if character == '\\' && quote != Some('\'') {
                escaped = true;
                continue;
            }
            if matches!(character, '\'' | '"') {
                if quote == Some(character) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(character);
                } else {
                    current.push(character);
                }
                continue;
            }
            if character.is_whitespace() && quote.is_none() {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            } else {
                current.push(character);
            }
        }
        assert!(quote.is_none(), "unterminated quote in {command}");
        assert!(!escaped, "trailing escape in {command}");
        if !current.is_empty() {
            words.push(current);
        }
        words
    }
}
