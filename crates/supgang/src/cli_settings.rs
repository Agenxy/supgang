//! CLI rendering for bounded owner-only local settings.

use std::{io::Write, path::Path, process::ExitCode};

use serde::Serialize;

use crate::{
    cli::{ConfigCommand, render_error, render_json},
    settings::{self, Settings},
};

#[derive(Debug, Serialize)]
struct SettingsOutput {
    schema: &'static str,
    status: &'static str,
    address_history: usize,
    source: &'static str,
}

pub fn config(
    state_directory: &Path,
    command: Option<&ConfigCommand>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let (result, source) = match command {
        None => match settings::load(state_directory) {
            Ok(settings) => (settings, "settings-or-default"),
            Err(settings_error) => return render_error(json, &settings_error.to_string(), output, error),
        },
        Some(ConfigCommand::Set { address_history }) => {
            match settings::set_address_history(state_directory, usize::from(*address_history)) {
                Ok(settings) => (settings, "settings.toml"),
                Err(settings_error) => return render_error(json, &settings_error.to_string(), output, error),
            }
        }
    };
    render_settings(result, source, json, output, error)
}

fn render_settings(
    settings: Settings,
    source: &'static str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = SettingsOutput {
        schema: "supgang.settings/v1",
        status: "ok",
        address_history: settings.address_history(),
        source,
    };
    if json {
        render_json(&result, output, error)
    } else if writeln!(output, "Peer address history: {}", result.address_history).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}
