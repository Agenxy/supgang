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
    applies_on: &'static str,
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
        applies_on: "next-service-start",
    };
    if json {
        render_json(&result, output, error)
    } else if writeln!(
        output,
        "Saved peer address history: {}\nRestart the service to apply saved settings.",
        result.address_history
    )
    .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}
