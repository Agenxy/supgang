//! Supgang command-line entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    supgang_core::cli::run_from_env()
}
