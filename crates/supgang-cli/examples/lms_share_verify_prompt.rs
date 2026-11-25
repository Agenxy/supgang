//! Test-only PTY harness exercising the production `lms-share-ceremony`
//! medium verification passphrase retry loop. Never shipped in `supgang`.

#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(label) = args.next().and_then(|arg| arg.into_string().ok()) else {
        return ExitCode::from(2);
    };
    let Some(path) = args.next().map(PathBuf::from) else {
        return ExitCode::from(2);
    };
    supgang_core::cli::run_lms_share_verify_prompt_probe(&label, &path)
}
