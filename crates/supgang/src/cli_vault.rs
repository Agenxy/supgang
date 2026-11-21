//! The `vault` commands: store, list, use and remove sealed secrets.
//!
//! Secrets travel only on stdin, a child's environment or a pipe: never in
//! argv, a URL, a log line or terminal output.

use std::{
    ffi::OsString,
    io::{self, IsTerminal, Read, Write},
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::Path,
    process::{Command, ExitCode, Stdio},
    time::{Duration, Instant},
};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    cli::{render_error, render_json},
    cli_args::VaultCommand,
    vault::{self, AgentPolicy, MAX_SECRET_BYTES, SecureEnclave, Summary},
};

mod keygen;
mod lms;
mod migration;
mod remote_keygen;
mod remote_sign;
pub use remote_sign::sign_remote;

const MAX_ENV_SECRETS: usize = 16;

#[derive(Debug, Serialize)]
struct SecretOutput {
    name: String,
    note: String,
    stored_at: u64,
    bytes: usize,
    kind: &'static str,
    fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_creator: Option<crate::ids::NodeId>,
}

impl From<Summary> for SecretOutput {
    fn from(summary: Summary) -> Self {
        Self {
            name: summary.name,
            note: summary.note,
            stored_at: summary.stored_at,
            bytes: summary.bytes,
            kind: summary.kind,
            fingerprint: summary.fingerprint,
            remote_creator: summary.remote_creator,
        }
    }
}

#[derive(Debug, Serialize)]
struct ListOutput {
    schema: &'static str,
    status: &'static str,
    custody: &'static str,
    secrets: Vec<SecretOutput>,
}

#[derive(Debug, Serialize)]
struct ChangeOutput {
    schema: &'static str,
    status: &'static str,
    action: &'static str,
    secret: Option<SecretOutput>,
    name: String,
}

#[derive(Debug, Serialize)]
struct PublicKeyOutput {
    schema: &'static str,
    status: &'static str,
    name: String,
    public_key: String,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct SshPublicOutput {
    schema: &'static str,
    status: &'static str,
    name: String,
    public_key: String,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_creator: Option<crate::ids::NodeId>,
}

#[derive(Clone, Copy)]
enum KeygenKind {
    Signing,
    Ssh,
}

#[derive(Clone)]
struct KeygenOptions {
    kind: Option<KeygenKind>,
    json: bool,
    owner_terminal: bool,
    contexts: Vec<String>,
    members: Vec<crate::ids::NodeId>,
    remote: Option<String>,
}

#[derive(Debug, Serialize)]
struct SignatureOutput {
    schema: &'static str,
    status: &'static str,
    signature: String,
    fingerprint: String,
    context: String,
    message_sha256: String,
}

pub fn run(
    state_directory: &Path,
    command: VaultCommand,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = match command {
        VaultCommand::List => list(state_directory, json, output),
        VaultCommand::Keygen {
            signing,
            ssh,
            contexts,
            members,
            remote,
            name,
            note,
        } => keygen::with_terminal(
            state_directory,
            &name,
            &note,
            KeygenOptions {
                kind: match (signing.is_some(), ssh.is_some()) {
                    (true, false) => Some(KeygenKind::Signing),
                    (false, true) => Some(KeygenKind::Ssh),
                    _ => None,
                },
                json,
                owner_terminal: io::stdin().is_terminal(),
                contexts,
                members,
                remote,
            },
            output,
            error,
        ),
        VaultCommand::MigrateAgentPolicy {
            name,
            expect_fingerprint,
            contexts,
            members,
        } => migration::run(
            state_directory,
            &name,
            &expect_fingerprint,
            contexts,
            members,
            json,
            output,
        ),
        VaultCommand::PublicKey { name } => public_key(state_directory, &name, json, output),
        VaultCommand::SshPublicKey { name } => ssh_public_key(state_directory, &name, json, output, error),
        VaultCommand::LmsKeygen { name, note } => lms::keygen(state_directory, &name, &note, json, output, error),
        VaultCommand::LmsPublicKey { name } => lms::public_key(state_directory, &name, json, output),
        VaultCommand::LmsSign {
            name,
            package,
            output: target,
            first_signature,
            after_q,
        } => lms::sign(
            state_directory,
            &name,
            &package,
            &target,
            first_signature,
            after_q,
            json,
            output,
            error,
        ),
        VaultCommand::LmsAdvance { name, to_q, after_q } => {
            lms::advance(state_directory, &name, to_q, after_q, json, output, error)
        }
        VaultCommand::Add {
            name,
            note,
            replace,
            from_keychain,
            account,
        } => add(
            state_directory,
            &name,
            &note,
            replace,
            from_keychain.as_deref(),
            account.as_deref(),
            json,
            output,
            error,
        ),
        VaultCommand::Run { env, command } => run_with(state_directory, &env, &command),
        VaultCommand::Get { name } => get(state_directory, &name, output),
        VaultCommand::Remove { name } => remove(state_directory, &name, json, output),
    };
    result.unwrap_or_else(|message| render_error(json, &message, output, error))
}

fn list(state_directory: &Path, json: bool, output: &mut dyn Write) -> Result<ExitCode, String> {
    let secrets = vault::list(state_directory).map_err(|error| error.to_string())?;
    if json {
        let mut sink = Vec::new();
        let code = render_json(
            &ListOutput {
                schema: "supgang.vault/v1",
                status: "ok",
                custody: "secure-enclave",
                secrets: secrets.into_iter().map(SecretOutput::from).collect(),
            },
            output,
            &mut sink,
        );
        return Ok(code);
    }
    let written = if secrets.is_empty() {
        writeln!(output, "The vault is empty. Add a secret: supgang vault add NAME")
    } else {
        secrets.iter().try_for_each(|secret| {
            let fingerprint = secret
                .fingerprint
                .as_ref()
                .map_or(String::new(), |value| format!("  {value}"));
            let note = if secret.note.is_empty() {
                String::new()
            } else {
                format!("  {}", secret.note)
            };
            let creator = secret
                .remote_creator
                .map_or(String::new(), |id| format!("  remote by {id}"));
            writeln!(
                output,
                "{}  {}{}{}{}",
                secret.name, secret.kind, fingerprint, note, creator
            )
        })
    };
    written.map_err(|_| "could not write the vault listing".to_owned())?;
    Ok(ExitCode::SUCCESS)
}

fn public_key(state_directory: &Path, name: &str, json: bool, output: &mut dyn Write) -> Result<ExitCode, String> {
    if vault::list(state_directory)
        .map_err(|error| error.to_string())?
        .iter()
        .any(|entry| entry.name == name && entry.kind == "lms-sha256-h20-w1")
    {
        return lms::public_key(state_directory, name, json, output);
    }
    let identity = vault::public_key(state_directory, &SecureEnclave, name).map_err(|error| error.to_string())?;
    show_public(name, &identity, json, output)
}

fn ssh_public_key(
    state_directory: &Path,
    name: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    let identity = vault::ssh_public_key(state_directory, &SecureEnclave, name).map_err(|error| error.to_string())?;
    show_ssh_public(name, &identity, json, output, error)
}

pub fn show_ssh_public(
    name: &str,
    identity: &vault::SshPublic,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    if json {
        let mut sink = Vec::new();
        return Ok(render_json(
            &SshPublicOutput {
                schema: "supgang.ssh-public-key/v1",
                status: "ok",
                name: name.to_owned(),
                public_key: identity.line.clone(),
                fingerprint: identity.fingerprint.clone(),
                remote_creator: identity.remote_creator,
            },
            output,
            &mut sink,
        ));
    }
    writeln!(output, "{}", identity.line).map_err(|_| "could not write the SSH public key".to_owned())?;
    writeln!(error, "{}", identity.fingerprint).map_err(|_| "could not write the SSH fingerprint".to_owned())?;
    if let Some(creator) = identity.remote_creator {
        writeln!(error, "Created remotely by member {creator}")
            .map_err(|_| "could not write the SSH creator".to_owned())?;
    }
    Ok(ExitCode::SUCCESS)
}

fn show_public(
    name: &str,
    identity: &vault::SigningPublic,
    json: bool,
    output: &mut dyn Write,
) -> Result<ExitCode, String> {
    let public = hex::encode(identity.public_key);
    if json {
        let mut sink = Vec::new();
        return Ok(render_json(
            &PublicKeyOutput {
                schema: "supgang.vault-public-key/v1",
                status: "ok",
                name: name.to_owned(),
                public_key: public,
                fingerprint: identity.fingerprint.clone(),
            },
            output,
            &mut sink,
        ));
    }
    writeln!(output, "Public key: {public}\nFingerprint: {}", identity.fingerprint)
        .map_err(|_| "could not write the public key".to_owned())?;
    Ok(ExitCode::SUCCESS)
}

/// Signs a bounded digest with a sealed signing key.
pub fn sign(
    state_directory: &Path,
    name: &str,
    context: &str,
    sha256: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = (|| {
        vault::validate_context(context).map_err(|problem| problem.to_string())?;
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(vault::VaultError::InvalidSigningRequest.to_string());
        }
        let digest: [u8; 32] = hex::decode(sha256)
            .map_err(|_| vault::VaultError::InvalidSigningRequest.to_string())?
            .try_into()
            .map_err(|_| vault::VaultError::InvalidSigningRequest.to_string())?;
        let signed = vault::sign(state_directory, &SecureEnclave, name, context, &digest)
            .map_err(|problem| problem.to_string())?;
        let signature = hex::encode(signed.signature);
        let digest_hex = hex::encode(digest);
        if json {
            let mut sink = Vec::new();
            return Ok(render_json(
                &SignatureOutput {
                    schema: "supgang.signature/v1",
                    status: "ok",
                    signature,
                    fingerprint: signed.identity.fingerprint,
                    context: context.to_owned(),
                    message_sha256: digest_hex,
                },
                output,
                &mut sink,
            ));
        }
        writeln!(
            output,
            "Signature: {signature}\nFingerprint: {}\nContext: {context}\nSHA-256: {digest_hex}",
            signed.identity.fingerprint
        )
        .map_err(|_| "could not write the signature".to_owned())?;
        Ok(ExitCode::SUCCESS)
    })();
    result.unwrap_or_else(|message| render_error(json, &message, output, error))
}

#[expect(clippy::too_many_arguments, reason = "one flat command with its streams")]
fn add(
    state_directory: &Path,
    name: &str,
    note: &str,
    replace: bool,
    keychain: Option<&str>,
    account: Option<&str>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    vault::validate_name(name).map_err(|vault_error| vault_error.to_string())?;
    let secret = match keychain {
        Some(service) => from_keychain(service, account)?,
        None => from_stdin(error)?,
    };
    let summary = vault::add(state_directory, &SecureEnclave, name, note, &secret, replace)
        .map_err(|vault_error| vault_error.to_string())?;
    if json {
        let mut sink = Vec::new();
        return Ok(render_json(
            &ChangeOutput {
                schema: "supgang.vault/v1",
                status: "ok",
                action: if replace { "stored-or-replaced" } else { "stored" },
                name: summary.name.clone(),
                secret: Some(summary.into()),
            },
            output,
            &mut sink,
        ));
    }
    writeln!(
        output,
        "Stored {} in this Mac's vault. Use it with: supgang vault run --env VAR={} -- PROGRAM",
        summary.name, summary.name
    )
    .map_err(|_| "could not write the result".to_owned())?;
    Ok(ExitCode::SUCCESS)
}

fn remove(state_directory: &Path, name: &str, json: bool, output: &mut dyn Write) -> Result<ExitCode, String> {
    vault::remove(state_directory, name).map_err(|error| error.to_string())?;
    if json {
        let mut sink = Vec::new();
        return Ok(render_json(
            &ChangeOutput {
                schema: "supgang.vault/v1",
                status: "ok",
                action: "removed",
                secret: None,
                name: name.to_owned(),
            },
            output,
            &mut sink,
        ));
    }
    writeln!(output, "Removed {name} from this Mac's vault.").map_err(|_| "could not write the result".to_owned())?;
    Ok(ExitCode::SUCCESS)
}

fn get(state_directory: &Path, name: &str, output: &mut dyn Write) -> Result<ExitCode, String> {
    match vault::list(state_directory)
        .map_err(|problem| problem.to_string())?
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.kind)
    {
        Some("signing-ed25519") => return Err(vault::VaultError::SigningKeyNotExportable.to_string()),
        Some("ssh-ed25519") => return Err(vault::VaultError::SshKeyNotExportable.to_string()),
        _ => {}
    }
    if io::stdout().is_terminal() {
        return Err(format!(
            "refusing to print {name} to a terminal; pipe it into the program that needs it, or use supgang vault run"
        ));
    }
    let secret =
        vault::reveal(state_directory, &SecureEnclave, name, Some("get")).map_err(|error| error.to_string())?;
    output
        .write_all(&secret)
        .and_then(|()| output.flush())
        .map_err(|_| "could not write the secret to stdout".to_owned())?;
    Ok(ExitCode::SUCCESS)
}

/// Replaces this process with `command`, its environment carrying the secrets.
fn run_with(state_directory: &Path, pairs: &[String], command: &[OsString]) -> Result<ExitCode, String> {
    if pairs.len() > MAX_ENV_SECRETS {
        return Err(format!("at most {MAX_ENV_SECRETS} --env secrets per program"));
    }
    let (program, arguments) = command.split_first().ok_or("name the program to run after --")?;
    let purpose = program.to_string_lossy();
    let mut child = Command::new(program);
    child.args(arguments);
    for pair in pairs {
        let (variable, name) = pair
            .split_once('=')
            .ok_or_else(|| format!("--env takes VARIABLE=name, not {pair}"))?;
        if !valid_variable(variable) {
            return Err(format!("{variable} is not an environment variable name"));
        }
        let secret =
            vault::reveal(state_directory, &SecureEnclave, name, Some(&purpose)).map_err(|error| error.to_string())?;
        if secret.contains(&0) {
            return Err(format!(
                "{name} contains a NUL byte and cannot go in an environment variable"
            ));
        }
        child.env(variable, std::ffi::OsStr::from_bytes(&secret));
    }
    // `exec` returns only on failure; the secrets leave with this process image.
    let failure = child.exec();
    Err(format!("could not start {purpose}: {failure}"))
}

fn valid_variable(variable: &str) -> bool {
    let mut bytes = variable.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_uppercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && variable.len() <= 64
}

fn from_stdin(error: &mut dyn Write) -> Result<Zeroizing<Vec<u8>>, String> {
    let stdin = io::stdin();
    // Sized once, so growth never leaves a copy of the secret in freed memory.
    let mut secret = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 2));
    if stdin.is_terminal() {
        let _prompt = write!(
            error,
            "Paste the secret, then press Return (it will not be shown; Ctrl-C cancels): "
        );
        let _flush = error.flush();
        let read = {
            let _raw = RawTerminal::enter(&stdin)?;
            read_hidden_line(&stdin, &mut secret)
        };
        let _newline = writeln!(error);
        read?;
    } else {
        stdin
            .lock()
            .take(u64::try_from(MAX_SECRET_BYTES).unwrap_or(u64::MAX) + 2)
            .read_to_end(&mut secret)
            .map_err(|_| "could not read the secret from stdin")?;
        trim_newline(&mut secret);
    }
    Ok(secret)
}

/// Echo, line editing and terminal signals off, restored on every exit path.
/// Canonical mode would cut a pasted line at the kernel's line limit (about
/// 1 KiB on macOS), and Ctrl-C would kill the process with echo still off.
struct RawTerminal {
    saved: rustix::termios::Termios,
}

impl RawTerminal {
    fn enter(stdin: &io::Stdin) -> Result<Self, String> {
        use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
        let saved = tcgetattr(stdin).map_err(|_| "could not read terminal settings")?;
        let mut raw = saved.clone();
        raw.local_modes
            .remove(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG | LocalModes::IEXTEN);
        raw.special_codes[SpecialCodeIndex::VMIN] = 1;
        raw.special_codes[SpecialCodeIndex::VTIME] = 0;
        // Flush drops anything typed before the prompt: canonical mode may already
        // have cut it at its line limit, and storing that would truncate silently.
        tcsetattr(stdin, OptionalActions::Flush, &raw).map_err(|_| "could not hide terminal input")?;
        Ok(Self { saved })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        let _restore = rustix::termios::tcsetattr(io::stdin(), rustix::termios::OptionalActions::Now, &self.saved);
    }
}

/// Reads raw bytes up to Return: Backspace edits, Ctrl-C or Ctrl-D cancels.
fn read_hidden_line(stdin: &io::Stdin, secret: &mut Zeroizing<Vec<u8>>) -> Result<(), String> {
    let mut chunk = Zeroizing::new([0_u8; 256]);
    loop {
        let count = rustix::io::read(stdin, chunk.as_mut()).map_err(|_| "could not read the secret")?;
        if count == 0 {
            return Err("input ended before Return".to_owned());
        }
        for byte in chunk.get(..count).unwrap_or_default() {
            match *byte {
                b'\r' | b'\n' => return Ok(()),
                0x03 | 0x04 => return Err("cancelled; nothing was stored".to_owned()),
                0x08 | 0x7f => {
                    secret.pop();
                }
                other => {
                    if secret.len() > MAX_SECRET_BYTES {
                        return Err(format!("a secret must be at most {MAX_SECRET_BYTES} bytes"));
                    }
                    secret.push(other);
                }
            }
        }
    }
}

/// Reads one login-keychain password through Apple's `security` tool, so the
/// owner approves this one copy; the value arrives on a pipe, never in argv.
/// The owner has two minutes to answer the keychain's dialog.
fn from_keychain(service: &str, account: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
    const DEADLINE: Duration = Duration::from_mins(2);
    if !cfg!(target_os = "macos") {
        return Err("--from-keychain needs macOS".to_owned());
    }
    let mut command = Command::new("/usr/bin/security");
    command.args(["find-generic-password", "-s", service]);
    if let Some(account) = account {
        command.args(["-a", account]);
    }
    let mut child = command
        .arg("-w")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "could not start /usr/bin/security")?;
    let stdout = child.stdout.take().ok_or("could not read /usr/bin/security")?;
    // The pipe closes when the child exits or is killed, which ends this read.
    let reader = std::thread::spawn(move || {
        let mut secret = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 2));
        stdout
            .take(u64::try_from(MAX_SECRET_BYTES).unwrap_or(u64::MAX) + 2)
            .read_to_end(&mut secret)
            .map(|_| secret)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < DEADLINE => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) | Err(_) => {
                let _kill = child.kill();
                let _reap = child.wait();
                break None;
            }
        }
    };
    let read = reader.join().map_err(|_| "the keychain read failed")?;
    let Some(status) = status else {
        return Err("the keychain did not answer within two minutes; approve its dialog and retry".to_owned());
    };
    let mut secret = match read {
        Ok(secret) if status.success() => secret,
        _ => {
            return Err(format!(
                "the login keychain has no readable item for service {service}, or access was declined"
            ));
        }
    };
    if secret.len() > MAX_SECRET_BYTES + 1 {
        return Err(format!("that keychain item is longer than {MAX_SECRET_BYTES} bytes"));
    }
    trim_newline(&mut secret);
    Ok(secret)
}

fn trim_newline(secret: &mut Zeroizing<Vec<u8>>) {
    if secret.last() == Some(&b'\n') {
        secret.pop();
        if secret.last() == Some(&b'\r') {
            secret.pop();
        }
    }
}

#[cfg(test)]
mod tests;
