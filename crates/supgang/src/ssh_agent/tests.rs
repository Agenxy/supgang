//! SSH-agent protocol and local integration tests.

use super::{
    Cursor, ExposedKey, FAILURE, IDENTITIES_ANSWER, MAX_MESSAGE_BYTES, REQUEST_IDENTITIES, SIGN_REQUEST, SIGN_RESPONSE,
    append_string, identities_response, respond, serve_until,
};
use crate::vault::{
    self,
    tests::{Software, state_directory},
};
use crate::{
    device_key::custody::SealedKey,
    vault::{Enclave, VaultError},
};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

fn exposed(name: &str, public: [u8; 32]) -> ExposedKey {
    ExposedKey {
        name: name.to_owned(),
        public,
        blob: vault::ssh_key_blob(&public),
        comment: format!("{name}@supgang").into_bytes(),
    }
}

struct SlowEnclave {
    calls: AtomicUsize,
    blocked: AtomicBool,
    release: (Mutex<bool>, Condvar),
}

impl SlowEnclave {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
            release: (Mutex::new(false), Condvar::new()),
        }
    }

    fn unblock(&self) {
        let (lock, condition) = &self.release;
        let mut ready = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *ready = true;
        drop(ready);
        condition.notify_all();
    }
}

impl Enclave for SlowEnclave {
    fn generate(&self) -> Result<(SealedKey, [u8; 33]), VaultError> {
        Software.generate()
    }

    fn generate_presence(&self) -> Result<(SealedKey, [u8; 33]), VaultError> {
        Software.generate_presence()
    }

    fn agree(&self, sealed: &SealedKey, peer: &[u8; 33]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
            self.blocked.store(true, Ordering::SeqCst);
            let (lock, condition) = &self.release;
            let mut ready = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*ready {
                ready = condition.wait(ready).unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            drop(ready);
        }
        Software.agree(sealed, peer)
    }
    fn agree_presence(
        &self,
        sealed: &SealedKey,
        peer: &[u8; 33],
        _reason: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        self.agree(sealed, peer)
    }
}

#[test]
fn identity_response_has_exact_ssh_wire_bytes() {
    let key = exposed("login", [0x42; 32]);
    let response = identities_response(&[key]);
    let mut golden = vec![IDENTITIES_ANSWER, 0, 0, 0, 1];
    golden.extend_from_slice(&[0, 0, 0, 51, 0, 0, 0, 11]);
    golden.extend_from_slice(b"ssh-ed25519");
    golden.extend_from_slice(&[0, 0, 0, 32]);
    golden.extend_from_slice(&[0x42; 32]);
    golden.extend_from_slice(&[0, 0, 0, 13]);
    golden.extend_from_slice(b"login@supgang");
    assert_eq!(response, golden);
}

#[test]
fn only_selected_ssh_key_signs_and_unknown_messages_fail() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, state) = state_directory()?;
    let public = vault::ssh_keygen(&state, &Software, "login", "")?;
    let key = exposed("login", public.public_key);
    assert_eq!(
        respond(&[0], &state, std::slice::from_ref(&key), &Software),
        vec![FAILURE]
    );
    assert_eq!(
        respond(&[27], &state, std::slice::from_ref(&key), &Software),
        vec![FAILURE]
    );
    assert_eq!(
        respond(&[REQUEST_IDENTITIES, 0], &state, std::slice::from_ref(&key), &Software),
        vec![FAILURE]
    );
    let mut request = vec![SIGN_REQUEST];
    assert!(append_string(&mut request, &key.blob));
    assert!(append_string(&mut request, b"challenge"));
    request.extend_from_slice(&0_u32.to_be_bytes());
    let reply = respond(&request, &state, std::slice::from_ref(&key), &Software);
    assert_eq!(reply.first(), Some(&SIGN_RESPONSE));
    let mut reply_body = Cursor(reply.get(1..).ok_or("missing reply body")?);
    let signed = reply_body.string().ok_or("missing signature blob")?;
    assert_eq!(reply_body.0, b"");
    let mut signature = Cursor(signed);
    assert_eq!(signature.string(), Some(b"ssh-ed25519".as_slice()));
    assert_eq!(signature.string().ok_or("missing raw signature")?.len(), 64);
    assert_eq!(signature.0, b"");
    let mut flagged = request.clone();
    *flagged.last_mut().ok_or("empty request")? = 1;
    assert_eq!(
        respond(&flagged, &state, std::slice::from_ref(&key), &Software),
        vec![FAILURE]
    );
    assert_eq!(respond(&request, &state, &[], &Software), vec![FAILURE]);
    let mut malformed = request;
    malformed.push(0);
    assert_eq!(respond(&malformed, &state, &[key], &Software), vec![FAILURE]);
    Ok(())
}

#[tokio::test]
async fn oversized_frame_gets_failure_and_connection_closes() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, state) = state_directory()?;
    let socket = state.join("agent.sock");
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let state_for_server = state.clone();
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        serve_until(&state_for_server, &socket_for_server, &[], Arc::new(Software), async {
            let _result = stop_receiver.await;
        })
        .await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut stream = tokio::net::UnixStream::connect(&socket).await?;
    assert_eq!(fs::metadata(&socket)?.permissions().mode() & 0o777, 0o600);
    stream
        .write_all(&u32::try_from(MAX_MESSAGE_BYTES + 1)?.to_be_bytes())
        .await?;
    let mut reply = [0_u8; 5];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply, [0, 0, 0, 1, FAILURE]);
    let mut tail = [0_u8; 1];
    assert_eq!(stream.read(&mut tail).await?, 0);
    let _result = stop_sender.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn agent_refuses_a_context_signing_key() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, state) = state_directory()?;
    vault::keygen(&state, &Software, "artifact", "")?;
    let socket = state.join("agent.sock");
    let result = serve_until(&state, &socket, &["artifact".to_owned()], Arc::new(Software), async {}).await;
    assert!(matches!(result, Err(super::AgentError::KeyUnavailable)));
    assert!(!socket.exists());
    Ok(())
}

#[tokio::test]
async fn slow_sign_does_not_block_other_clients_or_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, state) = state_directory()?;
    let public = vault::ssh_keygen(&state, &Software, "login", "")?;
    let socket = state.join("agent.sock");
    let enclave = Arc::new(SlowEnclave::new());
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let state_for_server = state.clone();
    let socket_for_server = socket.clone();
    let server_enclave = enclave.clone();
    let mut server = tokio::spawn(async move {
        serve_until(
            &state_for_server,
            &socket_for_server,
            &["login".to_owned()],
            server_enclave,
            async {
                let _result = stop_receiver.await;
            },
        )
        .await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut slow = tokio::net::UnixStream::connect(&socket).await?;
    let mut sign = vec![SIGN_REQUEST];
    assert!(append_string(&mut sign, &vault::ssh_key_blob(&public.public_key)));
    assert!(append_string(&mut sign, b"challenge"));
    sign.extend_from_slice(&0_u32.to_be_bytes());
    slow.write_all(&u32::try_from(sign.len())?.to_be_bytes()).await?;
    slow.write_all(&sign).await?;
    for _ in 0..100 {
        if enclave.blocked.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let entered_slow_sign = enclave.blocked.load(Ordering::SeqCst);
    let mut fast = tokio::net::UnixStream::connect(&socket).await?;
    fast.write_all(&[0, 0, 0, 1, REQUEST_IDENTITIES]).await?;
    let mut header = [0_u8; 5];
    let identity_result = tokio::time::timeout(Duration::from_secs(1), fast.read_exact(&mut header)).await;
    let _result = stop_sender.send(());
    let shutdown_result = tokio::time::timeout(Duration::from_secs(1), &mut server).await;
    enclave.unblock();
    if shutdown_result.is_err() {
        let _result = server.await;
    }
    assert!(entered_slow_sign, "fake enclave was not blocked during sign");
    assert!(
        identity_result.is_ok_and(|result| result.is_ok()),
        "second client stalled behind slow sign"
    );
    assert_eq!(header[4], IDENTITIES_ANSWER);
    assert!(shutdown_result.is_ok(), "shutdown stalled behind slow sign");
    Ok(())
}

#[test]
fn openssh_sign_and_verify_with_supgang_agent() -> Result<(), Box<dyn std::error::Error>> {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        return Ok(());
    }
    let (_temporary, state) = state_directory()?;
    let public = vault::ssh_keygen(&state, &Software, "login", "")?;
    let socket = state.join("agent.sock");
    let public_file = state.join("login.pub");
    let message_file = state.join("message.txt");
    let allowed = state.join("allowed_signers");
    let mut public_stdout = Vec::new();
    let mut fingerprint_stderr = Vec::new();
    let status =
        crate::cli_vault::show_ssh_public("login", &public, false, &mut public_stdout, &mut fingerprint_stderr);
    assert!(status.is_ok());
    assert_eq!(public_stdout, format!("{}\n", public.line).into_bytes());
    assert_eq!(fingerprint_stderr, format!("{}\n", public.fingerprint).into_bytes());
    fs::write(&public_file, public_stdout)?;
    let fingerprint = Command::new("ssh-keygen").arg("-lf").arg(&public_file).output()?;
    assert!(fingerprint.status.success(), "OpenSSH refused redirected public stdout");
    assert_eq!(
        String::from_utf8(fingerprint.stdout)?.split_whitespace().nth(1),
        Some(public.fingerprint.as_str())
    );
    fs::write(&message_file, b"Supgang OpenSSH agent round trip\n")?;
    fs::write(&allowed, format!("tester {}\n", public.line))?;
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let state_for_server = state.clone();
    let socket_for_server = socket.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime
            .block_on(serve_until(
                &state_for_server,
                &socket_for_server,
                &["login".to_owned()],
                Arc::new(Software),
                async {
                    let _result = stop_receiver.await;
                },
            ))
            .map_err(|error| error.to_string())
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "SSH agent did not bind");
    let signed = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&public_file)
        .args(["-n", "file"])
        .arg(&message_file)
        .env("SSH_AUTH_SOCK", &socket)
        .output()?;
    assert!(
        signed.status.success(),
        "ssh-keygen -Y sign failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let sig_file = state.join("message.txt.sig");
    let mut verifier = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "tester", "-n", "file", "-s"])
        .arg(&sig_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    verifier
        .stdin
        .take()
        .ok_or("verifier stdin")?
        .write_all(&fs::read(&message_file)?)?;
    let verification = verifier.wait_with_output()?;
    assert!(
        verification.status.success(),
        "ssh-keygen -Y verify failed: {}",
        String::from_utf8_lossy(&verification.stderr)
    );
    assert!(String::from_utf8(verification.stdout)?.contains("Good"));
    let audit = fs::read_to_string(state.join("vault-audit.log"))?;
    assert!(audit.contains(" read login ssh-sign\n"));
    let _result = stop_sender.send(());
    assert!(server.join().map_err(|_| "server panic")?.is_ok());
    Ok(())
}
