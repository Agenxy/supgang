use super::{KeygenKind, KeygenOptions, keygen_with_terminal, sign, trim_newline, valid_variable};
use zeroize::Zeroizing;

#[test]
fn environment_names_are_conventional() {
    for good in ["GH_TOKEN", "_X", "A1"] {
        assert!(valid_variable(good), "{good}");
    }
    for bad in ["", "gh_token", "1A", "A-B", "A=B"] {
        assert!(!valid_variable(bad), "{bad}");
    }
}

#[test]
fn only_one_line_ending_is_removed() {
    let mut secret = Zeroizing::new(b"value\r\n".to_vec());
    trim_newline(&mut secret);
    assert_eq!(secret.as_slice(), b"value");
    let mut secret = Zeroizing::new(b"value\n\n".to_vec());
    trim_newline(&mut secret);
    assert_eq!(secret.as_slice(), b"value\n");
}

#[test]
fn keygen_without_terminal_refuses_before_accessing_state() {
    let mut output = Vec::new();
    let result = keygen_with_terminal(
        std::path::Path::new("/missing-state"),
        "launcher",
        "",
        KeygenOptions {
            kind: Some(KeygenKind::Signing),
            json: false,
            owner_terminal: false,
            contexts: Vec::new(),
            members: Vec::new(),
        },
        &mut output,
        &mut Vec::new(),
    );
    assert!(matches!(result, Err(message) if message.contains("interactive terminal")));
    assert_eq!(output, Vec::<u8>::new());
}

#[test]
fn malformed_digest_refuses_before_accessing_state() {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = sign(
        std::path::Path::new("/missing-state"),
        "launcher",
        "agenxy-launcher.install",
        &"g".repeat(64),
        false,
        &mut output,
        &mut error,
    );
    assert_ne!(status, std::process::ExitCode::SUCCESS);
    assert_eq!(output, Vec::<u8>::new());
    assert!(String::from_utf8(error).is_ok_and(|message| message.contains("64 hex characters")));
}
