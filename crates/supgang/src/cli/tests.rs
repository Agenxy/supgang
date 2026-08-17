use super::run;

fn run_json(arguments: &[&str]) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = run(arguments.iter().copied(), &mut output, &mut error);
    if code != std::process::ExitCode::SUCCESS {
        return Err(format!("command failed: {}", String::from_utf8_lossy(&error)).into());
    }
    serde_json::from_slice(&output).map_err(Into::into)
}

#[test]
fn help_and_version_are_successful_stdout_commands() {
    for argument in ["--help", "--version"] {
        let mut output = Vec::new();
        let mut error = Vec::new();
        let code = run(["supgang", argument], &mut output, &mut error);
        assert_eq!(code, std::process::ExitCode::SUCCESS);
        assert!(!output.is_empty());
        assert!(error.is_empty());
    }
}

#[test]
fn json_lifecycle_has_stable_schemas_and_no_secret() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state");
    let state_text = state.to_str().ok_or("temporary path was not UTF-8")?;
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = run(
        ["supgang", "--json", "--state-dir", state_text, "init"],
        &mut output,
        &mut error,
    );
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let init: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(init.get("schema"), Some(&serde_json::json!("supgang.init/v1")));
    assert!(init.get("secret").is_none());

    output.clear();
    let code = run(
        ["supgang", "--json", "--state-dir", state_text, "doctor"],
        &mut output,
        &mut error,
    );
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let doctor: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(doctor.get("schema"), Some(&serde_json::json!("supgang.doctor/v1")));
    assert_eq!(doctor.get("public_dependencies"), Some(&serde_json::json!(0)));

    output.clear();
    let code = run(
        ["supgang", "--json", "--state-dir", state_text, "status"],
        &mut output,
        &mut error,
    );
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let status: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(status.get("schema"), Some(&serde_json::json!("supgang.status/v1")));
    assert_eq!(status.get("service"), Some(&serde_json::json!("stopped")));
    Ok(())
}

#[test]
fn offline_cli_join_round_trip_uses_recipient_generated_key() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let founder = directory.path().join("founder");
    let joiner = directory.path().join("joiner");
    let request = directory.path().join("join.request");
    let bundle = directory.path().join("join.bundle");
    let founder_text = founder.to_str().ok_or("founder path was not UTF-8")?;
    let joiner_text = joiner.to_str().ok_or("joiner path was not UTF-8")?;
    let request_text = request.to_str().ok_or("request path was not UTF-8")?;
    let bundle_text = bundle.to_str().ok_or("bundle path was not UTF-8")?;

    let initialized = run_json(&["supgang", "--json", "--state-dir", founder_text, "init"])?;
    let request_output = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "join-request",
        request_text,
    ])?;
    let invited = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        founder_text,
        "invite",
        request_text,
        bundle_text,
        "--days",
        "30",
    ])?;
    let join_result = run_json(&["supgang", "--json", "--state-dir", joiner_text, "join", bundle_text])?;

    assert_eq!(initialized.get("hive_id"), join_result.get("hive_id"));
    assert_eq!(request_output.get("node_id"), join_result.get("node_id"));
    assert_eq!(invited.get("node_id"), join_result.get("node_id"));
    assert!(request.exists());
    assert!(bundle.exists());
    Ok(())
}

#[test]
fn contact_import_and_explicit_resolution_are_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let founder = directory.path().join("founder");
    let joiner = directory.path().join("joiner");
    let request = directory.path().join("join.request");
    let bundle = directory.path().join("join.bundle");
    let contact = directory.path().join("joiner.contact");
    let founder_text = founder.to_str().ok_or("founder path was not UTF-8")?;
    let joiner_text = joiner.to_str().ok_or("joiner path was not UTF-8")?;
    let request_text = request.to_str().ok_or("request path was not UTF-8")?;
    let bundle_text = bundle.to_str().ok_or("bundle path was not UTF-8")?;
    let contact_text = contact.to_str().ok_or("contact path was not UTF-8")?;

    run_json(&["supgang", "--json", "--state-dir", founder_text, "init"])?;
    let requested = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "join-request",
        request_text,
    ])?;
    run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        founder_text,
        "invite",
        request_text,
        bundle_text,
    ])?;
    run_json(&["supgang", "--json", "--state-dir", joiner_text, "join", bundle_text])?;
    run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "publish",
        contact_text,
        "--local",
        "127.0.0.1:4433",
    ])?;
    run_json(&["supgang", "--json", "--state-dir", founder_text, "import", contact_text])?;
    let node_id = requested
        .get("node_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("node id missing")?;
    let resolved = run_json(&["supgang", "--json", "--state-dir", founder_text, "resolve", node_id])?;
    assert_eq!(resolved.get("node_id"), requested.get("node_id"));
    let address = resolved
        .get("candidates")
        .and_then(serde_json::Value::as_array)
        .and_then(|candidates| candidates.first())
        .and_then(|candidate| candidate.get("address"))
        .and_then(serde_json::Value::as_str)
        .ok_or("resolved address missing")?;
    assert_eq!(address, "127.0.0.1:4433");
    Ok(())
}
