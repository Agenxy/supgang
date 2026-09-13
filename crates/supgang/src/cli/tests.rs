use super::{reachability_check, run};

fn write_endpoints(path: &std::path::Path, listen: &str, kind: &str) -> Result<(), Box<dyn std::error::Error>> {
    let document = serde_json::json!({
        "listen": listen,
        "candidates": [{"kind": kind, "address": listen}],
    });
    crate::artifact::write_new(path, serde_json::to_string(&document)?.as_bytes(), 4 * 1024)?;
    Ok(())
}

fn run_json(arguments: &[&str]) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = run(arguments.iter().copied(), &mut output, &mut error);
    if code != std::process::ExitCode::SUCCESS {
        return Err(format!("command {arguments:?} failed: {}", String::from_utf8_lossy(&error)).into());
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
fn an_unrelated_active_peer_does_not_verify_a_router_report() {
    let router_only = ("mapped-unverified".to_owned(), "gateway-reported-address".to_owned(), 1);
    let check = reachability_check(Some(&router_only));
    assert_eq!(check.status, "warning");
    assert!(check.detail.contains("has not proved that it works"));

    let peer_reported = ("mapped-unverified".to_owned(), "peer-reported-address".to_owned(), 1);
    let check = reachability_check(Some(&peer_reported));
    assert_eq!(check.status, "warning");
    assert!(check.detail.contains("has not proved a return path"));
}

#[test]
fn background_service_help_uses_plain_lifecycle_commands() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = run(["supgang", "service", "--help"], &mut output, &mut error);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert!(error.is_empty());
    let help = std::str::from_utf8(&output)?;
    for command in ["install", "status", "start", "stop", "restart", "uninstall"] {
        assert!(help.contains(command));
    }
    assert!(help.contains("Keep Supgang running in the background"));

    output.clear();
    let code = run(["supgang", "service", "install", "--help"], &mut output, &mut error);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let install_help = String::from_utf8(output)?;
    assert!(install_help.contains("--endpoints <PATH>"));
    assert!(install_help.contains("--anchor"));
    Ok(())
}

#[test]
fn endpoint_addresses_are_not_accepted_as_command_arguments() -> Result<(), Box<dyn std::error::Error>> {
    for command in ["publish", "run", "anchor"] {
        let mut output = Vec::new();
        let mut error = Vec::new();
        let code = run(["supgang", command, "--help"], &mut output, &mut error);
        assert_eq!(code, std::process::ExitCode::SUCCESS);
        let help = String::from_utf8(output)?;
        for forbidden in ["--local", "--direct", "--listen", "IP:PORT"] {
            assert!(!help.contains(forbidden), "{command} help exposed {forbidden}");
        }
        assert!(help.contains("--endpoints <PATH>"));
    }
    Ok(())
}

#[test]
fn anchor_help_describes_a_user_owned_meeting_point() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = run(["supgang", "anchor", "--help"], &mut output, &mut error);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert!(error.is_empty());
    assert!(String::from_utf8(output)?.contains("user-owned meeting point"));
    Ok(())
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
    assert_eq!(init.get("schema"), Some(&serde_json::json!("supgang.init/v2")));
    assert!(
        init.get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| !name.is_empty())
    );
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
    assert_eq!(status.get("schema"), Some(&serde_json::json!("supgang.status/v4")));
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
    let expected_node = request_output
        .get("node_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("request node id missing")?;
    let expected_hive = initialized
        .get("hive_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("founder hive id missing")?;
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
        "--expect-node",
        expected_node,
    ])?;
    let join_result = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "join",
        bundle_text,
        "--expect-hive",
        expected_hive,
    ])?;

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
    let endpoints = directory.path().join("joiner.endpoints.json");
    let founder_text = founder.to_str().ok_or("founder path was not UTF-8")?;
    let joiner_text = joiner.to_str().ok_or("joiner path was not UTF-8")?;
    let request_text = request.to_str().ok_or("request path was not UTF-8")?;
    let bundle_text = bundle.to_str().ok_or("bundle path was not UTF-8")?;
    let contact_text = contact.to_str().ok_or("contact path was not UTF-8")?;
    let endpoints_text = endpoints.to_str().ok_or("endpoint path was not UTF-8")?;

    let initialized = run_json(&["supgang", "--json", "--state-dir", founder_text, "init"])?;
    let requested = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "join-request",
        request_text,
    ])?;
    let expected_node = requested
        .get("node_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("request node id missing")?;
    let expected_hive = initialized
        .get("hive_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("founder hive id missing")?;
    run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        founder_text,
        "invite",
        request_text,
        bundle_text,
        "--expect-node",
        expected_node,
    ])?;
    run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "join",
        bundle_text,
        "--expect-hive",
        expected_hive,
    ])?;
    let renamed = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "name",
        "set",
        "HomeServer",
    ])?;
    assert_eq!(renamed.get("name"), Some(&serde_json::json!("HomeServer")));
    write_endpoints(&endpoints, "127.0.0.1:4433", "local")?;
    run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        joiner_text,
        "publish",
        contact_text,
        "--endpoints",
        endpoints_text,
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

    let named = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        founder_text,
        "resolve",
        "HomeServer",
    ])?;
    assert_eq!(named.get("node_id"), requested.get("node_id"));
    let tagged = run_json(&[
        "supgang",
        "--json",
        "--state-dir",
        founder_text,
        "tag",
        "HomeServer",
        "home",
    ])?;
    assert_eq!(tagged.get("schema"), Some(&serde_json::json!("supgang.peer-tag/v1")));
    assert_eq!(tagged.get("tag"), Some(&serde_json::json!("home")));
    let by_tag = run_json(&["supgang", "--json", "--state-dir", founder_text, "home"])?;
    assert_eq!(by_tag.get("schema"), Some(&serde_json::json!("supgang.peer-search/v2")));
    assert_eq!(
        by_tag
            .get("matches")
            .and_then(serde_json::Value::as_array)
            .and_then(|matches| matches.first())
            .and_then(|matched| matched.get("peer"))
            .and_then(|peer| peer.get("node_id")),
        requested.get("node_id")
    );
    let by_partial = run_json(&["supgang", "--json", "--state-dir", founder_text, "homes"])?;
    assert_eq!(
        by_partial
            .get("matches")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    let resolved_tag = run_json(&["supgang", "--json", "--state-dir", founder_text, "resolve", "home"])?;
    assert_eq!(resolved_tag.get("node_id"), requested.get("node_id"));
    assert_eq!(resolved_tag.get("tags"), Some(&serde_json::json!(["home"])));
    let listed = run_json(&["supgang", "--json", "--state-dir", founder_text])?;
    assert_eq!(listed.get("schema"), Some(&serde_json::json!("supgang.peers/v5")));
    assert!(
        listed
            .get("this_computer")
            .and_then(|computer| computer.get("name"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| !name.is_empty())
    );
    let row = listed
        .get("peers")
        .and_then(serde_json::Value::as_array)
        .and_then(|peers| peers.first())
        .ok_or("listed peer missing")?;
    assert_eq!(row.get("name"), Some(&serde_json::json!("HomeServer")));
    assert_eq!(row.get("tags"), Some(&serde_json::json!(["home"])));
    assert_eq!(
        row.get("addresses")
            .and_then(serde_json::Value::as_array)
            .and_then(|addresses| addresses.first())
            .and_then(|address| address.get("scope")),
        Some(&serde_json::json!("local"))
    );
    assert_human_fleet_output(founder_text)?;
    Ok(())
}

fn assert_human_fleet_output(founder_state: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut human = Vec::new();
    let mut human_error = Vec::new();
    assert_eq!(
        run(["supgang", "--state-dir", founder_state], &mut human, &mut human_error,),
        std::process::ExitCode::SUCCESS
    );
    let human = String::from_utf8(human)?;
    assert!(human.contains("this computer"));
    assert!(human.contains("HomeServer (home) ["));
    assert!(human.contains("no address can be tried from this network"));
    assert!(!human.contains("device-signed"));
    assert!(human.contains("supgang --help"));
    assert!(human_error.is_empty());

    let mut detailed = Vec::new();
    assert_eq!(
        run(
            ["supgang", "--state-dir", founder_state, "peers", "--all"],
            &mut detailed,
            &mut human_error,
        ),
        std::process::ExitCode::SUCCESS
    );
    let detailed = String::from_utf8(detailed)?;
    assert!(detailed.contains("127.0.0.1:4433"));
    assert!(detailed.contains("unavailable from this network"));
    assert!(detailed.contains("device-signed"));
    Ok(())
}
