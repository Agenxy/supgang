use super::{classify, disabled_field, launchd_field, systemd_field, version_note};

#[test]
fn launchd_status_reads_only_its_own_fields_not_nested_pids_or_states() {
    let text = "gui/501/org.agenxy.supgang = {\n state = running\n inherited = {\n pid = 999\n state = stopped\n }\n pid = 42\n program = /safe/supgang\n}\n";
    assert_eq!(launchd_field(text, "pid"), Some("42"));
    assert_eq!(launchd_field(text, "state"), Some("running"));
    assert_eq!(launchd_field(text, "program"), Some("/safe/supgang"));
    assert_eq!(launchd_field("job = {\n nested = {\n pid = 999\n }\n}\n", "pid"), None);
    assert_eq!(launchd_field("job = {\n pid = 1\n pid = 2\n}\n", "pid"), None);
}

#[test]
fn launchd_disabled_parser_uses_the_exact_owner_label() -> Result<(), Box<dyn std::error::Error>> {
    let text = "disabled services = {\n \"org.agenxy.supgang.other\" => true\n \"org.agenxy.supgang\" => false\n}\n";
    assert!(!disabled_field(text, "org.agenxy.supgang")?);
    assert!(disabled_field(
        &text.replace("=> false", "=> true"),
        "org.agenxy.supgang"
    )?);
    assert!(!disabled_field("disabled services = {\n}\n", "org.agenxy.supgang")?);
    assert!(disabled_field(
        "disabled services = {\n \"org.agenxy.supgang\" => disabled\n}\n",
        "org.agenxy.supgang"
    )?);
    assert!(!disabled_field(
        "disabled services = {\n \"org.agenxy.supgang\" => enabled\n}\n",
        "org.agenxy.supgang"
    )?);
    assert!(
        disabled_field(
            "disabled services = {\n \"org.agenxy.supgang\" => perhaps\n}\n",
            "org.agenxy.supgang"
        )
        .is_err()
    );
    assert!(
        disabled_field(
            "disabled services = {\n \"org.agenxy.supgang\" => true\n \"org.agenxy.supgang\" => false\n}\n",
            "org.agenxy.supgang"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn systemd_status_reads_exact_flat_properties_not_embedded_fields() {
    let text =
        "ExecStart={ MainPID=999 ; ActiveState=failed }\nMainPID=42\nActiveState=active\nUnitFileState=disabled\n";
    assert_eq!(systemd_field(text, "MainPID"), Some("42"));
    assert_eq!(systemd_field(text, "ActiveState"), Some("active"));
    assert_eq!(systemd_field(text, "UnitFileState"), Some("disabled"));
    assert_eq!(systemd_field("MainPID=1\nMainPID=2\n", "MainPID"), None);
}

#[test]
fn status_distinguishes_installed_stopped_foreign_running_and_owner_disabled() {
    let mut report = super::super::report("launchd", true, false, false);
    classify(&mut report, false, false);
    assert_eq!(report.state, "stopped");
    report.observation.socket_pid = Some(42);
    classify(&mut report, false, false);
    assert_eq!(report.state, "running-outside-manager");
    assert!(report.running);
    classify(&mut report, false, true);
    assert_eq!(report.state, "disabled-by-owner");
    assert!(report.running);
}

#[test]
fn supervisor_and_payload_pids_are_not_falsely_reported_as_the_same_process() {
    let mut report = super::super::report("launchd", true, true, true);
    report.observation.manager_pid = Some(41);
    report.observation.socket_pid = Some(42);
    classify(&mut report, true, false);
    assert_eq!(
        report.observation.process_relationship,
        "different-pids-ownership-unverified"
    );
    report.observation.socket_parent_pid = Some(41);
    classify(&mut report, true, false);
    assert_eq!(report.observation.process_relationship, "supervisor-child");
    assert_eq!(report.state, "running");
    report.observation.socket_parent_pid = Some(99);
    classify(&mut report, true, false);
    assert_eq!(report.state, "running-outside-manager");
}

#[test]
fn an_older_or_unversioned_service_names_the_mismatch_and_refresh_remedy() -> Result<(), Box<dyn std::error::Error>> {
    for version in ["", "0.1.0"] {
        let note = version_note(version).ok_or("missing mismatch")?;
        assert!(note.contains("versions differ"));
        assert!(note.contains("supgang service refresh"));
    }
    assert_eq!(version_note(crate::VERSION), None);
    Ok(())
}
