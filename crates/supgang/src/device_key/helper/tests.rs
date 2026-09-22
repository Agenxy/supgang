use super::*;

#[test]
fn protocol_refusals_remain_distinct_and_framing_is_strict() {
    for (wire, reason) in [
        ("error no-hardware", UnavailableReason::NoHardware),
        (
            "error owner-declined-presence",
            UnavailableReason::OwnerDeclinedPresence,
        ),
        ("error refused -34018", UnavailableReason::HelperRefused(-34018)),
    ] {
        assert_eq!(parse_response(format!("{PROTOCOL} {wire}\n").as_bytes()), Err(reason));
    }
    for bytes in [
        b"supgang/custody/v2 ok probe\n".as_slice(),
        b"supgang/custody/v1 ok probe\nextra\n",
        b"supgang/custody/v1 ok probe",
        b"supgang/custody/v1 ok probe\r\n",
    ] {
        assert_eq!(parse_response(bytes), Err(UnavailableReason::HelperProtocol));
    }
}

#[test]
fn pipe_transport_bounds_time_and_output_and_detects_missing_helper() -> Result<(), Box<dyn std::error::Error>> {
    let timeout = Duration::from_secs(2);
    // Native utilities exercise the pipes without shell scripts or hardware.
    let response = exchange(
        Path::new("/usr/bin/tee"),
        "ok probe supgang-secure-enclave ready",
        timeout,
    )?;
    assert_eq!(response.as_str(), "probe supgang-secure-enclave ready");
    assert_eq!(
        exchange(Path::new("/supgang-missing-helper"), "probe", timeout),
        Err(UnavailableReason::HelperMissing)
    );
    assert_eq!(
        exchange(Path::new("/usr/bin/yes"), "probe", timeout),
        Err(UnavailableReason::HelperProtocol)
    );
    let start = Instant::now();
    assert_eq!(
        exchange_command(Command::new("/bin/sleep").arg("5"), "probe", Duration::from_millis(50)),
        Err(UnavailableReason::HelperTimedOut)
    );
    assert!(start.elapsed() < timeout);
    Ok(())
}
