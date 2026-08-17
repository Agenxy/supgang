# Supgang agent guide

Read the Agenxy [values](https://github.com/Agenxy/.github/blob/main/VALUES.md) and
[engineering standards](https://github.com/Agenxy/.github/blob/main/ENGINEERING.md) before changing this repository.

## Non-negotiable properties

- Apache-2.0 licensing.
- No telemetry, analytics, account, public discovery service, vendor relay, forced update, or remote kill switch.
- Strict mode must make no unexpected public connection.
- No unauthenticated input may change durable membership, revocation, sequence, generation, or endpoint state.
- No self-claimed address may be shown as independently observed reachability.
- Every input size, allocation, queue, retry loop, task, candidate set, and relay flow is bounded.
- No secret or peer address enters ordinary logs, command arguments, URLs, crash reports, or telemetry.
- Warnings and quality-gate failures are errors. Never weaken a gate to make a build pass.

## Development

The released artifact is one `supgang` binary. Keep protocol and durable-state types independent from the selected QUIC
implementation. Supgang-owned portable code forbids `unsafe`; isolate unavoidable platform bindings behind a small,
reviewed module.

Run the complete local gate with `cargo run --locked --package supgang-quality -- all` once that gate is available. Run
focused tests while iterating, then the complete gate before reporting completion.
