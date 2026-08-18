# Dual-protocol MCP acceptance

Date: 2026-08-17 America/Los_Angeles

Scope: the installed Supgang MCP standard-I/O server on MacMarine and MacSolis, both supported MCP
protocol eras, adversarial bounds, and an actual Codex tool invocation. This record contains names
and counts but omits addresses and stable identifiers.

## Accepted artifact

- Version: `supgang 0.1.0`
- SHA-256: `0aa17db234881ef0b40df44a85464a405e1047851379123f62686459e5b9fe13`
- MacMarine path: `/Users/lael/.local/bin/supgang`
- MacSolis path: `/Users/dr.marbles/.local/bin/supgang`
- Both installed files produced the same hash.
- Both installed commands exposed `supgang mcp` and returned a successful 2026-07-28
  `server/discover` response.

## Protocol and security checks

The repository gate passed with 78 core tests and one repository-policy test. MCP-specific coverage
proved:

- the 2025-11-25 `initialize` and `notifications/initialized` lifecycle;
- the 2026-07-28 handshake-free `server/discover` and self-contained request metadata lifecycle;
- official `rmcp` 3.1.3 clients negotiating and listing tools in both eras;
- exactly three deterministic tools: `fleet`, `resolve`, and `status`;
- JSON Schema 2020-12 closed input and output schemas;
- read-only, non-destructive, idempotent, closed-world annotations on every tool;
- protocol errors for unknown revisions, missing 2026 client capabilities, extra arguments, and
  invalid selectors;
- silent fail-closed termination above the 16 KiB input ceiling;
- a 256 KiB response ceiling and 96 KiB structured-value ceiling;
- offline status and fleet reads leaving an interrupted journal tail unchanged and not creating a
  missing peer journal.

RustSec scanned all 201 locked dependency identities with warnings denied. Cargo-deny passed
advisories, bans, licences, and sources; its only duplicate report was the documented `syn` 2/3
build-time exception.

## Codex client acceptance

The installed command was registered as a global local server:

```text
codex mcp add supgang -- /Users/lael/.local/bin/supgang mcp
```

A fresh Codex process with 2026-07-28 MCP enabled was restricted to the Supgang server and instructed
to call `status` followed by `fleet`. Both tool calls completed. Its address-redacted final result
identified this computer as MacMarine, the running service, one peer named MacSolis, and eight
retained candidates for each computer.

The already-running Codex task did not hot-load the newly registered server; a fresh process was
required. A separate forced legacy-mode Codex run did not initialize this server, and that client did
not expose the protocol revision it proposed. This is not used as 2025-11-25 evidence. The exact
2025-11-25 acceptance comes from the official SDK client test and direct wire regression test.

## Boundary

This acceptance proves local MCP interoperability and two-machine artifact installation. It does
not make the MCP process a relay, prove any reported address reachable, attest that a peer is
uncompromised, or prevent the configured MCP client from transmitting returned addresses according
to that client's own privacy policy.
