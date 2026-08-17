# Security policy

Supgang accepts packets, records, invitation bundles, local control requests, and filesystem state as hostile input.
The repository threat model is maintained in [docs/security/threat-model.md](docs/security/threat-model.md).

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could put users at immediate risk. Use GitHub's private security
advisory flow for `Agenxy/supgang`. If that is unavailable, contact an Agenxy maintainer privately before publishing
technical details.

Include the affected version, reachable attack path, expected invariant, observed behavior, and a minimal reproducer when
it is safe to share one. Never include real device keys, invitation bundles, peer addresses, or another person's data.

## Release rule

Supgang does not ship with a known exploitable vulnerability. A release is blocked until the finding is fixed and its
regression test passes on every supported target.
