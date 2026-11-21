# Remote SSH keygen: merged build and staged physical install

Date: 2026-11-21 UTC. Scope: PR #44 and the signed binary built from its squash
merge `5f063d4a83900ca0f46eb887c2bdd0ae345a8286`. This is a partial physical
install record, not Q42 acceptance or a public release.

## Source and signed bytes

- PR #44's final head `8aeba9c` passed the complete local gate, 21/21 stages
  and zero skips: 568 core tests passed, four declared ignores, and package
  verification passed. Hosted macOS, Ubuntu, RustSec and dependency checks all
  passed. The independent lead review approved that head.
- `make install` built into a staging root from the merged `main` commit. The
  binary SHA-256 is `d918ad5a522fead45d09cc3deb709b465e60298cf09457556aaa8c29f07c8274`;
  the Secure Enclave helper SHA-256 is
  `c758537bdfaea786de42c430312e0f4c1e5d09a36d2db2226b45d949968c5731`.
  Both passed strict macOS code-signature verification. Outside the checkout,
  the staged command path, hashes, help, remote SSH keygen options and JSON
  doctor were checked.

## Host results

- Solis: the exact signed binary and helper were installed with verified
  backups of the previous alpha.21 files. `service refresh` completed. The
  active slot, protected service program and running process image have binary
  hash `d918ad5a…`; installed help and JSON doctor passed. Doctor reported a
  warning status, so this is not a clean doctor claim. Two peers were connected
  after the refresh.
- pro: the active alpha.18 slot has a valid ad hoc `cdhash` designated
  requirement, SHA-256 `57f7ee74…`. The old and new commands have the valid
  owner-certificate requirement, SHA-256 `81f2b5c3…`. A refresh from the new
  command refused this identity change before changing the running service.
  The old alpha.17 command and helper were restored to their original hashes;
  the alpha.18 service remained running. `vault list` had zero entries before
  this attempt. No remote SSH key was created. The one-way service identity
  transition is tracked in the follow-up PR.
- Laptop: the installed alpha.21 binary and root vault were left untouched.
  The launcher signing window requires the installed alpha.21 command through
  Tuesday 2026-11-24 09:00 PT. The new binary is staged only.

## Rollback boundary

Any vault write by the PR #44 binary upgrades that host's vault document to
v5. Alpha.21 cannot read a v5 vault. A prior binary backup alone is therefore
not a safe rollback after a vault write: use a separately verified v5-capable
replacement or restore a verified pre-write vault snapshot with its matching
audit state. In particular, remote Q42 key creation on pro will cross this
boundary. The laptop's staged new client may be used before Tuesday only for
`vault keygen --ssh ed25519 --remote pro`; hash its local vault before and after to prove no local
vault write occurred.

The pro ad hoc slot predates this install: the 2026-08-30 home-network root
cause record already observed an ad hoc content-addressed service slot. The
exact event that installed the alpha.18 ad hoc slot is not established by the
available evidence.
