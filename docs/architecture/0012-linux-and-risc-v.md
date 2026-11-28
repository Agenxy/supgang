# ADR 0012: Linux and RISC-V as first-class platforms

Status: Accepted as direction. Phases 1 and 2 are dated commitments. Phase 3 is
a target date. Phase 4 has only a decision date.

Date: 2026-11-21

## Direction

The owner, 21 Nov 2026, quoted: "The goal of agenxy is to eventually be
completely and absolutely sovereign, so eventually everything we make must have
first class support for linux and riscv".

"Eventually" means this does not gate current macOS work. It does mean Linux
and riscv64 get a dated path, and no new design may assume Apple-only
primitives without naming the Linux equivalent or saying that there is none
yet.

## What first-class means

A platform is first-class when all of these hold:

- the complete quality gate runs on it in CI, and failures there block merges;
- a signed release artifact is published for it through the same release roles
  (ADR 0007);
- each milestone that changes the runtime or protocol is physically accepted on
  at least one real machine of that platform;
- `supgang --json doctor` states every property that is weaker there than on
  macOS. The main one is custody: a file-held key is labelled as file custody
  and is never presented as hardware custody.

## Where we are

The code is not macOS-only, and three pieces of Linux groundwork exist already:

- The quality gate runs on `ubuntu-24.04` (linux-amd64) in CI.
- `platform_service` renders and observes a systemd user unit (`systemd-user`).
- `CustodyKind::Tpm2` exists in the portable custody model, but no provider is
  built.

What is missing:

- arm64 and riscv64 CI;
- Linux release artifacts;
- a physical Linux member;
- any hardware custody provider off macOS.

The vault (ADR 0009) needs hardware custody, so it is macOS-only until phase 3.

## Phases

1. **CI on all three Linux architectures, merged by Fri 4 Dec 2026.**
   - linux-arm64: the full quality gate on GitHub-hosted `ubuntu-24.04-arm`.
   - linux-riscv64: build for `riscv64gc-unknown-linux-gnu`, and run the test
     suite under pinned qemu-user. Moving to a lab-hosted riscv64 runner is
     part of phase 2.
   - Toolchains and emulators are pinned and covered by `toolchain-drift`.
2. **First Linux member: the K3 (riscv64, Bianbu), physically accepted by Fri
   18 Dec 2026.**
   - Enrolment uses the existing join-request and invite flow; this ADR changes
     nothing about membership.
   - The member runs a systemd user service, the address plane, advertisements
     and tunnels.
   - Acceptance against the laptop covers revocation, plus `doctor` showing file
     custody.
   - The member has file custody, chosen explicitly. Its certificate records
     that custody label. Agent-key policies (ADR 0011) and certificate issuance
     refuse file-custody members unless the owner names one.
   - No vault is offered on file custody.
   - Signed linux-riscv64, linux-arm64 and linux-amd64 artifacts are produced
     and installed by the documented path. Publishing them publicly still needs
     the owner's word, as for any release.
3. **TPM 2.0 custody on linux-amd64 and linux-arm64, target Fri 26 Feb 2027.**
   - A `Tpm2` provider for the device identity and the vault's sealing key.
   - The owner-enrolled label is never attestation (ADR 0003).
   - Physical acceptance on one TPM machine.
   - Afterwards the vault and agent signing are available on Linux members with
     TPM custody.
4. **Hardware custody on RISC-V, decision by Wed 31 Mar 2027.**
   - Evaluate, in this order:
     - a discrete TPM 2.0 on SPI attached to the K3 or a successor board, which
       reuses phase 3;
     - a RISC-V TEE (OP-TEE or Keystone class) with sealed storage;
     - the key store in Agenxy's own silicon (the NC0 family), tracked with
       Agenxy Labs. That one has no date here.
   - The decision names the provider, its threat model and its implementation
     date.

## Boundaries

- KVM-class lab devices, which hold keyboard, video and mouse into a host,
  stay behind a sponsoring member and are not Supgang members. This applies
  even on Linux. A future guest shape for them belongs to ADR 0008.
- The macOS-only release-ceremony steps keep their current custody. They are
  Apple codesigning, and the LMS root (ADR 0010) on the Secure Enclave.
- No phase may weaken a gate on any platform to make another platform pass.

## Addendum: K3 self-hosted riscv64 CI runner (2026-11-28)

GitHub's official `actions/runner` does not publish a `linux-riscv64` release
binary. To run native `riscv64` CI on the lab K3 board without waiting for
upstream `.NET` and `actions/runner` packaging, `Agenxy/supgang` uses a pinned,
statically linked Go binary from
`ChristopherHX/github-act-runner` (`v0.13.0`, tag commit
`c934667526f602e5732e7072fcd53b36cf044e37`).

### Supply-chain pin and update policy

- Release archive (`binary-linux-riscv64.tar.gz`):
  - SHA-512: `7b74b58737f0f5ae062c46646c0e3a5befa5ec2c2f466604e6d77b48615ca81804f3363b0e079e37087b5be53172cf3144842b2da54d70ad74e86d4e23e8fc9b`
  - SHA-256: `be84104d5f8fcf12afe9fcc3541900f5ccd033687cfb9b32105208efa5a8234d`
- Extracted binary (`github-act-runner`; bundled `.sh` wrappers are never installed):
  - SHA-512: `83b124cb2067dc0b4eee68f2bd14ac135504c6f6581a910ebe1bb3d79ccfe2d5c89bc2649f89341361c70e7ed3a9166c14005044ceb779eaa22115a0a320f7c0`
  - SHA-256: `bbd2ef2dbefcfc18e48cc57412a3c8f8936d8249766288f4bb2d322e7e7714f0`
- Sigstore bundle (`binary-linux-riscv64.sigstore.json`) verified with `cosign verify-blob`
  binding OIDC issuer `https://token.actions.githubusercontent.com`, identity
  `https://github.com/ChristopherHX/github-act-runner/.github/workflows/build.yml@refs/heads/main`,
  repository `ChristopherHX/github-act-runner`, and workflow commit SHA
  `c934667526f602e5732e7072fcd53b36cf044e37`.
- Auto-update is disabled. Every upgrade requires a pull request that updates
  the pinned version, hashes, and Sigstore verification record here.

### Isolation and operational bounds

- Runs under a dedicated non-root Linux account (`gha-supgang`, mode `0700`
  home) with no access to `supgang`'s home directory, vault sockets, or any
  other bench account.
- Bounded by a root-owned systemd slice (`/etc/systemd/system/user-1006.slice.d/50-agenxy-runner.conf`:
  `CPUQuota=300%`, `MemoryHigh=7G`, `MemoryMax=8G`, `MemorySwapMax=0`,
  `TasksMax=2048`, `IOWeight=10`) plus `Nice=10` and `IOSchedulingClass=idle`
  on the user runner unit so shared K3 bench lanes are not starved.
- Runs only the non-required `riscv64 (k3)` job executing `ci-core` on
  `Agenxy/supgang` org-member pull requests (`head.repo.full_name ==
  github.repository && !head.repo.fork`) and pushes to `main`, backed by the
  repository's `all_external_contributors` fork-PR approval policy.
- Uses a clean per-job checkout directory wiped before and after every run, and
  prunes Cargo build caches whenever root disk usage reaches 70%.

### Removal

1. On the K3, stop and disable the runner systemd unit and remove the runner
   registration (`github-act-runner remove` or via GitHub repository
   Settings -> Actions -> Runners).
2. Remove the dedicated runner account, home directory, and systemd slice/unit
   on the K3.
3. Remove the `quality-core-riscv64` job from `.github/workflows/ci.yml` and
   note the retirement in this ADR.
