# Supgang product identity

Supgang is the product name. Agenxy is its publisher. Product names are not
derived from build output filenames, dependency defaults, hostnames or account
names. Computer names in the fleet remain owner-controlled device names.

| Surface | Identity |
| --- | --- |
| Command and executable | `supgang` |
| macOS display name | Supgang |
| macOS signed executable | `org.agenxy.supgang.runtime` |
| macOS login service | `org.agenxy.supgang` |
| macOS boot service | `org.agenxy.supgang.<owner uid>` |
| Linux user service | `supgang.service` |
| Linux service description | Supgang peer address discovery |
| Linux journal identifier | `supgang` |
| MCP server | Supgang, `org.agenxy.supgang` |
| Transport certificate subject | Supgang peer transport |
| Blocking worker threads | `supgang-io`, `supgang-mcp`, `supgang-update` |

The macOS executable embeds its product name, signing identifier, release,
copyright and local-network permission explanation before signing. The exact
SemVer release, including its prerelease suffix, is `SupgangReleaseVersion`;
the platform version fields contain the numeric version. The executable test
extracts the actual Mach-O metadata section and validates it with Apple's parser.
No Apple team identifier or notarization status is fabricated.

## Existing installations

The first service start or offline contact publication replaces a version-one
transport identity with a product-named certificate stored in format two. It
does not delete hive membership, the device signing key, settings or peer history.
It does change the transport certificate pin. An existing connected peer can
learn the new signed contact; simultaneously disconnected peers may need fresh
signed contacts carried between them before they reconnect.

The migration takes an exclusive transport lock, validates the old identity,
writes and synchronizes an owner-only replacement, and renames it atomically.
Corruption, unsafe permissions and lock contention do not authorize replacement.
Read-only loads never migrate. Publication acquires mutable state ownership
before loading or migrating the transport identity.

Older releases cannot read format two. This is an intentional development-time
cutover, not a transparent downgrade. Deploy and validate the new baseline on all
test peers before using it for subsequent unattended updates. Do not restore an
older binary and claim rollback acceptance against migrated state.

## Remaining visual acceptance

Embedded command metadata is not an application bundle or an icon installation.
Supgang-specific icon artwork and its native macOS and Linux packaging still need
to be completed and checked in the actual operating-system surfaces. An absent
icon is not an accepted final product state. The runtime naming checks do not
claim that Finder, permission dialogs or background-item settings have all been
visually verified.

The naming source follows Apple's
[single-file tool metadata guidance](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html).

## Verification, 2026-09-21

The complete repository gate passed on an isolated checkout: formatting,
warnings-fatal checks, 357 core tests, three ACL tests, two executable identity
tests, the repository policy test, 31 Python regressions, documentation and
registry-style package verification. The release executable's embedded plist
also passed Apple's parser.

The same owner-signed artifact was installed as command, supervisor and runtime
on two physical macOS computers. All six files matched and their signatures and
embedded names verified. Both live transport files use format two and the
Supgang peer transport subject and issuer. Membership identifiers and computer
names were unchanged. Fresh signed contacts were exchanged over a verified
owner SSH connection; both computers then had an authenticated neighbor in all
ten consecutive samples each. This is LAN cutover evidence, not WAN acceptance.
Linux unit rendering is covered by tests; this pass did not run a Linux service.
