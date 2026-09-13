# Operator safety core — offline, not an installer

This is an incremental implementation of the approved design's operator
package. `operator_core.py` implements byte-integrity checks for a future
pre-start guard and conservative rollback decisions. It has no command-line
entry point, process execution, network access, filesystem writes or service
operations. `operator_fs.py` adds a read-only Linux vendor-file reader; it has
no CLI, network, writes or service operations. `operator_bootstrap.py` loads the
fixed root-controlled manifest and public certificate. **No startup guard is installed
or operational on the VM.**

The candidate and existing contract remain unchanged. The core repeats the
reviewed pins deliberately; a CI test requires equality with `contract.json`.
Do not refresh either pin set automatically after a failed check.

## Implemented

`installed_checks(manifest_bytes)` accepts the pinned builder manifest only.
It rejects malformed/duplicate JSON, unrecognized pins, changed file inventory,
unsafe paths and invalid sizes. It translates the candidate to the installed
broker-client path and the packaged dependency files to their installed paths.
The original client is **not** an acceptable installed replacement. The primary
packaged Node binary and version header are added as pinned targets. The real
approved manifest yields 270 targets; deriving these paths does not read them.

`verify_installed_bytes(...)` rejects an unexpected package version or selected
Node path before calling its reader. It verifies sizes and hashes on two full
passes, including the candidate, dependencies and primary Node binary/header.
Missing/read-error/changed/oversized bytes fail with fixed diagnostic codes.
It returns `startup_authorized: false` even when byte checks pass.

The core's injected reader and version/runtime observations are not trusted
evidence merely because a caller supplies them. A caller can fake them; these
libraries are not a security boundary against their Python caller. Production
wiring must use fresh, independently verified observations, not owner-entered
paths or a saved JSON receipt. Native observations on the VM and execution of
packaged Linux Node are not claimed by these offline tests.

### Read-only native vendor reader

`operator_fs.InstalledReader(manifest_bytes)` derives its allowlist from
`installed_checks` without filesystem IO. Its callback accepts only exact listed
paths and their fixed limits. Each read requires Linux descriptor capabilities,
effective root and the named Dashboard service identity. There is no public
alternate-root, ownership or identity override.
The generic core manifest format admits Unicode paths; this native adapter does
not. Construction now checks every derived target's components, rejecting an
incompatible pinned inventory before any IO rather than during the first read.

Traversal anchors at `/`, opens every component relative to its checked parent
descriptor with no-follow flags, and retains those descriptors until final
readback. Ancestors must be root:root; the exact Dashboard subtree permits
root:root or the named service UID/GID pair. All components reject group/other
write and set-ID bits; leaves must be regular files. Nonblocking opens avoid
waiting on a substituted FIFO. File size is checked before opening/reading;
chunked binary reads stop at limit plus one byte, then reject overflow/truncation.
The reader rechecks descriptor and directory-entry identity/metadata after reading,
including ancestor entries. Detected replacement or drift fails closed and opened
descriptors are closed on success or exception. The private traversal primitive
accepts a test anchor; the production wrapper always opens `/`.

The shared primitive independently requires a non-empty tuple of single ASCII
components (no dot/dot-dot, separators, colon, controls, spaces or overlong names)
and an integer bound between zero and 100 MiB. Validation happens before any IO,
including for bootstrap callers. Root-owner lookup alone permits an empty tuple.

Fixed native diagnostics are `FS_PLATFORM`, `FS_ROOT_REQUIRED`,
`FS_SERVICE_IDENTITY`, `FS_TARGET`, `FS_COMPONENTS`, `FS_BOUND`, `FS_METADATA`, `FS_SIZE`, `FS_CHANGED`,
`FS_MISSING`, `FS_ACCESS`, `FS_SYMLINK`, `FS_NOT_DIRECTORY`, and `FS_IO`.
Native OSError details are suppressed; a link observed by metadata inspection
can yield `FS_METADATA` whereas an open-time ELOOP yields `FS_SYMLINK`.
The existing core intentionally reduces callback failures to `ARTIFACT_READ`.

The vendor reader does not discover package
or launch settings, exclude unlisted modules, verify resolution, freeze mutable
service-owned code, or authorize startup. Hashes remain the core's responsibility.
Memory is bounded by a target's limit (100 MiB maximum for Node), with an additional
bytes copy on return; memory/latency acceptance remains a deployment gate.
There are 540 fresh identity lookup pairs in a two-pass, 270-target read:
540 getpwnam calls plus 540 getgrnam calls. Actual NSS caching/remote-backend cost
must be measured; this is not necessarily 540 network round trips. No identity
cache or lookup bypass is introduced by this package.

### Root-controlled bootstrap

`operator_bootstrap.load_bootstrap()` exposes no path, pin or reader overrides.
It reads two public files, with effective root and root:root ownership required
at **every** component; no vendor/service ownership exception or NSS lookup:

Installation compatibility is an explicit gate: bootstrap requires root:root,
whereas the candidate requires root UID but does not constrain GID. A
root:service-group 0750 directory can therefore pass the candidate and fail
bootstrap. The proposed layout for **new public-only directories** is root:root
0755 and for the public certificate/manifest leaves root:root 0644. Existing
Dashboard configuration directories must first be inventoried and reviewed:
**do not chown/chmod them, broaden access, or change the trust pin/path to make a
check pass.** If this layout conflicts with existing protections, stop for a
separately reviewed layout/candidate decision. No installer or permission change
is included here, and public-file modes must never be copied to secret files.

| Fixed file | Bound | Status |
|---|---|---|
| `/etc/alertmind/broker-tls/manifest.json` | 512 KiB | Proposed installer destination, not created here |
| `/etc/wazuh-dashboard/certs/alertmind-server-api.pem` | 64 KiB | Same destination as the approved candidate, not installed here |

The manifest is validated against the core's independent pins/file inventory,
never trusted merely for residing in a root-owned directory. The certificate must
be one PEM block with canonical valid Base64 and the exact accepted DER SHA-256
`5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87`.
Duplicate certificates, private-key blocks, surrounding data, malformed encoding
and a different pin are rejected. Tests pin the destination and digest to policy.cjs;
neither the candidate nor its trust pin changed.

Each file is reread and revalidated on a second pass, then exact equality is
required. A malformed manifest stops before the certificate read. The frozen
result carries public bytes for later wiring, excludes them from its repr, and
always carries `startup_authorized=False`. It is not a persistable authority or
atomic snapshot. Pass its manifest to InstalledReader only inside the future
trusted operator process; this slice does not trigger vendor reads itself.

Bootstrap-specific codes are `BOOTSTRAP_TARGET`, `BOOTSTRAP_CERT_SIZE`,
`BOOTSTRAP_CERT_PEM`, `BOOTSTRAP_CERT_PIN` and `BOOTSTRAP_CHANGED`; manifest and
native reader rejections retain their existing fixed codes. No raw file bytes or
OS errors are emitted by a CLI (there is no CLI).

**Still not established:** X.509 current validity, SAN/hostname/revocation/TLS
success, Dashboard-user readability of the future certificate, or trusted Python
launch/import/code identity. An imported module cannot attest its own launch
after the fact. The approved client still performs its own date/hostname checks
at use. Root-controlled guard installation/import isolation, effective launch/
runtime selection and executable startup enforcement remain separate work.

`recovery_step(observation)` returns one next action from fresh observations:

| Observation | Next action |
|---|---|
| Startup inhibition absent or unknown | Inhibit startup, then re-observe |
| Dashboard stop not established | Stop Dashboard, then re-observe |
| Installed client missing/unrecognized | Hold; investigate, never overwrite unknown bytes |
| Exact private backup/metadata unverified | Hold; do not restore |
| Candidate still installed | Restore original atomically while inhibited and stopped |
| Original bytes restored, metadata not proven | Restore original metadata while inhibited and stopped |
| Original bytes and metadata restored | Keep Dashboard stopped and inhibited |

This implements rollback decision logic, **not atomic replacement, durable
journaling, power-loss recovery or service inhibition itself**. A transaction
journal may assist an operator, but cannot establish current file/service state.
Tests model interruptions before and after each observation transition, replay
the same observation and confirm deterministic decisions. They are not disk
crash simulations. Each physical action, once implemented, must have fresh
readback and independently tested interruption handling.

There is no restart, unmask, cleanup or delete action in this core. Restoring the
known non-verifying original never authorizes its execution. Exact original
bytes alone do not prove restoration of original owner/group/mode metadata.
Unknown state stays held; no backup, journal or success result is invented.

## Verification

Twenty network-free core tests run in the ordinary regression suite. Eight deliberately
removed controls were additionally checked during author verification: manifest
inventory pin, second pass, package/runtime identity, startup inhibition,
private-backup validation, unknown-client hold and no-restart terminal state.
These mutation runs are author checks, not additional unittest methods.

The September 13 test-only follow-up pins exact parser error codes (including
nested duplicate keys and all three non-finite JSON constants) and independently
exercises expected length versus maximum length. The upper-bound case uses the
runtime header target, whose exact size is intentionally unspecified, with all
preceding reads valid. Removing any of those four guards must now fail the
corresponding error-code assertion rather than pass on a later hash/contract
error. The suite still contains twenty operator methods; production core and
candidate bytes are unchanged. See
[follow-up verification](operator-test-verification-2026-09-13.json).

The subsequent native-reader slice adds sixteen methods: twelve portable policy
and simulated-descriptor fault tests, and four real Linux temporary-tree tests.
They cover bounded binary/empty reads, flags and ownership, exact allowlisting,
replacement/drift, symlinks/FIFOs, exception cleanup and descriptor leaks.
The latter four are explicitly skipped on Windows; Linux CI/reviewer execution
is required before claiming native traversal verification. They need no root,
Wazuh, credentials or networking and do not execute packaged Node. The core's
existing parser method also now rejects str, bytearray and memoryview manifests
with the exact `MANIFEST_SIZE` code. Neither the TLS candidate nor pins changed.

Claude's September 13 review ran that 214-method revision on Linux with zero
skips, including its four native tests. The bootstrap follow-up has 226 methods
in 22 files: eighteen reader methods (four Linux-only), ten new bootstrap methods,
and the unchanged twenty core methods among them. It adds independent primitive
component/bound tests and negative root-anchor/type cases to the existing tests;
bootstrap tests use synthetic pinned public bytes, not live X.509 acceptance.
Changed native code still needs fresh Linux reviewer/CI verification.

### Fresh package and on-disk runtime observations

`operator_runtime.observe_package_runtime(manifest_bytes)` validates the manifest
and native target compatibility before reading anything. It then reads the fixed
root:root `/var/lib/dpkg/status` database (32 MiB bound), requiring exactly one
`wazuh-dashboard` record, version `4.14.7-1`, architecture `amd64`, no error flag
and installed state. Both `install ok installed` and `hold ok installed` are
accepted; partial, pending-trigger, removal and reinstall-required states fail.

The bounded UTF-8 parser treats field names case-insensitively, rejects duplicate
fields and target records, ignores descriptive continuation content, and rejects
folded identity fields. Its format basis is [Debian's deb822 specification](https://manpages.debian.org/bookworm/dpkg-dev/deb822.5.en.html);
the fixed database is documented by [dpkg-query](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html).
It is not a general deb822 library. Unrelated package details are never returned.

Two passes read and hash only the approved Node binary and version header,
through InstalledReader with the independent core pins. Three fresh package
reads bracket those passes: package → Node/header → package → Node/header →
package. A changed accepted package identity, mismatched bytes or failed read
stops the observation. No subprocess is used, and Node is never executed.

The immutable result contains only the validated package identity, the pinned
Node version label, read/pass counts and **selected_runtime_proven=False** and
**startup_authorized=False**. It does not claim the host architecture, the runtime
the Dashboard selects, loaded code, launch environment, binary dependencies,
package signature/provenance or whole-package integrity. The status file is a
registry snapshot, not a dpkg lock or pending-update-journal check. Two passes
do not prevent an update after the check. Memory/latency and package-update
exclusion remain deployment gates; decoding/splitting the bounded database also
requires additional memory beyond its raw byte bound.

Additional fixed diagnostics: `PACKAGE_STATUS_SIZE`, `PACKAGE_STATUS_FORMAT`,
`PACKAGE_STATUS_DUPLICATE`, `PACKAGE_STATUS_AMBIGUOUS`, `PACKAGE_STATUS_MISSING`,
`PACKAGE_ARCHITECTURE`, `PACKAGE_NOT_INSTALLED`, `PACKAGE_CHANGED`, `RUNTIME_SIZE`
and `RUNTIME_DIGEST`; existing `PACKAGE_VERSION` and native errors are reused.

This slice adds thirteen portable runtime/parser tests: 239 methods in 23 files,
with the same four native tests requiring Linux. The previous 226-method revision
was independently approved on Linux; that does not stand in for testing this
revision. Bootstrap tests now cover manifest repr suppression, the component
test isolates a non-empty list, and dotted-name bootstrap invocation works.

Historical TLS fixture verification files remain unchanged. Claude's September
12 approval records the updated 16-group fixture passing on Linux Node 22.22.2
with inherited proxy settings; it does not close the native operator gates.

## Required next adapter package — not released here

1. Establish selected packaged Linux runtime and real Server certificate
   suitability without broker credentials; agree the 30-second timeout and
   performance acceptance criteria. Preserve the current public fingerprints.
2. Review the root-controlled manifest/certificate loader and rerun native Linux
   traversal tests after shared-primitive changes. Implement trusted guard launch/
   import bootstrap and deployment wiring. Preserve
   the distinction between root-controlled trust and service-mutable vendor code.
   Two equal byte passes cannot prevent edits after checking or attest running
   code. Verify the installed dependency resolution/file set too: matching listed
   files alone does not exclude an extra module or a changed resolution path.
3. Review the fresh package/on-disk runtime observer, then implement effective
   launch/environment, actual runtime selection and single broker host
   observations privately. No arbitrary executable override, fallback Node or
   `NODE_OPTIONS` preload may bypass the intended guard. Do not export secrets.
4. Build the root-controlled pre-start adapter and exact service drop-in from
   observed unit settings. Do not invent a unit override or silently overwrite
   existing drop-ins. A guard failure must prevent background/internal broker
   authentication as well as interactive requests.
5. Implement/rehearse durable inhibition, exact private backups, atomic installs,
   metadata preservation and recovery from interruption after every write.
   Do not remove the inhibitor on rollback to the original. Unknown file content
   or partially written state requires inspection, not unconditional replay.
6. Obtain explicit owner downtime/checkpoint approval and independent package
   review **before** any staging/apply/restart instructions. Preserve Snapshot 1.
   Then perform real internal/scoped broker, admin and saved-object acceptance;
   these do not follow from a core or fixture PASS.

No VM command is requested by this deliverable. No role, grant, credential,
certificate, SSH transport, benchmark, dependency or live Dashboard change is
included. The larger operator package and subsequent application work remain
incomplete until those separately reviewed steps are implemented and accepted.
