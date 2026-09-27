# Operator safety core — offline, not an installer

This is an incremental implementation of the approved design's operator
package. `operator_core.py` implements byte-integrity checks for a future
pre-start guard and conservative rollback decisions. It has no command-line
entry point, process execution, network access, filesystem writes or service
operations. `operator_fs.py` adds a read-only Linux vendor-file reader; it has
no CLI, network, writes or service operations. `operator_bootstrap.py` loads the
fixed root-controlled manifest and public certificate. `operator_runtime.py`
observes the package registry and pinned Node/header files without executing Node.
`operator_service.py` adds fixed read-only local systemd queries through busctl;
unlike the earlier libraries it can spawn that specific OS utility when invoked.
It has no CLI or service mutation operation. `operator_process.py` adds a separate
running-process observation via fixed systemd queries and procfs reads; it is not
a pre-start requirement. **No startup guard is installed
or operational on the VM.**

### Current launch/composition work (27 September 2026)

The working candidate now connects the checks described below. Earlier sections
that say a component is dormant/outside the capsule describe the prior individual
slices; the new full path uses the original thirteen-source capsule plus eight
separately pinned Python-observer sources. The owner explicitly approved the
scoped test-contract transition on 27 September after reviewing its risks.
This is an **offline connected candidate, not deployment or startup approval**.
Independent review remains deferred; author verification is not that review.

`build_guard_launch.render_launch_candidate()` produces a fixed POSIX-shell
launcher for offline review, in memory only. It has no installation/execution CLI
or caller-provided paths, pins or approval flags. The template checks root IDs,
root-controlled non-symlink ancestors/files, sizes, link counts and SHA-256 for
81 inputs: nine mapped objects, loader cache, 49 source files, entry and 21
capsule sources. It checks 517 absent paths (514 selected Python alternatives,
global preload, Python ZIP and the native hwcaps tree), `/dev/null` metadata and
the ELF interpreter/SONAME aliases twice. No `ldd` or Python is run to learn pins.
It sets cwd `/`, disables core dumps, uses null stdin and starts the fixed Python
argv with exactly the three proposed environment values via `env -i`.

The trust anchor is explicitly the administrator-controlled **OS/kernel,
supervisor, shell, coreutils and their dependencies**, plus the reviewed installed
launcher bytes. The parent must already supply a clean helper-launch environment
and no extra inherited descriptors. Clearing the child's environment is too late
to protect the helper programs themselves. Root/admin compromise, concurrent
privileged changes, package authenticity, arbitrary OpenSSL/NSS configuration
and every possible loader influence are not attested by this shell program.
No concurrent update/configuration work is allowed. Pathname checks are not an
atomic filesystem lock; these assumptions require deployment review, not a fake
`trusted=true` input. The launcher itself is pinned by the future installation
transaction, not by a self-referential checksum.

The [dynamic loader's documented input order](https://man7.org/linux/man-pages/man8/ld.so.8.html)
is why environment, preload, cache and hardware-directory inputs are addressed
before Python. Post-start mapping checks are additional observations, not a way
to undo earlier execution. [Python isolation](https://docs.python.org/3.14/using/cmdline.html#cmdoption-I)
does not authenticate the interpreter or libraries.

The entry's full sequence is now:

1. Check launch settings and fixed entry/source metadata; retain verified bytes.
2. Prepare the eighteen roots and require the exact 104-key prepared table.
3. Load all 21 pinned children from held bytes under the private deny-finder;
   require the exact 126-key full table and retain existing module identities.
4. Run the seven Python observers, then fresh bootstrap/package checks, nine
   broker observers and installed-byte verification; recheck bootstrap/package.
5. Repeat the seven Python observers, unload the private namespace and require
   the prepared table again. Every subject call is bracketed by full phase checks.

The selected-import and built-in/frozen observers now accept only the exact
entry-defined held finder in that phase; their default three-finder policy stays
strict. No code temporarily removes the blocker to satisfy an old assertion.
The pre-start path excludes running-process/post-start checks. Passing the pinned
Node path to the byte comparator describes the on-disk target, not observed live
Node selection. Private bootstrap contents and subject exception text are not
printed. All paths, **including success**, still exit 1; there is no Dashboard
startup permit, service drop-in, durable installer or live acceptance claim.

New fixture tests cover ordering, each subject failure, identity drift, strict
finder handling, full-capsule execution/cleanup, renderer pins and shell syntax.
They do not prove Ubuntu 3.14/native compatibility, production timing or actual
launcher installation. Twenty-eight launch tests and the updated existing
contracts retain failure-at-every-phase checks, original capsule restrictions,
full-capsule byte/metadata rejection, private import blocking and nonzero exits.
No VM command is released; the VM may remain off.

#### Scoped test-contract transition

| Prior assertion | Connected replacement; retained protection |
| --- | --- |
| Main calls only the compile-only helper | Main calls the fixed observation path once; success, errors and interrupts all exit 1; the old helper still never executes code. |
| Preparation is never called by entry | Only the launch path calls it, after entry/source checks and before private loading; failed prerequisites stop later phases. |
| Python observer names never occur in entry source | Eight exact additional runtime pins, no eager project imports, unchanged original thirteen pins, fixed phase order and exclusion of post-start observers. |
| Both import observers have zero parameters | Exactly one keyword-only `held_finder=None`; default remains strict, only the validated entry-defined finder is accepted, platform gates and refusal of arbitrary overrides remain. |

These are not blanket exemptions for fifteen failing tests. Every old assertion
was mapped to its new phase responsibility; no tests were skipped or xfailed to
resolve the transition. Synthetic tests are not a native launch proof.

#### Connected observation-result policy (27 September 2026)

The entry now consumes all 19 result kinds across the 28 observer calls. A
pure, explicit contract requires the exact held dataclass (or exact core-result
dictionary), complete field set, strict primitive types, expected coverage
counts and non-authorizing flags. Unknown fields/classes/versions, missing
results, false success flags and contradictory file-tree counts stop the
sequence before another observer runs. No truthiness or Boolean/integer
coercion is accepted. This policy adds no imports or capsule sources.

The service/launch result must describe the reviewed single wrapper, no
execution flags, environment sources, alternate root or drop-ins, and the
expected service identity/working directory. Dependency coverage must match
the pinned package's reviewed counts. Bootstrap byte bounds are checked; the
existing pinned bootstrap observer remains responsible for validating the
manifest/certificate contents. Nested package records require the exact
versions, architecture, set and order; both installed `install` and `hold`
selections remain valid. Neither permits silently accepting an upgrade.

Repeated results are compared using private immutable snapshots, including
the Python package selections across the two Python passes. Cache entry counts
may differ between those passes within the existing 0–9 bound: legitimate
invalidation is not repaired or rejected. Each pass still verifies the cache
metadata. The file-set contract preserves the observer's allowance for extra
empty directories within its budget, with consistent file/entry/directory
counts. These are point-in-time observations, not an atomic lock.

**Not a final startup policy:** `active`, `inactive` and `failed` remain
visibility-only service states, not proof of stopped/inhibited startup.
`SetLoginEnvironment` may report either Boolean value; neither proves the
complete environment. All unproven/runtime-trust/startup flags remain false.
The current empty-auxiliary-command/no-drop-in baseline deliberately does not
accommodate a future `ExecStartPre` installation or its `activating` state.
That requires a separately reviewed lifecycle contract, not weakening these
checks in an installer. Final startup admission, durable inhibition and
installation/recovery are still absent; main always exits 1.

Twenty-three offline result-policy tests cover all fields' Boolean/integer
semantics, types/coverage/version drift, real held versus ambient classes,
every connected call returning missing or false-authority evidence, repeated
package drift, cache flexibility, private diagnostics and successful-path
nonzero exit. The 28 phase-order tests now use genuine typed summaries instead
of `None` results; observer I/O remains mocked. No VM acceptance is claimed.

#### Upgrade and revalidation requirement — open before deployment

The owner explicitly requires a maintainable upgrade path for Wazuh, the
Python build and Ubuntu. The [offline maintenance lifecycle planner](UPGRADES.md)
now implements a strict versioned baseline format and one-step advisory
upgrade/recovery decisions. It is outside the guard capsule, performs no I/O
and never permits mutation or startup. This is **not an operational upgrade
workflow**, nor a reason to hold back security updates indefinitely. The separate
`operator_maintenance_state.py` observer now reads fixed persistent-mask metadata
and systemd-reported activity without changing the existing guard contract.
Its inactive/zero-PID result is not complete stopped-process proof; its output
cannot clear a maintenance gate. Twenty-seven tests (two Linux-only) cover this
read-only, non-authorizing slice; no native service-bus acceptance is claimed.
The companion `operator_maintenance_cgroup.py` now checks the fixed cgroup-v2
tree (including its descendant population indicator), boot identity and bounded
suspend-inclusive timing, bracketed by unchanged mask/manager observations.
Twenty-five tests (two Linux-only) cover this separate non-authorizing slice.
It cannot exclude outside-unit instances or establish exclusive control; neither
observer clears the planner's stopped-process gate. The separate
`operator_maintenance_lock.py` now provides a lifetime-bound, nonblocking
cooperative lock at one pre-provisioned private `/run` anchor. Twenty-nine tests
(three Linux-only) cover contention, metadata drift and cleanup. It does not
exclude package managers, other administrators or service-owned writes; no
planner permission, provisioning command or live transaction is supplied.
`operator_maintenance_processes.py` adds a bounded read-only process-leader scan
for service UID/GID and packaged-Node-path candidates, including outside the unit.
Thirty-five tests (two Linux-only) cover matching, privacy and fail-closed drift.
No argv/environment or executable payload is read. Zero matches does not exclude
all copied/renamed instances or nonleader-only credential changes and cannot
grant stopped-process or exclusive-control permission. The public census now
runs inside a held namespace alignment boundary, checking five active namespace
types and child PID/time targets against visible PID 1 before/after observation.
Thirty-two additional tests (two Linux-only) cover this connection. Alignment is
not intended-host attestation, and the explicit candidate-coverage policy is not
full shutdown proof. Root-controlled host launch and noncooperating update/start
controls still precede maintenance admission. See [the exact contract](UPGRADES.md#namespace-boundary-and-candidate-coverage--connected-to-the-census).
`operator_maintenance_packages.py` now adds a dormant default-path APT/dpkg
record-lock barrier for observation/backup, not for invoking an upgrade. All
four locks must be held and rechecked; partial acquisition unwinds without
creating/deleting locks, repairing metadata or waiting. Thirty-three tests
(four Linux-only) cover requests, contention, lifetime, drift and cleanup.
Installed paths, bounded package handover, service-start inhibition and trusted
host launch remain open; arbitrary writers and pre-lock package housekeeping
are not excluded. No authority flag is promoted. See [the package barrier contract](UPGRADES.md#package-manager-lock-barrier--observation-and-backup-only).
`operator_maintenance_inhibit.py` adds private persistent-mask disk preparation:
no-clobber creation of the exact symlink or fresh verification of an existing
one, held-path checks and deepest-first directory synchronization. Failure
never deletes a mask. Thirty-two tests (four Linux-only) cover the disk portion.
The public entry always refuses before I/O; external owner/host authorization is
not connected. A disk result
is not manager inhibition, process quiescence or reboot acceptance. See [the disk contract](UPGRADES.md#persistent-mask-disk-preparation--live-entry-blocked).
`operator_maintenance_manager.py` adds private reload, effective-mask readback,
stop and fresh manager/cgroup/census sequencing. Forty-four mocked tests cover
ordering, bounded client waits, drift, revocation, failure cleanup and refusal
of successful-exit-only evidence. A timed-out client does not cancel its manager
job; failures never unmask, retry or restart. Reload is manager-wide and stop
can run hooks/dependency jobs. Intended-host trust, installed effects and native
compatibility still need review before release.
Its public entry is unconditionally blocked; counts do not become full process
quiescence or planner admission. See [the manager contract](UPGRADES.md#manager-reloadstopreadback--live-entry-blocked).
`operator_maintenance_control.py` now privately composes namespace, cooperative
and package-lock lifetimes around disk preparation and manager sequencing.
Thirty-two tests (two Linux-only) check acquisition/unwind order, fresh held
checkpoints, boot/caller/deadline continuity and fail-closed cleanup. The exact
busctl/systemctl child exception is explicit, not arbitrary fork permission.
Selected loaded-unit stop-effect checks now run under those controls before
mask preparation, before reload and after reload before stop: empty stop hooks,
selected propagation/trigger edges and emergency actions, stable unit identity/
state and a conservative signal policy. Thirty-five mocked regressions cover
these checks and all three integration points. This is not complete generator/
dependency review, installed-version acceptance or external authorization.
The composed 30-second bound and public mutation refusal are unchanged; no
live query is released. See [the scoped contract](UPGRADES.md#selected-stop-effect-checks--not-complete-manager-effect-proof).
The existing namespace contract caps the entire window at 30 seconds; this was
not widened to the manager's longer budget. No live authorization, installed
hook/dependency safety or complete process-absence claim follows. Its public
entry still refuses before I/O. See [the held-control contract](UPGRADES.md#held-control-composition--private-and-non-authorizing).
The following live collection/execution/acceptance requirements remain open:

- Record a versioned compatibility baseline for the OS/architecture, interpreter,
  stdlib/native libraries, loader cache, Wazuh/Node/plugins and guard artifacts.
  Retain the previous baseline and evidence; never rewrite A-C3 observations.
- Assess the upgrade in a disposable clone/snapshot first. Re-derive candidate
  pins from reviewed package/provenance and fresh observations, review changed
  import/dependency behavior, and rerun regression plus native launch, TLS,
  authorization and recovery checks affected by the change. A version-string
  or hash replacement alone is not compatibility evidence.
- Specify a maintenance transaction that inhibits broker startup across package
  changes/reboots and atomically installs the matching reviewed guard baseline.
  Keep an explicit owner downtime decision and tested interruption/recovery path.
- Report a useful, sanitized incompatibility reason, including expected and
  observed public version identifiers where safe. Unknown versions/hashes stay
  refused; no auto-learning, broad version ranges, skip/force flag or silent
  fallback to the original non-verifying broker client.
- Treat loader-cache regeneration and other legitimate drift as requiring review,
  not automatically as compromise. Measure validation/startup duration and set
  bounded timeouts before service wiring. Test both planned upgrades and an
  unexpected drift/reboot, including how an operator safely recovers.

Until this workflow is implemented and accepted, a legitimate update may cause
the candidate to refuse execution. Restoring an old snapshot/baseline is an
operator recovery decision, not permission to restart vulnerable broker bytes.

The September 14 trust-path revision changes the candidate and its contract.
The core repeats the candidate pins deliberately; a CI test requires equality
with `contract.json`. Claude approved those pins on September 14; PR #41
merged them. This is offline review, not deployment approval.
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

**September 14 layout decision, approved by Claude and merged in PR #41:** the exact vendor
4.14.7-1 package records `/etc/wazuh-dashboard` as service-owned 0750 and its
postinst recursively reapplies service ownership to that tree and
`/usr/share/wazuh-dashboard`. Root-only trust checks cannot pass that stock
layout. The proposed certificate now lives under the separate `/etc/alertmind`
tree, outside those two vendor-maintained prefixes; no vendor chown is bypassed
and there is no fallback to the old path. The certificate DER pin is unchanged.

Bootstrap still requires root:root; the candidate still requires root UID but
does not constrain GID. A root:service-group 0750 directory can therefore pass
the candidate and fail bootstrap. The proposed layout for **new public-only
directories** is root:root 0755 and for public leaves root:root 0644, so the
Dashboard can read the certificate without controlling it. Existing `/etc/alertmind`
components must be inventoried before any future install; incompatible ownership,
permissions, symlinks or contents remain a STOP, not permission to overwrite.
**Do not chown/chmod vendor directories or broaden access to make checks pass.**
No installer or permission change is included here. Public-file modes must never
be copied to secret files. This addresses the known vendor-prefix conflict,
not native readability, general upgrade safety or deployment acceptance.

| Fixed file | Bound | Status |
|---|---|---|
| `/etc/alertmind/broker-tls/manifest.json` | 512 KiB | Proposed installer destination, not created here |
| `/etc/alertmind/certs/alertmind-server-api.pem` | 64 KiB | Reviewed candidate destination; not installed here |

The manifest is validated against the core's independent pins/file inventory,
never trusted merely for residing in a root-owned directory. The certificate must
be one PEM block with canonical valid Base64 and the exact accepted DER SHA-256
`5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87`.
Duplicate certificates, private-key blocks, surrounding data, malformed encoding
and a different pin are rejected. Tests pin the destination and digest to policy.cjs;
the path change does not change this trust pin. Candidate/policy/file-inventory
hashes are regenerated together; old manifests are rejected, not upgraded in
place. Earlier dated verification records remain unchanged and apply only to
their recorded candidate. Current results: [September 14 verification](verification-2026-09-14.json).

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

Twenty-one network-free core tests run in the ordinary regression suite. Eight deliberately
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

The runtime/parser module now has sixteen methods. Whitespace-only lines are
deliberately treated as stanza separators: a following orphan continuation is
rejected, including in an unrelated package. That conservative availability
tradeoff is tested, not silently relaxed. NUL/control bytes and invalid UTF-8 in
unrelated values are explicitly rejected. Returned identity fields and repr are
checked for data minimization; this does not promise memory zeroization or make
retaining ignored values an observable output difference.

### Systemd launch-configuration observations (not process attestation)

`operator_service.observe_service_configuration()` queries a fixed, already
loaded `wazuh-dashboard.service` object through `/usr/bin/busctl`. It uses only
Properties.Get, never LoadUnit, Set, reload, restart or a broker endpoint.
The Linux/root capability gate and no-follow root:root read of the busctl file
and ancestors precede execution. The host OS, tool and its libraries are trust
assumptions, not independently pinned package-authenticity proof; this check
does not prevent a privileged concurrent replacement before exec. The verified
path components are now derived from the same BUSCTL path used by Popen, so a
future maintained path change cannot silently leave verification on the old path.

Each of two passes queries seven Unit and thirty-seven Service properties, including
ExecStartEx and six auxiliary-command arrays, the inverse `TriggeredBy` edges,
`OpenFile`, file-descriptor-store capacity/count, extra descriptor names and
standard-input mode/name, four non-payload credential-source metadata fields,
explicit Environment,
environment-file references, passed/unset names, login-environment and
directory settings, user/group, working directory,
alternate-root settings, MainPID and the main-process monotonic start timestamp.
Native typed JSON is parsed strictly, including argument arrays, extended execution flags,
integer widths, duplicate/extra keys and exact property ordering. Records are
split on LF bytes; literal Unicode separators inside JSON values are not record
boundaries. A single terminal LF is optional; extra empty records are rejected.
The format basis is
the [systemd D-Bus interface](https://github.com/systemd/systemd/blob/v257/man/org.freedesktop.systemd1.xml)
and [busctl's get-property JSON implementation](https://github.com/systemd/systemd/blob/v257/src/busctl/busctl.c).
Unsupported/missing properties fail closed; host-version compatibility remains
to be established independently before release of a live operator packet.

Four fixed helper processes run sequentially. Each reply has a 256 KiB cap and
a five-second parent deadline, plus a one-second cleanup wait. The helper has
no shell, no stdin, a fixed working directory, a minimal environment and no
inherited file descriptors. Stderr is discarded. Timeout, overrun and errors
kill/reap the helper and close the pipe; a cleanup failure is itself a STOP.
This is not an absolute wall-time guarantee for blocked process creation or
kernel IO. Flags request noninteractive/no-auto-start behavior; the safety
boundary is the fixed Properties.Get operation on PID 1's known unit object,
not a claim that every busctl version honors every flag for this subcommand.

Only frozen counts, booleans and fixed classifications leave the public
observation function. Raw arguments, environment values, file paths and user
names are neither printed nor included in its repr. The parser necessarily
returns private intermediate data to its caller: do not log that data. Raw
values exist in memory; a future privileged launcher still needs core-dump,
debugging and trusted-import controls. No credential payload or standard-input payload
property is requested here.

Full private snapshots are compared, not just sanitized summaries. A pending
daemon reload, transient state, wrong unit, malformed environment or any
between-pass difference fails closed. Unknown executables or extra configuration
are reported conservatively, not approved. `configured_executable=packaged_node`
is only an exact configured path classification; a wrapper may select another
runtime, and argv, execution flags, namespaces or additional environment sources
can change behavior. The three flags `selected_runtime_proven`,
`effective_environment_proven` and `startup_authorized` remain **false**.

Not covered: manager environment, environment-file contents, PAM configuration,
embedded credential payloads, wrapper execution, actual `/proc`
executable/argv/environment, all unit properties,
launch-file hashes, host architecture, broker configuration or runtime imports.
No safe-environment conclusion follows from `runtime_override_named=False`; that
flag detects only a small fixed list of explicit Environment names. No observed
path is opened or executed. Equal passes are not an atomic systemd snapshot.

Fixed diagnostics: `SERVICE_TARGET`, `SERVICE_SIZE`, `SERVICE_JSON`,
`SERVICE_SHAPE`, `SERVICE_TIMEOUT`, `SERVICE_QUERY`, `SERVICE_CLEANUP`,
`SERVICE_IDENTITY`, `SERVICE_RELOAD_PENDING`, `SERVICE_TRANSITION`,
`SERVICE_ENVIRONMENT`, `SERVICE_CHANGED`, plus the reused native reader codes.

### Running-process executable observations (separate from pre-start safety)

`operator_process.observe_running_process()` derives MainPID only from the fixed
service configuration query. It requires an active named service, nonzero start
timestamp, and the expected configured user/group. Three full private manager
reads bracket two procfs snapshots. There is no public caller-PID override.

**Do not start an unpatched/unsafe Dashboard to make this check pass.** An absent
process stops this observation. The future pre-start guard must work while no
Dashboard process exists, and must not depend on this function. It is a later
point-in-time acceptance/diagnostic component, not permission to run the broker.

The implementation holds root, proc and PID-directory descriptors and opens
stat, status, cmdline and environ relative to them with no-follow flags. Bounds
are respectively 8 KiB, 64 KiB, 128 KiB and 1 MiB. Unlike normal files, procfs
content is not required to have the size reported in st_size. Stat parsing handles
parentheses/spaces/newlines in comm and checks the process start-time field;
status requires all four UID and GID values to match the service identity.
Unexpected credentials, unsupported state, malformed or oversized data stop.

Only the kernel's `exe` magic link is deliberately followed, relative to the
held PID descriptor. The link text must equal the pinned Node path without a
deleted-file suffix; it is never reused as an open pathname. The opened backing
executable is streamed through SHA-256 with a 100 MiB cap, checked against the
existing independent Node pin, and checked for metadata/link drift. Proc start
time and credentials are checked again. All descriptors close on success/failure.
The [Linux procfs documentation](https://docs.kernel.org/filesystems/proc.html)
describes these process files and the dead-process descriptor behavior.

Both private proc snapshots (including raw arguments/environment, start time
and executable inode) and the manager snapshots must agree. Only counts,
argv0-path equality and a fixed runtime-variable-name indicator leave the public
function, along with `process_executable_matches_pin=True`. This last flag means
the observed backing executable matched the approved bytes during these reads;
it does not mean loaded libraries, JIT code, modules or process memory are intact.
`loaded_code_proven`, `effective_environment_proven` and `startup_authorized`
remain false. A private snapshot suppresses argument/environment bytes in repr;
do not serialize it, parser results or exception frame locals. No raw-data
hashes, PID, credentials or variable names/values are exported in the summary.

Trust/limits: host kernel, procfs mount, PID namespace, host OS tools and Python
launch are assumed trusted; there is no hostile-root/kernel attestation, procfs
mount-type or cgroup-membership proof. Access denials and process exit stop rather
than changing permissions. Multiple reads are not atomic; an exec or process
change between observations may be missed. Command-line storage can be changed by
the target process, and procfs environment content is not all current setenv state
or the provenance of inherited environment. Empty environment is an observation,
not evidence of a safe one. Environment-source, wrapper/launch-file identity and
module-resolution checks remain pending. Streaming file IO has byte bounds but
no kernel-IO deadline; manager queries reuse the bounded helper. Performance and
concurrent-update acceptance remain live deployment gates. No signals or ptrace
are used against the Dashboard, and no executable is launched through procfs.

New fixed diagnostics: `PROCESS_PID`, `PROCESS_STAT`, `PROCESS_IDENTITY`,
`PROCESS_CMDLINE`, `PROCESS_ENVIRONMENT`, `PROCESS_TARGET`, `PROCESS_CHANGED`,
`PROCESS_SIZE`, `PROCESS_EXECUTABLE`, `PROCESS_DIGEST`, `PROCESS_NOT_RUNNING`,
`PROCESS_IO`; service and native trust codes are reused.

Current suite at this process-observer stage: 341 methods in 29 files,
including twenty-three service methods, nine manager-environment methods and
seventeen process methods. Seven require
Linux: four native-reader tests and three procfs/executable/descriptor tests.
These inspect the test process and a private copy of `/bin/cat` launched with
a clean environment and mode 0500. The child
waits on a test-owned pipe and is reaped before temporary-file cleanup. Test-only
pins are used; no Wazuh, Node execution or system bus call. The shared CI Python
executable's ownership/permissions are not assumed or changed.
Portable tests use syscall/manager doubles, including directory cleanup and drift.
Fresh independent Linux review is required. Prior 258-method Linux and fake-tool
approval is neither this revision's native verification nor real systemd framing
compatibility. No live operator packet is released by this library change.

Historical TLS fixture verification files remain unchanged. Claude's September
12 approval records the updated 16-group fixture passing on Linux Node 22.22.2
with inherited proxy settings; it does not close the native operator gates.

### Fixed launch-file observations (not executable selection)

`operator_launch.observe_launch_files()` validates these three exact files with
the existing descriptor-relative vendor reader. Each read is capped at its
pinned length and must match both that length and SHA-256. The source is the
already approved 4.14.7-1 amd64 package, SHA-256
`83f472d9e5f59b28b1abb6260c466e77b99ae427ce8c5f76203d847f2f598b6f`.
The author re-read that exact archive with `build_candidate.archive_bytes`, then
streamed its tar members without extracting or executing them. Existing candidate
manifest, package pin, dependency set and historical verification are unchanged.

Paths below are relative to `/usr/share/wazuh-dashboard/`:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `bin/opensearch-dashboards` | 939 | `30993e61fae26ab0c7d73836fd510f1c9a54e9110a7e9c63edc9cbaff505f9d5` |
| `bin/use_node` | 3531 | `e1ec334650c93f2a4869cd679f2ff5a434a580f2c9b0e15cc4ef4f826803c464` |
| `src/cli/dist.js` | 1187 | `3425aafe16f4e139902826a4b929c61e74f930f2e7ef08cf7fe123cb81b7eefe` |

Two complete file passes are bracketed by three package-identity reads and three
full private manager snapshots. Package selection or manager changes stop the
observation. RootDirectory/RootImage are rejected because host paths do not prove
files inside those roots; other namespace settings are not comprehensively read.
An inactive loaded service is allowed: no process, PID or unsafe startup is needed.
Only fixed paths are read; an unknown configured command is never opened or run.
Returned flags distinguish the configured wrapper path, exact single wrapper
argv, explicit execution flags and a fixed set of environment-variable names.
Raw arguments/environment and their hashes are not returned. Unknown commands or
extra arguments can still produce an observation, but not a startup approval.

Package-source review explains why byte identity alone is insufficient:

- The first script derives OSD_HOME and invokes `bin/use_node`, supplying
  OSD_PATH_CONF, OSD_NODE_OPTS_PREFIX, OSD_USE_NODE_JS_FILE_PATH and NODE_ENV.
- `use_node` considers OSD_NODE_HOME, NODE_HOME, bundled Node, a fallback Node
  directory and system Node lookup. It can execute bundled Node with `-v` during
  selection; **do not execute the wrapper as a harmless inventory probe**.
- It reads `${CONFIG_DIR}/node.options` through shell tools and builds arguments
  from option variables. Shell interpretation, inherited environment and external
  utilities are not verified by hashing the script. The name indicator includes
  OSD variables but remains visibility only, not a complete allowlist.
- The wrapper passes extensionless `/src/cli/dist`; this package contains
  `dist.js`, which loads apm, setup_node_env/dist and cli. Pinning dist.js does not
  prove Node chooses it, exclude a shadowing `dist` file, or verify its imports.

`launch_bytes_match_pins=True` reports only these three backing-file byte checks.
`selected_runtime_proven`, `effective_environment_proven`,
`dependency_resolution_proven` and `startup_authorized` remain false. Existing
root/service ownership policy is reused, not strengthened; service-owned files
can still change after inspection. Reads are not atomic; syscall IO has byte
bounds, not a kernel deadline. Full environment sources, shell/utility identity,
unit files/drop-ins, import resolution and deployment remain later work.

Fixed new diagnostics: `LAUNCH_SIZE`, `LAUNCH_DIGEST`, `LAUNCH_NAMESPACE`,
`LAUNCH_CHANGED`; package, service and native reader codes are reused. No CLI,
write, shell/Node/broker execution or live operator packet is introduced. Twelve
new portable tests cover pins, bounded reads, both passes, drift, namespace,
non-authorizing flags, unknown paths and sanitized errors using existing native
reader contracts. They do not establish fresh live Linux/VM acceptance.

### Fixed node.options content policy (not the effective environment)

`operator_node_options.observe_node_options()` reads three fixed files per pass:
`/etc/wazuh-dashboard/node.options` (capped at 16 KiB), the 939-byte
SHA-256-pinned `bin/opensearch-dashboards` wrapper and the 3531-byte pinned
`bin/use_node` from the approved 4.14.7-1 package. Both scripts must match
the launch observer's existing exact byte pins. Fixed wrapper line sentinels
cover its home derivation and single dispatch line; that line literally assigns
`OSD_PATH_CONF="/etc/wazuh-dashboard"`,
`OSD_NODE_OPTS_PREFIX="--no-warnings --max-http-header-size=65536"`,
`OSD_USE_NODE_JS_FILE_PATH=/src/cli/dist` and `NODE_ENV=production` before
`exec ${OSD_HOME}/bin/use_node`. `use_node` sentinels cover config-directory
selection, `grep -v ^#`/`xargs`, and both `NODE_OPTIONS`/`exec` branches. The
sentinels are review tripwires for a future pin change, not a shell interpreter
or a substitute for whole-file digests. The wrapper and `use_node` pins and
sentinels were rechecked against the 193952104-byte, SHA-256-pinned Dashboard
4.14.7-1 `.deb` without installing or executing it. This is source identity,
not a fresh VM observation.

The observer does not follow an observed environment-file path or argument.
It establishes the wrapper's **literal** config assignment and prefix, not that
this wrapper executes or that its assignments become the process's effective
environment. It now also applies the existing exact-argv/queried-unit-source
policy to all three private service snapshots, and requires two empty
`Manager.Environment` replies around the file reads. An alternate unit command,
explicit environment source, auxiliary command, non-payload credential source
or nonempty global export stops with an existing fixed diagnostic. These
checks share one bracketed observation instead of relying on separate observer
results from unrelated times. No raw property values are returned.

Two reads of each file are checked independently; the conffile is also
compared byte-for-byte across passes. Three fresh package and private service
snapshots bracket those reads. Alternate RootDirectory/RootImage namespaces
reject before file reads. Missing files fail closed, even though the wrapper
treats a missing conffile as optional. An inactive service is supported; no
PID is needed. The reads are not atomic or a launch lock.

The shared descriptor-relative, no-follow bounded reader is reused with a narrow
owner policy: root:root above `/etc/wazuh-dashboard`, root:root or the named
Dashboard UID/GID pair inside that exact tree. It retains regular-file, mode,
set-ID and replacement/drift checks. The general vendor reader and root-only
manifest/certificate policy are unchanged. Service-owned configuration remains
service-mutable; equal reads are neither an atomic snapshot nor a lock.

The policy is content-based, not a hash of this editable conffile. It permits:

- Exactly one active `--unhandled-rejections=warn` (the shipped active setting).
- Optionally one `--max-old-space-size=4096` (the exact shipped commented example).
- ASCII LF text, blank space/tab lines and comments beginning with `#` in column
  zero. No final LF is required. Each active line must be one exact token.

Unknown options, other values, duplicates, loaders/preloads, debug/CA switches,
quotes, escapes, expansion/globbing, inline or indented comments, active-token
whitespace, CRLF, non-ASCII and control bytes reject with static codes. This is
intentionally narrower than Node syntax; changing memory values or other flags
requires separate policy review, not a blind hash refresh. Allowing the vendor's
4 GiB example is not a capacity recommendation or live performance acceptance.
Stock 4.14.7-1 `use_node` removes only `^#` lines then uses `xargs` and unquoted
shell expansion. The restricted grammar avoids their quoting/token ambiguities;
the observer never runs those tools, the wrapper or Node to parse the file.

Only an option count, fixed read counts and flags are returned.
`content_policy_passed`, `queried_unit_sources_constrained`,
`manager_global_export_empty`, `wrapper_bytes_match_pin`,
`wrapper_literal_config_assignment`, `wrapper_literal_prefix_assignment`,
`launcher_bytes_match_pin` and `source_contract_passed` are narrow checks;
`selected_source_proven`,
`effective_prefix_proven`, `effective_environment_proven` and
`startup_authorized` are always false. The combined snapshot still does not
resolve manager-process/generated variables, embedded credential payloads,
other socket/descriptor paths, inherited `NODE_OPTIONS` or `OSD_NODE_OPTS`,
external shell tools, shell expansion, runtime selection, later file edits or
the complete process environment. It is not a trusted launch proof or startup
permission.

Codes: `NODE_OPTIONS_SIZE`, `NODE_OPTIONS_FORMAT`, `NODE_OPTIONS_OPTION`,
`NODE_OPTIONS_DUPLICATE`, `NODE_OPTIONS_REQUIRED`, `NODE_OPTIONS_CHANGED`,
`NODE_PIPELINE_TARGET`, `NODE_PIPELINE_SIZE`, `NODE_PIPELINE_DIGEST` and
`NODE_PIPELINE_CONTRACT`, plus `NODE_WRAPPER_TARGET`, `NODE_WRAPPER_SIZE`,
`NODE_WRAPPER_DIGEST` and `NODE_WRAPPER_CONTRACT`; existing
package/namespace/native, `UNIT_SOURCE_*` and `MANAGER_ENV_*` errors are reused.
Twenty-eight portable tests use synthetic files, ownership, pinned scripts,
unit snapshots and manager exports; no new native/live acceptance claim.
The launch observer's flag is now `inline_wrapper_environment_override_named`
(old ambiguous name removed); it still inspects only inline `Environment=`.
Two added launch tests isolate multiple ExecStart rows and the inline-only scope,
bringing that module to fourteen tests. No production caller used the old name.

### Running Node launch-shape observation — post-start only

`operator_effective_launch.observe_effective_launch()` composes the fixed
node.options/wrapper policy with the existing pinned-executable procfs reader.
It requires an **already running** Dashboard. Two equal process snapshots are
bracketed by fixed systemd MainPID/configuration reads, and the options policy
is repeated on both sides. The observed argv must consist exactly of the pinned
Node path, the wrapper's two literal prefix flags, the stock warning option,
optionally the one reviewed heap-size option, and the fixed CLI entrypoint.
Either order of the two allowed conffile options is accepted. Additional flags,
arguments or a different executable/entrypoint stop with a static diagnostic.

The initial procfs environment must contain the four exact wrapper-origin
assignments (`OSD_PATH_CONF`, `OSD_NODE_OPTS_PREFIX`,
`OSD_USE_NODE_JS_FILE_PATH`, `NODE_ENV`). Inherited Node/OSD, `LD_`, `OPENSSL_`
and `SSL_` override names, plus selected shell controls, are rejected,
including `NODE_OPTIONS`, `NODE_PATH`, `NODE_TLS_REJECT_UNAUTHORIZED`,
`LD_PRELOAD` and `BASH_ENV`. Other names are not globally
allowlisted; `PATH` and external shell-tool resolution are still unproven.
Only counts and narrow flags are returned. Raw argv/environment bytes, values,
PID and private systemd properties are not logged or returned. Ten portable
tests cover allowed shapes, extra arguments, required/forbidden environment,
drift and sanitized errors. There is no VM execution in this package.

This is an observation of an existing process, **not** proof that the named
conffile supplied its flags, that all current environment state or loaded code
is safe, or that later service-owned files cannot change. Procfs cmdline can be
changed by the process; procfs environ reflects the initial exec environment,
not all subsequent changes. Observations are not atomic. The result retains
`actual_config_source_proven`, `external_utility_resolution_proven`,
`complete_effective_environment_proven`, `loaded_code_proven`,
`prestart_applicable` and `startup_authorized` as false. Never start an
unguarded Dashboard to satisfy this post-start observer, and never wire it as
the pre-start guard. New diagnostics: `EFFECTIVE_POLICY`, `EFFECTIVE_ARGV`,
`EFFECTIVE_ENV`, `EFFECTIVE_CHANGED`, `EFFECTIVE_IO`; existing process, unit,
options, package and native-reader diagnostics remain unchanged.

### Explicit unit launch-source boundary

`operator_unit_sources.observe_unit_sources()` makes a separate, read-only
check of the loaded unit's explicit launch fields. It requires one exact
Dashboard wrapper command with only its own argv[0], no extended execution
flags, and no `ExecConditionEx`, `ExecStartPreEx`, `ExecStartPostEx`,
`ExecReloadEx`, `ExecStopEx` or `ExecStopPostEx` commands. These are the
[systemd v257 Service D-Bus extended command arrays](https://raw.githubusercontent.com/systemd/systemd/v257/man/org.freedesktop.systemd1.xml);
their arguments remain private. It also requires empty inline `Environment`,
`EnvironmentFiles`, `PassEnvironment` and `UnsetEnvironment`, empty `PAMName`
and `ExecSearchPath`, and the expected
Dashboard user, group and working directory. It now also rejects `DynamicUser`
and any configured `RuntimeDirectory`, `StateDirectory`, `CacheDirectory`,
`LogsDirectory` or `ConfigurationDirectory`. It also rejects any observed
`TriggeredBy` edge, `OpenFile` entry, nonzero file-descriptor-store capacity
or occupancy, extra descriptor name, or standard input other than `null`
with an empty descriptor name. These properties represent selected routes by
which the service could receive files, sockets or input despite its exact
command line. `TriggeredBy` covers more than socket units, so a nonempty
list stops for review rather than being classified as a socket. The
[systemd v257 service interface](https://raw.githubusercontent.com/systemd/systemd/v257/man/org.freedesktop.systemd1.xml)
defines the queried signatures. The [systemd v257 execution
settings](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.exec.xml)
identify PAM sessions as a possible variable source and `ExecSearchPath` as a
PATH selector; service-directory settings can generate path variables.
RootDirectory/RootImage, a pending daemon reload or a malformed manager reply
also stop the check through the existing service reader.

Two complete private manager snapshots must match. The fixed busctl target,
root/tool gate and bounded reads are reused; configured paths and values are
never opened, run, logged or returned. The result contains only fixed booleans
and counts. It works with an inactive loaded unit and does not need MainPID.
An extra argument, auxiliary command, flag, explicit environment source, PAM
service, search path, dynamic user, directory source or selected descriptor
input returns a static error. No PAM configuration or configured path is
opened. `StandardInputData` and the byte-array `SetCredential*` properties are
intentionally not queried, since they can contain secrets. Four fixed,
non-payload Service properties (`LoadCredential`, `LoadCredentialEncrypted`,
`ImportCredential`, `ImportCredentialEx`) are queried with exact D-Bus types;
any nonempty value stops with a static diagnostic. Their configured names and
source paths remain private. This establishes only that those *queried*
credential-source metadata fields are empty; it does not prove embedded
credential payloads are absent or establish complete credential isolation.
The v257 interface describes these types, but installed property availability
and busctl framing still require separate review. A non-null input mode stops
without a payload read. This is deliberately strict: a
legitimate local customization requires separate review instead of silent
acceptance. A future trusted pre-start guard would itself appear in
`ExecStartPreEx`; this baseline policy must be replaced by an independently
reviewed exact guard-command policy before installation. Do not waive the
check merely to make startup pass. The exact typed `SetLoginEnvironment`
value is reported as `login_variables_enabled`; it is **not** a gate. With the required `User=`,
systemd may set `HOME`, `LOGNAME` and `SHELL` by default, so silently asserting
their absence would be wrong. A true value still yields no environment or
startup approval.

The result proves only that these *queried unit fields* met this policy at the
time of observation. Manager defaults/inheritance, other unit mechanisms and
generated variables (including `PATH` and `INVOCATION_ID`), embedded credential
directives and unqueried credential mechanisms,
unqueried descriptor/output mechanisms, complete socket activation state,
wrapper-created or process environment, shell expansion,
selected `node.options` source, imports and later edits are unresolved. It does
not request `SetCredential*` payloads; the already queried inline `Environment`
field may itself contain secrets and remains private in memory. Therefore
`manager_inheritance_proven`, `embedded_credential_sources_proven`,
`selected_config_source_proven`,
`effective_environment_proven` and `startup_authorized` remain false even
on success. This is not a startup gate or a broker authorization decision.
Eighteen portable tests cover the exact command, six auxiliary command arrays,
each explicit source, PAM and search-path rejection, generated-directory sources,
dynamic user, selected descriptor/trigger inputs and login
visibility, identity, namespace/tool gates, an inactive unit and
between-pass drift. No new native Linux or VM acceptance is claimed. New
static codes are `UNIT_SOURCE_EXEC`, `UNIT_SOURCE_AUX_EXEC`, `UNIT_SOURCE_INLINE_ENV`,
`UNIT_SOURCE_ENV_FILE`, `UNIT_SOURCE_PASS_ENV`,
`UNIT_SOURCE_UNSET_ENV`, `UNIT_SOURCE_PAM`, `UNIT_SOURCE_SEARCH_PATH`,
`UNIT_SOURCE_DYNAMIC_USER`, `UNIT_SOURCE_DIRECTORIES`,
`UNIT_SOURCE_TRIGGER`, `UNIT_SOURCE_OPEN_FILE`, `UNIT_SOURCE_FD_STORE`,
`UNIT_SOURCE_EXTRA_FDS`, `UNIT_SOURCE_STDIN`,
`UNIT_SOURCE_CREDENTIAL_METADATA`,
`UNIT_SOURCE_IDENTITY`, `UNIT_SOURCE_CHANGED`.

### Manager-wide exported environment

`operator_manager_environment.observe_manager_environment()` separately queries
the fixed `org.freedesktop.systemd1.Manager.Environment` D-Bus property. Per the
[systemd v257 interface](https://raw.githubusercontent.com/systemd/systemd/v257/man/org.freedesktop.systemd1.xml),
this is the manager environment block passed to executed services. The adapter
reuses the bounded, clean-environment busctl subprocess and root/tool check; no
caller can select a different object or property. It parses two complete private
replies and accepts only equal, empty lists. Any nonempty export, including a
benign-looking variable, requires explicit review instead of an implicit
allowlist. Malformed names, duplicates, unexpected signatures or shapes and
between-read drift fail with static codes. No raw entry, secret or name is
returned or included in an error.

This is deliberately narrower than claiming the final process environment.
The systemd [execution-environment documentation](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.exec.xml)
describes other sources, including service-generated variables, unit settings,
manager-process inheritance via `PassEnvironment=`, PAM and final unset rules.
The separate unit-source check requires `PassEnvironment=[]` and `PAMName=''`,
but these checks are not an atomic combined gate; wrapper-created variables,
actual selected conffile, imports and future edits remain unresolved. A
successful result keeps `unit_environment_proven`, `wrapper_environment_proven`,
`effective_environment_proven` and `startup_authorized` false. This module does
not query the VM, start a service or authorize broker requests. Nine portable
tests use synthetic manager replies only; stock Ubuntu/Wazuh behavior has not
been observed. New diagnostics are `MANAGER_ENV_SIZE`, `MANAGER_ENV_FORMAT`,
`MANAGER_ENV_SHAPE`, `MANAGER_ENV_ENTRY`, `MANAGER_ENV_CHANGED` and
`MANAGER_ENV_PRESENT`; existing fixed-tool/query codes are reused.

### Direct axios shadow boundary — offline only

`operator_dependency.observe_direct_axios_shadow()` checks one narrow module
resolution hazard without invoking Node. The patched, manifest-pinned broker
client imports `axios` by package name. Under the [packaged Node 18.19.0
CommonJS lookup rules](https://nodejs.org/download/release/v18.19.0/docs/api/modules.html#all-together),
a nearer `node_modules` entry can take precedence over the Dashboard-root
copy; file alternatives with `.js`, `.json` and `.node` matter as well. The
observer checks four fixed nearer ancestor locations for `axios` and those
three file alternatives, plus the three root-level file alternatives: 19
absence checks per pass. It separately checks the pinned candidate client and
root `node_modules/axios/package.json` bytes. The bootstrap manifest/public
certificate and package identity bracket the two passes. The native absence
primitive holds no-follow directory descriptors, rejects untrusted ancestors,
and rechecks a missing child before returning. It reports only booleans and
counts; no path, module contents or certificate bytes appear in the result.

This is **not** proof of `require.resolve('axios')`, loaded code or the
transitive dependency graph. Package self-resolution, `NODE_PATH`, preload
hooks, other imports, symlink/namespace behavior and later edits remain open.
The service-owned plugin tree is mutable; even matching passes are not atomic.
`root_axios_selected_proven`, `transitive_resolution_proven`,
`effective_environment_proven` and `startup_authorized` therefore remain
false. No live VM or installed-path result is claimed. Ten new methods cover
fixed targets, both-pass shadow and drift failures, static diagnostics and
descriptor-relative absence/presence. Two native filesystem tests require
Linux; the portable descriptor doubles run in ordinary Windows test discovery.

### Declared axios package graph — offline only

`operator_dependency_graph.observe_declared_axios_graph()` extends the narrow
direct-import check to the **declared** `package.json` dependencies in the
manifest-pinned candidate. The exact reviewed Dashboard package yields 26
reachable package roots, 35 declared edges and 238 unique shadow candidates
(including the direct axios set). The observer reads and hashes the patched
client and every package-root `package.json` on each of two passes, validates
package names and bounded dependency maps, requires every staged package root
to be reachable, and rejects nearer directory/file alternatives with the
no-follow native absence primitive. Bootstrap and package identity bracket
the passes. The exact `.deb` was inspected offline: none of those 238 shadow
candidates exists in its archive. No package was installed or executed.

The search slots start at **package roots**, not each actual importing JS file.
A nested importer can have a nearer `node_modules` directory. Dynamic/relative
imports, package self-resolution, package exports/main behavior, `NODE_PATH`,
preloads, unlisted files, changed resolution paths and later service-owned
edits are not proven away. The result therefore leaves `import_sites_proven`,
`actual_node_resolution_proven`, `loaded_code_proven`,
`effective_environment_proven` and `startup_authorized` false. This is not
a complete Node dependency attestation or a live VM observation. Nine offline
methods cover closure, malformed metadata, missing/orphan roots, first/later
shadow failure, pinned-byte drift, package/bootstrap drift, static diagnostics
and authority limits; native Linux checks remain a separate gate.

### Pinned-code import-site overapproximation — offline only

`operator_import_sites.observe_pinned_import_sites()` checks the next search
depth without parsing or executing vendor JavaScript. From the independently
pinned manifest, it assigns each staged `.js`, `.cjs`, `.mjs` or `.node` file
to its deepest package root and treats its directory as a **possible** import
origin for *every declared dependency* of that package. On each of two passes,
it verifies the client, all package metadata and all selected code-file bytes,
then checks the package-root shadows plus file/directory alternatives in the
additional search slots. A site resolving to a different staged package than
its package-root dependency fails closed. The exact reviewed `.deb` yields
153 pinned code files in 46 distinct directories, 89 site/dependency pairs and
478 unique absence candidates; a POSIX-path membership check found
none in that package archive. The observer has not run on the installed VM.

This is an **overapproximation**, not evidence that any given file executed or
imported any given dependency. Unlisted code, dynamic imports, generated files,
symlinks/realpaths, package self-resolution/exports, `NODE_PATH`, preloads,
other Wazuh modules and post-check service-owned edits remain outside proof.
The result keeps `executed_imports_proven`, `unlisted_code_absent_proven`,
`actual_node_resolution_proven`, `loaded_code_proven`,
`effective_environment_proven` and `startup_authorized` false. Ten portable
offline methods cover site ownership, closure, divergent/missing selections,
first/later-pass shadows and byte drift, bounded work, static diagnostics and
the non-authorizing result. This does not install a guard or change Wazuh.

### Selected package-root file set — offline only

`operator_file_set.observe_package_file_set()` uses the root-controlled manifest
to derive the selected axios dependency-package roots. It scans only the
outermost selected roots, so nested selected packages are visited once. The
walk uses held directory descriptors, fresh no-follow metadata checks and a
fixed entry/depth budget. It requires every listed package file to exist and
rejects an unlisted regular file, symlink or special object inside those roots.
Empty extra directories are permitted but included in the two-pass metadata
comparison. Package identity and bootstrap are rechecked; the result exposes
counts, never file names, paths or contents.

The approved, SHA-256-pinned 4.14.7-1 `.deb` contains 26 selected package
roots, 267 regular files and 53 archive directory entries inside those roots;
no selected special archive member was found. This is an **offline archive
check**, not an installed-file observation. The method has not run on the VM.
Thirteen tests cover root selection, native no-follow FD use and cleanup,
unlisted/missing/symlink rejection, bounds, drift, sanitized diagnostics and
false authority flags. Four real-directory tests need Linux and are skipped
by the author's Windows runtime.

This does not read or hash file contents, exclude files outside selected
package roots, prove actual Node import resolution or attest loaded code.
Service-owned files can change after either scan. `file_bytes_verified`,
`unlisted_files_outside_package_roots_excluded`,
`actual_node_resolution_proven`, `loaded_code_proven` and
`startup_authorized` remain false. Installed Linux execution and independent
review are required before using this as evidence; it is not a startup guard.

### Candidate guard entry boundary — fail-closed, not deployable

`operator_guard_entry.py` is the first source file for a possible root-controlled
pre-start guard at `/usr/local/libexec/alertmind-broker-tls/guard_entry.py`.
It is **not installed**, and this candidate location must be confirmed against
the actual host before any service-unit design. The file has no project imports
before its checks and accepts only an already-root Linux Python process in
isolated, no-site, no-bytecode mode with the exact script argument. Python's
[`-I`, `-S` and `-B` options](https://docs.python.org/3.10/using/cmdline.html)
provide the intended launch shape; the actual interpreter, standard library,
unit command and environment are not pinned by this module. It then checks the
fixed entry path using no-follow descriptor-relative metadata, rejecting
service ownership, writable ancestors, links, replacement and oversize files.
It now also requires an **exact, empty-extra-file source capsule** at that
candidate directory: `guard_entry.py` plus thirteen SHA-256/size-pinned LF
operator modules needed by the possible pre-start path. The two post-start
process-observation modules are excluded. A bounded `scandir` enumeration,
no-follow/nonblocking descriptor opens, exact-length reads and post-read
metadata checks reject additions, missing files, links, unsafe ownership,
drift and byte changes. Python's [descriptor APIs](https://docs.python.org/3.10/library/os.html)
support this candidate check. The verified bytes are retained in memory,
rechecked and compiled with a fixed synthetic filename, `dont_inherit=True`
and `optimize=0`. A separately callable offline loader candidate is exercised
by tests using those code objects in dependency order under the private
`_alertmind_guard_held` package; it does not reopen project source paths.
**The guard entrypoint does not call the loader**: it only compiles the bytes
and returns nonzero until interpreter/stdlib/import-system trust is reviewed.
The temporary package has no filesystem
search path, an early finder rejects unknown private-module imports, and a
pre-existing private namespace or post-execution namespace/finder drift fails
closed. The loader removes its private modules and finder even after an
exception. Python's [`compile()` contract](https://docs.python.org/3.10/library/functions.html#compile)
and [import system](https://docs.python.org/3.10/reference/import.html)
distinguish byte compilation, module execution, `sys.modules` and finders.
Only fixed diagnostic codes are emitted by the entrypoint. Twenty-three
portable tests cover the entry, capsule, offline held-code loading, relative imports, unknown-import
denial, collision/drift cleanup and the nonzero-only result. No VM or systemd
command is executed by these tests.

**There is deliberately no success path:** even if all entry checks pass, it
prints `GUARD_NOT_READY` and exits 1. The capsule is a source-level contract,
not installed files; this dormant loader is an offline candidate, not a verified
production importer, guard decision, drop-in, installer or start permission.
A Python script cannot authenticate
itself before the interpreter has already read and executed its first lines;
the after-load metadata check is a tripwire, not a trust anchor. The private
package prevents path fallback for its own relative module names, but is not
a sandbox or proof that ambient standard-library modules, import finders,
compiler audit hooks, interpreter and startup environment are trusted. It
also cannot prevent pinned executed code itself from using arbitrary ambient
imports or mutating process state; integrity pins require independent review
of those bytes. The future
reviewed installation must establish root-controlled file provenance and
interpreter/stdlib trust *before* use, then make the exact guard failure block
the Dashboard `ExecStart`. The [systemd v257 service contract](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.service.xml)
states that an unsuccessful, non-ignored `ExecStartPre` prevents `ExecStart`;
no such command is configured here. Do not deploy this entrypoint alone: it
would intentionally prevent Dashboard startup. This also does not solve
service-mutable vendor-code changes after a pre-start check.

### Python import contract — offline, not runtime attestation

Four additional CI methods pin the direct absolute-import roots of each of
the thirteen proposed capsule sources, check relative imports remain in
dependency order, and reject recognized dynamic-import/execution call forms.
The module bodies have sixteen direct standard-library roots; the later
`operator_fs._identity()` path adds `pwd` and `grp`, for eighteen direct roots
in the possible guard call path. This catches source-contract drift, not
transitive imports, selected file origins, C extensions or a compromised
interpreter. The exact roots and outstanding external checks are in the
[Python runtime trust runbook](../../../docs/runbooks/rbac-guard-python-runtime-trust.md).
The owner has reported completed A/B1/B2/C1/C2/C3 diagnostics: candidate
metadata, system-Python package/import observations, source/cache metadata,
unprivileged redirected-cache/mapped-path observations and nine mapped files'
metadata/direct ELF declarations. System Python 3.14 is still a **provisional
diagnostic target**, not a selected guard runtime. None is independent
runtime attestation. The loader remains dormant and the entrypoint exits 1.

### Python mapped-file and launch-data policy — offline only

`operator_python_policy.py` pins the nine mapped files, seven package versions,
15 declared dependency edges and generated loader-cache hash reported at C3.
It validates the retained owner transcript and compares typed caller-supplied
metadata without I/O. A separate pure check constrains proposed interpreter
argv/cache redirection and an exact three-variable environment. Sixteen tests
exercise pin drift, partial/duplicate/malformed reports, false authority flags,
argument/environment injection and continued exclusion from the guard capsule.

This is not a native reader, a launch wrapper, package authenticity, complete
stdlib/native closure, an update lock or a proof of a fresh host observation.
The launch environment must be established by an independently trusted launcher
before interpreter startup; matching a Python-side data structure cannot do so.
No policy function executes a command, reads an environment/file or modifies
state. All returned runtime-trust/startup flags remain false. See the
[accepted C3 report and limitations](../../../docs/runbooks/rbac-guard-python-runtime-trust.md#c3-accepted-owner-report-and-offline-policy-26-september-2026).
The new module is intentionally not added to the pinned capsule or called by
the guard entry. No VM output is requested for this offline policy slice.

### Python fixed-file reader — dormant, not a runtime trust decision

`operator_python_runtime.py` adds a no-argument Linux/root-only reader for the
existing C3 byte pins and 49 C1 source pins. It makes two passes over the nine
mapped files, generated `/etc/ld.so.cache` and 49 standard-library source files,
bracketed by three reads of the fixed `/var/lib/dpkg/status` database: 121
bounded reads in total. Mapped/cache reads match exact size and SHA-256;
source reads match SHA-256 within a 1 MiB ceiling. C1 did not report source
sizes: that ceiling is a policy bound, not an observed exact size. Nothing
refreshes pins on drift; file bytes are not normalized before hashing.
The adapter reuses the unchanged root-owned descriptor-relative reader in
`operator_fs.py`, including no-follow opens and before/open/after metadata and
ancestor checks. There is no service-owner exception, NSS lookup, command,
network request, report replay, alternate root or caller-supplied pin.

The bounded status parser selects seven exact amd64 package names/versions.
It handles the unqualified `Package` field and separate `Architecture` field;
foreign architectures cannot substitute for amd64. Duplicate selected records,
malformed identity fields, changed versions and non-installed states fail.
An `install` or `hold` selection is accepted only with `ok installed`; the
selection is retained, so a change between snapshots fails too. Unrelated
field values never enter the result or error codes. See the
[dpkg-query field/status contract](https://manpages.debian.org/unstable/dpkg/dpkg-query.1.en.html).

This reads current **on-disk bytes and package status identities**, not the
package file-ownership registry, whole-package verification or signed package
authenticity. It compares the 49 reported source paths' bytes, but does not
establish that Python selected those origins, resolve ELF imports,
prove loaded code or establish the caller's launch environment. Two equal
passes are not an atomic snapshot or an update lock. Those proof flags and
`runtime_trusted`/`startup_authorized` stay false. The calling interpreter and
import environment must already be trusted by a separate mechanism; this
Python reader cannot bootstrap that trust.

Twenty-one tests cover the package parser, exact read order/bounds, every byte
pin drifting on either pass, package drift, sanitized errors, shared-reader
metadata failures and non-authorizing results. Two use Linux temporary-file
fixtures and are skipped on Windows; the portable tests use synthetic bytes
and fake descriptors, not a live VM or production-root trust proof. The module
is outside the thirteen-source capsule, not installed and never called by
the compile-only guard. No VM command is released by this implementation.

Seven additional source-pin tests reproduce the accepted C1 manifest, B2/C2
path sets and `_hashlib` overlap, and cover evidence integrity, every source
digest, index/type/size bounds and immutable pins. The retained
[C1 owner transcript](../../../evidence/rbac/python-runtime-c1-owner-report-2026-09-26.txt)
is historical evidence, not a fresh or independently captured VM observation.
Its 49 cache records are retained only as reported metadata; they are not
accepted as bytecode equivalent to the sources or code actually loaded.
The new source pins all name the already-covered libpython3.14-minimal amd64
package/version, so the package count remains seven. Source-pin coverage is
not complete import closure: unobserved function-local/dynamic imports, caches,
shadowing, import machinery and loader-input controls remain separate work.

### Python fixed-name inputs — dormant observations only

`operator_python_paths.py` adds `observe_python_path_inputs()`, a no-argument
root/Linux observer separate from the byte-pin reader and proposed guard:

- Two passes require `/usr/lib/python314.zip` and `/etc/ld.so.preload` to be
  absent. Any object, including an empty file, directory or dangling symlink,
  fails. Required ancestors are held through no-follow descriptors and must be
  root:root without group/other write permission. Missing ancestors are errors,
  not evidence that the optional child is safely absent.
- Both passes inspect `/dev/null` as a direct root:root character device with
  Linux major/minor 1:3. Normal 0666 or stricter rw-only permissions are allowed;
  execute, set-ID and sticky bits are rejected. These are explicit candidate
  policy requirements, not metadata claimed to have appeared in C3.
- The device is opened only with `O_PATH|O_NOFOLLOW|O_CLOEXEC`, never for
  payload reads/writes. Device numbers participate in before/open/after/name
  comparisons, as well as descriptor and ancestor metadata. A replacement
  between passes fails. Missing `O_PATH` support fails without a read-open
  fallback. OS failures become fixed codes; descriptors close on failure.

The [Linux null-device contract](https://man7.org/linux/man-pages/man4/null.4.html)
defines device 1:3 and usual writable permissions. The
[O_PATH contract](https://man7.org/linux/man-pages/man2/open.2.html) permits
metadata inspection without opening the device for I/O. A character-device
anchor cannot be traversed as a cache directory. This does **not** establish
that the running interpreter actually uses the proposed
`/dev/null/alertmind-c2` cache prefix. Likewise, absence of the
[global loader-preload file](https://man7.org/linux/man-pages/man8/ld.so.8.html)
does not establish the absence of environment-driven or earlier injection.

Fifteen tests exercise fixed paths/order, first/second-pass presence, symlink
and owner/mode/device failures, absence/name/descriptor races, metadata-only
open flags, cleanup and non-authorizing results. Two Linux-only tests use
temporary-tree absence fixtures and the test host's `/dev/null` metadata;
they need no VM or device-payload I/O and are skipped on Windows. Native
Linux execution remains necessary; portable fake-descriptor passes do not
substitute for it.

No complete import-search, cache-redirection, loader-environment, native-
resolution, loaded-code or atomic-snapshot proof is claimed. Runtime trust
and startup authorization remain false. Kernel/device semantics and the
caller's interpreter/import environment must already be trusted separately.
The byte adapter and this observer run independently, not as one coherent
snapshot. Neither is in the thirteen-source capsule, installed, or called by
the compile-only guard. No launcher, pin refresh or new VM gate is released.

### Python in-process import state — selected metadata only

`operator_python_import_state.py` adds a dormant no-argument root/Linux
observer, still outside the guard capsule. It reads the current process's
reported settings and selected module metadata twice, without file reads,
module imports, finder/loader calls, environment repair or process launch.

It requires the proposed CPython 3.14.4 executable/argv, isolation and no-site
flags, safe-path and no-bytecode settings, optimization level zero, the
three B2 search paths and C2's explicit cache prefix. These are candidate
requirements; the full combination has not been exercised on the VM. It
checks `sys.orig_argv` separately from script `sys.argv` and requires exactly
the proposed `pycache_prefix` X option. It does not read the environment.

All **50 selected file-backed modules must already be loaded**: the 49
C1-pinned sources plus `_hashlib`. Source paths determine the B2 dotted names;
`__init__.py` identifies six packages. Missing modules fail; the observer does
not preload them. A future reviewed initializer must arrange the call point.
For these modules it checks module/spec name and file/origin independently,
exact current source/extension loader types and object identity, loader
name/path, materialized cache paths, package search paths and parent-child
bindings. It inspects dictionaries, not lazy `ModuleSpec.cached` properties.
The three meta finders must match the current bootstrap classes by identity,
not just class-name strings. Selected module/spec/loader references are held
between passes to detect replacements without relying on reusable object IDs.

These checks use Python's documented [original argv and cache-prefix state](https://docs.python.org/3.14/library/sys.html)
and [module/spec metadata contract](https://docs.python.org/3.14/library/importlib.html#importlib.machinery.ModuleSpec).
Module and spec fields are mutable and not automatically synchronized. The
[import system](https://docs.python.org/3.14/reference/import.html) also uses
cached modules and path hooks; checking these selected fields is not a full
import-resolution proof.

Seventeen portable tests use synthetic Python module/spec/loader objects.
They cover settings drift, every selected source/origin/cache, finder identity,
package shadows, module/spec/loader replacements, malformed metadata, bounded
module tables, no subject execution and deliberately non-authorizing results.
They do **not** constitute execution on the selected Linux Python 3.14 runtime.

The result describes matching **reported settings and selected metadata**,
not authenticated machine code, bytecode or module functions. Other modules,
built-in/frozen provenance, `path_hooks`, `path_importer_cache`, native loader
resolution and the initial environment remain unproven. Even matching finder
identities are relative to the current mutable interpreter, not independent
authentication. Two passes do not lock state, attest earlier imports or
prevent subsequent changes. All runtime/startup authority flags stay false.
This does not compose the byte/path observers into a trusted guard or release
a new VM command; the entrypoint remains compile-only and exits 1.

### Python path hooks and cached importers — candidate metadata only

`operator_python_path_importers.py` is a separate dormant no-argument
root/Linux observer. It reuses the candidate runtime/settings checks and
examines `sys.path_hooks` and `sys.path_importer_cache` twice. It neither
loads missing modules nor invokes hooks, finders, loaders or cache invalidation.

The proposed policy requires the current ZIP importer class followed by the
current FileFinder factory's closure. Code-object/global-dictionary identity,
closure class and loader details are checked against current bootstrap objects.
It requires extension/source/sourceless loader order and the proposed release
Linux x86-64 suffixes (`.cpython-314-x86_64-linux-gnu.so`, `.abi3.so`, `.so`,
`.py`, `.pyc`). This follows the structure in
[CPython 3.14.4's path-import implementation](https://github.com/python/cpython/blob/v3.14.4/Lib/importlib/_bootstrap_external.py),
but is **candidate policy, not a B2/C2 observation or native compatibility proof**.

The importer cache may contain only the two stdlib directories, six selected
package directories and an optional negative (`None`) ZIP entry. Missing keys,
including an empty cache, are allowed without populating them. Present directory
entries must be exact current FileFinder instances with matching paths and
loader tables. Extra instance fields, including method overrides, fail closed.
Directory-name caches are type/size bounded; the Linux relaxed-name cache must
be empty. The two passes compare retained object references and copied directory
name/mtime values. No source/cache/device payload is read or modified.

Twenty portable synthetic tests cover hooks/closures, loader identity/order,
cache paths, instance-method shadows, bounded metadata, replacements and
between-pass drift. They do not run the selected Linux Python 3.14 interpreter.
The strict cache policy may need a separately reviewed adjustment for the final
initializer; it must never auto-learn paths or silently clear rejected state.

Matching mutable metadata is not authenticated hook code or actual resolution.
Directory caches can be stale or forged; no directory inventory is proved.
The default sourceless loader remains present: cache-prefix redirection does
**not** rule out standalone `.pyc` files or native modules shadowing sources.
Filesystem candidate exclusion, remaining module coverage, bootstrap provenance,
native resolution and externally trusted initialization/composition stay open.
No earlier/later or atomic snapshot is claimed. Runtime/startup flags remain
false; this observer is outside the capsule and unused by the compile-only
entrypoint. No VM command or deployment is released.

### Selected Python filesystem candidates — dormant fixed-name checks

`operator_python_candidates.py` adds a no-argument root/Linux observer for
the **50 selected file-backed module names**, not the whole standard library.
Its fixed policy derives 514 alternate names from the existing source/extension
origins, two directory search roots, six package paths and the prior candidate
suffix policy. It requires all selected origins to be trusted regular files
and rejects any object at the alternate names, including dangling symlinks,
directories and special files. Filesystem names are never auto-learned.

The checks cover sibling source, legacy standalone bytecode, three native
extension suffixes, same-name package directories and alternate package
initializers. This uses the candidate structure of
[CPython 3.14.4 FileFinder](https://github.com/python/cpython/blob/v3.14.4/Lib/importlib/_bootstrap_external.py).
The policy is deliberately stricter than resolution precedence: later fallback
peers and even empty same-name namespace directories are rejected. A collision
requires review, not deletion or automatic acceptance. This is proposed policy,
not a claim that these names were absent in the earlier VM diagnostics.

Eleven directory descriptors, including `/`, are held across two passes. All
ancestors are root-owned, no-follow, non-group/world-writable directories.
Selected origins receive no-follow metadata checks and across-pass comparisons;
each alternate receives an absence check in both passes. Directory names and
held descriptors are rechecked after each pass. There are no payload reads,
candidate-file opens, directory listings, NSS calls, subject imports or writes.
Extension size is pinned; sources use the existing 1 MiB ceiling. Byte hashes
remain the separate fixed-file reader's responsibility. Descriptors close on
success and failure, and OS errors use fixed diagnostic codes.

Twenty regression methods include exhaustive rejection of all 514 alternates,
both-pass object checks, every expected origin, unsafe ownership/symlinks,
descriptor/name races, errors and cleanup. Two Linux-only tests use disposable
trees, including a FIFO and dangling symlink, without reading their payloads.
Windows synthetic results are not native selected-runtime acceptance.

This does not enumerate or reject unrelated modules, authenticate built-in or
frozen code, check the ZIP input, prove effective cache-prefix use, or validate
native dependency resolution. Existing `__pycache__` files are deliberately
untouched; the separate cache-redirection controls remain necessary. Leaf
contents are not held or hashed here, and directory descriptors do not freeze
names or content. There is no earlier/future-import or atomic-snapshot proof.
It stays outside the guard capsule; runtime/startup authorization remains false.
No deployment command or additional VM output is requested.

### Built-in and frozen Python modules — dormant selected metadata checks

`operator_python_embedded.py` adds a no-argument root/Linux observer for the
36 built-in and 17 frozen `sys.modules` keys reported in B2. All subjects must
already be loaded. It reuses the candidate settings checks and takes two
bounded observations of module/spec names, origin, informational file, absent
cache/package-path metadata, loader class identity and parent bindings.
The current `sys` identity, selected builtin-name availability, ordered meta
finders and six public import-machinery class bindings must agree. Available
but unloaded builtins are allowed; this is not a whole-module-table allowlist.

Four alias pairs are explicit: the two frozen bootstrap aliases, `os.path` /
`posixpath`, and `collections.abc` / `_collections_abc`. Module and spec names
are checked separately: legitimate aliases need not have matching key/name/spec
strings. Retained object references detect replacements between passes.
The observer does not invoke import machinery, lazy cache properties, subject
imports, filesystem reads or repairs. Fixed diagnostic codes suppress raw data.

The [retained B2 projection](../../../evidence/rbac/python-runtime-b2-embedded-modules-2026-09-27.tsv)
contains only the owner's 53 built-in/frozen name/origin/file/cache rows. The
runtime does not load this historical file. Alias identity, loader identity,
module/spec/package names and builtin availability were **not recorded by B2**;
they are candidate policy based on the version-matched
[import bootstrap](https://github.com/python/cpython/blob/v3.14.4/Lib/importlib/_bootstrap.py),
[importlib initialization](https://github.com/python/cpython/blob/v3.14.4/Lib/importlib/__init__.py),
[collections initialization](https://github.com/python/cpython/blob/v3.14.4/Lib/collections/__init__.py),
[_collections_abc](https://github.com/python/cpython/blob/v3.14.4/Lib/_collections_abc.py)
and [os initialization](https://github.com/python/cpython/blob/v3.14.4/Lib/os.py).
Native Ubuntu Python 3.14.4 compatibility remains unverified.

Twenty portable synthetic tests cover the projection hash, aliases, every
selected name/origin/file, missing subjects, loaders, package/cache metadata,
parent/machinery bindings, type traps, replacement/drift, sanitized errors and
explicitly limited results. They also exercise the existing file-backed-module
observer against the same synthetic state; this is not a combined trust proof.

Matching mutable metadata cannot authenticate embedded code or bootstrap
functions. Frozen `__file__` is informational, not proof that source bytes ran.
The entry module, guard-private modules, remaining table coverage, native
resolution and externally trusted initialization/composition still need review.
No earlier/future import or atomic snapshot is attested. All trust/startup flags
remain false. The observer is outside the capsule and not called by the
compile-only guard. No VM output or deployment is released by this package.

### Entry/private modules and closed table — dormant pure policy

`operator_guard_entry.py` now contains `_check_module_table()`, an offline
policy function over caller-supplied module objects and, for the held phase,
the supplied held-loader registry. It adds **no imports** and is not called by
`_check_entry()`, `main()` or the held loader. The entry still compiles only and
always exits nonzero. Successful policy checking returns `None`, not a permit.

There are two explicit candidate call points:

- **Prepared:** exactly the 103 selected B2/C1 stdlib keys plus direct-file
  `__main__` (104 keys). All are required, not optional or auto-imported.
- **Held:** the same keys plus exactly `_alertmind_guard_held` and its thirteen
  pinned children (118 keys). The registry must contain those fourteen private
  keys and refer to the identical module objects. Partial bundles fail closed.

The policy rejects extra or substituted keys, non-module values, broken aliases
and shared identities except the four declared stdlib alias pairs. Entry file,
package/spec/cache metadata, current SourceFileLoader identity/name/path, known
entry import bindings and builtins identity are checked. The candidate direct
script shape follows [CPython 3.14.4's file runner](https://github.com/python/cpython/blob/v3.14.4/Python/pythonrun.c)
and [Python's `__main__` specification](https://docs.python.org/3.14/reference/import.html#special-considerations-for-main);
it is **not** the `<stdin>` entry recorded by B2 or a verified guard launch.

Prepared meta finders must be the three default classes. Held state additionally
requires the entry's deny-fallback instance first, with no instance overrides
and matching function globals/filename/default metadata. No finder is called.
The private package has an empty tuple path, no filesystem loader/spec, and
exact child bindings. Children have the held compiler's synthetic filename,
private package/name, no loader/spec/cache/path, and the supplied builtins
dictionary. These shapes follow the existing held loader, not a new importer.

Two passes retain module, entry-loader, registry, parent, finder and relevant
binding references; fixed diagnostics reject replacement or selected metadata
drift. No source is loaded, compiled, imported or repaired by this checker.
Twenty-three regressions include exhaustive missing/substituted-key checks,
both phases, private children, alias/binding/metadata errors and drift. One test
uses the actual existing held loader's thirteen pinned sources in the trusted
local test interpreter, inserting only its private objects into synthetic
candidate state. It is not a native Ubuntu guard/process acceptance test.

The closed-table checker alone does not initialize the interpreter. A dormant
fixed preparation routine is now described below; the trusted call point is
still absent. The pure table-checking function
does not acquire live `sys.modules`, establish that a supplied registry came
from verified bytes, or attest stdlib globals, function code, bootstrap or
earlier/later imports. The selected-origin, hook and byte observers are **not
automatically composed** here. In particular, the older import-state observers
expect the three-finder prepared state; do not invoke them unchanged while the
held deny-finder is present, or remove that finder to make a check pass.
Future composition must define the call order without creating a trust gap.
Two equal passes are not atomic. No startup, installation or VM step is released.

### Python native mappings — dormant current-process observer

`operator_python_native.py` adds `observe_python_native()`, a no-argument
root-Linux observer outside the capsule. It reads only its own numeric PID's
`maps`, `map_files` and `exe`, plus the nine canonical C3 paths. No external PID,
reader, transcript, alternate root or pin override is accepted by that API.
The kernel/procfs and the already-running interpreter must be trusted separately.

The bounded parser requires precisely the nine file paths, consistent device/
inode identities, page-aligned sorted non-overlapping segments within rounded
file bounds, a readable offset-zero and an executable segment for each file.
It checks non-executable file segments too. Unknown/deleted/escaped paths,
memfd, shared mappings, writable-executable regions and anonymous executable
regions fail. Explicit kernel names have candidate permissions; only `[vdso]`
and optional `[vsyscall]` may be executable without a backing file. Their bytes
are not checked. The 4-KiB x86-64 policy and segment assumptions need native
acceptance; C2/C3 did not record these detailed fields.

The [Linux maps format](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
defines device/inode and optional path fields. Anonymous trailing padding is
handled according to the [kernel's maps producer](https://github.com/torvalds/linux/blob/v7.0/fs/proc/task_mmu.c).
No pathname unescaping or generic bracket-name exception is used.

Canonical files/ancestors are held via root-owned no-follow descriptors.
For each file, one deliberately followed kernel
[`map_files` magic link](https://man7.org/linux/man-pages/man5/proc_pid_map_files.5.html)
opens the actual backing object. Its metadata/identity must equal the held
canonical object, and every segment's link is checked before and after hashing.
The returned link text is never used as an open path. Lack of permission for
this procfs operation fails closed; there is no pathname-only fallback or
request to broaden capabilities. The interpreter's `exe` identity must match.

Two streaming byte-pin passes are bracketed by four maps reads. File segments
and kernel executable extents must agree; selected metadata/names/ancestors
are rechecked and descriptors close on success or error. Non-executable
anonymous extents can grow during allocation and are intentionally excluded
from equality, though each fresh parse still checks their permissions.

Thirty tests cover exact selection, permission/range/type/size boundaries,
all digests, link/descriptor substitution, cross-pass drift, denied access,
fixed diagnostics and cleanup. One Linux-only temporary-tree test exercises
actual no-follow syscalls with test-owner policy, not VM/root-runtime acceptance.
The remaining tests use a synthetic descriptor tree and synthetic byte pins.

`mapped_backing_pins_match` is not memory or full native-resolution proof.
Relocations, private COW changes, symbol bindings, previously unloaded code,
future loads and bootstrap execution are not established; neither are an atomic
snapshot or signed package provenance. Loader environment/search/cache behavior
must be constrained before startup by a separately trusted launch boundary;
see [the dynamic loader's search rules](https://man7.org/linux/man-pages/man8/ld.so.8.html).
All runtime/startup/provenance flags remain false. No memory inspection, library
loading, `ldd`, shell, network, credential, write or activation is performed.
No new imports were added to the entry and its thirteen capsule pins are intact.
The entry remains compile-only and exits 1. This adapter is not wired into it.

### Fixed stdlib preparation — dormant entry routine

`operator_guard_entry.py` now contains `_prepare_stdlib()`. It imports precisely
the eighteen direct roots in the original B2 order, including `sys` first and
the deferred `pwd`/`grp` roots. Merely importing those built-ins does not perform
NSS user/group lookups. The function is **not called** by `main()`, `_check_entry()`
or the held loader. Its API accepts no root list, callback or approval flag and
success returns `None`, not startup permission.

Before the first import and after each root, it requires the proposed direct
entry, isolated root CPython 3.14.4, exact candidate argv/search/cache settings,
working directory `/` and the three-value environment already documented in
the launch-data policy. It observes those settings; it never repairs them.
The initial table may be a subset of the fixed prepared keys, but never contain
site/project/private/unknown entries or non-module values. Entry bindings and
metadata, default meta-finder identities, the current builtin import function
and stable path-hook identities are checked. Existing module objects may not
be removed or replaced; imports may only grow the declared table.

The returned root must be its identical `sys.modules` object. After all eighteen
imports, the existing exact 104-key prepared-table policy must succeed, followed
by a final settings/identity check. A failure stops immediately, with no retry,
automatic deletion of partial imports, rollback claim or capsule execution.
Subject exceptions (including SystemExit and a subject-raised GuardLaunchError)
become fixed diagnostics. The eventual caller must abandon the failed process.

Unlike the earlier metadata-only observers, this routine **can execute stdlib
and native import-time code** if explicitly called in a matching runtime.
Python's [import function](https://docs.python.org/3.14/library/functions.html#import__)
uses the current import machinery; [isolation flags](https://docs.python.org/3.14/using/cmdline.html#cmdoption-I)
do not authenticate it. Interpreter/source/native-loader/bootstrap trust must
therefore be established by a separately trusted launcher **before entry code
runs**. Checking the current environment cannot undo earlier loader inputs.
Current finder/hook identity is not hook-code or source-byte authentication.
One regression explicitly demonstrates that preparation does not replace the
separate origin/hook/byte observers.

Twenty-five synthetic tests cover the recorded import sequence, launch settings,
progressive table growth, identity drift, per-root failures, exception privacy,
final exact-table enforcement and dormant entry behavior. They rebind the actual
entry functions into fixture globals and stub the private import operation;
they do not run initialization on the VM or validate its exact native import
closure. No additional top-level import, capsule source/pin or launch command
was added. Externally trusted launch and phase-aware observer/capsule composition
remain to implement. Do not drop the held deny-finder to satisfy prepared-phase
checks. The entry remains compile-only, always exits 1 and is not deployable.

## Required next adapter package — not released here

1. Establish selected packaged Linux runtime and real Server certificate
   suitability without broker credentials; agree the 30-second timeout and
   performance acceptance criteria. Preserve the current public fingerprints.
2. Review the root-controlled manifest/certificate loader and rerun native Linux
   traversal tests after shared-primitive changes. The non-deployable guard
   entry and pinned capsule candidate exist, but trusted interpreter and
   verified-byte import bootstrap, a complete guard decision and deployment
   wiring remain to implement. Preserve
   the distinction between root-controlled trust and service-mutable vendor code.
   Two equal byte passes cannot prevent edits after checking or attest running
   code. Verify the installed dependency resolution/file set too: matching listed
   files alone does not exclude an extra module or a changed resolution path.
3. Review the fixed launch-file, explicit unit-source and manager-export
   observers, then inspect remaining service-generated and wrapper-created
   environment, prefix options, selected conffile, full launch/dependency
   resolution and single broker host privately. No arbitrary executable
   override, fallback Node or `NODE_OPTIONS` preload may bypass the intended
   guard. Do not export secrets.
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
