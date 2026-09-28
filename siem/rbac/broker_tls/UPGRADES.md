# Maintenance lifecycle and upgrade planning — offline only

`operator_maintenance.py` is a pure planner, not a collector, installer,
package manager or startup guard. It performs no I/O, accepts no journal
position, emits no commands and never authorizes mutation or startup. Inputs
are caller-supplied claims; setting them to true is not evidence. No populated
production baseline is shipped and no new VM operation is released.

The companion `operator_maintenance_state.py` now implements a dormant, read-only
observer for the exact persistent mask and systemd-reported state. It does not
supply the planner's complete observation or clear a maintenance gate. Durable
inhibition as a complete transaction, process-quiescence proof,
backup/install/recovery and final service admission remain unimplemented;
native compatibility is not yet accepted.

`operator_maintenance_cgroup.py` now adds a separate dormant observation of the
fixed Dashboard cgroup-v2 tree, including boot identity and suspend-inclusive
collection timing. It does not close the outside-unit process or exclusivity
requirements, supply the planner's complete input or authorize a live step.

`operator_maintenance_lock.py` adds a held, nonblocking **cooperative** lock.
It coordinates callers using the same fixed inode; it is not host-wide exclusive
maintenance control. It is privately composed with inhibition, not the final planner/executor.

`operator_maintenance_processes.py` adds a bounded read-only process-leader
census for service-credential and packaged-Node-path matches outside the unit.
It detects known candidates, not every possible Dashboard copy or full shutdown.
Its public entry now runs inside `operator_maintenance_namespaces.py`'s held,
rechecked namespace window. Alignment with visible PID 1 is not host attestation.

`operator_maintenance_packages.py` adds a dormant record-lock barrier for the
four default APT/dpkg lock inodes. It is for observation/backup, not for running
an upgrade. Installed package configuration, host launch and service-start
controls remain unverified; no maintenance or startup permission is supplied.

`operator_maintenance_inhibit.py` implements the private disk portion of
persistent masking with disposable-tree tests. Its public entry always refuses
before I/O. No live executor, manager reload/stop or complete inhibition is released.

`operator_maintenance_manager.py` adds the private ordered reload/stop/readback
sequence with mocked systemd tests. Its public entry also refuses before I/O.
`operator_maintenance_control.py` now privately composes the namespace and lock
lifetimes around disk preparation and that sequence. This is not the external
authorization/host launch boundary, an installer or a released VM operation.

`operator_maintenance_effects.py` now checks selected loaded-unit stop effects
before private mask preparation, again before reload, and after reload before
stop. It does not establish the complete installed-effect or authorization boundary.

## Default-path generator inventory — evidence only, not reload admission

`operator_maintenance_generators.py` adds dormant, no-argument read-only
observers outside the guard capsule and maintenance executor. The unit class
inventories four fixed candidate directories in order: `/run/systemd/system-generators`,
`/etc/systemd/system-generators`, `/usr/local/lib/systemd/system-generators`,
`/usr/lib/systemd/system-generators`. The environment class separately inventories
`/run/systemd/system-environment-generators`,
`/etc/systemd/system-environment-generators`,
`/usr/local/lib/systemd/system-environment-generators`, and
`/usr/lib/systemd/system-environment-generators`, in that order. It never runs a generator, calls systemd,
imports observed code, reads credentials or inspects PID 1's environment.
The [upstream generator manual](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.generator.xml)
and [environment-generator manual](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.environment-generator.xml)
describe default precedence and reload execution; those are contract references,
not proof of the installed manager's compiled paths or behavior. Upstream
[manager source](https://raw.githubusercontent.com/systemd/systemd/main/src/core/manager.c)
runs environment generators before unit generators and passes a derived manager
environment to the latter. This inventory does not read or prove those values.
That source also has an unsandboxed fallback for some namespace-fork failures;
no sandbox property of the installed VM is inferred from upstream defaults.

The result records directory presence and every immediate entry's name, type,
size, mode, owner and SHA-256, including earlier same-named directory indices.
Regular files are hashed as bytes; symlinks are hashed as link text and never
followed. `/dev/null` link text is distinguished from other unresolved links,
but its target is **not verified**. Empty regular files and non-executable files
remain visible. Hidden/backup names are included, not silently filtered.
`earlier_same_name` is calculated **within each class** and means only
default-directory name precedence, **not** a
selected executable, effective mask or invocation order. This avoids claiming
that a non-executable or unresolved earlier entry necessarily overrides code.

Only root:root ancestors/directories and regular files without group/world
write or set-ID bits are accepted. Root-owned symlinks may have the usual 0777
link mode; no target trust is inferred. Directory traversal is descriptor-relative
and no-follow. An absent component is recorded only for ENOENT and rechecked;
denied access, symlinked ancestors and unexpected leaf types fail closed.
There is no recursive descent into discovered entries, caller-selected path,
alternate-root public API or package/provenance subprocess.

Two full passes compare private file and ancestor stamps as well as bytes/link
digests. Names, opened descriptors and ancestors are rechecked; cleanup failure
prevents success. The combined catalog observes both classes through one held
root FD and one same-caller window; each complete pass shares a 256-entry and
64-MiB budget across all eight default directories, including shadowed entries.
The two single-class APIs retain the same limits for their four paths. Bounds
are 16 MiB per regular file and 4096 bytes per link text. Streaming reads are
at most 64 KiB. PID/native-thread and
suspend-inclusive BOOTTIME checks reject changes or elapsed time >=30 seconds.
This is an elapsed-result bound, not a watchdog for blocking filesystem calls.
Two equal passes are not atomic and do not exclude later privileged writers.

Each class has its own version-1 canonical inventory digest binding ordered
paths, presence, public
metadata and typed content/link hashes; elapsed time and inode/timestamp stamps
are excluded from those portable digests but stamps must agree during collection.
The combined catalog has a separate digest binding the two class digests and
refuses a change in either class. Scan order is not execution order.
No file contents, link targets or raw errors are emitted. All effective-path,
selection, target verification, effects, dependency/provenance, atomicity,
continuous-control and authorization flags stay false. In particular an empty
environment-generator directory does not prove an empty generated environment.
Fifty-three tests cover the candidate; eight use disposable Linux trees and are
skipped on Windows.

**Next:** bind an independently reviewed installed search-path/selection and
content baseline, resolve any relevant generator links and review selected
code/interpreters/tools/dependencies and their package-lock interactions before
connecting a fresh check ahead of private mask/reload. A default-path inventory
cannot supply this authority, nor can empty results or auto-learning pins.
Actual environment-generator **selection, output and downstream effects**,
other manager-wide reload behavior and indirect unit-graph effects still need
review. This package releases no VM command or deployment.

### PID 1 initial generator-path override check — narrow evidence only

`operator_maintenance_generator_overrides.py` adds a separate dormant,
no-argument, read-only candidate. It checks only whether the exact names
`SYSTEMD_GENERATOR_PATH` and `SYSTEMD_ENVIRONMENT_GENERATOR_PATH` occur in
PID 1's **initial** `/proc/1/environ` data. [systemd's environment contract](https://github.com/systemd/systemd/blob/main/man/systemd.xml)
allows these names to replace or extend the usual generator search paths.
The [Linux procfs contract](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)
says this file need not reflect later environment changes and may be redirected
by the process; an absent name here is therefore **not** proof of its current
`getenv()` state or effective paths. The existing `Manager.Environment` check
is a different property and does not close that gap.

The candidate requires root/Linux, a validated procfs mount without a numeric
PID submount, root-owned non-kernel/non-zombie PID 1, a present executable
link, a fixed bounded descriptor-relative `/proc/1/environ` read, two equal
snapshots and one suspend-inclusive 30-second same-caller window. It rejects
either override name and malformed/oversized/changing data with fixed error
codes. The environment bytes are necessarily read into the observer process;
they may contain secrets, are never logged/returned or included in an error,
and Python memory erasure is **not** guaranteed. Do not paste, export or save
`/proc/1/environ` to run this check. No caller-selected path, shell, systemd
request, generator execution or manager mutation is used.

The result exposes only boot ID, PID 1 start tick, elapsed time and explicit
non-authorizing flags. It does not establish that PID 1 is the installed
systemd binary, compile-time vendor directories, current manager environment,
effective generator search paths/selection, host identity, atomicity or
continuous control. Twenty-four tests include one disposable Linux fixture;
that fixture is skipped on Windows. This observer is not connected to the
catalog, guard, executor or planner. It releases **no VM command**; native
compatibility and a separate installed-binary/path baseline remain to be
reviewed before any live collection or pre-reload binding.

### PID 1 executable and local dpkg-claim inventory — evidence only

`operator_maintenance_pid1_image.py` adds another dormant, no-argument,
read-only candidate outside the guard and executor. The fixed candidate path
`/usr/lib/systemd/systemd` appears in [Ubuntu's resolute systemd package file
list](https://packages.ubuntu.com/resolute/all/systemd/filelist); that public
listing is **not** the VM's installed package baseline. A different running
path, including a deleted or relocated binary, fails closed rather than being
learned automatically.

The collector checks the visible PID 1 procfs mount, root UID/GID, non-kernel
and non-zombie state, start tick and boot ID. It checks the exact `/proc/1/exe`
link text before following that kernel magic link, then compares the opened
running executable's inode metadata and complete bounded bytes with the fixed
root-owned on-disk file. Fixed descriptor-relative reads also check the local
`/var/lib/dpkg/status` record for one installed amd64 `systemd` package and
that `/var/lib/dpkg/info/systemd.list` names the candidate path exactly once.
Only the candidate path, image SHA-256, local dpkg-claimed version, boot/start
identity and elapsed time leave the collector; raw records and bytes do not.
Two equal passes run in a same-caller, suspend-inclusive window under 30
seconds. They are **not atomic** and no package-manager lock is held.

The dpkg database is a local claim, not authenticated package provenance.
There is no independently reviewed expected image digest or version in this
module, and no assertion about the installed VM, loaded code, current manager
environment, compiled generator paths, selected generators, host namespace or
future mutations. All of those and startup/mutation authorization remain
explicitly false. The collector calls no package manager or systemd process,
performs no write, and releases **no VM command**. Twenty offline mocked tests
cover the parser, fixed reads, process/disk comparison, drift and sanitized
errors; native installed behavior still requires separate review.

### PID 1 image reference comparison — offline candidate contract

`operator_maintenance_pid1_reference.py` parses a small, exact-schema public
reference containing the fixed candidate path, `systemd`/`amd64` identity,
expected executable SHA-256 and expected local dpkg-claimed version. It does
not include an installed value: a separately reviewed reference and its
provenance must be retained and pinned outside this module. Its canonical
SHA-256 identifies reference *content*, not approval. The pure comparator
validates the observation's complete public shape and non-authorizing flags,
then rejects any image-digest or version mismatch with a fixed diagnostic.
It accepts no path override, performs no file/process/package read or write,
and is not connected to the guard, catalog, controller or reload sequence.

A match says only that two caller-supplied candidate records agree. Either
record can be forged by an untrusted caller; a dpkg status/list claim is not
package provenance. The result keeps reference provenance, observation
authenticity/freshness, package authenticity, effective generator paths,
mutation and startup authorization explicitly false. Thirteen offline tests
cover malformed/duplicate/extra fields, exact identity, drift, forged public
claims and the no-live-wiring contract. Native inventory compatibility, an
independently reviewed VM image/package reference, current effective path
source and manager-wide effects remain prerequisites before a live gate.

## Selected stop-effect checks — not complete manager-effect proof

The separate fixed-property reader queries 33 properties on the existing
Dashboard Unit and Service interfaces, without loading a unit or opening paths
returned by it. Its strict parser rejects missing/unknown record fields, wrong
types, duplicates, invalid text, unsupported properties and oversized replies.
Two complete snapshots must match; neither is returned or persisted. Commands,
arguments and related-unit names remain private; errors use fixed codes.

The conservative candidate requires no `ExecStopEx` or `ExecStopPostEx` hooks;
empty `RequiredBy`, `RequisiteOf`, `BoundBy`, `ConsistsOf`, `PropagatesStopTo`,
`OnFailure`, `OnSuccess`, `TriggeredBy`, `Triggers` and `UpheldBy`; and `none`
for `FailureAction`, `SuccessAction`, `StartLimitAction` and `JobTimeoutAction`.
It rejects aliases/following/transient units, unknown/transitional states,
pending jobs, a control PID or refusal of manual stop. The field signatures
come from upstream [Unit properties](https://raw.githubusercontent.com/systemd/systemd/main/src/core/dbus-unit.c)
and [Service properties](https://raw.githubusercontent.com/systemd/systemd/main/src/core/dbus-service.c).
OnSuccess/OnFailure can activate other units; the selected inverse and explicit
edges matter to stop propagation and reactivation. See [unit semantics](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.unit.xml).

The selected kill policy is deliberately narrow: `control-group`, initial
SIGTERM (15), final SIGKILL (9), SendSIGKILL true, SendSIGHUP false and
TimeoutStopFailureMode `terminate`. Other configurations stop for review; this
does not change any installed setting or prove that the VM satisfies this
candidate. These controls govern configured signal behavior, not proof that
all processes actually exit. See [kill properties](https://raw.githubusercontent.com/systemd/systemd/main/src/core/dbus-kill.c)
and [kill semantics](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.kill.xml).
Existing cgroup/census postchecks remain mandatory and keep their limitations.

Checks are connected in the private composition at three phases:

1. With all namespace/lock controls held, before opening the root for mask work.
2. Immediately before manager reload, after the persistent disk mask exists.
3. After masked-manager readback and before the stop request.

Only phase 2 permits NeedDaemonReload=true, because mask preparation may cause
it. Phase 3 additionally requires LoadState=masked. A fresh read is made at
each phase; cached observations cannot substitute. A check failure before mask
preparation prevents that write. Failure after masking retains the mask; failure
after reload prevents stop but does not undo/cancel the reload or other jobs.
Masked/unloaded property unavailability fails closed, without unmask/load fallback.

The new queries use only fixed `busctl get-property` argv, close unrelated FDs,
discard stderr, bound each reply to 64 KiB and each query to five seconds, and
poll with checkpoint checks at most 250ms apart while waiting for pipe readiness.
Exit/cleanup and same-caller BOOTTIME checks must pass before accepting results.
This is not a watchdog, and pipe/wait checkpoints do not make every syscall
interruptible. The whole composed window remains 30 seconds; the extra reads
do not extend it. Native timing and JSON/property availability remain unverified.

**Still open:** global daemon-reload generators and their interpreter/tool
dependencies, indirect dependency effects (including other units' unneeded-stop
behavior), unit-file/package authenticity and continuous external writer/start
exclusion. Empty selected edges are not a complete dependency graph, a review
of signal handlers in existing processes, package-lock compatibility or target-only
side-effect proof. Loaded metadata does not replace reviewed on-disk sources.
No host/downtime authorization or planner Boolean is inferred. Public mutation
entries remain blocked, and existing guard/capsule sources and pins are unchanged.

Thirty-five mocked tests cover parser/policy/transport failures, changed readback,
cleanup, all three private integration points and the actual collector composed
with private sequencing. They never access a real service bus or execute a
manager action; they are not installed-version or VM acceptance. The public
read-only observer has no CLI/target overrides; no live command is released here.

## Held-control composition — private and non-authorizing

`run_maintenance_inhibition()` always raises `CONTROL_NOT_RELEASED` before I/O.
The private `_inhibit(boundary_checkpoint=...)` seam acquires, in fixed order,
namespace alignment, the cooperative lease and all four package record locks.
It checks selected stop effects, then opens the fixed root, prepares/synchronizes the mask and runs the existing
reload/stop/readback sequence. One lifetime-bound checkpoint is passed to both
operations. There is no caller-selected command, path, resource list, saved
receipt, package invocation or planner dispatch.

Every acquired resource is freshly checkpointed after acquisition and before/
after protected phases; the manager wait loop invokes the same checkpoint.
The dedicated caller PID/native thread, boot/capture identity, nondecreasing
namespace elapsed time and whole-window BOOTTIME are checked. A changed lease,
revoked boundary, unexpected observation type, namespace drift or reentrant/
escaped checkpoint fails closed. Partial acquisition unwinds in reverse order.
Root close, each resource's own successful-exit checks and final lifetime checks
must all complete before returning any result. Failure does not retry, reacquire,
remove a mask/lock file or start a service. Cleanup releases advisory resources;
the result describes a **completed window**, never currently held controls.

The outer budget is **30 seconds**, preserving the existing namespace limit,
including acquisition, disk work, manager operations, observations and cleanup.
It is stricter than the standalone manager's 180-second budget. No rolling renewal,
fresh-window reset or implicit timeout increase is allowed. Slow/stalled operations
fail rather than stretching this contract. This is a candidate check-based limit,
not a kernel watchdog or deadline-interruptible filesystem I/O; installed latency
needs measurement before release. BOOTTIME is not converted into planner time.

### Explicit fixed-child exception

The cooperative/package/namespace handle contracts now explicitly permit only
the existing fixed busctl property readers and the fixed systemctl reload/stop
clients inside this private composition. All use `close_fds=True`, no `pass_fds`
or `preexec_fn`, fixed command/cwd/environment, bounded wait/cleanup, and never
receive or operate a Python handle. No raw fork, descriptor duplication/passing,
controller exec, arbitrary child program, APT/dpkg transaction or handle delegation
is permitted. This is a scoped change from the earlier blanket cooperative-lock
no-fork wording, not a general process-launch API.

Python may internally fork/exec or spawn; `close_fds` closes nonstandard FDs
**before exec**, not necessarily at the instant of process creation. Existing
held descriptors remain close-on-exec and the parent retains ownership throughout.
No Python pre-exec callback may manipulate shared open-file descriptions. See
[Python subprocess](https://docs.python.org/3/library/subprocess.html) and
[Linux flock lifetime](https://man7.org/linux/man-pages/man2/flock.2.html).

Thirty-two tests cover composition, partial failure, cleanup, deadlines and
revocation; two are Linux-only disposable-file/child fixtures. Those substitute
an isolated Python probe for the asserted fixed systemctl request: they check
that even an intentionally inheritable sentinel FD is closed in the executed
child, that parent flock/OFD locks still block independent acquisitions, and
that timeout cleanup reaps the child without unlocking the parent. They never
run systemctl or real package locks and do not establish VM compatibility.

### Controls this does not establish

The private boundary callback returns `None` by contract, **not approval**. A
future trusted launcher must independently establish owner downtime, intended
host/runtime, continuous noncooperating writer/start-path control, installed
tool/generator/unit/hook/dependency effects and package-lock path compatibility.
The public refusal cannot be bypassed with a callback or environment setting.
Private Python methods are not a sandbox against arbitrary trusted-code misuse.

In particular, manager reload may run generators and stop may propagate jobs or
execute hooks; their installed dependencies must not deadlock against the package
barrier. Killing a client does not cancel its manager job. If cleanup/reaping or
any phase fails, no success escapes, but running jobs may outlive this window;
keep inhibition and require fresh reconciliation under renewed external controls.
The two advisory locks still do not exclude arbitrary privileged/service-owned
writes, and visible-PID1 alignment is not intended-host attestation. No full
process-quiescence, exclusivity, package/mutation/startup permission is promoted.
Disk/manager public entries, guard pins and final startup refusal are unchanged.

## Manager reload/stop/readback — live entry blocked

`establish_maintenance_inhibition()` always raises `MANAGER_NOT_RELEASED`.
The private `_sequence(checkpoint=...)` is not an operator API, authorization
boundary or planner dispatcher. It accepts no saved mask result, census result,
journal, or caller-provided state as evidence. A future controller must first
authorize downtime, establish the intended host/runtime and continuous writer/
start-path control, compose held locks, and prepare/synchronize the disk mask.
Returning `None` from a callable checkpoint does not establish these controls.

The private sequence freshly reads the exact persistent mask and boot identity,
then requires two equal manager snapshots with no pending unit job, no triggering
units, a known stable active/inactive/failed state and the fixed cgroup path.
It performs, in order:

1. Fresh selected stop-effect check, then fixed synchronous system-manager daemon reload.
2. Fresh equal manager reads reporting both persistent mask states and no reload
   pending. A successful client exit alone is insufficient.
3. Fresh selected stop-effect check, then fixed Dashboard stop request with `--job-mode=fail`, not replacement/force or
   dependency suppression. A nonzero client result is a failure even if the
   service happens to look inactive afterward.
4. Fresh equal masked/stopped manager reads, zero main/control PIDs and no job;
   empty fixed-cgroup observation; zero-match namespace-aligned candidate census;
   another empty fixed-cgroup observation and unchanged terminal manager reads.

Only `/usr/bin/systemctl` with the two fixed argument lists is spawned. The
child has closed inherited descriptors, fixed cwd/environment, no shell or
interactive authentication, and discarded stdin/stdout/stderr. Its root-owned
tool/ancestor metadata is checked, like `busctl`; this is **not** package
authenticity, native-library closure or protection from a hostile root. Toolchain
trust must be supplied by the future launch boundary.

Reload affects the **whole manager**, rerunning generators and rebuilding unit
dependencies; it is not a Dashboard-only operation. Stop may execute unit hooks
and propagate dependency jobs. The selected job mode is not a universal
conflict/exclusivity guarantee. Installed generators, unit/hooks/dependencies,
tool versions and their effects require review and disposable-clone validation
before deployment. ([systemctl semantics](https://raw.githubusercontent.com/systemd/systemd/main/man/systemctl.xml))

The same PID/native thread, caller checkpoint, same boot, unchanged disk-mask
token and monotonic-in-boot elapsed time are checked between phases and during
client waits. Candidate budgets are 30 seconds for reload, 60 for stop and 180
for the sequence, using suspend-inclusive `CLOCK_BOOTTIME`; client waits poll
at most every 250 ms. These are not a kernel watchdog or measured VM budgets;
individual filesystem/creation calls are not made deadline-interruptible. Each
observer must return a same-boot timestamp within its actual call window and
at most 30 seconds of collection time. No conversion to planner monotonic
claims or replayable admission receipt is introduced.

Timeout, checkpoint revocation, interrupt, late/nonzero exit or failed cleanup
aborts. Only the owned systemctl child is killed/reaped if needed; this **does
not cancel an already-submitted manager job**, stop its hooks, or undo reload.
No automatic retry, cancel, mask removal, recovery write or service start is
issued. Keep inhibition and reconcile fresh manager/job/host state before a
separately authorized recovery. An unobservable masked/unloaded service still
fails closed; it is never explicitly loaded or unmasked to obtain properties.

The immutable result reports scoped observations only. Candidate-count zero
still misses the census's documented copied/renamed/nonleader cases, and reads
are not atomic. Full quiescence, exclusive control, host attestation, reboot
persistence, mutation and startup authority remain false. The existing guard,
planner contracts are unchanged. The private held-control composition above
documents the exact fixed-child exception to the original no-fork wording;
it is not a general permission to fork or pass lock handles.
Forty-four offline tests and eight in-memory negative mutations cover this
slice; no real systemd command, VM action or new native acceptance is claimed.

## Separate the lifecycle contracts

| Phase | Required boundary | Current implementation |
| --- | --- | --- |
| Maintenance / recovery | Owner downtime approval, exclusive control, persistent inhibition, stopped Dashboard, fresh inventory and verified source backup | Planner rejects missing claims; mask/manager, fixed-cgroup, process-leader census and cooperative/package-lock primitives do not constitute admission. |
| Guarded service start | Exact reviewed unit/hook and activating-state contract; trustworthy fresh guard observations before broker execution | Not implemented. Existing empty-hook/no-drop-in baseline must not be widened implicitly. |
| Live acceptance | Actual broker TLS, effective process context, human/admin reads and denials | Separate pending acceptance; not inferred from an offline PASS. |

The existing connected entry remains unchanged and always exits 1. It requires
no auxiliary commands/drop-ins and does not accept `activating`; installing it
as an `ExecStartPre` hook now would not work. Upstream systemd runs `ExecStart`
only after successful, non-ignored pre-start commands. A future hook must not
ignore failures or move verification after broker execution.
([systemd.service source](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml))

Persistent inhibition and stopped-process proof are separate requirements.
Disabling a unit is not equivalent to masking it; a runtime mask ends at reboot,
and masking without stopping does not establish that the process has exited.
([systemctl source](https://raw.githubusercontent.com/systemd/systemd/main/man/systemctl.xml))

The exact persistent-mask disk primitive is implemented privately below, but a
complete authorized transaction is not. The read-only observer understands the
intended symlink and manager mask state without changing either.
A masked/unloaded unit may not expose the properties
needed for a complete read; that fails closed, without loading or unmasking it.
Final start admission needs its own reviewed lifecycle policy. The existing
steady-state observers and capsule pins are unchanged.

## Persistent-mask disk preparation — live entry blocked

`prepare_maintenance_inhibition()` unconditionally raises `INHIBIT_NOT_RELEASED`
before any I/O. There is no CLI, environment switch, force flag or receipt that
enables it. The private `_prepare_at` seam is for disposable tests and future
trusted controller wiring only; it is not an operator command or security sandbox.
It requires a caller-held root descriptor and fresh checkpoint function. A
callable returning `None` is a sequencing contract, **not proof of approval,
lock ownership, host identity or exclusive control**.

The only disk target is `/etc/systemd/system/wazuh-dashboard.service`, with
literal symlink contents `/dev/null`. Existing trusted directories are opened
no-follow and held; the null device is checked with the existing metadata-only
anchor reader. No parent directory is created. An absent leaf is created using
descriptor-relative `symlink`, whose no-overwrite behavior closes the absence/
creation race. An `EEXIST` race is rejected even if the other writer installed
the expected mask; it is not adopted mid-transaction.
([Linux symlink creation](https://man7.org/linux/man-pages/man2/symlink.2.html))

An already-present exact root:root, singly linked mode-0777 symlink may instead
be freshly verified and synchronized without recreation. Regular units, empty
files, other/relative symlinks, unsafe metadata or distinct-device leaves are
refused, never renamed or overwritten. Existing local unit files require a
separately reviewed backup/replacement design; this primitive does not cover
that layout. It does not inspect unit payloads or copy package files.

An `O_PATH|O_NOFOLLOW` descriptor holds the symlink itself, never its device
target. Held/named identity, full leaf metadata, exact link text, close-on-exec,
ancestor identities and null anchor are rechecked around writes and syncs.
Caller PID/native-thread is checked around each checkpoint. Directories are
`fsync`ed deepest-first through the held root; no temporary leaf, rename or
global sync is used. Directory synchronization is required separately from
file content synchronization. ([Linux fsync](https://man7.org/linux/man-pages/man2/fsync.2.html))
Storage/kernel guarantees, filesystem compatibility and actual power-loss/reboot
behavior remain external validation work; successful syscalls are not a tested
reboot guarantee or defense against privileged later replacement.

Failure after creation **never removes the mask**. A failed sync means durability
is uncertain, not success. An independently authorized fresh attempt must read
the current path and synchronize again; it must not resume from a saved progress
counter. Existing masks are not treated as owned by this tool and there is no
unmask/rollback operation. Cleanup closes descriptors even on interruption; a
close error also prevents a successful result. Unexpected checkpoint exceptions
are sanitized, not printed with arbitrary caller details.

The immutable result reports only creation versus pre-existence, an observed
exact disk entry and completed directory syncs. Manager reload/inhibition,
process quiescence, exclusive control, tested reboot persistence and mutation/
startup authorization remain false. The mask file alone is not the running
manager's effective state, does not stop a process and cannot block manually
executed broker code. The later authorized controller must refresh the manager,
verify masked state, stop and prove quiescence under continuous controls before
protected work. Systemd distinguishes masking from stopping; neither disabling
a unit nor a runtime-only mask substitutes for persistent inhibition.
([systemctl semantics](https://raw.githubusercontent.com/systemd/systemd/main/man/systemctl.xml))

Thirty-two tests cover create/no-clobber, existing-mask retry, strict metadata,
path/caller races, checkpoints, directory-sync ordering/failures and retention
after interruption. Four Linux-only tests use disposable directories and real
symlink/directory-sync syscalls with normalized owner metadata and a mocked null
anchor; they do not touch `/etc`, query systemd, test power loss or prove VM
compatibility. They are skipped on Windows. No live command is released.

## Read-only mask and manager observation — not admission

`observe_maintenance_state()` takes no arguments and has no CLI. Production
reads are fixed to `/etc/systemd/system/wazuh-dashboard.service`, the `/dev/null`
metadata anchor, `/usr/bin/busctl` and the fixed systemd Dashboard object. The
root/Linux caller, Python/import context, OS and busctl/libraries must already
be trusted; this module does not establish its own launch or tool authenticity.
It is outside the held guard capsule and has no planner/executor integration.

The disk reader holds no-follow ancestor descriptors, requires root ownership
and safe directory/file modes, reads only the symlink target and rechecks names
and metadata. It never reads a unit payload or opens a device for payload I/O.
Only the exact root-owned `/dev/null` symlink with a verified character-device
anchor is a positive mask observation. An absent entry, another root-owned
symlink or regular file (even empty) is negative. This is intentionally narrower
than every mask representation systemd supports. Untrusted ownership, unsafe
parents, unexpected types or visible replacement produce a fixed error.

The fixed D-Bus queries read only unit identity/load/file/activity/substate,
reload/job/trigger metadata and service main/control PIDs and control-group
name. No environment, command line, credential or configuration payload is
queried. `ControlGroup` is queried on the **Service** interface; `Job` is the
Unit `(uo)` property, whose zero ID denotes no scheduled/executing job.
([systemd D-Bus interface](https://raw.githubusercontent.com/systemd/systemd/main/man/org.freedesktop.systemd1.xml))

Both disk and manager must report the persistent mask, with no pending reload,
for `persistent_inhibition_observed=true`. `masked-runtime` does not qualify.
Separately, `manager_reports_stopped=true` requires an exact inactive/dead or
failed/failed state, loaded/masked unit, zero main/control PIDs, no job and no
pending reload. **It is not stopped-process proof**: descendants, a populated
cgroup or another manually launched instance have not been checked. The
returned control-group presence and trigger count are metadata, not permission.
Neither field may be promoted to the planner's `dashboard_stopped=true`.

Two complete manager reads are bracketed by disk reads. All compared raw
properties and mask/ancestor/device tokens must remain equal; a change that
leaves the public summary identical is still rejected. Reads are not atomic,
do not detect ABA and do not lock out later changes. Per-query replies are
limited to 16 KiB with a five-second wait, and the whole observed interval has
a candidate 30-second bound. Child environment/arguments are fixed, stdin and
stderr discarded, and timeout/error paths kill/reap the child and close handles.
No unit is loaded, reloaded, masked, unmasked, started or stopped.

Only minimized Boolean/count/elapsed-time fields are returned; no raw paths,
PIDs, job IDs or response bodies. Process-quiescence, exclusive-control and
atomic-snapshot proof flags remain false, as do mutation/startup authorization.
This result is not a persisted freshness receipt: boot binding, complete trusted
collection, review and subsequent decision/execution remain separate work.
Twenty-seven tests cover the parser, mask metadata/races, query bounds/cleanup,
72 disk/manager/reload combinations and non-authorizing results. Two use native
Linux descriptor operations on disposable trees with normalized owner metadata
and a mocked null anchor; they do not query the real service bus or modify `/etc`.
Those two are skipped on Windows. No live execution block is released.

## Fixed service-tree observation — not host-wide process absence

`observe_maintenance_cgroup()` has no arguments, CLI, stored receipt, planner
adapter or guard integration. It first verifies the tool/platform prerequisites,
persistent disk mask and exact masked/stopped manager state. Nonzero main/control
PIDs, a queued job, reload, transition, runtime-only mask or unexpected manager
cgroup path stops collection. The only accepted manager cgroup names are empty
or `/system.slice/wazuh-dashboard.service`; neither supplies a filesystem path.

The reader always targets `/sys/fs/cgroup/system.slice/wazuh-dashboard.service`.
It checks bounded `/proc/<own-pid>/mountinfo` against one full-root cgroup-v2
mount at `/sys/fs/cgroup`, rejects submounts below it and matches the reported
major/minor device to held cgroup directories and files. Ancestors must be
root-owned, non-symlink directories with safe modes. The trusted host namespaces,
procfs/kernel, Python and OS tools are **external prerequisites**, not established
by root UID or these checks. Full mount bytes bracket each kernel observation.
([mountinfo format](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html))

An existing unit tree must be a normal `domain` cgroup. The strict `cgroup.events`
parser accepts exactly one binary `populated` and `frozen` field each. The kernel's
`populated` value covers live processes in the group **and its descendants**;
zero is not a count of all host processes or unreaped zombies. Freezing is not
process exit, so frozen and populated remain separate fields. Unknown additions
or threaded layouts fail pending compatibility review, not automatic acceptance.
([Linux cgroup-v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#un-populated-notification))

If only the unit leaf is absent beneath the required trusted slice, the reader
records an absent/empty tree; missing parents or a missing events file in an
existing group are errors. No directory is created. Descriptor-relative reads
are no-follow, bounded and rechecked; kernel files may report size zero despite
readable content. Nothing is signalled, stopped, migrated, frozen or written.

Two complete snapshots must agree on boot ID, cgroup presence/content, mount
digest and metadata, with unchanged mask and full manager properties before and
after. The boot ID is read at both ends of each snapshot. `CLOCK_BOOTTIME` bounds
the whole collection to a candidate 30 seconds and includes suspend time. Its
`captured_boottime_ms` is deliberately distinct from the planner's monotonic
field; no clock conversion or receipt-replay adapter is provided.
([Linux boot-inclusive clock](https://man7.org/linux/man-pages/man2/clock_gettime.2.html))

The result reports only boot/time and minimized cgroup fields. A populated tree
returns `unit_tree_empty_observed=false`; an empty tree is still **not** complete
Dashboard shutdown. Escaped or manually launched instances outside the unit
have not been checked. Host-namespace, host-wide quiescence, exclusive-control,
atomic-snapshot, mutation and startup proof flags remain false. Equality neither
detects ABA nor prevents later process creation or migration. No claim can be
promoted to planner `dashboard_stopped=true` without the remaining controls.

Twenty-five tests cover these scope, parser, path/device/metadata, drift, boot,
timeout and cleanup rules. Two Linux-only tests exercise descriptors on disposable
regular-file fixtures with normalized ownership. They do not establish real
kernel/procfs/cgroup or VM acceptance and are skipped on Windows. No new live
command or VM-output request is released.

## Namespace boundary and candidate coverage — connected to the census

`hold_maintenance_namespaces()` is a no-argument, read-only context manager for
the existing Linux x86-64 target. It holds fourteen namespace handles: mount,
PID, user, cgroup, time, PID-for-children and time-for-children for visible PID 1
and the collector's own process. The caller must be a single-threaded process
leader with all four UID/GID slots zero. Root ownership, a trusted kernel/procfs
and trusted Python launch/imports remain prerequisites, not results.

The fixed `/proc/<pid>` ancestors are held no-follow, with the existing bounded
mount/visibility checks rejecting filtered procfs or PID/boot-path submounts.
Only the seven allowlisted kernel namespace links are intentionally followed.
Link syntax/inode, held descriptor identity/type, `NS_GET_NSTYPE`, ownership and
close-on-exec are checked. Namespace identity comparison includes device and
inode, not just equal link text. Namespace descriptors retain their objects;
the code never enters, creates or changes a namespace. See the Linux
[namespace interface](https://man7.org/linux/man-pages/man7/namespaces.7.html)
and [namespace type query](https://man7.org/linux/man-pages/man2/NS_GET_NSTYPE.2const.html).
The numeric ioctl/type constants use the reviewed Linux x86-64 ABI from
[nsfs.h](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/nsfs.h)
and [sched.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/sched.h).
Other architectures are rejected pending review, not silently assumed compatible.

All five active namespace identities must match visible PID 1; both processes'
child PID/time targets must also match their active identities. Time namespaces
can offset boot/monotonic clocks, so checking only PID/mount membership is not
sufficient for the collection clock context.
([time namespace clocks](https://man7.org/linux/man-pages/man7/time_namespaces.7.html))
An absent/empty child target, denied namespace, unexpected type, multiple caller
threads or mismatch aborts. No namespace is skipped and no access is repaired.

The handle checks boot identity, mount bytes, process start/credential/thread
identity, held namespace objects, reopened current names and ancestors before
yield, at checkpoints and at successful exit. Same-caller PID/native-thread
checks reject cross-thread/fork reuse; use after exit fails. All descriptors close
on failure. The candidate 30-second BOOTTIME bound includes the entire context
and suspend; it is not preemptive cancellation of a stalled syscall. Observations
are not atomic and cannot detect a change-and-return between checks.

The public `observe_maintenance_processes()` brackets its scans and manager
checks with this context, verifies common boot identity and discards the result
on exit drift. It now reports `visible_pid1_alignment_observed=true`, while
`host_namespace_proven` and all authority flags stay false. The census's fixed
busctl queries already use `close_fds=True`, no passed descriptors or pre-exec
callback, and bounded child cleanup; they never receive the namespace handle.
Raw fork/delegation, descriptor passing, credential or namespace changes inside
the context are unsupported. The private held-control composition above now
uses an explicit fixed busctl/systemctl child exception for all held handles;
independent/native review and external host/start/writer controls remain pending.

**External launch requirement:** a container can match its own visible PID 1.
These checks cannot prove initial namespaces, the intended host identity or the
system bus's relationship to that host. A trusted root-controlled host launcher,
mount/procfs context and no concurrent privileged namespace changes remain
required before maintenance admission. No installer or launcher is released.

**Candidate coverage contract:** the census labels its existing predicate
`leader-credential-or-packaged-node-v1`. It matches any leader UID/GID slot for
the service identity, or the exact packaged Node path (including its deleted
suffix), across the visible process-leader population. Counts are candidate
matches, not script attribution. It covers these observed identities/paths only:
nonleader-only credentials, supplementary-group-only identity, renamed/copied
executables under other IDs, future launches and privileged evasion are not
excluded. Service zombies are conservatively counted. Matching PID 1 does not
expand that coverage. This policy is explicit but **not accepted as sufficient
shutdown proof**; zero census matches plus an empty cgroup still cannot supply
`dashboard_stopped=True`. Host launch and noncooperating update/start controls
must establish the remaining scope before any such composition is authorized.

Thirty-two new tests cover namespace identity/type, metadata/races, lifetime,
clock bounds and connected census ordering/failure. Two Linux-only syscall
tests query only the test process's namespace handles and a non-namespace file;
they do not compare host PID 1, scan host processes, change namespaces or prove
VM compatibility. Windows skips them. Existing census tests stub the boundary
when testing scan-specific behavior; separate integration tests require the
boundary before/after the scan and rejection of failed exit. No guard capsule,
planner contract, live service, credential or historical evidence is changed.

## Package-manager lock barrier — observation and backup only

`hold_maintenance_package_locks()` has no arguments, CLI, planner adapter or
guard-capsule integration. It takes nonblocking whole-file write record locks,
in fixed order, on these existing files only:

- `/var/lib/dpkg/lock-frontend`
- `/var/lib/dpkg/lock`
- `/var/lib/apt/lists/lock`
- `/var/cache/apt/archives/lock`

This coordinates package tools that do not use AlertMind's separate cooperative
lock but do honor these record locks. It does not inspect or kill an updater,
disable a timer or authorize a package transaction. Upstream APT uses traditional
`F_SETLK` locks, with configurable paths and a `Debug::NoLocking` bypass; those
are not audited installed-VM settings here. See the
[APT lock implementation](https://raw.githubusercontent.com/Debian/apt/main/apt-pkg/contrib/fileutl.cc),
[dpkg integration](https://raw.githubusercontent.com/Debian/apt/main/apt-pkg/deb/debsystem.cc)
and [lists/archive acquisition](https://raw.githubusercontent.com/Debian/apt/main/apt-pkg/acquire.cc).

The implementation uses Linux **OFD record locks**, not `flock`. OFD locks
conflict with traditional record locks, including in the same process, and
survive closing an unrelated descriptor for that inode. Their lifetime ends
when the last descriptor referring to the locked open-file description closes.
Traditional `F_GETLK` reports an OFD conflict with PID -1, whereas `F_OFD_GETLK`
would ignore this description's own lock. These semantics follow the Linux
[record-lock interface](https://man7.org/linux/man-pages/man2/fcntl_locking.2.html).
The packed `struct flock` layout is restricted to little-endian Linux x86-64;
other architectures, missing OFD support and unsupported filesystems fail closed.

All four must be acquired before yielding. Busy/error paths release any acquired
subset without waiting, retrying, stealing a lock or deleting a lock file. Safe
root-owned no-follow ancestors and empty, singly linked root:root regular files
with mode 0600, 0640 or 0644 are required. Distinct inode identities and same-device
leaf/parent checks reject aliases and different-device leaf mounts; they do not
authenticate the host mount namespace or every bind mount. Missing/unsuitable
locks are not created or repaired. Opening for write is required for `F_WRLCK`,
but this code never reads/writes payloads, truncates or unlinks files.

Held descriptors, named files, complete leaf metadata and ancestors are checked
before yield, at `checkpoint()` and at successful exit. A checkpoint queries
the existing lock without reacquiring it: a renewal could hide an unprotected
gap. The query proves a conflicting OFD record, not owner identity; ownership
also relies on trusted code retaining its private acquired descriptors unchanged.
Visible drift aborts; a change-and-return between checks is not detected.

Use only a dedicated trusted root-controlled host process, with trusted runtime,
local filesystems and **no pre-existing traditional locks on these inodes**.
It must not run inside APT/libapt: closing any descriptor can release that
process's traditional locks. The private handle rejects cross-PID/thread and
after-exit use. Do not raw-fork/delegate, duplicate/pass its descriptors or exec
the controller inside the context. Only the fixed busctl queries and systemctl
reload/stop children in the private composition are excepted: close unrelated
FDs, receive no passed descriptors/pre-exec callback and use bounded wait/cleanup.
Cleanup closes descriptors without `F_UNLCK`, so a copied child cannot explicitly
unlock the parent's OFD through cleanup. An illicit surviving duplicate can
still prolong the lock; this is not a sandbox against trusted-code violations.

**Limits and handover:** these advisory locks do not prevent arbitrary root or
service-owned writes, manual launches, alternate package directories, lock
bypasses or other package systems. They do not make all package activity inert:
upstream [dpkg opens lock files with `O_TRUNC` before locking](https://raw.githubusercontent.com/guillemj/dpkg/main/lib/dpkg/dbmodify.c),
and APT may prepare partial directories before acquiring a lock. Such pre-lock
work is not excluded; changed lock metadata is rejected by this reader. A clean
checkpoint is not evidence of zero filesystem mutations or package authenticity.

Do **not** invoke APT/dpkg while holding this barrier: the intended upgrade
would also contend. Bounded ownership, installed-path/behavior validation,
persistent startup inhibition and a reviewed release-to-package-transaction
handover remain separate work. There is no watchdog, timer suppression or
reboot-persistent lock; a future controller must bound the interval and preserve
inhibition through interruption. Security updates must not be deferred indefinitely.

The immutable observation reports four held locks and path rechecks only; host,
package-configuration, noncooperating-writer, service-start, quiescence and
exclusive-control proof flags remain false. Mutation, package-transaction and
startup authorization remain false. The result is not a replayable receipt or
planner permission, and no installed lock files have been inspected here.

Thirty-three tests cover exact locking/query requests, partial acquisition,
metadata/races, lifetime, cleanup and non-authorizing output. Four Linux x86-64
tests use disposable files and independent Python processes with traditional
record locks, including contention and release. They never touch real package
locks or invoke APT/dpkg. Windows skips these four; native fixture/installed-VM
compatibility remains to be verified. No new VM command is released.

## Held cooperative lock — not host-wide exclusive control

`hold_maintenance_lock()` is a no-argument context manager, outside the guard
capsule and not connected to an installer or planner. The trusted root/Linux
caller must already be in the host mount namespace with a trusted local `/run`,
kernel and Python runtime. These are prerequisites, not conclusions of UID 0.
No live invocation or provisioning command is released.

The fixed anchor is `/run/alertmind-broker-maintenance/owner.lock`. A future
reviewed installer must provision the private root:root `0700` directory and
empty, singly linked root:root `0600` regular file. Missing or unsuitable
objects fail closed. The module does not create, truncate, read/write payloads,
chmod, unlink or repair anything. The directory and file must share `/run`'s
device. This rejects distinct-device submounts, not every possible bind mount;
host namespace/local-filesystem trust remains external.

All ancestors and the file are opened relative to held no-follow descriptors.
Names, inode identity, ownership and modes are rechecked before the context is
yielded, on `checkpoint()` and at successful exit. The private directory and
file also have complete metadata stamps checked; unrelated `/run` timestamp
changes are tolerated. Name replacement, hard links, symlinks, unsafe modes,
payload contents and inheritable descriptors are refused. Visible changes are
detected, not an atomic filesystem snapshot or ABA protection against root.

Acquisition is exactly Linux `flock(LOCK_EX | LOCK_NB)`: contention returns a
fixed busy error, with no wait/retry, stale-PID heuristic or lock stealing.
The descriptor stays open for the whole context and is closed on success,
caller failure or acquisition/readback failure. Never delete a lock file to
"release" it: that can leave two different inodes independently locked.
The kernel lock, not file existence or a stored observation, coordinates users
of the same anchor. [`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html)
documents that this is advisory, not a block on other writers.

The returned handle is for trusted code only. Check it immediately before each
future protected operation, not merely once at transaction entry. It rejects
use after context exit or by a different PID; the observation is immutable,
minimized and not a replayable authority. Do not raw-fork, duplicate/pass its private
descriptor, exec the controller or delegate the handle inside the critical section.
Only the fixed busctl/systemctl child exception documented above is permitted. Descriptors
are close-on-exec; cleanup only closes them, never explicitly unlocks a shared
open-file description. If a caller violates the no-fork/no-dup contract, an
inherited descriptor can prolong the lock until its holder exits. Do not steal
it. Private composition is implemented, but independent/native review remains open.

The lock alone does **not** stop Dashboard processes or exclude apt/dpkg,
unattended upgrades, systemd activation, service-owned code changes or other
administrators. Such actors do not automatically acquire this lock. It also
does not survive reboot or provide persistent startup inhibition. All
exclusive-control, quiescence, persistent-inhibition, mutation and startup proof
flags remain false. It cannot populate planner `exclusive_control=True`.
Reviewed coordination/inhibition of other writers and outside-unit process
coverage remain necessary, along with a trusted composition holding the lock
from preflight through durable verification and cleanup.

Twenty-nine tests cover fixed targeting, metadata/path races, nonblocking
acquisition, lifetime/PID checks, error cleanup and non-authorizing summaries.
Three Linux-only tests use temporary fixtures (ownership normalized for
unprivileged CI) for actual lock contention, release, symlink/hardlink/replacement
rejection and an independent child contender. They are skipped on Windows and
are not real `/run`, provisioning or VM acceptance.

## Process-leader census — outside-unit candidate detection

`observe_maintenance_processes()` has no arguments or CLI. It requires the
existing persistent mask and exact masked/stopped manager precondition. It then
scans numeric process-leader entries under fixed `/proc`, without using a caller
PID, command or path. Root/Python/busctl, the kernel/procfs and the host PID,
mount, user and cgroup namespaces remain trusted launch prerequisites. Neither
UID 0 nor seeing PID 1 proves the host namespace; this code does not assert it.

The bounded mount reader requires one full-root procfs mount at `/proc`, matching
its held device, without nonzero `hidepid` or `subset` filtering. It rejects
mounts over numeric PID trees or the boot-ID path/ancestors. Unrelated non-PID
mounts, such as `/proc/sys/fs/binfmt_misc`, are allowed and never traversed.
The PID set must include PID 1 and the observer itself. These are consistency
checks, not authenticity or namespace proof.

Only `stat`, selected `status` fields, `cgroup` and the `exe` symlink text are
used for each leader. No command line, environment, process memory, descriptor
table, executable payload or script is read. The symlink is **not followed**.
Kernel process names and other incidental fields in the small files are not
returned or logged. Native procfs per-process owners need not be root, but held
directories/files must be on the procfs device, of the expected type and
non-writable; payloads are bounded and descriptor-relative/no-follow.

A candidate matches either any real/effective/saved/filesystem UID or GID slot
equal to the Dashboard service identity, or the exact packaged Node executable
path (also accepting its kernel ` (deleted)` suffix) under any UID. Supplementary
groups are not scanned. The matches are conservative: a service-UID helper or
another script using this Node also counts. Exact unit/descendant membership is
reported separately from outside-unit matches, with overlap counted once.
No classification terminates or signals a process.

Each leader is sampled twice; start time, selected credentials, thread count,
kernel/zombie classification, executable-path hash and cgroup membership/hash
must agree. PID sets are checked before/after each full scan, and two full scans
must match on private records, boot and mount/metadata tokens. Service identity,
mask and complete manager metadata are rechecked afterward. Changes, access
errors and disappearing processes abort collection, never skip a row or produce
a partial success. Normal process churn may therefore require a fresh attempt;
the collector does not automatically retry or suppress it.

Missing `exe` link targets are accepted only for a kernel-thread flag or a
single-thread zombie. A live userspace process, or an exited main thread with
other threads remaining, is not silently ignored. Permission errors and a
missing proc entry remain errors. Service-credential matches remain conservative
candidates even in the zombie case. The Linux flag policy needs native version
validation; metadata flags do not authorize skipping service matches.
([process stat](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html),
[credential fields](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html),
[executable-link behavior](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html),
[kernel flag definitions](https://raw.githubusercontent.com/torvalds/linux/master/include/linux/sched.h))

Limits are 8,192 leaders, 16,384 root entries, 8 KiB stat/cgroup and 64 KiB
status payloads, and a candidate 30-second suspend-inclusive `CLOCK_BOOTTIME`
interval. Checks occur during enumeration/reads and at completion; they are
not preemptive cancellation of every kernel syscall. Timing is not the planner's
monotonic timestamp and is not a replayable freshness receipt.

Output is limited to boot/time, aggregate counts and scope flags. Zero matches
does **not** exclude renamed/copied executables under different identities,
nonleader-only credential changes, undetected ABA or subsequent launches.
It is not host-wide quiescence or proof of all Dashboard code absence. All
quiescence/exclusive/atomic/mutation/startup proof flags remain false. The
cooperative lock is not acquired here, and no planner Boolean is populated.
Trusted launch scope, appropriate handling of these coverage limits, other
writer/start-path control and held transaction composition remain required.

Thirty-five tests cover candidate matching, privacy, parsers, bounds, partial
reads/disappearance, PID/credential/exec/cgroup/mount/boot drift and non-authorizing
results. Two Linux-only tests use disposable regular-file proc fixtures with
normalized ownership, not real host processes. Those tests are skipped on
Windows; no new VM command or native compatibility acceptance is supplied.

## Versioned compatibility baseline

`parse_baseline(bytes)` accepts schema version 1 with exactly `schema`,
`versions` and `digests`. Unknown schemas, duplicate/missing/extra fields,
non-finite JSON, malformed UTF-8, coercions and inputs above 16 KiB fail with
fixed diagnostics. Version strings use a bounded public-token grammar; digests
are exactly 64 lowercase hexadecimal characters. Parsed records are immutable
and ordered. `baseline_fingerprint()` hashes canonical JSON so whitespace and
key order do not redefine baseline identity.

The 24 required components are:

- Versions: OS ID/version, architecture, kernel release, Python, Wazuh manager,
  indexer and Dashboard, Node, Wazuh/main and core plugins, security plugin.
- Digests: Python executable, source manifest, native dependency manifest,
  loader cache, Dashboard package, broker client, dependency manifest, guard
  entry, guard bundle, launcher, unit contract and trust certificate.

These hashes identify content, **not authenticity or approval**. Aggregate
manifest formats, provenance and trusted collection must be implemented/reviewed
before live use. This parser intentionally can describe future versions for
comparison; it does not add them to the current guard allowlist. No production
values are invented from earlier incomplete observations.

Keep source and target baseline artifacts separately, content-addressed, along
with reviewed package provenance and evidence. Never overwrite the source or
historical A–C3 evidence. Both content addresses and a non-empty evidence digest
must match the revalidation record before the planner proposes an upgrade.
That record also requires independent-review/native-validation claims; the
current independent-review deferral does not satisfy live acceptance.

## One next step, not an executable queue

`next_maintenance_step()` takes source/target baselines, a typed observation,
typed review evidence and a current boot ID/monotonic time. It checks every
input's shape/types before evaluating safety prerequisites. `False` and `None`
never satisfy a prerequisite. A changed boot ID, future timestamp or age over
30 seconds yields `HOLD_STALE_OBSERVATION`. The 30-second value is candidate
policy, not measured VM performance; trusted collection and timing remain to
be validated. A fresh-looking timestamp supplied by an untrusted caller proves
nothing.

The decision order is:

1. Freshness, explicit owner downtime approval and exclusive control.
2. Persistent inhibition, then stopped Dashboard; re-observe after each action.
3. Fresh installed inventory with verified metadata; reject unexplained drift
   and mixed source/target components before proposing writes.
4. Verified backup bound to the exact source baseline. It must cover the entire
   planned restore scope (a broker JavaScript backup alone cannot undo an OS or
   Python upgrade).
5. Upgrade: require evidence bound to both baselines and reviewed native results.
   Propose `PLAN_UPGRADE_WHILE_INHIBITED` only from a complete source match.
   A complete target match returns `TARGET_MATCHES_KEEP_INHIBITED`.
6. Recovery: only a complete target match can propose
   `PLAN_SOURCE_RESTORE_WHILE_INHIBITED`; an exact restored source returns
   `SOURCE_RESTORED_KEEP_INHIBITED`. Failed target validation does not block
   planning recovery, but no recovery result permits starting old broker bytes.

Unknown components produce `HOLD_UNREVIEWED_DRIFT`; a mixture of known old/new
values produces `HOLD_PARTIAL_UPGRADE_FOR_RECOVERY`. Neither automatically
resumes, overwrites, downgrades or deletes anything. Mixed-state repair needs a
separately reviewed exact recovery plan. Loader-cache regeneration is drift
requiring review, not automatically compromise.

Every result contains one fixed step code and the *planned source-to-target*
changed component names (not raw versions, paths, secrets or observed contents).
All results retain `review_required=true`, `mutation_authorized=false` and
`startup_authorized=false`. A future caller must not dispatch writes by step
name without separately reviewed authorization and execution controls.

## Interruption and upgrade acceptance still required

The planner has no persisted progress counter: after suspension, failed install,
reboot or service failure, collect new facts. A journal is diagnostic history,
not proof of the current installation. Do not reuse an old backup-verification
claim, matching baseline digest or successful observation as authority.

The next implementation work completes trusted maintenance collection/execution:

- Complete the narrow mask/manager/fixed-tree/candidate-census observations and
  cooperative/package locks with externally established host launch trust and
  service-start control. Private persistent-mask disk preparation now exists;
  private manager reload/stop and fresh scoped readback sequencing also exists.
  Private held-control composition and the fixed-child exception now exist.
  Selected loaded-unit stop hooks/edges/actions/kill policy now have fresh checks
  before mask, reload and stop. Next bind the external authorization/host/start/writer
  boundary and remaining installed generator/unit/dependency prerequisites, keeping public execution
  blocked until the complete controller is reviewed. The default-path package barrier is implemented only
  for observation/backup/private inhibition; installed path/behavior validation and a bounded,
  inhibited handover to the intended package transaction remain open. Neither
  advisory lock excludes arbitrary privileged writes. The census checks namespace alignment,
  but its explicit coverage policy still needs acceptance in that controlled
  context. Complete trusted launch/boundary integration,
  private exact backup and
  root-controlled versioned baseline/evidence
  binding. Verify rather than trusting hand-entered Booleans or a stored receipt.
- Implement interruption-safe installation and recovery with exact metadata,
  parent-directory durability, independently inspected package transactions and
  refusal of unknown installed bytes. Atomic replacement of one file is not an
  atomic multi-file/package upgrade. Preserve inhibition through every failure
  and reboot; never restore non-verifying broker bytes and automatically start.
- Reconcile installed hooks and systemd lifecycle explicitly, then test in a
  disposable clone: planned Wazuh/Python/Ubuntu upgrades, package/cache drift,
  every interrupted write, timeout/reboot, rollback, native guard launch and
  affected TLS/authorization acceptance. Record owner downtime decisions and
  sanitized incompatibility details before separately releasing live steps.

Do not solve availability by suppressing security updates indefinitely,
auto-learning new hashes, adding a force/skip flag or using the original
non-verifying client as fallback. The separate legacy `operator_core.recovery_step`
still models a single broker-client rollback; this broader planner neither
executes it nor claims that it restores packages or an entire baseline.

Twenty-nine synthetic tests cover parsing, binding, strict types, freshness,
every component's digest/delta, 243 prerequisite combinations, drift, partial
updates, recovery, replay refusal, preservation and non-authorizing output.
They are not native filesystem, systemd, package-manager or VM evidence.
