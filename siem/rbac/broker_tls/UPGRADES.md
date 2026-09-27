# Maintenance lifecycle and upgrade planning — offline only

`operator_maintenance.py` is a pure planner, not a collector, installer,
package manager or startup guard. It performs no I/O, accepts no journal
position, emits no commands and never authorizes mutation or startup. Inputs
are caller-supplied claims; setting them to true is not evidence. No populated
production baseline is shipped and no new VM operation is released.

The companion `operator_maintenance_state.py` now implements a dormant, read-only
observer for the exact persistent mask and systemd-reported state. It does not
supply the planner's complete observation or clear a maintenance gate. Durable
inhibition, process-quiescence proof, backup/install/recovery and final service
admission remain unimplemented; native compatibility is not yet accepted.

`operator_maintenance_cgroup.py` now adds a separate dormant observation of the
fixed Dashboard cgroup-v2 tree, including boot identity and suspend-inclusive
collection timing. It does not close the outside-unit process or exclusivity
requirements, supply the planner's complete input or authorize a live step.

`operator_maintenance_lock.py` adds a held, nonblocking **cooperative** lock.
It coordinates callers using the same fixed inode; it is not host-wide exclusive
maintenance control. It is not wired to the observers or planner yet.

`operator_maintenance_processes.py` adds a bounded read-only process-leader
census for service-credential and packaged-Node-path matches outside the unit.
It detects known candidates, not every possible Dashboard copy or full shutdown.

## Separate the lifecycle contracts

| Phase | Required boundary | Current implementation |
| --- | --- | --- |
| Maintenance / recovery | Owner downtime approval, exclusive control, persistent inhibition, stopped Dashboard, fresh inventory and verified source backup | Planner rejects missing claims; mask/manager, fixed-cgroup, process-leader census and cooperative-lock primitives do not constitute admission. |
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

An exact persistent-mask transaction is a candidate mechanism, not implemented
here. The new observer understands the intended symlink and manager mask state
without changing either. A masked/unloaded unit may not expose the properties
needed for a complete read; that fails closed, without loading or unmasking it.
Final start admission needs its own reviewed lifecycle policy. The existing
steady-state observers and capsule pins are unchanged.

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
minimized and not a replayable authority. Do not fork, duplicate/pass its private
descriptor, exec or delegate the handle inside the critical section. Descriptors
are close-on-exec; cleanup only closes them, never explicitly unlocks a shared
open-file description. If a caller violates the no-fork/no-dup contract, an
inherited descriptor can prolong the lock until its holder exits. Do not steal
it. Actual process-launch composition remains to be implemented and reviewed.

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
  cooperative lock with host launch-namespace trust, an accepted process-coverage
  policy and control of noncooperating update/start paths. Implement trusted held-lock composition,
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
