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

## Separate the lifecycle contracts

| Phase | Required boundary | Current implementation |
| --- | --- | --- |
| Maintenance / recovery | Owner downtime approval, exclusive control, persistent inhibition, stopped Dashboard, fresh inventory and verified source backup | Planner rejects missing claims; separate mask/manager observer supplies narrow metadata only, not admission. |
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

- Extend the narrow mask/manager observation with exclusive-update control,
  stopped-process status, private exact backup and root-controlled versioned baseline/evidence
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
