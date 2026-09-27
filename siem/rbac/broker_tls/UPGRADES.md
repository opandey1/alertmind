# Maintenance lifecycle and upgrade planning — offline only

`operator_maintenance.py` is a pure planner, not a collector, installer,
package manager or startup guard. It performs no I/O, accepts no journal
position, emits no commands and never authorizes mutation or startup. Inputs
are caller-supplied claims; setting them to true is not evidence. No populated
production baseline is shipped and no new VM operation is released.

This implements the baseline format and advisory decision portion of the
owner-required upgrade workflow. Native evidence collection, durable inhibition,
backup/install/recovery and final service admission remain unimplemented.

## Separate the lifecycle contracts

| Phase | Required boundary | Current implementation |
| --- | --- | --- |
| Maintenance / recovery | Owner downtime approval, exclusive control, persistent inhibition, stopped Dashboard, fresh inventory and verified source backup | Planner rejects missing claims; no mechanism establishes them yet. |
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

An exact persistent-mask transaction is a candidate mechanism, not chosen or
implemented here. A masked unit may no longer expose the loaded-unit metadata
expected by existing observers. The future maintenance collector must verify
the inhibitor and intended unit artifacts in that state without temporarily
unmasking to obtain a convenient PASS. Final start admission needs its own
reviewed lifecycle policy. Do not change the present baseline observers or
capsule pins merely to accommodate an installation script.

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

The next implementation work is the trusted maintenance collector/executor:

- Establish the actual inhibitor, exclusive-update control, stopped-process
  status, private exact backup and root-controlled versioned baseline/evidence
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
