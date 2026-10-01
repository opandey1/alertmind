# Compact broker clone rehearsal — blank worksheet

**Template only. No execution or PASS is recorded.** Use the
[Batch B packet](../../docs/runbooks/rbac-broker-tls-compact-clone-rehearsal.md).
Create a separate dated result record after execution; preserve this template.

## Authorization and provenance

- Batch A review: owner confirmed focused independent approval of `7e53ecd`
  and reused TLS candidate in chat on 1 October 2026. This is an owner-reported
  approval, not a Codex self-review or a supplied reviewer artifact.
- This Batch B packet's focused reviewer/verdict/reference: **PENDING**.
- Owner's explicit release for ONE clone run: **NOT RELEASED**.
- Run date/time/timezone: **NOT TESTED**.
- Committed driver/packet source revision: **NOT RECORDED**.
- Public packet SHA-256:
  `f36ac4e7566890162045ecf5da27b31bcda8d669ede98971272aa59f5010bc68`.
- Public packet byte count: `55784`; five public stage files.
- Original VM untouched / Snapshot 1 retained: **NOT RECONFIRMED**.
- Clone: `Ubuntu SOC 201 - Current Isolated Clone`; identity checked in
  VirtualBox, every adapter disabled: **NOT RECONFIRMED**.
- No app uses clone, stable host/console, no intervening updates/concurrent
  configuration work: **NOT RECONFIRMED**.

## One-run results

| Checkpoint | Result | Sanitized observed output / retained reference |
| --- | --- | --- |
| Exact host packet hash/source revision | NOT TESTED | |
| New root-private stage; syntax only | NOT TESTED | |
| Read-only compatible package/client/unit/config/trust and health | NOT TESTED | |
| Durable prepare: inhibited/stopped, private backup/receipt | NOT TESTED | |
| Abrupt install exit 73 after public trust write | NOT TESTED | |
| Prepared partial state and native inhibitor refusal | NOT TESTED | |
| Secure install/resume/check; native startup, active service | NOT TESTED | |
| Missing new trust copy: exact mandatory guard rejects startup | NOT TESTED | |
| Inhibition restored after negative probe; secure recovery | NOT TESTED | |
| Rollback: original client/metadata restored, native start inhibited | NOT TESTED | |
| Verified secure restoration and health | NOT TESTED | |
| Final pause: secure candidate retained, Dashboard stopped/inhibited | NOT TESTED | |

Do not paste private receipt/configuration hashes, raw YAML, raw journal, HTTP
responses, credentials, keys or tokens. No assumptions about original-VM health.
Record failures before subsequent corrections; never combine partial runs as one
uninterrupted result. A later recovery can be a separate, explicitly labeled run.

## Required limitations / acceptance

- Selected **process-exit** checkpoint only: no power-cut/reboot/all-position
  native proof, atomic snapshot, hostile-root containment or OS attestation.
- Starting Dashboard may perform ordinary vendor loopback broker traffic using
  existing credentials; driver/operator do not issue API calls.
- Actual login/scoped read/refresh TLS, human RBAC, safe backend write/action
  denials, administrator/two-dashboard continuity: **NOT TESTED (P1-03–06)**.
- P1-02 output review/verdict: **PENDING**; original-VM release: **NOT RELEASED**.
- Phase 1 complete: **NO**; OIDC/application integration acceptance: **NO**.
