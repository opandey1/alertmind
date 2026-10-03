# Compact broker TLS — accepted owner-executed clone rehearsal

Recorded/assessed: 3 October 2026, Asia/Calcutta (UTC+05:30).
P1-02 PASS was assessed by Codex as author against the reviewed checkpoint
contract, not independently observed on the VM. The exact execution time was
not supplied. Source: the owner's sanitized chat output, also retained in the
outside-Git `COMPACT-BROKER-CLONE-PROOF-2026-10-03.md` coordination record.

## Authority and provenance

- Clone: **Ubuntu SOC 201 - Current Isolated Clone**. The owner reconfirmed
  disabled adapters, no app use, stable host/console, Snapshot 1 retained, no
  concurrent or other intervening changes, and original VM untouched.
- Focused review of `7e53ecd`, `d5741e9`, `9dda08b` and `6ca2090` was confirmed
  by the owner. Reviewer name/artifact was not supplied; no Codex self-approval.
- Fresh 3 October owner release: "Yes, approved." to ONE remaining E3 -> E4 ->
  existing finite Block 4, including interruption/refusal/rollback scope.
- Source main: `87d69a1d39ea728726bae599eee57682a78e10a2`.
- Corrected five-file TLS packet SHA-256:
  `20d1ec0813bdf782708d7c44721820f8a3dee1c7bf976994f2465d8780e69a7c`;
  R1 source `e5d6fb45963c32ef9d52881661e1797abfb405fe`.
- Additive two-file endpoint packet SHA-256:
  `8a5b7014ee8b462cb912955e5111a46f42e554d62582413402f5077d62681a71`;
  14,326 bytes; E1 source `87d69a1d39ea728726bae599eee57682a78e10a2`.
- Packet hashes came from retained build/staging results. The successful run
  printed checksum rows, not packet hashes. Old preparation labels and the
  [blank worksheet](compact-broker-clone-proof-template.md) remain unchanged.

Execution contract: [endpoint E3/E4](../../docs/runbooks/rbac-broker-tls-compact-clone-endpoint-correction.md)
then [finite Block 4](../../docs/runbooks/rbac-broker-tls-compact-clone-rehearsal.md).

## Earlier observations — not spliced into this successful run

Initial preflight TOOL remains unexplained. PARENT_METADATA led to the reviewed
public-certificate reader correction; CONFIG_ENDPOINT identified the IP URL.
The first endpoint E3 stopped TOOL. Read-only diagnosis found Indexer/Manager
startup timeouts and absent endpoint/TLS maintenance state. One explicitly
approved sequential service recovery passed, four units active. Why those
initial starts timed out remains unknown. These failures, staging and recovery
outputs remain in HANDOFF and dated coordination aids.

The successful sequence below followed fresh release using the retained stages.
No package/timeout change, adapter reconnect or repeated SSH/rotation drill was
reported. It is not evidence of one uninterrupted run encompassing earlier failures.

## Retained sanitized output

### E3

```text
Type CLONE-URL-CORRECTION to reconfirm the reviewed one-URL mutation and clone conditions: CLONE-URL-CORRECTION
compact_clone_endpoint.py: OK
PASS clone endpoint: apply; Dashboard remains stopped/inhibited
PASS clone-only URL correction; private backup retained; no Dashboard start
```

### E4

```text
compact_clone_endpoint.py: OK
PASS clone endpoint: preflight-inhibited; Dashboard remains stopped/inhibited
PASS compatibility preflight in the exact stopped/inhibited phase
```

### Block 4

```text
Type CLONE-REHEARSAL to confirm the released interruption/missing-trust/rollback scope on the isolated clone: CLONE-REHEARSAL
candidate.cjs: OK
compact_operator.py: OK
bundle.json: OK
compact_clone_rehearsal.py: OK
PASS compact broker TLS: prepare
EXPECTED interruption: public trust durable; exit 73
PASS clone rehearsal: prove-interruption
PASS compact broker TLS: install
PASS compact broker TLS: resume
PASS compact broker TLS: check
PASS clone rehearsal: final
PASS clone rehearsal: refuse-missing-trust
PASS compact broker TLS: install
PASS compact broker TLS: resume
PASS compact broker TLS: check
PASS compact broker TLS: rollback
PASS clone rehearsal: prove-rollback
PASS compact broker TLS: install
PASS compact broker TLS: resume
PASS compact broker TLS: check
PASS clone rehearsal: final
PASS compact broker TLS: pause
PASS finite clone rehearsal finished; secure candidate retained; Dashboard stopped/inhibited
STOP POINT: return static PASS/STOP lines and expected exit 73; no original-VM release
```

## Checkpoint assessment and limits

| Checkpoint | Accepted observation |
| --- | --- |
| Endpoint correction / inhibited preflight | E3/E4 PASS; private backup, stopped Dashboard and inhibition retained |
| Prepare / interrupted install | Expected exit 73 after public trust durable; `prove-interruption` checks prepared partial state, original client/backup and exact failed inhibitor pre-start |
| Secure install/start/check | First install/resume/check/final PASS, active Dashboard and other-three service health checked by driver |
| Missing-trust startup refusal | `refuse-missing-trust` verifies exact mandatory guard failure and restores inhibition; secure reinstall/resume/check PASS |
| Rollback refusal / secure restoration | Original client/metadata/backup and inhibited startup verified; secure reinstall/resume/check/final PASS |
| Final pause | Secure candidate retained; Dashboard stopped/inhibited |

All 18 action observations match the reviewed order. Codex inspected the driver
and runbook; generic PASS text alone is not the proof contract. No further clone
replay is needed. Final state is a recorded checkpoint, not current VM health.

This demonstrates a process-exit interruption at the scripted position, not
power-cut/reboot/all-position resilience, hostile-root containment, continuous
integrity, atomic snapshot or OS/runtime attestation. Startup may perform ordinary
vendor loopback traffic; these helpers issue no API requests. Actual broker
login/scoped read/refresh TLS, administrator/two-dashboard continuity, human
read-only permissions and safe backend denials remain **NOT TESTED (P1-03–06)**.

Preserve private clone state and disconnected adapters; do not manually restart
Dashboard or delete stages. No private configuration, receipt or private hash is
published. Separate focused review and owner release are required for original-VM
maintenance. This record neither releases it nor closes Phase 1 or review debt.
