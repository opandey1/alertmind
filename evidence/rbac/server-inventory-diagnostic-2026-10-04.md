# Server-only inventory diagnostic — failed owner run, 4 October 2026

Owner-reported output under the separately authorized read-only diagnostic.
Codex assessment, not independent approval or a VM observation by Codex.
Historical execution aid/result remains outside Git. No private input supplied.

## Returned evidence

```text
Type APPROVED-SERVER-DIAGNOSTIC only on the original VM with approved stable/private conditions: APPROVED-SERVER-DIAGNOSTIC
collect_human_baseline.py: OK
collect_server_inventory.py: OK
scope-contract.json: OK
indexer-role_socanalyst_ro.json: OK
indexer-role_assistant_alerts_ro.json: OK
indexer-role-mapping_socanalyst_ro.json: OK
indexer-role-mapping_assistant_alerts_ro.json: OK
collect_server_inventory.py: OK
PASS service health: wazuh-indexer=active
PASS service health: wazuh-manager=active
PASS service health: filebeat=active
PASS service health: wazuh-dashboard=active
PASS unchanged reviewed Server reader and existing stage; no Indexer run or live change
Type REVIEWED only after independent approval of this package: REVIEWED
PASS this client: verified/pinned localhost TLS and hostname rejection; no credentials sent yet.
Existing SERVER administrator username (not assumed Indexer admin):
Existing SERVER administrator password:
STOP: Server inventory failed at inventory; no result accepted. Do not paste credentials or raw responses.
```

The exact previously approved reader pin verified in this attempt was
`08ff077faa6f33a1e6bcd431c1f059ded3b753c63e975127451d5a4771e7aef5`.
The corrected stage's packet was
`55ffb1119b33e2b002d05540cbfab6873a3ed814b9030a8236c3640f178d4dc0`.
This is old-reader evidence, not execution of the new diagnostic revision.

## Interpretation and limits

- Public guards, service checks at execution and pre-credential TLS proof passed.
- The standalone reader assigns `inventory` only after `authenticate()` returns:
  the supplied Server credentials were accepted and a valid-shaped token parsed.
  This is NOT completed administrator identity/scope verification.
- Its predefined `InventoryError` branch would print a code. A generic STOP
  means another exception type or KeyboardInterrupt; exact type, HTTP read,
  response shape, graph-validation point and root cause remain UNKNOWN.
- Offline synthetic KeyError, JSONDecodeError and TimeoutError each reproduce
  the same generic STOP with private payload redacted. Those are examples of
  ambiguity, not diagnoses of the VM failure. No credential reset is warranted.
- Unlike combined H3's broad stage label, this standalone entry point performs
  no final Indexer checks. Thus the current failure is localized to Server
  inventory. It does not retrospectively identify the combined run's exact cause.
- No summary or human baseline accepted. One diagnostic release consumed;
  preserve both earlier stages, packets, failed outputs and old aids. No retry,
  role/configuration change, service restart or another login automatically allowed.

The owner subsequently authorized implementation of a **diagnostic-only**
correction and regression tests for focused review. The new held
[runbook](../../docs/runbooks/rbac-server-inventory-diagnostics.md) reports fixed
operation/category labels without raw errors or responses. This does not claim
the live defect repaired. It needs independent review and a new run release.
