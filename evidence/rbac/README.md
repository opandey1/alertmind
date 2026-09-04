# RBAC and read-only integration evidence

This directory contains sanitized proof for the post-v1 least-privilege Wazuh
integration.

**Current status:** The sanitized Phase 0 owner checklist and enrollment
fingerprints in [`phase0-owner-checklist.md`](phase0-owner-checklist.md) were
independently approved and merged. The pre-mapping check in
[`phase1b-inherited-access-check.md`](phase1b-inherited-access-check.md)
identified an inherited `own_index` write grant. The owner subsequently
applied the reviewed correction and both direct-user mappings, then completed
the declarative, read-scope and fail-safe write-denial checks recorded in
[`phase1b-indexer-enforcement-proof.md`](phase1b-indexer-enforcement-proof.md).
That live proof is independently approved and merged through PR #10. It closes
only the Indexer gate. The sanitized SSH package prerequisite is recorded in
[`phase1c-ssh-prerequisite-check.md`](phase1c-ssh-prerequisite-check.md). The
owner subsequently installed the reviewed restricted SSH configuration and
completed the live transport, paired TLS/read and same-key denial checks now
recorded in
[`phase1c-ssh-transport-proof.md`](phase1c-ssh-transport-proof.md). Commits
`af571b1` and `0767a89` were independently approved and merged through PR #16,
closing the transport evidence gate. The rollback/revocation drill now has an
unexecuted [evidence worksheet](phase1c-rollback-revocation-proof-template.md)
and a package awaiting review; neither is evidence that the drill succeeded.
Wazuh Server/Dashboard configuration, OIDC/application authorization and the
constrained reader/UI remain unimplemented, so neither Phase 1C as a whole nor
the complete feature is finished.

Accepted evidence may include:

- snapshot identifier/time and service-health summary;
- hashes of committed secret-free templates;
- OIDC allow/deny results with a pseudonymized subject;
- `socanalyst` positive reads and negative administration/action tests;
- non-secret enrollment fingerprints tying DLS agent IDs 001/002 to the
  reviewed enrollment state;
- `assistant-svc` declarative `authinfo`/role readback and search/get success
  in the approved `wazuh-alerts-4.x-*` scope;
- complete inherited-role/mapping readback proving that `own_index` and every
  unexpected effective role are absent before and after project mappings;
- read-only `403` results for both username-named indices, without creating a
  probe index or issuing a write request;
- fail-safe `_create`, `_update` and DELETE denials using one positively read
  existing document and random nonexistent literal IDs, plus hashes/lookups
  proving zero state change;
- proof that no disposable alert/probe index or sentinel was created;
- verified-TLS SSH-tunnel connectivity, host-only listener scope and denial of
  interactive shell or unapproved forwarding for the dedicated key;
- one sanitized live alert reaching a schema-valid DRAFT through the shared
  guarded path; and
- rollback/revocation, restoration and service health before, during and after
  the disabled state.

Dashboard evidence captured as `socanalyst` must be labelled **DLS-scoped**:
the approved `agent.id` 001/002 filter excludes agent 000, so those totals are
not expected to match administrator screenshots.

Do not commit credentials, enrollment keys, client secrets, HMAC keys, SSH or
Indexer private keys,
authorization headers, unrestricted error bodies, unredacted alert `_source`,
raw pasted input or screenshots containing those values. Evidence filenames
must not imply implementation success until the complete acceptance matrix has
passed independent review.
