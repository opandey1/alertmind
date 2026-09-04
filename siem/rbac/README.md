# Wazuh RBAC artifacts

This directory is the secret-free source location for the post-v1 human and
machine read-only Wazuh role templates.

**Current status:** Phase 0 and the Phase 1A/1B Indexer identity and enforcement
gates are independently approved and merged through PR #10. The Phase 1C SSH
transport was then owner-executed, independently reviewed and merged through
PR #16 at `0ebc665`. Its rollback/revocation drill is now a secret-free,
unexecuted review package; Phase 1C is not complete until that drill and its
sanitized evidence receive independent approval. Wazuh Server/Dashboard, OIDC
and application integration remain unimplemented.

Planned identities:

- `socanalyst`: routine human dashboard investigation with no administration,
  rule/decoder changes, agent management or active response;
- `assistant-svc`: machine-only Indexer search/get access to the approved alert
  scope, with no Dashboard tenant and no Wazuh Server API identity. Its initial
  scope is `wazuh-alerts-4.x-*` with DLS on `agent.id` 001/002.

The machine-checked [`scope-contract.json`](scope-contract.json) pins the
approved index namespace, DLS query, canonical principal/role names and the
non-secret enrollment fingerprints current when agent IDs `001` and `002`
were approved. Re-enrollment invalidates that binding until reviewed again.

Committed Phase 1A artifacts and the Phase 1B correction package:

- `scope-contract.json` — non-executable source of approved names and scope;
- `indexer-role_socanalyst_ro.json` — exact OpenSearch role API payload;
- `indexer-role_assistant_alerts_ro.json` — exact OpenSearch role API payload;
- `indexer-role-mapping_socanalyst_ro.json` — direct-user mapping;
- `indexer-role-mapping_assistant_alerts_ro.json` — direct-user mapping;
- `indexer-role-mapping_own_index_scoped.patch.json` — normal-path JSON Patch
  that replaces the inherited wildcard with the seven pre-existing users;
- `indexer-role-mapping_own_index_rollback.patch.json` — rollback-only JSON
  Patch that restores the wildcard after both new identities are revoked;
- `SHA256SUMS` — LF-stable transfer hashes for all six executable payloads;
  and
- `negative-test-matrix.md` — executed and reusable zero-state-change proof.

Executed and independently reviewed Phase 1C transport inputs:

- `sshd-alertmind.conf` — host-only, public-key-only server drop-in with a
  source-scoped `notroot` match, local forwarding only, server-side
  `PermitOpen`, no shell sessions and no alternate facilities;
- `ssh-authorized-key-options.txt` — exact prefix for the dedicated public key;
  it contains no key material; and
- `SSH-SHA256SUMS` — LF-stable transfer hashes for those two public inputs.

The original execution and immediate fail-safe rollback sequence is in
`docs/runbooks/rbac-wazuh-ssh-transport.md`. The live transport proof is in
`evidence/rbac/phase1c-ssh-transport-proof.md`.

Unexecuted Phase 1C rollback/revocation inputs:

- `build_assistant_svc_rotation_payload.py` — interactively requires a
  confirmed password distinct from the current one and emits the replacement
  user payload only to standard output for an anonymous pipe; and
- `ROLLBACK-SHA256SUMS` — LF-stable transfer hash for that helper.

The proposed drill sequence is in
`docs/runbooks/rbac-phase1c-rollback-revocation-drill.md`. The helper contains
no credential and must never be redirected or logged when it emits a live
payload. Its existence does not claim that the drill has run.

## Inherited `own_index` correction

Before correction, the live `own_index` role was reserved/static and granted
`cluster_composite_ops` plus `indices_all` on `${user_name}`. Its separate role
mapping was editable (`reserved: false`) and matched every user through
`users: ["*"]`. OpenSearch permissions are additive, so applying the narrower
AlertMind mappings would not have removed that write path.

The applied normal-path patch changed only the mapping's `users` selector. It
now preserves
`own_index` for the seven internal users that existed before this feature—
`admin`, `anomalyadmin`, `kibanaro`, `kibanaserver`, `logstash`, `readall` and
`snapshotrestore`—while excluding `socanalyst` and `assistant-svc`. It also
deliberately stops future internal users from receiving an automatic private
write index. The pre-apply gate must prove that all other selectors are empty,
only basic internal HTTP authentication is enabled and both new user records
carry no backend or direct security roles.

The rollback patch is not part of normal application. Restoring `users: ["*"]`
while either new identity can authenticate recreates the vulnerability. First
remove the AlertMind mappings, revoke or delete both new identities and prove
both credentials fail authentication; only then may a separately reviewed
rollback restore the historical wildcard behavior.

Security-plugin authinfo may still report private-tenant metadata. That does
not mitigate Indexer permissions, and the live Wazuh Dashboard configuration
currently has multitenancy disabled. Later evidence must still prove that
`assistant-svc` cannot use Dashboard.

There is intentionally no custom Wazuh Server role payload. The human
`socanalyst` is planned to use Wazuh's built-in `readonly` Server role,
whose broader read scope must be disclosed and whose write/active-response
denials must be tested. `assistant-svc` must not receive any Wazuh Server API
identity or Dashboard tenant.

The same DLS also filters human dashboards: `socanalyst` sees only agent IDs
001/002 (about 24,557 of 35,992 inventoried alert documents), excluding about
11,445 agent-000 documents. Any dashboard capture under this role must be
labelled **DLS-scoped** and must not be compared to an administrator screenshot
as though their totals should match.

No disposable alert/probe index or sentinel may be created. The completed live
denial proof follows the fail-safe matrix in `negative-test-matrix.md`; the
optional index-level DELETE test remains prohibited in this lab.

Passwords, password hashes, tokens, private keys, authorization headers and
raw alert documents must never be committed. Internal-user passwords are
entered only by the human operator through an approved interactive path; no
password-bearing user payload belongs in this directory.
