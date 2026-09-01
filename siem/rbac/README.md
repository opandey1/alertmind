# Wazuh RBAC artifacts

This directory is the secret-free source location for the post-v1 human and
machine read-only Wazuh role templates.

**Current status:** Phase 0 is independently approved and merged. Phase 1A
defines the exact, secret-free Indexer role and direct-user mapping payloads
for independent review. No role, user or mapping has been created in Wazuh
yet; live application remains blocked until this package is approved.

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

Committed Phase 1A artifacts:

- `scope-contract.json` — non-executable source of approved names and scope;
- `indexer-role_socanalyst_ro.json` — exact OpenSearch role API payload;
- `indexer-role_assistant_alerts_ro.json` — exact OpenSearch role API payload;
- `indexer-role-mapping_socanalyst_ro.json` — direct-user mapping;
- `indexer-role-mapping_assistant_alerts_ro.json` — direct-user mapping;
- `SHA256SUMS` — LF-stable transfer hashes for the four executable payloads;
  and
- `negative-test-matrix.md` — pre-registered zero-state-change proof.

There is intentionally no custom Wazuh Server role payload. The human
`socanalyst` is planned to use Wazuh's built-in `readonly` Server role,
whose broader read scope must be disclosed and whose write/active-response
denials must be tested. `assistant-svc` must not receive any Wazuh Server API
identity or Dashboard tenant.

No disposable alert/probe index or sentinel may be created. Live denial proof
uses the fail-safe matrix in `negative-test-matrix.md`; the optional
index-level DELETE test is prohibited in this lab.

Passwords, password hashes, tokens, private keys, authorization headers and
raw alert documents must never be committed. Internal-user passwords are
entered only by the human operator through an approved interactive path; no
password-bearing user payload belongs in this directory.
