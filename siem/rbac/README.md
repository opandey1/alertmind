# Wazuh RBAC artifacts

This directory is the secret-free source location for the post-v1 human and
machine read-only Wazuh role templates.

**Current status:** Phase 0 scaffold only. No role, user or mapping has been
created in Wazuh, and no YAML template is authoritative yet.

Templates are deliberately deferred until the read-only inventory in
[`docs/runbooks/rbac-wazuh-read-only-setup.md`](../../docs/runbooks/rbac-wazuh-read-only-setup.md)
confirms the real alert index, template/ISM matches and usable DLS fields.

Planned identities:

- `socanalyst`: routine human dashboard investigation with no administration,
  rule/decoder changes, agent management or active response;
- `assistant-svc`: machine-only Indexer search/get access to the approved alert
  scope, with no Dashboard tenant and no Wazuh Server API identity.

Planned committed artifacts:

- `indexer-role_socanalyst_ro.yml`;
- `indexer-role_assistant_alerts_ro.yml`;
- `server-role_socanalyst_ro.yml`; and
- `negative-test-matrix.md`.

Only role names, action groups, index patterns, DLS expressions and placeholder
mapping names belong here. Passwords, hashes, tokens, private keys,
authorization headers and raw alert documents must never be committed.
