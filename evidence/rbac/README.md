# RBAC and read-only integration evidence

This directory will contain sanitized proof for the post-v1 least-privilege
Wazuh integration.

**Current status:** The sanitized Phase 0 owner checklist and enrollment
fingerprints are recorded in
[`phase0-owner-checklist.md`](phase0-owner-checklist.md) and await independent
review. No live RBAC proof has been captured, and the feature must still be
described as planned.

Accepted evidence may include:

- snapshot identifier/time and service-health summary;
- hashes of committed secret-free templates;
- OIDC allow/deny results with a pseudonymized subject;
- `socanalyst` positive reads and negative administration/action tests;
- non-secret enrollment fingerprints tying DLS agent IDs 001/002 to the
  reviewed enrollment state;
- `assistant-svc` declarative `authinfo`/role readback and search/get success
  in the approved `wazuh-alerts-4.x-*` scope;
- fail-safe `_create`, `_update` and DELETE denials using one positively read
  existing document and random nonexistent literal IDs, plus hashes/lookups
  proving zero state change;
- proof that no disposable alert/probe index or sentinel was created;
- verified-TLS SSH-tunnel connectivity, host-only listener scope and denial of
  interactive shell or unapproved forwarding for the dedicated key;
- one sanitized live alert reaching a schema-valid DRAFT through the shared
  guarded path; and
- rollback/revocation and post-rollback service health.

Do not commit credentials, enrollment keys, client secrets, HMAC keys, SSH or
Indexer private keys,
authorization headers, unrestricted error bodies, unredacted alert `_source`,
raw pasted input or screenshots containing those values. Evidence filenames
must not imply implementation success until the complete acceptance matrix has
passed independent review.
