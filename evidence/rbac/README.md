# RBAC and read-only integration evidence

This directory will contain sanitized proof for the post-v1 least-privilege
Wazuh integration.

**Current status:** Phase 0 scaffold only. No live RBAC proof has been captured,
and the feature must still be described as planned.

Accepted evidence may include:

- snapshot identifier/time and service-health summary;
- hashes of committed secret-free templates;
- OIDC allow/deny results with a pseudonymized subject;
- `socanalyst` positive reads and negative administration/action tests;
- `assistant-svc` search/get success and index/update/delete denials against the
  disposable probe;
- proof that the sentinel remained unchanged and the probe index was removed;
- verified-TLS connectivity and firewall-scope evidence;
- one sanitized live alert reaching a schema-valid DRAFT through the shared
  guarded path; and
- rollback/revocation and post-rollback service health.

Do not commit credentials, client secrets, HMAC keys, private keys,
authorization headers, unrestricted error bodies, unredacted alert `_source`,
raw pasted input or screenshots containing those values. Evidence filenames
must not imply implementation success until the complete acceptance matrix has
passed independent review.
