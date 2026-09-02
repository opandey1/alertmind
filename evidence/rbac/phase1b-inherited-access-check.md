# Phase 1B evidence — inherited `own_index` access check

**Captured:** 2 September 2026 (owner-executed on `wazuh-siem`)

**Status:** Historical sanitized pre-correction evidence. At capture time the
custom roles and internal users existed, but no AlertMind direct-user mapping,
SSH transport or live assistant integration had been applied. The correction
and direct mappings were subsequently approved and executed; see
[`phase1b-indexer-enforcement-proof.md`](phase1b-indexer-enforcement-proof.md).

## Successful live steps

- Rechecked Manager, Indexer, Filebeat and Dashboard: all four were active.
- Recomputed the enrollment fingerprints for agents 001/002; both matched the
  approved Phase 0 bindings.
- Verified both canonical custom role/mapping namespaces and both internal-user
  namespaces were absent before creation.
- Transferred the four approved Phase 1A payloads to a mode-0700 staging
  directory and verified every LF-stable SHA-256 and JSON parse.
- Created `alertmind_socanalyst_ro` and
  `alertmind_assistant_alerts_ro`; both returned HTTP 201 and exact payload
  readback. The server added only `hidden`, `reserved` and `static` metadata.
- Created `socanalyst` and `assistant-svc` with owner-entered passwords; both
  returned HTTP 201. Sanitized readback showed empty backend roles, empty
  direct security roles and empty attributes. Password hashes were neither
  copied nor committed.

The two AlertMind direct-user role mappings were **not** applied.

## Inherited access finding

Before applying project mappings, authinfo for both new identities reported:

- the expected username;
- no backend roles; and
- effective role `own_index`.

The reserved/static `own_index` role grants `cluster_composite_ops` and
`indices_all` on `${user_name}`. Its separate editable mapping read back as:

```json
{
  "and_backend_roles": [],
  "backend_roles": [],
  "description": "Allow full access to an index named like the username",
  "hosts": [],
  "users": ["*"]
}
```

OpenSearch permissions are additive. Applying the narrower AlertMind mappings
would therefore have left an unrelated index write path on each identity. The
operator stopped before project mappings or any behavioral write check.

## Compatibility inventory

The internal users present after creation were `admin`, `anomalyadmin`,
`assistant-svc`, `kibanaro`, `kibanaserver`, `logstash`, `readall`,
`snapshotrestore` and `socanalyst`. The proposed normal-path correction
preserves `own_index` for the seven users that predated this feature and
excludes only the two new identities.

Only the basic internal HTTP authentication domain was enabled. Client
certificate, JWT, Kerberos, LDAP and proxy authentication domains were
disabled; both LDAP authorization domains were disabled. The mapping had no
backend-role, conjunction-role or host selector.

Security-plugin authinfo reported private-tenant metadata for both identities,
but Wazuh Dashboard configuration had multitenancy disabled and only
`.kibana_1` existed. This metadata is not proof of Dashboard access and does
not mitigate the Indexer write grant. Later proof must still show that
`assistant-svc` cannot use Dashboard.

## Gated correction design

The repository package narrows only the editable `own_index` mapping's
`users` selector. Before applying it, the operator must re-verify the exact
mapping, role definition, authentication configuration and internal-user
inventory. After application, both identities must show no `own_index` or
other unexpected effective role and must receive `403` for a read-only search
of their username-named index. Only then may the two AlertMind mappings be
applied.

The wildcard rollback is unsafe while either new identity can authenticate.
Both project mappings and both new identities must first be revoked or deleted,
and both credentials must fail authentication, before rollback can restore the
historical wildcard.

## Subsequent resolution

The live action-group readback later confirmed that
`cluster_composite_ops` included bulk and reindex writes and that
`indices_all` expanded to `indices:*`. The reviewed patch removed both new
identities from the wildcard mapping before either project mapping was applied.
Post-correction authinfo, username-index denials, DLS/read controls and the
fail-safe write matrix passed as recorded in the linked enforcement proof. No
claim is made that alert data was copied during the pre-correction interval.

## Secret and state boundary

No password, password hash, authorization header, enrollment key, private key,
token or raw alert was captured in this record. Indexer remains bound to VM
loopback, SSH remains disabled, and no index or document was created, changed
or deleted during this check.
