# Phase 1B evidence — Indexer least-privilege enforcement proof

**Captured:** 2 September 2026 (owner-executed on `wazuh-siem`)

**Status:** Sanitized live Indexer proof, awaiting independent review. The
scoped `own_index` correction, both direct-user mappings and the
`assistant-svc` read/write boundary were exercised successfully. This closes
only the Indexer enforcement gate; SSH transport, the Wazuh Server/Dashboard
role path, OIDC and application integration remain unimplemented.

## Preconditions and payload integrity

- Wazuh Manager, Indexer, Filebeat and Dashboard were active before and after
  the change.
- Enrollment fingerprints for `001` (`win-victim`) and `002`
  (`linux-victim`) matched the approved scope contract.
- All six transferred role, mapping and correction payloads matched
  `siem/rbac/SHA256SUMS` and parsed as JSON.
- The two internal users still had empty backend roles, direct security roles
  and attributes. Only the basic internal HTTP authentication domain was
  enabled; both LDAP authorization domains and every other HTTP
  authentication domain were disabled.
- Passwords were entered interactively. No password, password hash,
  authorization header, enrollment key, private key, token or raw alert was
  retained in this evidence.

## Inherited-role correction

Before correction, both new users had only the reserved/static `own_index`
role. The live action-group expansion was enumerated rather than inferred:

- `cluster_composite_ops` expanded to read actions plus alias actions,
  `indices:data/write/bulk` and `indices:data/write/reindex`;
- `indices_all` expanded to `indices:*` on `${user_name}`.

At that point the users had no AlertMind alert-read mapping, so the check did
not demonstrate that alert content had been copied or that DLS had been
bypassed. It demonstrated the unsafe additive combination that would have
existed if the project mappings had been applied first: the service identity
would have combined DLS-scoped alert reads with bulk/reindex actions and full
control of its username-named index. The operator prevented that combination
by stopping before project mappings.

The reviewed one-operation patch then narrowed the editable `own_index`
mapping to exactly:

```text
admin, anomalyadmin, kibanaro, kibanaserver, logstash, readall,
snapshotrestore
```

The wildcard, `socanalyst` and `assistant-svc` were absent; `backend_roles`,
`and_backend_roles` and `hosts` remained empty. Before project mapping, both
new users had an empty effective-role list and received `403` for a read-only
search of their username-named index.

## Direct mappings and effective identities

The two reviewed direct-user mappings were then applied and read back exactly:

- `socanalyst` → `alertmind_socanalyst_ro` only;
- `assistant-svc` → `alertmind_assistant_alerts_ro` only.

Neither identity inherited `own_index` or another effective role. Both
username-index searches remained `403`. Private-tenant metadata reported by
authinfo was treated as metadata, not Indexer role authority; Wazuh Dashboard
multitenancy remains disabled and the service identity has no configured
Dashboard tenant.

## Service-role read boundary

Declarative readback confirmed that `alertmind_assistant_alerts_ro` has:

- no cluster permission and no tenant permission;
- only `indices:data/read/search` and `indices:data/read/get`;
- only the `wazuh-alerts-4.x-*` namespace; and
- DLS limited to `agent.id` values `001` and `002`.

The live checks agreed with the role definition:

- an administrator search found `11,816` current agent-000 documents, while
  the same bounded count as `assistant-svc` returned zero;
- bounded search and concrete GET succeeded for one DLS-visible agent-002
  document in `wazuh-alerts-4.x-2026.08.02`;
- the selected document ID was `ubqgw58B_gEKJ1h80t7D`, and canonicalized
  `_source` SHA-256 was
  `fe4bd839165b7600ae6c1a41450e4bf6a5ab33b0d287673ace4e0474d6ab8a68`;
  the raw `_source` was not retained; and
- cluster-health read, `.opendistro_security` read and `.kibana_1` read each
  returned `403`.

No concrete `wazuh-archives-*` index existed, so denial against live archive
data was not testable. A wildcard search returned an empty `200` with zero
shards and zero hits; that result is vacuous and is not recorded as an access
grant or a denial. A read-only search against the literal archive-namespace
control `wazuh-archives-4.x-alertmind-read-denial-e52c0c3584c5c53f3fdd9786`
returned `403`. Future reruns must use a concrete archive index when one
exists.

## Fail-safe write-denial matrix

The same `assistant-svc` identity that completed the positive read was used
for all three write attempts:

| Operation | Safe target | Result |
|---|---|---|
| `_create` | Existing concrete index and existing document ID | `403`, `security_exception` |
| `_update` with `doc_as_upsert:false` and no `upsert` | Proven-absent random ID `alertmind-denial-update-02c95c541aabd4c4bbb28fea5b96b74681d9435d5401ce3c` | `403`, `security_exception` |
| DELETE | Different proven-absent random ID `alertmind-denial-delete-4dd94c365f74979d0294b4846c54f81430462faef9d0b2f1` | `403`, `security_exception` |

The original document hash was identical before and after all denials. Both
random IDs returned `404` before and after. These checks prove zero visible
state change without creating a probe index, sentinel or expected-success
write.

## TLS verification note

The Wazuh CA and the node certificate's `IP:127.0.0.1` SAN validated with
curl. Python 3.14's default context additionally enabled
`VERIFY_X509_STRICT`, which rejected the existing Wazuh CA because it lacks a
key-usage extension. The evidence harness cleared only that compatibility
flag. It retained `CERT_REQUIRED`, hostname verification and the configured
CA; the verified handshake passed and an unauthenticated request returned
`401`.

This is not authority to disable TLS verification. The later Windows client
must either use an independently reviewed compatibility context with those
same verification properties or replace the certificate chain in a separate,
reviewed infrastructure change. `verify=False`, `--insecure` and unverified
SSL contexts remain prohibited.

## Stop point

The Indexer remains on VM loopback and SSH remains disabled. No transport,
Wazuh Server role, Dashboard mapping, OIDC or application integration change
was made. The next privileged gate is the separately reviewed host-only,
key-restricted SSH local forward; this evidence requires independent review
before that gate begins.
