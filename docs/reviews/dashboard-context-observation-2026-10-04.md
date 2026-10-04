# Dashboard-scoped account/context equivalence and two-rule review

**Codex author analysis, 4 October 2026; awaiting focused independent review.**
No new native result, reviewer approval, exact run-as wire-body observation or
VM/browser execution release is asserted. This is the derivation argument for
the [finite observation package](../runbooks/rbac-dashboard-context-observation.md).

## Public version-matched evidence

Read-only extraction from the official Wazuh Dashboard 4.14.7-1 amd64 `.deb`,
193952104 bytes, SHA-256
`83f472d9e5f59b28b1abb6260c466e77b99ae427ce8c5f76203d847f2f598b6f`.
Archive/source bytes were parsed, not executed or installed. Source-map comment
payloads were not used as executable evidence. This is the same public package
identified in the [earlier broker review](dashboard-broker-control-flow-tls-2026-09-09.md).

| Vendor file under `plugins/` | Relevant compiled lines | Observation |
| --- | --- | --- |
| `securityDashboards/common/index.js` | 38–39 | API prefix `/api/v1`, configuration prefix `configuration` |
| `securityDashboards/server/routes/index.js` | 243–267, 829–838 | GET resource route returns `{total,data}`; absent data-source query selects request-scoped current-user client |
| `securityDashboards/server/backend/opensearch_security_configuration_plugin.js` | 54–64 | `listResource` reads `/_plugins/_security/api/<resourceName>`; observation fixes `account` |
| `wazuhCore/server/services/security-factory/factories/opensearch-dashboards-security-factory.js` | 17–37 | Wazuh context derives from `/_opendistro/_security/api/account` through `asCurrentUser`; `user_name` is extracted from the returned body |

The four complete-file hashes are explicit `CODE_PINS` in the observer; they are
not learned from the VM. The vendor broker-client hash is deliberately **not**
used for the patched client. The [OpenSearch 2.19.5 account handler](https://github.com/opensearch-project/security/blob/2.19.5.0/src/main/java/org/opensearch/security/dlic/rest/api/AccountApiAction.java)
defines the nine emitted account fields. [Prefix registration](https://github.com/opensearch-project/security/blob/2.19.5.0/src/main/java/org/opensearch/security/dlic/rest/support/Utils.java)
maps both legacy/current account prefixes to the same handler. The security
Dashboard wraps this account as `data` and counts its keys as `total`, not as
an affected-item catalog. The browser script must unwrap and validate that
wrapper; a direct Indexer response or `authinfo` is not interchangeable.

The supported empty-custom-attribute SOC account includes identity/internal
flags, requested tenant, backend roles, custom attribute names, tenants and
effective roles. Arbitrary account extensions or custom attributes stop. This
avoids exporting their values and prevents partial-context matching. Unknown
response fields must not be discarded to obtain acceptance.

## Scope of equivalence, not stronger instrumentation

The existing account route observes the actual authenticated Dashboard scoped
identity. The Wazuh factory uses the corresponding account handler under the
same identity, so this is an explicit **equivalence argument** for the factory's
context shape/identity, supported by current code pins and a fresh human session.
It does not execute that factory function solely to inspect its result, capture
the precise outgoing run-as body, inspect a JWT or establish human Server policy.
The human carries only a sanitized summary. Its provenance is attested by the
owner, not cryptographically established by the pasted JSON/challenge. Focused
review must accept this evidence boundary explicitly; no full context is sent
to a new probe service and no live logging/patch/instrumentation is introduced.

## All current predicates, not just a proposed rule

The accepted H3 graph has two predicates linked to `administrator`:

- `FIND {username: elastic}`, canonical predicate SHA-256
  `10d03aa9909848c52412d09eef05217bd66b87fbcff341a216d31cc97d506a8d`.
- `FIND {user_name: admin}`, canonical predicate SHA-256
  `2be3d3cd964f20af71a8d2147003264e751ae61f6ace42131461e6a08d8ddc74`.

The new observer rereads the complete graph with the unchanged approved reader,
requires **exactly** these predicates and their current unique administrator
relationship, and rejects unknown predicates before the browser run. Live rule,
administrator and readonly IDs are observations, not historical constants. The
broker ID 2 requirement is separately explicit because the
[v4.14.7 RBAChecker](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/rbac/auth_context.py)
restricts reserved-rule application by that broker ID.

For this literal single-field subset, `FIND` searches dictionaries recursively,
including dictionaries inside lists; a matching literal in an attribute list
also satisfies non-strict `MATCH`. The browser implementation covers that subset
only. It is not a general Wazuh predicate interpreter: regex, AND/OR/NOT, MATCH$,
FIND$, extra predicates or unexpected account shapes refuse rather than being
treated as false. Every current rule is checked; any positive match ends the
pre-mapping observation instead of granting or silently inheriting its role.

The final result records the observed top-level `user_name=socanalyst` binding,
no current matching role, current readonly ID and a sanitized full-Server-summary
fingerprint. It emits **no mapping payload**. Selecting a later exact top-level
predicate and validating actual human Server policy remain separate reviewed
implementation/acceptance work. Changed catalogs, returned roles, source bytes,
browser account or unsupported versions fail closed without automatic retry.
