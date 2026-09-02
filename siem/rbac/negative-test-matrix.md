# Phase 1 fail-safe Wazuh denial matrix

**Status:** Executed by the owner on 2 September 2026 after the inherited
`own_index` grant was removed and both independently approved AlertMind role
mappings were applied. All required write attempts returned `403`; the
original hash was unchanged and both random IDs remained absent. Sanitized
results are recorded in
`evidence/rbac/phase1b-indexer-enforcement-proof.md`. Retain this matrix as the
normative procedure for reruns.

This matrix proves the effective `assistant-svc` boundary without creating a
probe index, sentinel document or any expected-success write. It must be run
with the same `assistant-svc` credential used for the positive read. Never use
the administrator credential for a denial row.

## Read-scope controls

Before the write matrix, prove a positive bounded search and concrete GET for
one DLS-visible document. Require `403` for cluster health and for existing
restricted Security/Dashboard indices.

For `wazuh-archives-*`, first enumerate concrete archive indices as
administrator without retrieving document bodies:

- if one exists, search a concrete archive index as `assistant-svc` and require
  `403`;
- if none exists, record that denial against live archive data is not
  testable. An empty wildcard `200` with zero shards and zero hits is vacuous,
  not proof of a grant or denial. Use a cryptographically random literal name
  in the `wazuh-archives-4.x-*` namespace for a read-only `403` control, and
  repeat the concrete-index test when archive data exists.

Do not create an archive index merely to make this row testable.

## Preconditions

- Recompute the enrollment fingerprints for agents `001` and `002` and match
  them to [`scope-contract.json`](scope-contract.json).
- Read back the complete `own_index` mapping. Require its `users` selector to
  equal the seven preserved pre-existing users in the scope contract; require
  `backend_roles`, `and_backend_roles` and `hosts` to be empty. The wildcard,
  `socanalyst` and `assistant-svc` must all be absent.
- Authenticate separately as `socanalyst` and `assistant-svc`. Confirm
  `own_index` is absent and that each identity has only its expected AlertMind
  role, with no backend role, direct internal-user security role or unexpected
  effective role.
- Read back `alertmind_assistant_alerts_ro`, its role mapping and
  `_plugins/_security/authinfo`; sanitize the output before committing it.
- Confirm the role has no cluster permission, no Dashboard tenant, the exact
  `wazuh-alerts-4.x-*` pattern, DLS on `agent.id` values `001`/`002`, and only
  `indices:data/read/search` plus `indices:data/read/get`.
- Select one real DLS-visible document using a bounded search. Record only its
  concrete index, document ID and a SHA-256 of canonicalized `_source` in the
  private operator worksheet; do not commit the raw alert.
- Generate two different cryptographically random document IDs for the same
  positively read concrete index. First GET each one and require `404`, not
  `403`: this proves read access to the containing index while proving both IDs
  are absent.

## Inherited-role check

Before step 1, perform a read-only search against each username-named index:
`GET /socanalyst/_search` and `GET /assistant-svc/_search`. Both must return
`403`. Do not issue a write request and do not create either index. This check
must pass once before the project mappings are applied and again after they are
applied; it proves that neither the old `own_index` grant nor a sibling mapping
survives outside the approved alert namespace.

## Required sequence

| Step | Request | Expected result | Fail-safe property |
|---|---|---|---|
| 1 | Search, then GET the selected existing document by concrete index and ID | `200` and the same document | Makes later denials non-vacuous for authentication, index scope and DLS. |
| 2 | `_create` using that existing concrete index and existing ID | `403` | If write were accidentally allowed, create-only semantics conflict and cannot overwrite. |
| 3 | In the same positively read concrete index, `_update` the first proven-absent random ID with a `doc` body, `doc_as_upsert:false`, and **no** `upsert` field | `403` | The precheck's `404`, rather than `403`, proves index read access; this result therefore isolates the denied update action. If accidentally allowed, update returns not found and cannot create. |
| 4 | In the same positively read concrete index, DELETE the second proven-absent random document ID | `403` | The precheck's `404`, rather than `403`, proves index read access; this result therefore isolates the denied delete action. If accidentally allowed, deleting an absent ID changes no document. |
| 5 | Re-GET and re-hash the original; GET both random IDs | Original hash unchanged; both random IDs remain absent | Explicitly proves zero state change. |

Stop immediately if any request in steps 2–4 returns anything other than
`403`. Preserve only sanitized status, correlation and hash evidence, disable
the service role mapping, and review the role before continuing.

The 2 September execution used create-only semantics on the positively read
document, a non-upserting update against one proven-absent random ID and DELETE
against a different proven-absent ID, all in the same positively read concrete
index. Both random-ID prechecks returned `404`, not `403`, establishing index
read access before the action-level denials. Each write returned `403` with a
`security_exception`; the original canonical `_source` hash matched before and
after, and both random IDs returned `404` after the attempts.

## Prohibited checks

Do not create or delete an index. The live ISM policy auto-attaches to the
broader `wazuh-alerts-*` namespace, and the effective cluster setting
`action.destructive_requires_name=false` makes the optional index-delete check
unsafe in this lab. Do not change that setting to make a test possible. Never
use `*`, `_all`, a comma-separated index list or an existing index name in an
index DELETE request.
