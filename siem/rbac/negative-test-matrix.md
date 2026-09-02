# Phase 1 fail-safe Wazuh denial matrix

**Status:** Pre-registered; do not execute until the inherited `own_index`
grant has been removed from both new identities and both AlertMind role
mappings have then been applied from independently approved templates.

This matrix proves the effective `assistant-svc` boundary without creating a
probe index, sentinel document or any expected-success write. It must be run
with the same `assistant-svc` credential used for the positive read. Never use
the administrator credential for a denial row.

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
- Generate two different cryptographically random document IDs and first GET
  each one to prove both are absent.

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
| 3 | `_update` the first proven-absent random ID with a `doc` body, `doc_as_upsert:false`, and **no** `upsert` field | `403` | If accidentally allowed, update returns not found and cannot create. |
| 4 | DELETE the second proven-absent random document ID | `403` | If accidentally allowed, deleting an absent ID changes no document. |
| 5 | Re-GET and re-hash the original; GET both random IDs | Original hash unchanged; both random IDs remain absent | Explicitly proves zero state change. |

Stop immediately if any request in steps 2–4 returns anything other than
`403`. Preserve only sanitized status, correlation and hash evidence, disable
the service role mapping, and review the role before continuing.

## Prohibited checks

Do not create or delete an index. The live ISM policy auto-attaches to the
broader `wazuh-alerts-*` namespace, and the effective cluster setting
`action.destructive_requires_name=false` makes the optional index-delete check
unsafe in this lab. Do not change that setting to make a test possible. Never
use `*`, `_all`, a comma-separated index list or an existing index name in an
index DELETE request.
