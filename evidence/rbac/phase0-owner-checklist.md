# Phase 0 owner evidence — RBAC and read-only Wazuh integration

**Captured:** 2 September 2026 (owner-supplied, IST)

**Status:** Sanitized pre-implementation evidence; independently approved in
Claude's 2 September 2026 review of `882c465` and merged to `main`

**Scope:** This record closes the human-input portion of Phase 0. It does not
claim that Wazuh RBAC, SSH transport, OIDC or live assistant integration has
been implemented.

## Enrollment-state fingerprints

The owner ran the reviewed command in
[`docs/runbooks/rbac-wazuh-read-only-setup.md`](../../docs/runbooks/rbac-wazuh-read-only-setup.md).
That command reads the protected enrollment file inside a privileged process
and emits only the agent ID, agent name and SHA-256 digest. No enrollment key
was printed, pasted or stored.

| Agent ID | Agent name | Enrollment SHA-256 |
|---|---|---|
| `001` | `win-victim` | `ce6dbeeff3df5ffef33e643ea36b60ffaf4f9b73577bf8c68789c867d672a5b7` |
| `002` | `linux-victim` | `483a8b3caa8e9a252aa8ea632d7a5c1ab04358c170f314ec01f1d696dfffdebf` |

The owner confirmed that neither agent had been re-enrolled since the live
inventory. These digests bind the initial DLS allowlist to the reviewed
enrollment state; they are not permanent endpoint identities. Re-enrolling
either agent invalidates this approval until its ID, name, fingerprint and DLS
scope are reviewed again.

## Owner safety checklist

- [x] Powered-off VM snapshot `Snapshot 1` remains available.
- [x] Agents `001` and `002` have not been re-enrolled since inventory.
- [x] The owner approves the reviewed host-only, key-restricted SSH local
  forward while the Indexer remains bound to `127.0.0.1:9200`.
- [x] No enrollment key, password, private key, token or other secret was
  pasted or committed while collecting this evidence.
- [x] The capture commands were observational; they did not create a Wazuh
  role/user/mapping, enable SSH, or create an index or document.

## Destructive-action safety setting

The owner read the effective cluster setting with certificate verification and
an interactively entered admin password. The sanitized response was:

```json
{"defaults":{"action":{"destructive_requires_name":"false"}}}
```

Because the effective value is `false`, the optional index-level DELETE denial
proof is **prohibited and will be omitted**. The setting must not be weakened or
changed merely to run that test. Phase 1 retains the fail-safe document-level
denial matrix: positive read, existing-ID `_create`, nonexistent-ID `_update`
with no `upsert`, nonexistent-ID document DELETE, and explicit zero-state-change
verification.

## Review gate

Closed: Claude returned `approve` for `882c465` on 2 September 2026. This
approval permits Phase 1 to begin but does not approve any later role, user,
mapping, SSH or denial-proof change; each remains independently review-gated.
