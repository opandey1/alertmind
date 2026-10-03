# Human baseline — failed attempt and read-only diagnosis, 3 October 2026

Scope: owner-reported original-VM observations and offline author reproduction.
This is **not** a completed H3/Server baseline, independent review or execution
release. No raw responses, passwords, hashes of passwords, tokens or alert sources
were supplied. Existing packets/stages/failed outputs are retained unchanged.

## Original released attempt

The owner confirmed focused independent approval of `207bffb` and authorized one
H2-H3 run on the original wazuh-siem with retained snapshots/before-state, stable
console/host/VM, stopped applications and no concurrent maintenance. That approval
was owner-confirmed; no independent reviewer artifact was supplied here.

- H1: public packet SHA-256
  `aff08cf4c170fec2d4a86eacc0b254eab02107222fb12839c4099954740e9cd1`.
- H2: eight exact root-private public files; syntax only; same packet digest.
- H3: seven payload checksums and all four service-health checks passed.
  Indexer CA/name/exact-peer and wrong-hostname checks passed before credentials.
  The helper then stopped with:

```text
STOP: human baseline failed at socanalyst Indexer; no result accepted; no mapping or service action issued
```

The original HTTP status/internal exception code was not emitted. Do not infer
which password was supplied or promote a guessed `IDENTITY_DRIFT` to an observed
original error code. The assistant-svc and Server inventory phases were not
reached. The failed run ended its execution release; do not replay it.

## Separate, later read-only diagnostics

The owner executed fixed GET-only diagnostics on the original VM. Bodies were
processed locally into whitelisted metadata, without printing raw responses or
changing credentials, roles, mappings, services or configuration.

1. `socanalyst` authinfo: curl exit `0`, HTTP `200`.
2. Both authinfo and the installed legacy account route reported matching
   `user_name`, present/empty backend roles, a present role list of length one,
   and the exact role `alertmind_socanalyst_ro`.
3. The exact H3 count queries returned:

| Identity | agent.id | Exact total |
| --- | --- | ---: |
| admin | 000 | 13305 |
| socanalyst | 000 | 0 |
| socanalyst | 001 | 778 |
| socanalyst | 002 | 15121 |

All four responses had `timed_out=false`, zero failed shards, total relation
`eq`, zero returned hits and the collector's count-shape predicate passing.
These are separately observed current controls, not an atomic snapshot, a
substitute for the full H3 rechecks/Server graph, or actual Dashboard context.

## Offline reproduction and correction scope

The old collector returned whole authinfo/account objects and compared them
across fresh connections. `remote_address` includes the source TCP port per the
[OpenSearch authinfo contract](https://docs.opensearch.org/latest/security/api/authentication/auth-info/).
The author reproduced `IDENTITY_DRIFT` locally by changing only that source port
while holding the role, account and all count controls constant. A constant-port
control passed. No API/VM requests or real credentials were used for reproduction.

The correction removes only a validated source port from a copy of authinfo for
comparison. Host/presence changes, malformed metadata, effective-role/backend
role changes, tenant/attribute/unknown authinfo changes and any account changes
remain rejected. It does not relax TLS, allow extra grants or modify vendor/API
configuration. The public packet and new staging path require their own focused
review and renewed owner release. No VM run of the corrected collector is claimed.

## Separate P1-03 disposition and remaining gates

The owner separately confirmed focused reviewer acceptance of the retained
synthetic token-retry tests plus warning-free trusted-profile L6 reauthentication
for P1-03. Actual issued-token refresh/HTTP-401 retry remains **NOT TESTED**.
This is owner-confirmed scoped evidence acceptance, not Codex self-review or a
newly executed retry. Existing failed browser attempt and later trusted L6 result
remain distinct. P1-04 baseline/context/mapping/UI, P1-05 analyst acceptance and
P1-06 recovery/evidence/closure remain pending; the assistant remains Indexer-only.
