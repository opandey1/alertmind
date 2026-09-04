# Phase 1C evidence template — rollback and revocation drill

**Status:** Unexecuted template. This file is not evidence that the drill ran.
Copy it to `phase1c-rollback-revocation-proof.md` only after every reviewed
stage in the drill runbook completes. Replace each `PENDING` value with a
sanitized observed result; never overwrite this template.

**Runbook:**
[`docs/runbooks/rbac-phase1c-rollback-revocation-drill.md`](../../docs/runbooks/rbac-phase1c-rollback-revocation-drill.md)

## 1. Provenance and scope

| Item | Sanitized value |
|---|---|
| Owner execution date/time and timezone | `PENDING` |
| Repository commit containing the reviewed drill | `PENDING` |
| VM snapshot confirmed available | `PENDING` |
| Pre-drill application state | `PENDING` — must say no live analyst/Wazuh profile existed |
| Explicitly untouched | `socanalyst`, custom roles, DLS, scoped `own_index`, frozen evidence |
| Raw alert or `_source` captured | `PENDING` — expected `no` |
| Probe/index/document created | `PENDING` — expected `no` |

This drill covers the currently implemented restricted transport and
`assistant-svc` credential only. It cannot establish rollback of the future
OIDC/application/live-reader layer.

## 2. Reviewed artifact integrity

| Artifact | SHA-256/result |
|---|---|
| `siem/rbac/SHA256SUMS` | `PENDING` |
| `siem/rbac/SSH-SHA256SUMS` | `PENDING` |
| `siem/rbac/ROLLBACK-SHA256SUMS` | `PENDING` |
| Rotation helper syntax check | `PENDING` |

Do not place a password, password hash, public-key line, private key,
authorization header, raw response body or verbose diagnostic log in this
file. Public SHA-256 key/certificate fingerprints are permitted.

## 3. Pre-drill boundary

| Check | Result |
|---|---|
| Owner confirmed app stopped; no visible Streamlit CLI process | `PENDING` — not a claim about inaccessible/nonstandard processes |
| Existing Windows tunnel | `PENDING` — expected loopback `127.0.0.1:19200` only |
| Existing SSH client public fingerprint | `PENDING` |
| Pinned VM host-key fingerprint | `PENDING` |
| Wazuh public CA SHA-256 | `PENDING` |
| Exact `alertmind_assistant_alerts_ro` role and mapping | `PENDING` |
| Exact `assistant-svc` effective role | `PENDING` |
| Scoped `own_index` unchanged | `PENDING` |
| `socanalyst` user/mapping present and untouched | `PENDING` |
| Wazuh health: Indexer → Manager → Filebeat → Dashboard | `PENDING` |

## 4. Disabled and revoked state

| Check | Result |
|---|---|
| Windows TCP 19200 listener absent | `PENDING` |
| `ssh.service` / `ssh.socket` masked and inactive | `PENDING` |
| VM TCP 22 listener absent | `PENDING` |
| SSH drop-in absent and authorized-key entry count zero | `PENDING` |
| OpenSSH packages retained at reviewed versions | `PENDING` |
| `alertmind_assistant_alerts_ro` mapping absent | `PENDING` |
| `assistant-svc` user absent | `PENDING` |
| Old service password rejected after deletion | `PENDING` — expected HTTP `401` |
| Custom role, `socanalyst` and scoped `own_index` retained | `PENDING` |
| Wazuh health: Indexer → Manager → Filebeat → Dashboard | `PENDING` |

## 5. Service-credential rotation and restoration

| Check | Result |
|---|---|
| Replacement password transported only through anonymous pipe | `PENDING` |
| Replacement differs from old value | `PENDING` — human attestation only; no value recorded |
| Replacement user initially has zero effective roles | `PENDING` |
| Old password rejected after recreation | `PENDING` — expected HTTP `401` |
| Reviewed direct-user mapping restored exactly | `PENDING` |
| Replacement effective role | `PENDING` — expected only `alertmind_assistant_alerts_ro` |
| Bounded metadata-only read | `PENDING` — record failed shards, hit count and relation only |
| Cluster-health and username-index reads denied | `PENDING` — expected HTTP `403` / `403` |

## 6. SSH-key rotation and transport restoration

| Check | Result |
|---|---|
| Revoked client public fingerprint | `PENDING` |
| Replacement client public fingerprint | `PENDING` |
| Fingerprints differ | `PENDING` |
| VM authorized-key entry count and installed fingerprint | `PENDING` |
| Old SSH key denied with no authentication marker | `PENDING` — expected old fingerprint offered and explicit public-key denial |
| VM host-key fingerprint unchanged | `PENDING` |
| One VM listener at `192.168.56.102:22`; socket masked | `PENDING` |
| One Windows listener at `127.0.0.1:19200` | `PENDING` |
| Wrong-hostname TLS leg | `PENDING` — expected curl exit `60` |
| Correct-identity TLS/read leg | `PENDING` — metadata only |
| Replacement key promoted to canonical ignored path | `PENDING` |
| Revoked local key files removed | `PENDING` — do not claim forensic erasure |
| Canonical-path tunnel and bounded read repeated | `PENDING` |
| Shell, PTY, remote-forward, alternate-destination and password denials using promoted key | `PENDING` — after canonical-path positive proof |

## 7. Final state and claim boundary

| Check | Result |
|---|---|
| Exact replacement service role/mapping | `PENDING` |
| Scoped `own_index` still excludes both AlertMind principals | `PENDING` |
| `socanalyst` unchanged | `PENDING` |
| Restricted SSH transport restored | `PENDING` |
| Wazuh health: Indexer → Manager → Filebeat → Dashboard | `PENDING` |
| Frozen artifacts and model runs unchanged | `PENDING` |

**Allowed conclusion after independent approval:** the currently implemented
Phase 1C transport and `assistant-svc` credential were disabled, revoked,
rotated and restored without broadening the reviewed read boundary or changing
Wazuh service health.

**Not established:** application-profile rollback, OIDC, Dashboard/Server RBAC,
live alert ingestion, model-path execution, production readiness, certificate
revocation availability or secure erasure of a deleted private-key file.

## 8. Deviations and failures

`PENDING` — list every failed or aborted attempt and the fail-closed state. Do
not omit a failed stage or turn a partial run into a passing conclusion.

## 9. Independent review

| Item | Value |
|---|---|
| Reviewer | `PENDING` |
| Reviewed commit | `PENDING` |
| Verdict | `PENDING` |
| Required corrections | `PENDING` |
