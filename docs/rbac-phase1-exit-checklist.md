# Phase 1 exit checklist — local-first release

**Decision date:** 1 October 2026. **Status:** owner-selected implementation scope;
Phase 1 is not complete and no live commands are released by this document.

We are delivering working human RBAC and a read-only assistant integration in
an owner-controlled lab. This checklist is the active Phase 1 release scope. It
supersedes the expanded runtime-attestation/maintenance work as a prerequisite,
not the existing TLS, authorization, secret-handling or recovery requirements.
The [main plan](rbac-wazuh-read-only-implementation-plan.md) remains the feature
contract; the [human-access runbook](runbooks/rbac-server-dashboard-readonly.md)
supplies the detailed acceptance boundaries.

## 1. Finite exit checklist

There is one completed foundation and six scoped outcomes. **Three outcomes
remain after focused package approval, the accepted 3 October clone rehearsal
and owner-confirmed scoped P1-03 evidence acceptance.**
The source-certificate reader and clone-only URL correction have owner-confirmed
focused approval. The separately released remaining E3/E4/Block 4 passed; see the
[dated owner-executed result](../evidence/rbac/compact-broker-clone-proof-2026-10-03.md).
These are
acceptance outcomes, not a promise of six VM commands or six review cycles.
An outcome closes only when its required evidence is recorded and accepted.

| ID | Outcome | Required evidence | Current status |
| --- | --- | --- | --- |
| P1-00 | Preserve accepted foundation | Indexer roles/direct mappings, agent-001/002 DLS, scoped `own_index`, service read/write-denial proof, restricted SSH/TLS and completed credential/key drill | Complete recorded checkpoints; not a fresh health assertion |
| P1-01 | Reviewed, deployable broker TLS package | Existing shared-client candidate/actual-client fixture; compact startup check; exact supported package; scoped install, private backup and interruption-safe recovery instructions; focused independent review | Complete: focused approvals owner-confirmed for `7e53ecd`, `d5741e9`, `9dda08b` and `6ca2090`; new original-VM entry/packet still requires its own review/release |
| P1-02 | Disposable-clone deployment rehearsal | New package installs, starts securely, rejects drift, survives interrupted installation in a stopped state and restores a verified secure configuration | Complete recorded owner-executed checkpoints, 3 October: E3/E4, expected exit 73, native inhibitor/guard refusals, rollback, secure restoration and final pause; not actual broker acceptance |
| P1-03 | Actual Dashboard broker TLS and continuity | Actual login, scoped Server read and refresh/re-authentication path; correct peer identity; synthetic negative TLS tests; administrator and two saved dashboards preserved | Complete scoped recorded checkpoints: original deployment and trusted L6 PASS; owner confirms focused reviewer acceptance of retained synthetic retry plus trusted reauthentication. Actual issued-token HTTP-401 retry remains NOT TESTED; no reviewer artifact supplied here |
| P1-04 | Exact human read-only configuration | Actual Dashboard authorization context and matching rules; fresh relevant permission baseline; exact `socanalyst` Server mapping and read-only UI label; owner decision on broader Server reads | Pending; broader readonly scope and complete owner-executed H3 baseline accepted, 4 October. Earlier failed attempts retained/unexplained. [Dashboard-scoped account/context and all-current-rule observation package](runbooks/rbac-dashboard-context-observation.md) prepared; awaits focused review of its equivalence/evidence limits and separate one-run release. No actual context result or mapping/UI change yet |
| P1-05 | Human allow/deny acceptance | Fresh analyst session can perform approved reads and view both dashboards; agent 000 excluded from alert data; backend writes/admin/actions denied using reviewed safe probes; administrator still works | Pending |
| P1-06 | Recovery, evidence and Phase 1 closure | Scoped rollback and secure restoration of the new changes; sanitized results and limitations; focused independent approval of the deployed path and acceptance record | Pending |

Do not replay P1-00's completed rotation/revocation, enrollment or reboot drills.
Refresh only the current invariants relevant to the upcoming change during its
preflight. Existing saved objects, identities, scoped mappings and transport
must remain intact.

## 2. Smallest deployable TLS package

We retain the [existing candidate](../siem/rbac/broker_tls/README.md): one shared
client, verified certificate and hostname, fixed `https://localhost:55000`,
bounded loopback resolution, no proxy/redirect or insecure fallback, and the
root-controlled **public** Server certificate. No broker secret moves into the
assistant, a browser widget or Git.

The [offline implementation](runbooks/rbac-broker-tls-compact-deployment.md) is a
**separate compact operator package**, not a
successful exit added to `operator_guard_entry.py`, and not release of
`operator_maintenance_control.py`. Both experimental paths remain blocked.
It uses conventional root-admin/systemd tooling under the trust assumptions below.
The compact package must include:

- One supported package/client contract and root-controlled startup-check
  inputs. A mandatory pre-start failure must prevent Dashboard startup on an
  unknown package, changed patched client, missing/changed public trust or
  incompatible configuration. Never learn or bless new hashes on failure.
- Fixed, bounded checks for the deployed patch, trust, relevant endpoint and
  startup wiring. Vendor dependencies/runtime are trusted package inputs;
  whole Python/ELF/systemd dependency attestation is not required.
- Stopped applications and Dashboard, no concurrent updates/configuration
  work, private before-state backups and durable startup inhibition before
  editing. Compare before replacement, verify after replacement, and make an
  interrupted/rebooted installation remain inhibited until explicit recovery.
- A reviewed recovery procedure for only the touched files/settings. Restoring
  the original unverified broker bytes must **not** resume Dashboard service;
  secure restoration or an accepted vendor fix is required before restart.
- Behavioral tests for success, refusal, interruption and recovery. The real
  packaged-client TLS fixture remains required; a mocked success is insufficient.

The implementation must verify its selected startup wiring on the supported
systemd version. Standard `ExecStartPre` failure stops service startup; this is
not continuous integrity monitoring or protection against privileged writers.
([systemd service contract](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml))

## 3. Live RBAC and acceptance boundaries

After TLS acceptance, observe the **actual** Dashboard context and every
matching Server rule. Do not invent a browser-controlled context, numeric role
ID or wildcard mapping. Preserve the existing Indexer DLS and read-only grants.
Add only the reviewed Server mapping and exact Dashboard read-only role label;
UI hiding is not backend authorization.

Wazuh documents a separate Server `readonly` mapping with `run_as=true`.
Our narrow Indexer scope is retained rather than copying the guide's wildcard
index example. ([Wazuh mapping guide](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html))
The built-in Server role permits broader system/agent reads than Indexer
agent-001/002 DLS. **Owner accepted that trade-off for this lab on 3 October 2026.**
That acceptance is not activation, execution release or a claim of Server DLS.
If scope changes, stop for a scoped custom Server-role decision; do not silently
claim that all Dashboard data is DLS-isolated. The assistant stays Indexer-only.

Use separate fresh analyst/admin sessions. Record effective permissions and
positive read controls before negative tests. Real-credential TLS acceptance
uses the correct trusted peer; intentionally untrusted-peer tests use synthetic
credentials. For write/admin/action probes, demonstrate safety on the supported
version before any live request: no real agent restart/removal, active response,
configuration mutation, global token revocation or unsafe bulk request.

Distinguish authentication 401, authorization 403, validation, not-found and
partial results. A hidden button, malformed body or absent target is not proof
of backend denial. Unrun rows stay **NOT TESTED** and block the corresponding
acceptance claim until safely tested or an explicit scoped review decision
changes that criterion. Account for issued-token lifetime during rollback;
removing a mapping is not an instant logout guarantee.

## 4. Four delivery batches

| Batch | Scope | Stop/acceptance boundary |
| --- | --- | --- |
| A — deployable package | Implement P1-01 using the existing candidate and a compact operator/startup/recovery package; focused tests and review | No VM mutation; no live execution release |
| B — rehearsal | One separately authorized disposable-clone deployment/recovery rehearsal for P1-02; correct actual failures | Accept rehearsal before touching the original VM; do not repeat PID 1 diagnostics |
| C — live feature | Owner-approved maintenance window: P1-03 TLS, then P1-04 exact human configuration and P1-05 behavior | TLS acceptance before credentialed run-as/configuration; explicit permission-scope decision before human activation |
| D — close Phase 1 | P1-06 recovery/evidence/review, then proceed directly to Phase 2 | No completion claim until all six outcomes are accepted |

Batch A/B and scoped corrections have owner-confirmed focused approval, not
Codex self-review or reviewer artifacts supplied in this repository. Earlier
failed preflights, staging and approved service recovery remain separate history.
The [accepted remaining clone sequence](../evidence/rbac/compact-broker-clone-proof-2026-10-03.md)
closes P1-02. Do not rebuild/replay it or use its clone-only helper/driver as an
original-VM execution release. Next is a separately reviewed and owner-released
Batch C human work using the [fresh baseline package](runbooks/rbac-human-permission-baseline.md)
after focused review/release. Original-VM TLS deployment/start and fresh trusted
L6 functional results are recorded; the owner confirmed focused acceptance of
retained synthetic retry plus trusted reauthentication for P1-03. The actual live
HTTP-401 row remains NOT TESTED. See the [later disposition and failed-baseline
diagnosis](../evidence/rbac/human-baseline-diagnostic-2026-10-03.md).

4 October follow-up: corrected H2 passed and combined H3 reached the Server
phase before stopping. A separately released Server-only run authenticated then
failed during inventory without a code; [result retained](../evidence/rbac/server-inventory-diagnostic-2026-10-04.md).
The [diagnostic-only revision](runbooks/rbac-server-inventory-diagnostics.md)
reports fixed operation/category labels, without weakening TLS, read scopes,
limits or validation. It is held for review/release, not a proven live fix or
P1-04 acceptance. Do not reset passwords or replay accepted drills to address it.
P1-04–06 remain unclosed; human context/mapping/UI/denials are pending. Do not
rerun the old failed H3; the corrected packet uses a new stage and requires renewed
focused approval and owner run release, without altering the existing permissions.
No additional approval cycle is needed at every successful checkpoint of that
single released batch; an actual failure still stops the run for correction.

New stop points must cite a concrete failure affecting one of these outcomes,
the minimal corrective work and the acceptance check. A precautionary desire
for broader OS attestation is deferred, not a new release gate. A genuine TLS,
authorization, secret-exposure or recovery failure still blocks its outcome.
Do not claim a fixed calendar duration before the deployment rehearsal.

## 5. Trusted lab boundary and deferred work

We explicitly trust the owner-controlled OS/kernel, root administrator,
systemd, normal shell/package tools and supported vendor runtime. We assume
no concurrent privileged maintenance. This release does not attest a hostile
host, contain root, defend an already compromised Dashboard process or prove
atomic/continuous loaded-code identity. Pre-start checks protect subsequent
starts under that boundary, not runtime changes by privileged actors.

Preserve but defer the full custom held-code Python guard, PID 1/library/source
and generator attestation, system-wide census/exclusivity framework and general
transactional OS/runtime upgrade engine. These are experimental, not deployed
and not Phase 1 prerequisites for this selected path. Keep their tests and
evidence. Independent review debt from `cc125c0` onward remains open; deferral
is neither approval nor a finding closure. A focused release review must cover
every component actually deployed, including reused candidate code.

For upgrades: stop/inhibit the relevant feature/Dashboard, preserve recoverable
before-state, perform normal supported package updates, then review/rebuild the
patch and compact contract on a clone before secure restart. Unknown or replaced
inputs refuse startup. Do not suppress security updates indefinitely, restore
insecure fallback, auto-refresh pins or describe this as a general upgrade engine.

## 6. CI and the route through Phases 2–5

Keep the full existing offline CI suite and frozen-evidence verifier. The
current 1294-method baseline is regression coverage, not live-feature proof or
a target to increase. No tests are deleted or weakened by this scope decision.
Add tests only for changed active-path behavior, documented failure modes and
the actual feature contract. Test consolidation is a separate future task.

After Phase 1 closes, use the existing phase order with one working vertical
slice per phase:

| Phase | Deliverable | Exit demonstration |
| --- | --- | --- |
| 2 | Local Keycloak/OIDC, separate offline/analyst profiles and server-side permissions | Valid analyst allowed; unauthenticated/unknown/ambiguous/expired identities denied; offline workflow unchanged |
| 3 | Bounded fixed-surface Indexer reader | `assistant-svc` search/get succeeds through verified TLS; arbitrary paths, indices and queries cannot be expressed |
| 4 | Live alerts through the existing shared triage and sanitized audit path | An authenticated analyst selects one live alert and gets a schema-valid DRAFT; reauthorization, audit and no SIEM action path are proven |
| 5 | Full-feature acceptance, profile-level rollback and publication | Integrated allow/deny/recovery matrix accepted; living documentation updated accurately; `v1.0` and frozen evidence untouched |

Phase 5 covers the new application's complete rollback. It must not become a
replay of already accepted Phase 1 drills without a concrete changed property.
OIDC authenticates AlertMind; it does not unify Wazuh Dashboard login in this
release. No new cloud, RAG, model or redaction-expansion work joins this scope.
