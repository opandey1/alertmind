# AlertMind — RBAC and read-only Wazuh integration

**Document status:** Review-corrected implementation plan; implementation not
started

**Date:** 1 September 2026

**Applies to:** current `assistant/` package, Wazuh 4.14.5, Streamlit
`>=1.59` user specification and Streamlit 1.62.0 CI lock

**Roadmap item:** Post-v1 local-first access control and live alert ingestion

---

## 1. Executive decision

Implement RBAC and live read-only Wazuh ingestion as one opt-in **analyst
profile**. The current offline/frozen-corpus workflow remains the default and
continues to work without Wazuh, an identity provider, or network access.

The implemented feature will establish these properties:

1. A human analyst must authenticate before seeing live Wazuh data or invoking
   a protected model call.
2. Application permissions are checked server-side immediately before every
   protected operation; hidden controls and `st.session_state` are not treated
   as authorization.
3. The assistant uses a dedicated, non-interactive `assistant-svc` credential
   that can search approved Wazuh alerts and cannot write documents, administer
   Wazuh, manage agents or rules, or invoke active response.
4. Live alerts enter the existing redaction, view, prompt-boundary, model-call,
   schema-validation and mandatory-review path.
5. The model remains text-only and draft-only. This feature adds a read path,
   not an action path.

The live alert source is the **Wazuh Indexer API on HTTPS port 9200**, because
Wazuh stores alerts in `wazuh-alerts-*`. The Wazuh Server API on port 55000 is
a management plane and is not part of the assistant runtime. Existing diagrams
and documentation that show `:55000` as the planned alert-ingestion path must
be corrected when the feature is proven.

---

## 2. Validated starting point

The plan is based on the current repository rather than the earlier
`assistant_v4` proposal:

- `assistant/app.py` currently has no authentication and writes user-entered
  provider URLs and keys into process-wide environment variables.
- `assistant/paste_tab.py` and `assistant/paste_core.py` already implement
  Paste & inspect, input limits, redaction with trace, injection visibility,
  the independent delimiter gate, egress consent, schema validation and an
  optional sanitized audit record.
- Paste & inspect is explicitly local and single-user today.
- `assistant/requirements.txt` is the flexible user-install specification and
  currently permits `streamlit>=1.59`; `assistant/requirements-ci.lock` is the
  reproducible Python 3.12 Linux CI lock and pins Streamlit 1.62.0. Neither
  currently includes the Streamlit authentication extra/Authlib.
- Wazuh 4.14.5 is an all-in-one deployment. Only `admin` exists; the indexer is
  documented as localhost-only; `socanalyst`, `assistant-svc` and live
  ingestion are unimplemented.
- The pre-feature regression baseline was 78 assistant tests plus the frozen-
  evidence verifier. Phase 0 adds eight characterization tests, bringing the
  branch to 86 tests without changing prompts, views, redaction, schema,
  scoring or frozen evidence. Frozen corpus files and committed run evidence
  are immutable.

No benchmark model rerun is required if this work leaves prompts, views,
redaction semantics, schema, scoring and accepted run artifacts unchanged.
Offline CI and the frozen-evidence verifier are the regression gate.

---

## 3. Scope and non-goals

### 3.1 In scope

- local OIDC authentication for the Streamlit analyst profile;
- application roles and named permissions;
- a read-only Wazuh dashboard identity for routine human investigation;
- a machine-only Wazuh Indexer identity for the assistant;
- network-restricted, certificate-verified Indexer access;
- bounded recent-alert search and single-alert retrieval;
- normalization of a Wazuh hit into an AlertMind model input;
- a live-alert Streamlit tab that reuses the guarded triage path;
- subject-attributed, sanitized authorization and retrieval auditing;
- positive and negative permission evidence; and
- architecture, runbook and public-document updates after proof passes.

### 3.2 Explicitly out of scope

- active response, agent control, rule/decoder changes or any Wazuh write;
- giving the model tools, retrieval credentials or direct network access;
- arbitrary OpenSearch query DSL, arbitrary index names or arbitrary API paths;
- using the Wazuh Server API on `:55000` as an alert store;
- production multi-tenancy, high availability or internet exposure;
- replacing or extending the frozen benchmark with live alerts;
- re-running published model comparisons solely because integration code was
  added;
- a new password database inside Streamlit; and
- full SSO unification between Wazuh Dashboard and Streamlit in the first
  increment.

---

## 4. Local-first deployment model

### 4.1 Profiles

Add an explicit server-side application profile:

| Profile | Authentication | Inputs | Providers | Persistence |
|---|---|---|---|---|
| `offline` (default) | None; localhost only | Frozen corpus and synthetic Paste fixtures | `mock` and loopback Ollama only | Existing local evidence behavior |
| `analyst` | OIDC required | Frozen corpus, approved Paste input and live Wazuh alerts | Server-allowlisted local or hosted provider | Sanitized multi-session audit store |

`analyst` must fail at startup if OIDC, Wazuh URL, CA or service credentials
are missing. There is no runtime flag that turns an unauthenticated session
into an analyst. Tests inject identities through Python dependencies, not a
shipped browser-visible “development login”.

### 4.2 Authentication choice

Use Streamlit's native OIDC flow (`st.login`, `st.user`, `st.logout`) with a
local Keycloak realm as the reference lab deployment. Add the Streamlit auth
extra/Authlib to the flexible requirement and regenerate the CI lock under the
bounded dependency gate in Phase 2. A different standards-compliant OIDC
provider may be substituted without changing the application authorization
contract.

For the first increment, keep the two human login realms explicit:

- Keycloak authenticates the analyst to Streamlit and supplies the
  `alertmind-socanalyst` group claim.
- A Wazuh internal user named `socanalyst` proves read-only Dashboard access.

These are two credentials for the same lab duty, not one shared credential.
The application never receives the analyst's Wazuh password. A later Keycloak
SAML integration can unify Wazuh Dashboard sign-in, but it is deferred because
it changes the Indexer authentication domain and materially expands rollback
risk.

### 4.3 Data and trust-boundary flow

```text
browser
  │ OIDC login
  ▼
Streamlit analyst profile ── validates claims ── authorizes named permission
  │
  │ server-side HTTPS + assistant-svc + trusted CA
  ▼
Wazuh Indexer :9200 / wazuh-alerts-*/_search
  │ bounded hits; DLS/index role remains authoritative
  ▼
normalize one selected hit
  ▼
redact → apply view → marker scan + independent delimiter gate
  ▼
approved model provider → validate JSON → DRAFT for analyst review
```

The browser never receives the Wazuh service password, authorization header,
OIDC client secret, provider key or raw audit database.

---

## 5. Identity and permission contract

### 5.1 Principal matrix

| Principal | Authentication plane | Allowed | Explicitly denied |
|---|---|---|---|
| `admin` | Existing Wazuh administrator; local setup operator | Create/revoke roles, configure network and secrets, perform rollback | Routine assistant runtime and daily triage |
| `socanalyst` | Wazuh internal user | Read approved alerts and read-only dashboards | Index writes, active response, agent/rule/security administration |
| OIDC `alertmind-socanalyst` | Streamlit | Search and triage live alerts, use approved Paste flow, make permitted provider calls, save sanitized audits | Provider-secret entry, arbitrary query/API access, system configuration |
| `assistant-svc` | Wazuh Indexer internal user; non-interactive | Server-side search/get from the approved alert scope | Dashboard tenant, Streamlit login, Server API role, writes and administration |
| unknown/unauthenticated | None | Login page only | All alert content and protected operations |

`assistant-svc` is not an application role and must never be accepted as a
human OIDC identity.

### 5.2 Application permissions

Use named permissions rather than role-name checks scattered through the UI:

```text
view_corpus
paste_alert
retrieve_wazuh_alerts
triage_wazuh_alert
call_remote_model
save_sanitized_audit
view_connection_status
run_connection_preflight
```

The OIDC `alertmind-socanalyst` role receives every permission above except
`run_connection_preflight`. Its connection status is limited to availability,
last-check time and a correlation ID. `run_connection_preflight` is reserved
for a local setup administrator and may report sanitized identity, role and
read health. Neither view exposes an endpoint, credential, certificate path,
index detail or alert body. Configuration remains file/secret-store based; the
application has no widget for entering secrets or changing endpoints.

Unknown, missing, expired or ambiguous role claims fail closed. Validate the
expected issuer, audience, subject, expiry and exact group claim. Streamlit's
identity cookie can outlive an IdP token, so expiry is checked again before
Wazuh retrieval, hosted calls and audit writes.

---

## 6. Wazuh least-privilege design

### 6.1 Pre-change inventory and recovery point

Before editing Wazuh:

1. Snapshot the `wazuh-siem` VM and record Wazuh Dashboard, Server and Indexer
   versions.
2. Export or capture current internal users, Indexer roles/mappings, Server API
   roles/mappings and relevant security configuration.
3. Record `network.host`, the Indexer certificate subject/SAN, the host-only
   adapter address, firewall state and the actual alert index pattern.
4. Enumerate composable and legacy index templates, aliases and ISM pattern
   attachments that could affect either the real alert indices or the planned
   RBAC probe index. Select a probe name inside the final service-role pattern
   but outside every template or policy that would add a rollover, retention,
   ingestion or other side effect.
5. Confirm the in-scope agents (`win-victim`, `linux-victim`) and the exact
   mapped field used for document-level security.
6. Verify current services and dashboards before change so rollback has a
   known-good comparison.

### 6.2 `socanalyst` human role

Create a Wazuh internal user `socanalyst` and map it to:

- an Indexer role `alertmind_socanalyst_ro` with
  `cluster_composite_ops_ro`, read access only to `wazuh-alerts-*`, read-only
  access to the required dashboard tenant, and document-level filtering to the
  two AlertMind agents where the tested field permits it; and
- the minimum Wazuh Server API read role required by the Dashboard. If the
  built-in `readonly` role is used for compatibility, document that it is
  broader than alert-only access and verify that all write/active-response
  operations are still denied.

Do not use the Wazuh documentation's general `*` index example. Add
`wazuh-monitoring-*` only if a specific required dashboard fails without it
and the need is recorded.

### 6.3 `assistant-svc` machine role

Create an internal Indexer user `assistant-svc` mapped only to
`alertmind_assistant_alerts_ro`:

```yaml
cluster_permissions: []
index_permissions:
  - index_patterns:
      - wazuh-alerts-*
    dls: <simple tested filter for win-victim and linux-victim>
    allowed_actions:
      - indices:data/read/search
      - indices:data/read/get
tenant_permissions: []
```

Start with these explicit actions. Add a read-only action only when a captured
403 from a required fixed client request proves it is necessary. Never add a
wildcard permission for convenience. Wildcard resolution or a fixed preflight
may reveal that `indices:admin/resolve/index` is required; treat it as a
candidate, not a baseline permission. Record the triggering 403 and the final
minimal action set in the proof artifact.

Do not create a Wazuh Server API user/role for `assistant-svc`. It therefore
has no credential with which to call manager, agent, ruleset, security or
active-response endpoints on `:55000`.

### 6.4 Network and TLS

The preferred lab path exposes Indexer HTTPS only on the host-only adapter,
with the Windows firewall/Ubuntu firewall allowing TCP 9200 solely from the
physical assistant host. Do not bind the Indexer to every interface. The
certificate must contain the address or DNS name used by the client; copy only
the public root CA to the assistant host.

If the existing certificate cannot validate the host-only address, regenerate
the node certificate or use a hostname that is present in its SAN. Do not ship
`verify=False` or suppress certificate warnings. Preserve the NAT-isolated
lab boundary and keep port 9200 unreachable from untrusted networks.

Treat the Indexer endpoint allowlist as optional hardening after role tests:
it is cluster-wide and can disrupt Dashboard/Filebeat behavior if enabled
without a complete endpoint inventory.

---

## 7. Application implementation

### 7.1 New and changed modules

| Path | Responsibility |
|---|---|
| `assistant/app_config.py` | Parse and validate `offline`/`analyst` profile, immutable endpoints, limits and provider allowlist |
| `assistant/auth.py` | `UserContext`, OIDC claim mapping, expiry checks and `authorize()` |
| `assistant/permissions.py` | Static roles-to-permissions map |
| `assistant/wazuh_reader.py` | Narrow HTTPS search/get client; no generic request method |
| `assistant/wazuh_normalize.py` | Validate and normalize one Indexer hit for triage |
| `assistant/live_wazuh_tab.py` | Bounded live-alert search, selection, preview and triage UI |
| `assistant/triage_core.py` | Shared object-to-redaction/view/boundary/model/schema path for Paste and live Wazuh inputs |
| `assistant/audit_store.py` | Sanitized SQLite audit events for concurrent local sessions |
| `assistant/app.py` | Profile gate, login/logout, server-configured provider and protected tabs/actions |
| `assistant/paste_core.py` / `paste_tab.py` | Delegate common triage stages and enforce permissions without changing current guardrails |

Keep `runner.py`, scoring, frozen corpus and accepted run directories out of
this refactor. Add characterization tests before extracting common code so the
existing Paste outcomes remain byte/field compatible where documented.

### 7.2 Remove browser-controlled runtime configuration

In the analyst profile:

- remove API-key and base-URL input widgets;
- do not mutate `os.environ` from a session;
- load provider, model, endpoint and credentials from server-side secrets;
- expose only an allowlisted provider/model choice, or pin one provider/model;
- never place secrets or authorization headers in `st.session_state`; and
- authorize `view_connection_status` before rendering only availability,
  last-check time and a correlation ID to an analyst.

The offline evaluation CLI retains its existing environment-based
configuration for reproducibility. The new Wazuh connection preflight is a
separate local-administrator operation guarded by `run_connection_preflight`;
it is not an analyst UI control.

### 7.3 Wazuh reader contract

The reader exposes only:

```python
search_recent_alerts(*, since, agent_names, min_level, limit)
get_alert(*, index_name, document_id)
```

Requirements:

- constant base path and `wazuh-alerts-*` index pattern;
- fixed Query DSL templates assembled from validated scalar filters;
- agent names intersected with the server-side allowlist;
- lookback capped at 24 hours and result count capped at 50;
- descending `@timestamp` order and a bounded `_source` field set;
- no scroll, scripts, aggregations, user-supplied sort, query strings or raw
  request bodies;
- index-name validation against the resolved Wazuh alert-index pattern;
- connect/read timeouts, maximum response bytes and at most one safe retry;
- HTTPS with the configured CA and hostname verification;
- credentials supplied only by the server-side configuration; and
- sanitized exceptions that retain status and correlation ID but remove URLs
  containing credentials, headers and response bodies that may contain data.

The Wazuh role and DLS remain authoritative if application validation fails.

### 7.4 Normalization contract

Keep transport metadata separate from model input:

```python
RetrievedAlert(
    ref=WazuhAlertRef(index, document_id, timestamp),
    display=WazuhAlertSummary(rule_id, level, description, agent, timestamp),
    alert=<validated normalized dictionary>,
)
```

The normalized dictionary contains the alert timestamp, agent, rule metadata,
MITRE metadata when present, decoder/location and relevant event fields. It
must not contain the service credential, HTTP headers or raw `_index`/`_id`.
Preserve sufficient raw event evidence for triage, subject to a serialized
size cap; reject oversized documents rather than silently truncating them.

Live operational/evaluation views may be selected for diagnostics, but live
alerts are never scored as part of the frozen benchmark.

### 7.5 Protected UI flow

Add a third analyst tab, **Live Wazuh alerts**:

```text
authorize retrieve_wazuh_alerts
  → bounded search
  → show timestamp / agent / rule / level / description
  → select one reference
  → authorize triage_wazuh_alert
  → re-fetch and validate the selected alert
  → redact + view + marker visibility + independent boundary gate
  → if remote: authorize call_remote_model + obtain fresh consent
  → one model call
  → schema validation
  → DRAFT result under mandatory analyst review
  → optional authorized sanitized audit save
```

Re-authorize immediately before search, re-fetch, provider call and audit
write. A session-state role or a hidden/disabled widget never satisfies the
check. Consent is bound to subject, alert fingerprint, provider, model and
endpoint and resets when any changes.

### 7.6 Audit contract

The current JSONL helper is explicitly single-writer. For the authenticated
analyst profile, use a local SQLite store with a unique event ID and
transactional inserts. Batch evidence and historical ad-hoc JSONL remain
unchanged.

Record:

- UTC timestamp and event/decision ID;
- HMAC-pseudonymized OIDC subject, non-secret HMAC key identifier/version,
  resolved role and auth source;
- permission, action, allow/deny result and denial reason category;
- source (`wazuh`, `paste`, `frozen_corpus`, `synthetic_fixture`);
- hashed Wazuh reference and service identity name, never its password;
- provider/model, call status, usage and response metadata;
- consent, redaction, marker, delimiter and schema outcomes; and
- `analyst_review_required: true`.

Do not record tokens, passwords, authorization headers, raw pasted input,
unredacted Wazuh `_source`, planted secrets or unrestricted provider error
bodies. Document Windows ACL, retention and rotation; `chmod 0o600` alone is
not a Windows security guarantee.

Load `ALERTMIND_AUDIT_SUBJECT_HMAC_KEY` only from the server-side secret store
and expose its non-secret identifier separately as
`ALERTMIND_AUDIT_SUBJECT_HMAC_KEY_ID`. In a two- or three-person lab the HMAC
is pseudonymization for storage hygiene, not anonymity: anyone holding the key
can enumerate the small subject population. Rotation changes the correlation
domain, so record the key identifier and rotation event without retaining the
old or new key in Git or the audit database.

---

## 8. Configuration and committed artifacts

Add sanitized, secret-free templates and runbooks:

```text
docs/rbac-wazuh-read-only-implementation-plan.md
docs/runbooks/rbac-wazuh-read-only-setup.md
assistant/.streamlit/secrets.example.toml
deployment/oidc/keycloak/README.md
deployment/oidc/keycloak/realm-template.json
siem/rbac/README.md
siem/rbac/indexer-role_socanalyst_ro.yml
siem/rbac/indexer-role_assistant_alerts_ro.yml
siem/rbac/server-role_socanalyst_ro.yml
siem/rbac/negative-test-matrix.md
evidence/rbac/README.md
evidence/rbac/rbac-proof.md
```

Templates may contain role names, endpoints, index patterns and placeholder
claims. They must not contain passwords, client secrets, bearer tokens,
authorization headers, private keys or unredacted alerts. Add
`.streamlit/secrets.toml`, `assistant/.secrets/`, local CA copies, audit
databases and Keycloak data directories to `.gitignore` before local setup.

The analyst-profile secret inventory is the OIDC client secret,
`assistant-svc` password, any hosted-provider key and
`ALERTMIND_AUDIT_SUBJECT_HMAC_KEY`. Example files contain placeholders only;
the HMAC key identifier is non-secret, but the key itself is handled and
rotated like the OIDC client secret.

---

## 9. Work order

### Phase 0 — preserve and characterize

1. **Done:** create `feat/rbac-wazuh-readonly` from `main` at `8f2d179`, merge
   the approved plan to `main` at `39c989a`, then create the fresh
   implementation branch `feat/rbac-wazuh-phase0` from that merge.
2. **Done:** run the 78-test baseline and frozen-evidence verifier before the
   plan commit.
3. **Done:** add eight characterization tests for current Paste results,
   provider behavior and the default offline Streamlit UI. All 86 tests pass.
4. **Partly done — human/admin:** the owner reports a powered-off Wazuh
   snapshot was taken and all four services passed the recovery gate. The
   read-only inventory in Section 6.1, including the candidate probe's
   template and ISM matches, remains pending.
5. **Done:** add the secret-free implementation checklist, Git ignore rules
   and Phase 0 scaffolds under `siem/rbac/`, `deployment/oidc/keycloak/` and
   `evidence/rbac/`.

Phase 0 remains open until the inventory is complete and independently
reviewed.

**Gate:** clean baseline, recoverable Wazuh snapshot and no secrets in Git.

### Phase 1 — Wazuh RBAC and transport

1. Create and test `socanalyst`.
2. Create and test machine-only `assistant-svc`.
3. Apply the narrow alert index pattern and tested DLS.
4. Configure host-only reachability, firewall restriction and valid TLS.
5. Capture effective role mappings and representative allow/deny responses.

**Gate:** both identities can perform their intended reads; writes and
management operations fail at Wazuh before any app integration begins.

### Phase 2 — Streamlit authentication and authorization

1. Change the flexible user specification in `assistant/requirements.txt` to
   include the supported Streamlit authentication extra/Authlib, then
   regenerate `assistant/requirements-ci.lock` for Python 3.12 Linux. Before
   accepting it:
   - diff the old and new locks and record every moved package/version and the
     dependency reason;
   - reject or separately review unexplained unrelated upgrades;
   - install the regenerated hashed lock in a clean environment; and
   - run the complete assistant suite and frozen-evidence verifier in that
     environment.
2. Configure local Keycloak and a secret-free realm/client template.
3. Add profile configuration, `auth.py` and `permissions.py`.
4. Require OIDC for the analyst profile and fail closed on claim defects.
5. Remove browser-entered provider credentials and process-global mutation in
   the analyst profile.
6. Put authorization immediately before every protected callback.

**Gate:** unauthenticated, unknown, ambiguous and expired identities cannot
reach alert data or side effects; analyst permissions pass.

### Phase 3 — constrained Wazuh reader

1. Add the reader, response validator and normalization layer.
2. Test fixed path/query construction, allowlists, limits, TLS and sanitized
   failures with recorded fixtures—never live credentials.
3. Add a local-administrator preflight, authorized by
   `run_connection_preflight`, that reports sanitized identity, role and read
   health without exposing secrets, alert bodies, endpoints, certificate paths
   or index details.
4. Add an analyst-safe `view_connection_status` result containing only
   availability, last-check time and a correlation ID.

**Gate:** a mocked arbitrary path/index/query cannot be expressed through the
public interface; live search/get succeeds with `assistant-svc`.

### Phase 4 — shared triage and live UI

1. Extract the shared object-triage stages with characterization coverage.
2. Keep Paste behavior and frozen batch evidence unchanged.
3. Add the Live Wazuh alerts tab and the protected flow in Section 7.5.
4. Add transactional sanitized auditing and denial records.

**Gate:** one controlled Wazuh alert reaches a validated DRAFT through the
same redaction/boundary/model/schema code used by Paste; no Wazuh mutation is
possible from the UI or client.

### Phase 5 — proof, rollback drill and publication

1. Run the complete automated and live verification matrices.
2. Disable the feature, rotate/revoke the service credential and restore it to
   demonstrate rollback.
3. Produce a sanitized proof artifact with hashes and screenshots.
4. Update README, assistant README/changelog, architecture source/render,
   report, presentation and evaluator questionnaire from **planned** to
   **implemented** only after all acceptance criteria pass. This applies only
   to living copies on `main` and actively maintained external source
   artifacts; do not modify the `v1.0` tag or retro-edit submitted artifacts.
5. Correct every planned alert-source reference from Server API `:55000` to
   Indexer API `:9200`; keep `:55000` identified as a separate management
   plane.

**Gate:** independent review returns `approve`; only the human pushes.

---

## 10. Verification matrix

### 10.1 Automated tests

Add:

- `test_app_config.py` — profile validation and fail-closed startup;
- `test_auth.py` — issuer/audience/expiry/group mapping and ambiguous/unknown
  denial;
- `test_permissions.py` — complete role-permission matrix;
- `test_wazuh_reader.py` — fixed API surface, query bounds, index allowlist,
  DLS-compatible filters, TLS and sanitized errors;
- `test_wazuh_normalize.py` — representative Linux, Windows, missing-field and
  oversized fixtures;
- `test_live_wazuh_ui.py` — login gate, role-specific controls,
  re-authorization and stale-result handling;
- `test_audit_store.py` — uniqueness, concurrent inserts, subject attribution
  and absence of secrets/raw alerts; and
- regression tests proving Paste and existing provider paths remain intact.

Required commands:

```powershell
cd assistant
python -m unittest discover -s tests -p "test_*.py"
cd ..
python measurement/verify_frozen_evidence.py
git diff --check
```

Offline CI must remain network-free; all new Wazuh/OIDC tests use fixtures and
mocks. Live integration proof runs manually in the isolated lab.

### 10.2 Live positive and negative tests

| Principal | Operation | Expected |
|---|---|---|
| unauthenticated | Open analyst profile | Login only; no alert metadata |
| unknown/ambiguous/expired OIDC user | Invoke protected callback | Denied and sanitized audit event |
| OIDC analyst | Search recent approved alerts | Allowed |
| OIDC analyst | Hosted call without fresh bound consent | Blocked before provider request |
| `socanalyst` | View required Wazuh dashboards/alerts | Allowed |
| `socanalyst` | Change rules, agents, RBAC or run active response | Wazuh denial |
| `assistant-svc` | Search/get in-scope `wazuh-alerts-*` documents | Allowed |
| `assistant-svc` | Read `wazuh-archives-*`, security or unrelated indices | 403 |
| `assistant-svc` | Get the DLS-visible sentinel from the disposable in-pattern probe index | Allowed before mutation checks |
| `assistant-svc` | Index/update/delete in that same probe index | 403; sentinel unchanged and no document created |
| `assistant-svc` credentials | Authenticate to Server API `:55000` | Rejected; no Server API identity |
| browser/session tamper | Change role, index, query or endpoint | Server-side denial/validation |
| analyst profile | Inspect rendered page/network and audit output | No service/provider/OIDC secret |

Run mutation-denial probes only against a disposable, administrator-created
index on the VM snapshot. A candidate is
`wazuh-alerts-rbacprobe-000001`: it is inside the planned
`wazuh-alerts-*` service-role pattern but outside the documented
`wazuh-alerts-4.x-*` retention pattern. Do not rely on that name until the
Phase 0 inventory confirms that no composable/legacy template or ISM policy
attaches a rollover, retention, ingestion or other side effect.

The administrator creates one sentinel with a unique recorded `_id`, an
unmistakable marker such as `alertmind.rbac_probe: true`, and an in-scope DLS
field value. Keep its time field outside active dashboard evidence windows and
omit detection/ATT&CK fields. The same `assistant-svc` principal must read that
sentinel successfully before index, update and delete attempts are made. This
proves that any later 403 comes from the action boundary rather than the index
pattern or DLS.

Run the probe outside all alert/dashboard evidence-capture windows and never
against an index used by Wazuh or Filebeat. Record the probe index and `_id`.
After the denied attempts, the administrator verifies the sentinel is
unchanged, removes the complete probe index and proves it no longer exists
before any RBAC screenshot or dashboard evidence is collected. If a supposedly
denied operation succeeds, stop, preserve the failure evidence, disable live
access and repair the role before continuing.

---

## 11. Acceptance criteria

- [ ] The offline profile remains the default and needs no Wazuh or IdP.
- [ ] The analyst profile cannot start incompletely configured.
- [ ] OIDC is required for all live alert access.
- [ ] Unknown, ambiguous and expired identities fail closed.
- [ ] Every protected operation performs server-side authorization at the
      action boundary.
- [ ] Analysts can see only coarse connection status; detailed identity, role
      and read preflight output remains a local-administrator operation.
- [ ] Provider and Wazuh secrets are absent from widgets, session state,
      downloads, model prompts, logs and source control.
- [ ] `admin` is absent from routine application and service configuration.
- [ ] `socanalyst` can investigate but cannot alter Wazuh state.
- [ ] `assistant-svc` has only tested search/get access to the approved alert
      scope, has no Dashboard tenant and has no Server API identity.
- [ ] The same `assistant-svc` principal can read the isolated in-pattern
      sentinel and is then denied index/update/delete; the sentinel remains
      unchanged and the probe index is removed before evidence capture.
- [ ] Indexer access is host-only/firewall-restricted and TLS verification is
      enabled with a valid hostname/SAN.
- [ ] The UI cannot submit arbitrary Query DSL, index names, endpoints or HTTP
      methods.
- [ ] Search lookback, agent scope, result count, response size and timeouts are
      bounded.
- [ ] Retrieved alert transport metadata is separated from model input.
- [ ] Redaction precedes prompt construction and literal delimiters still block
      the model call independently of marker scanning.
- [ ] Hosted calls require both permission and fresh context-bound consent.
- [ ] Every output remains schema-checked, DRAFT-only and subject to mandatory
      analyst review.
- [ ] Live alerts and ad-hoc labels never enter frozen benchmark scoring.
- [ ] Sanitized allow, deny, retrieval, provider and audit events are
      attributable to a pseudonymous human subject.
- [ ] The audit-subject HMAC key is server-side, ignored by Git, versioned only
      by a non-secret identifier and documented as pseudonymization rather
      than anonymity.
- [ ] Existing tests and all frozen-evidence checks pass without modifying
      committed run evidence.
- [ ] A rollback drill succeeds.
- [ ] Public documentation says **implemented** only after the live negative
      tests and proof artifact receive independent approval.

---

## 12. Rollback

1. Set the analyst/live-Wazuh profile off and restart Streamlit; offline mode
   remains available.
2. Remove any disposable RBAC probe index and verify it no longer exists.
3. Revoke/rotate `assistant-svc` and remove its role mapping.
4. Remove or disable the `socanalyst` mappings if they caused a Dashboard
   regression.
5. Revert the Indexer bind/firewall change and restore the saved security
   configuration or VM snapshot if required.
6. Revoke/rotate the OIDC client secret and
   `ALERTMIND_AUDIT_SUBJECT_HMAC_KEY` if exposure is suspected or the rollback
   drill calls for rotation. Record only the new HMAC key identifier and note
   that it begins a new subject-correlation epoch.
7. Verify Wazuh Indexer, Manager, Filebeat and Dashboard health in order.
8. Preserve sanitized failure evidence; do not alter frozen corpus or run
   artifacts.

Rollback does not require a model rerun because no accepted model artifact is
part of the live integration state.

---

## 13. Proposed implementation commits

1. **Done — `9b91a02`:**
   `docs(rbac): finalize local-first Wazuh integration plan`
2. **Done — `8ebbc1f`:**
   `docs(rbac): tighten security proof and dependency gates`
3. **Current Phase 0:**
   `test(rbac): characterize offline path and scaffold inventory`
4. `chore(rbac): add secret-free identity and role templates`
5. `feat(auth): add OIDC profiles and server-side authorization`
6. `feat(wazuh): add constrained read-only alert client`
7. `feat(assistant): triage live Wazuh alerts through guarded pipeline`
8. `test(rbac): cover identity, reader, audit and denial boundaries`
9. `evidence(rbac): record least-privilege integration proof`
10. `docs(architecture): publish implemented read-only Wazuh path`

Each commit stages explicit paths only. Never use `git add -A` in this
repository because of the known line-ending churn risk.

---

## 14. Human tasks and decision points

Before implementation, the project owner must:

1. create and retain a clean Wazuh VM snapshot;
2. confirm the host-only IPs, in-scope agent names/IDs and current Indexer
   certificate SAN;
3. confirm the live index, template and ISM patterns used to select a
   side-effect-free RBAC probe name;
4. choose strong passwords, client secrets and an audit-subject HMAC key
   locally and never paste them into an agent chat or commit them;
5. approve installation of a local Keycloak instance or nominate an existing
   OIDC provider;
6. perform the privileged Wazuh/Keycloak configuration steps while the agent
   supplies reviewed commands and secret-free templates; and
7. personally exercise the final analyst login and approve the sanitized
   positive/negative evidence.

The first implementation turn should stop after Phase 0 inventory if the
Indexer cannot be exposed on the host-only network with valid TLS and a
recoverable rollback path.

---

## 15. Authoritative references

- [Wazuh RBAC and read-only users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html)
- [Wazuh Indexer alert-search examples](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)
- [Wazuh Indexer API configuration](https://documentation.wazuh.com/current/user-manual/indexer-api/configuration.html)
- [Securing the Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/securing-indexer-api.html)
- [Wazuh Server API RBAC](https://documentation.wazuh.com/current/user-manual/api/rbac/index.html)
- [OpenSearch access control and action groups](https://docs.opensearch.org/latest/security/access-control/index/)
- [OpenSearch document-level security](https://docs.opensearch.org/latest/security/access-control/document-level-security/)
- [Streamlit OIDC authentication](https://docs.streamlit.io/develop/concepts/connections/authentication)
- [Streamlit `st.login`](https://docs.streamlit.io/develop/api-reference/user/st.login)

---

## 16. Final claim boundary

On completion, AlertMind may claim a **demonstrated local least-privilege read
path**: an authenticated analyst can ask a server-side application to retrieve
an approved Wazuh alert with a machine identity that cannot write or act, and
the alert is triaged through the existing guarded draft workflow.

It must not claim production readiness, complete multi-tenant isolation,
universal prompt-injection resistance, universal redaction, autonomous
response, or improved benchmark accuracy from this feature.
