# AlertMind — RBAC and read-only Wazuh integration

**Document status:** Phase 0 and the Phase 1A/1B Indexer identity and
enforcement gates are independently approved and merged through PR #10. The
owner removed an unrelated broken, unused Postfix package after a separate
simulation/approval gate; package consistency and Wazuh health remain intact.
This branch prepares the exact Phase 1C SSH installation, configuration,
pre-enable proof and rollback package. It is not authority to execute that
package before independent review. SSH transport, Wazuh Server/Dashboard
configuration, OIDC and application integration remain unimplemented.

**Date:** 1 September 2026

**Last updated:** 2 September 2026

**Applies to:** current `assistant/` package; submitted-v1 Wazuh 4.14.5
baseline; current live `wazuh-indexer` 4.14.7-1 / OpenSearch 2.19.5;
Streamlit `>=1.59` user specification and Streamlit 1.62.0 CI lock

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

The live alert source is the **Wazuh Indexer API on HTTPS port 9200**. The live
inventory found 25 production alert indices under `wazuh-alerts-4.x-*`; that
observed namespace is the initial application and service-role allowlist. The
broader `wazuh-alerts-*` string is used by the live ISM auto-attachment policy
and is not, by itself, authority to grant broader read access. The Wazuh Server
API on port 55000 is a management plane and is not part of the assistant
runtime. Existing diagrams and documentation that show `:55000` as the planned
alert-ingestion path must be corrected when the feature is proven.

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
- The submitted v1 used an all-in-one Wazuh 4.14.5 deployment. The current live
  Indexer package is 4.14.7-1 with OpenSearch/OpenSearch Security 2.19.5; this
  is post-v1 lab drift and does not retroactively change the v1 evidence. The
  Indexer remains localhost-only. The Phase 0 baseline found the canonical
  roles, mappings and users absent. The two custom roles and users were later
  created on VM loopback. A pre-mapping check exposed inherited `own_index`
  access; after independent review, the owner narrowed that mapping, applied
  both direct-user mappings and completed the fail-safe Indexer matrix. That
  proof is independently approved and merged in PR #10. SSH transport and live
  ingestion remain incomplete.
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
Windows 127.0.0.1:19200 ── restricted SSH local forward
  │
  ▼
Wazuh Indexer 127.0.0.1:9200 / wazuh-alerts-4.x-*/_search
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
2. Export or capture current internal users, every effective Indexer role and
   role mapping (including reserved roles and wildcard/backend/host selectors),
   Server API roles/mappings and relevant security configuration. Authenticate
   as each new identity before project mapping and treat any inherited role as
   a blocker until its source is resolved.
3. Record `network.host`, the Indexer certificate subject/SAN, the host-only
   adapter address, firewall state and the actual alert index pattern.
4. Enumerate composable and legacy index templates, aliases and ISM
   auto-attachment patterns separately. A composable-template simulation is
   not evidence that no legacy template or ISM policy matches.
5. Confirm the in-scope agents and the exact mapped DLS field. Record a SHA-256
   fingerprint of each current enrollment key beside the non-secret ID/name,
   without printing or storing the key itself. Agent IDs can be reassigned on
   re-enrollment, so re-verify both fingerprint and DLS scope after any
   re-enrollment.
6. Record the Indexer package, OpenSearch Security plugin and OpenSearch
   versions rather than inferring the current live version from submitted-v1
   documentation.
7. Verify current services and dashboards before change so rollback has a
   known-good comparison.

The 1 September 2026 inventory established the following design inputs:

- Indexer is bound to `127.0.0.1:9200`; its HTTP certificate SAN contains only
  `IP:127.0.0.1`.
- All 25 observed alert indices and the legacy Wazuh alert template use
  `wazuh-alerts-4.x-*`; no alert aliases exist.
- No composable template matched the former candidate probe, but the live ISM
  policy auto-attaches to every `wazuh-alerts-*` index. That simulation was a
  false negative for lifecycle effects. No disposable alert/probe index may be
  created.
- `agent.id` is a searchable keyword. IDs `001` (`win-victim`) and `002`
  (`linux-victim`) are the initial DLS allowlist. ID `000` is excluded: its
  historical documents use both `wazuh-siem` and `Ubuntu`, demonstrating that
  names are not a stable DLS key.
- On 2 September 2026, the owner recorded SHA-256 enrollment fingerprints for
  IDs `001` and `002`, confirmed neither had been re-enrolled since inventory,
  and retained only the ID, name and digest in
  [`evidence/rbac/phase0-owner-checklist.md`](../evidence/rbac/phase0-owner-checklist.md).
  Any later re-enrollment invalidates this binding until it is reviewed again.
- The effective `action.destructive_requires_name` default is `false`.
  Therefore the optional index-level DELETE denial proof is prohibited in the
  current lab. The document-level zero-state-change denial matrix remains the
  planned behavioral proof.
- OpenSearch Security is 2.19.5.0. Its versioned permissions documentation does
  not provide the newer `perform_permission_check` facility, so this plan does
  not attempt to feature-detect it with a request that might mutate data.
- The pre-mapping Phase 1 check found that both new internal users inherited
  reserved role `own_index` through an editable mapping with `users: ["*"]`.
  Live action-group expansion showed `cluster_composite_ops` included bulk and
  reindex writes, while `indices_all` expanded to `indices:*` on
  `${user_name}`. Permissions are additive, so direct project mappings could
  not compensate for it. The owner applied the independently reviewed scoped
  mapping first, proved both users had no effective role, and only then applied
  the two project mappings.

### 6.2 `socanalyst` human role

Create a Wazuh internal user `socanalyst` and map it to:

- an Indexer role `alertmind_socanalyst_ro` with
  `cluster_composite_ops_ro`, read access only to `wazuh-alerts-4.x-*`,
  read-only access to the required dashboard tenant, and document-level
  filtering on `agent.id` values `001` and `002`; and
- the minimum Wazuh Server API read role required by the Dashboard. If the
  built-in `readonly` role is used for compatibility, document that it is
  broader than alert-only access and verify that all write/active-response
  operations are still denied.

Do not use the Wazuh documentation's general `*` index example. Add
`wazuh-monitoring-*` only if a specific required dashboard fails without it
and the need is recorded.

The DLS scope deliberately excludes agent ID 000. Based on the live inventory,
`socanalyst` sees about 24,557 of 35,992 alert documents and excludes about
11,445 server-local documents. Dashboard evidence captured under this role is
**DLS-scoped** and its totals are not expected to match admin screenshots.

### 6.3 `assistant-svc` machine role

Create an internal Indexer user `assistant-svc` mapped only to
`alertmind_assistant_alerts_ro`:

```yaml
cluster_permissions: []
index_permissions:
  - index_patterns:
      - wazuh-alerts-4.x-*
    dls: <tested terms filter on agent.id values "001" and "002">
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

The machine-checked `siem/rbac/scope-contract.json` and the eventual proof
artifact record the enrollment fingerprints that were current when IDs `001`
and `002` were approved. A changed fingerprint or re-enrolled agent closes
live access until the mapping and DLS scope are reviewed again.

### 6.4 Inherited-role gate

The `own_index` role itself is reserved/static and remains unchanged. Its
separate mapping is editable and historically matched all internal users. The
normal correction uses one JSON Patch operation to replace only `/users` with
the seven users that existed before this feature: `admin`, `anomalyadmin`,
`kibanaro`, `kibanaserver`, `logstash`, `readall` and `snapshotrestore`.
`socanalyst`, `assistant-svc` and the wildcard are excluded. This preserves
observed existing-user behavior while deliberately preventing future users
from receiving an automatic write index.

Before applying the patch, require an exact internal-user inventory, empty
backend/direct roles on both new identities, only basic internal HTTP auth,
the unchanged `own_index` role and a mapping whose only non-empty selector is
`users: ["*"]`. After the patch and before project mappings, require both
identities to have no effective role and receive `403` for a read-only search
of their username-named index. Repeat both checks after project mappings,
requiring only the intended AlertMind role for each user.

The wildcard rollback is not a normal inverse operation: it recreates the
vulnerability while either new identity can authenticate. Remove project
mappings, revoke or delete both new users, prove both credentials fail, and
obtain separate approval before restoring `users: ["*"]`.

Security-plugin private-tenant metadata does not mitigate Indexer permissions.
Dashboard multitenancy is disabled in the live configuration; later proof must
still show that `assistant-svc` has no usable Dashboard path.

### 6.5 Network and TLS

The preferred lab path keeps Indexer HTTPS bound to VM loopback and uses a
restricted SSH local forward over the VirtualBox host-only network:

```text
Windows 127.0.0.1:19200
  → SSH 192.168.56.102:22
  → VM 127.0.0.1:9200
```

This preserves the existing `IP:127.0.0.1` certificate SAN and fails closed if
the tunnel stops; Indexer never becomes reachable on a VM network interface.
The Windows client validates `https://127.0.0.1:19200` with a copied public
root CA. Do not ship `verify=False`, suppress certificate warnings or copy any
private Indexer key.

The Phase 1C Windows transport proof found that the current private CA exposes
neither a CRL distribution point nor Authority Information Access. Schannel's
default revocation check therefore cannot produce a status. A separately
reviewed proof-only compatibility path may use curl's
`--ssl-revoke-best-effort` together with a required hostname-mismatch negative
control, while retaining the pinned CA and hostname verification. This is not
authority to use `--ssl-no-revoke`, `--insecure` or `-k`. The missing
revocation locations are permanent for this chain rather than a transient
outage: best-effort accepts unknown revocation status on every use for the life
of the chain unless it is replaced, so its revocation check provides no
protection here. This proof does not settle the later application's
certificate-chain or Python-context decision.

The first post-merge proof also characterized two Windows PowerShell 5.1
behaviours that the operator runbook must handle explicitly. A single
`Get-NetTCPConnection` result is normalized with `@(...)` before its count is
checked. JSON is never supplied to native curl as an inline argument: PowerShell
removed the field-name quotes and OpenSearch returned HTTP 400 with a
`json_parse_exception` at column 2. The fixed, non-secret `size:0` query is
written as UTF-8 without a byte-order mark, passed with curl's `@file` form and
removed in `finally`. Each listener, CA and TLS proof is one invoked script
block with terminating-error behaviour so a `STOP` cannot fall through to a
later PASS when commands are pasted interactively.

The expected-failure TLS leg also leaves native stderr unmerged: under Windows
PowerShell 5.1, `2>&1` converts native stderr into an error record and the
terminating-error policy can abort the block before `$LASTEXITCODE` is checked.
The proof therefore observes curl's native exit code directly.

Python 3.13+ enables `VERIFY_X509_STRICT` in its default SSL context. The live
Wazuh CA triggered a Python 3.14 rejection because it lacks a key-usage
extension. The VM evidence harness disabled `VERIFY_X509_STRICT` wholesale,
not as a targeted exception: the flag gates a broader bundle of strict RFC
5280 checks, including CA basic constraints, key-usage consistency and
duplicate or malformed extensions. The harness retained the configured CA,
`CERT_REQUIRED` and hostname verification, and the endpoint still rejected an
unauthenticated request with `401`. Before implementing the Windows client,
prefer replacing the certificate chain in a separate infrastructure cycle. A
reviewed compatibility context must preserve those verification properties
and explicitly accept the broader strictness reduction; never substitute an
unverified context.

SSH is currently inactive. Its reviewed Phase 1 configuration must:

- listen only on VM host-only address `192.168.56.102`, not NAT or wildcard;
- disable root, password and keyboard-interactive login;
- allow only public-key authentication for `notroot`;
- bind the client forward only to Windows loopback and set
  `ExitOnForwardFailure=yes`;
- restrict the dedicated key in `authorized_keys` with
  `restrict,port-forwarding,permitopen="127.0.0.1:9200",command="/bin/false"`,
  so that `restrict` blocks every facility by default, `port-forwarding`
  re-enables TCP forwarding generally, `permitopen` bounds the local (`-L`)
  destination to Indexer loopback, and the forced command prevents a shell;
- set `AllowTcpForwarding local` under a `Match User notroot` block in
  `sshd_config`, so remote (`-R`) forwarding remains disabled; and
- retain `GatewayPorts no`, no agent/X11 forwarding and no unrestricted TCP
  forwarding.

Before enabling the service, capture context-aware effective configuration for
both `notroot` and a different user with `sshd -T -C`. The `notroot` result must
report `allowtcpforwarding local`; the control user must not inherit that
`Match User notroot` value. A plain `sshd -T` is insufficient because it does
not evaluate `Match` rules. Then verify the listener, certificate, Indexer,
Manager, Filebeat and Dashboard afterward. If these restrictions cannot be
enforced reliably, stop and review the more invasive host-only Indexer bind
plus certificate-regeneration path. Do not silently fall back to an
all-interface Indexer or SSH listener.

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
search_recent_alerts(*, since, agent_ids, min_level, limit)
get_alert(*, index_name, document_id)
```

Requirements:

- constant base path and `wazuh-alerts-4.x-*` index pattern;
- fixed Query DSL templates assembled from validated scalar filters;
- agent IDs intersected with the server-side `{"001", "002"}` allowlist;
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

Add sanitized, secret-free templates and runbooks. The `siem/rbac/*.json`
payloads, JSON Patch documents and `negative-test-matrix.md` form the current
Phase 1 identity/correction package; the authentication, Keycloak and proof
paths below are later-phase artifacts:

```text
docs/rbac-wazuh-read-only-implementation-plan.md
docs/runbooks/rbac-wazuh-read-only-setup.md
assistant/.streamlit/secrets.example.toml
deployment/oidc/keycloak/README.md
deployment/oidc/keycloak/realm-template.json
siem/rbac/README.md
siem/rbac/scope-contract.json
siem/rbac/indexer-role_socanalyst_ro.json
siem/rbac/indexer-role_assistant_alerts_ro.json
siem/rbac/indexer-role-mapping_socanalyst_ro.json
siem/rbac/indexer-role-mapping_assistant_alerts_ro.json
siem/rbac/indexer-role-mapping_own_index_scoped.patch.json
siem/rbac/indexer-role-mapping_own_index_rollback.patch.json
siem/rbac/negative-test-matrix.md
evidence/rbac/README.md
evidence/rbac/phase1b-inherited-access-check.md
evidence/rbac/rbac-proof.md
```

The JSON role and project-mapping files are exact OpenSearch Security REST
payloads; the two `.patch.json` files target only the existing `own_index`
mapping's `/users` selector. The wildcard restore is rollback-only and unsafe
until both new identities are revoked.
There is no custom Wazuh Server role template: `socanalyst` uses the built-in
`readonly` role after its broader read scope is disclosed and tested, while
`assistant-svc` receives no Server API identity. No password-bearing internal
user payload is committed.

Templates may contain role names, endpoints, index patterns and placeholder
claims. They must not contain passwords, password hashes, client secrets,
bearer tokens, authorization headers, private keys or unredacted alerts. Add
`.streamlit/secrets.toml`, `assistant/.secrets/`, local CA copies, audit
databases and Keycloak data directories to `.gitignore` before local setup.

The analyst-profile secret inventory contains five classes: the OIDC client
secret, `assistant-svc` password, any hosted-provider key,
`ALERTMIND_AUDIT_SUBJECT_HMAC_KEY`, and the SSH tunnel private key. Store the
tunnel key under the ignored `assistant/.secrets/` directory, never in a
Streamlit widget or repository file, and restrict its Windows ACL to the
account running the local application. Example files contain placeholders
only. The HMAC key identifier and SSH public-key fingerprint are non-secret;
the corresponding secret/private keys require documented generation,
rotation, revocation and rollback.

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
4. **Done — human/admin:** the owner recorded a powered-off Wazuh snapshot,
   verified all four services and supplied the sanitized read-only inventory
   summarized in Section 6.1. The inventory prohibited the former probe,
   selected `agent.id` values `001`/`002`, narrowed the alert namespace and
   selected a restricted SSH tunnel as the preferred transport.
5. **Done:** add the secret-free implementation checklist, Git ignore rules
   and Phase 0 scaffolds under `siem/rbac/`, `deployment/oidc/keycloak/` and
   `evidence/rbac/`.
6. **Done — `f92db3d`, `fde2fe4`, `73efcd7`:** reconcile this plan, the Phase 0
   runbook and evidence checklist with the live inventory and independent
   review, including the restricted local-forward-only SSH design and its
   match-aware pre-enable proof.
7. **Done — `882c465`, independently approved:** record the non-secret
   enrollment fingerprints, snapshot/transport/secrets confirmations and
   effective destructive-action setting before any role is created.

Phase 0 is closed. The approved commit is merged to `main` at `de4b6a5`.

**Gate:** clean baseline, recoverable Wazuh snapshot and no secrets in Git.

### Phase 1 — Wazuh RBAC and transport

1. **Done and approved:** add the secret-free scope contract, exact Indexer
   role payloads, direct-user mappings and pre-registered denial matrix. Seven
   offline contract tests brought the suite from 86 to 93 tests.
2. **Done:** on VM loopback, create the two custom roles and the internal users
   `socanalyst` and `assistant-svc` with human-entered passwords. Work stopped
   before project mappings when pre-mapping authinfo exposed inherited
   `own_index` access.
3. **Done and approved:** add the scoped `own_index` JSON Patch, rollback-only
   patch, transfer hashes, sanitized finding evidence and drift tests. Recheck
   every mapping selector and authentication domain before applying it.
4. **Done, approved and merged in PR #10:** narrow the wildcard mapping,
   prove `own_index` and every unexpected role absent for both users, require
   `403` on both username-named read-only searches, then apply the two project
   mappings and repeat authinfo and username-index checks.
5. **Current package gate:** independently review
   `docs/runbooks/rbac-wazuh-ssh-transport.md`, the secret-free SSH payloads,
   prerequisite evidence and contract tests. Only after approval may the owner
   install OpenSSH with both activation paths masked, capture both
   context-aware `sshd -T -C` outputs and stop before enabling SSH.
6. **Done, approved and merged in PR #10:** execute the
   fail-safe document-level allow/deny sequence in Section 10.2 and
   `siem/rbac/negative-test-matrix.md`; the optional index-level test remains
   prohibited.
7. Verify `socanalyst` Dashboard read access and Wazuh write,
   administration and active-response denials. If built-in `readonly` is
   used, disclose its broader read scope in the proof. Label dashboard evidence
   DLS-scoped because agent ID 000 is excluded.

**Gate:** both identities can perform their intended reads; writes and
management operations fail at Wazuh before any app integration begins;
`own_index` and every unexpected effective role are absent; the tunnel key
cannot open a shell or reach any destination except `127.0.0.1:9200`.

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
| `assistant-svc` | Search/get in-scope `wazuh-alerts-4.x-*` documents for agent IDs 001/002 | Allowed |
| `assistant-svc` | Read a concrete `wazuh-archives-*` index, when one exists | 403; otherwise record the live-data row as not testable and do not create an archive index |
| `assistant-svc` | Read Security, Dashboard or unrelated indices | 403 |
| both new Indexer users, before project mapping | Authinfo after scoped `own_index` patch | Correct username; no backend/direct role; no effective role; no `own_index` |
| both new Indexer users, before and after project mapping | Read-only search of the corresponding username-named index | 403; no index is created |
| `assistant-svc` | `GET _plugins/_security/authinfo` plus admin readback of its role/mappings | Only expected service identity/role; no `own_index`, cluster, tenant or write grant |
| `assistant-svc` | `_create` with an already-existing, positively read document ID | 403; accidental allow can only conflict, never overwrite |
| `assistant-svc` | In the same positively read concrete index, `_update` a random nonexistent ID with no `upsert` field | Precheck 404 proves index read access; write returns 403 and ID remains absent |
| `assistant-svc` | In the same positively read concrete index, DELETE a second random nonexistent document ID | Precheck 404 proves index read access; write returns 403 and ID remains absent |
| `assistant-svc` credentials | Authenticate to Server API `:55000` | Rejected; no Server API identity |
| SSH tunnel key | Request shell or any forward except `127.0.0.1:9200` | Rejected |
| browser/session tamper | Change role, index, query or endpoint | Server-side denial/validation |
| analyst profile | Inspect rendered page/network and audit output | No service/provider/OIDC secret |

The 2 September VM-local run had no concrete archive index. Its wildcard
search returned an empty `200` with zero shards and zero hits, which is vacuous
and is not evidence of either access or denial. A literal archive-namespace
control and existing Security/Dashboard indices returned `403`. Repeat the
archive row against a concrete archive index if one later exists.

Do not create a disposable probe or sentinel. The live ISM policy
auto-attaches to `wazuh-alerts-*`, so every candidate inside the former broad
service-role namespace has a lifecycle side effect.

The behavioral denial sequence uses one real DLS-visible document and two
cryptographically random, literal nonexistent IDs:

1. As `assistant-svc`, search an actual `wazuh-alerts-4.x-*` index for an
   agent-ID 001/002 document, then GET that same concrete index and `_id`.
   Record a content hash rather than `_source`. This positive read makes the
   subsequent denials non-vacuous for index pattern and DLS.
2. Attempt `_create` on the same concrete index with the already-existing
   `_id`. Expected: 403. If write permission was accidentally granted,
   create-only semantics return conflict and cannot overwrite the document.
3. In the same positively read concrete index, GET the first random
   nonexistent `_id` and require 404, not 403, proving index read access. Then
   attempt `_update` with only a `doc` body and `doc_as_upsert:false`. The body
   must contain **no `upsert` field**. Expected: 403; an accidental allow
   returns not found and cannot create a document.
4. In that same index, GET the second random nonexistent literal `_id` and
   require 404, not 403. Then attempt document DELETE. Expected: 403; an
   accidental allow returns not found.
5. Re-GET and re-hash the original document, then GET both random IDs to prove
   zero state change.

Optional index-level create/delete checks use literal concrete names only.
First read `action.destructive_requires_name` from effective cluster settings
and require it to be `true`. The 2 September 2026 inventory resolved the
effective default to `false`, so these optional checks are **omitted and
prohibited in the current lab**. Do not weaken or change that cluster setting
merely to run a test. If a separately reviewed future configuration resolves
every effective value to `true`, test create against the already-existing
concrete index name and delete against one cryptographically random nonexistent
literal name matching `wazuh-alerts-4.x-*`. Never use `*`, `_all`, a comma list
or any existing name in an index DELETE. If any supposedly denied request does
not return 403, stop, preserve sanitized evidence, disable live access and
repair the role; the chosen fallback outcomes must still leave state unchanged.

Pair behavioral evidence with declarative readback: capture sanitized
`GET _plugins/_security/authinfo` output for both identities before and after
project mapping; admin readback of the complete `own_index` mapping and both
AlertMind roles/mappings; and read-only username-index denials. This combination
shows both the configured grant and the enforced boundary. Stop on any
wildcard, alternate selector, backend/direct role or unexpected effective role.

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
- [ ] The editable `own_index` mapping contains exactly the seven preserved
      pre-existing users, no wildcard and no alternate selector; neither new
      identity inherits `own_index` or any unexpected effective role.
- [ ] Both username-named index searches return 403 before and after project
      mappings without creating an index or issuing a write request.
- [ ] DLS uses `agent.id` 001/002, the corresponding non-secret enrollment
      fingerprints are recorded, and scope is re-verified after re-enrollment.
- [ ] Dashboard evidence captured as `socanalyst` is labelled DLS-scoped and
      does not present its agent-001/002 totals as equivalent to admin totals.
- [ ] The same `assistant-svc` principal positively reads one real DLS-visible
      document and is then denied the fail-safe create/update/delete requests;
      the original hash is unchanged and both random IDs remain absent.
- [ ] Declarative `authinfo` and role readback agree with the behavioral proof.
- [ ] Indexer remains loopback-only; the host-only SSH local forward verifies
      TLS against the existing `IP:127.0.0.1` SAN and fails closed when stopped.
- [ ] The dedicated SSH key cannot open a shell or forward anywhere except
      `127.0.0.1:9200`.
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
- [ ] The SSH private key is server-side/local-only, ignored by Git, protected
      by Windows ACLs, and covered by rotation, revocation and rollback.
- [ ] Existing tests and all frozen-evidence checks pass without modifying
      committed run evidence.
- [ ] A rollback drill succeeds.
- [ ] Public documentation says **implemented** only after the live negative
      tests and proof artifact receive independent approval.

---

## 12. Rollback

1. Set the analyst/live-Wazuh profile off and restart Streamlit; offline mode
   remains available.
2. Stop and disable the SSH tunnel/listener, remove its restricted public-key
   entry and revoke/rotate the local SSH private key.
3. Remove both AlertMind Indexer mappings, then revoke or delete
   `assistant-svc` and `socanalyst`; prove both credentials fail authentication.
4. Keep the scoped `own_index` mapping by default. Restoring its wildcard is a
   separately reviewed compatibility rollback and is prohibited until step 3
   passes; restoring it earlier recreates the inherited write grant.
5. Remove or disable the later Wazuh Server/Dashboard `socanalyst` mappings if
   they caused a Dashboard regression.
6. Restore the saved SSH configuration or VM snapshot if required; Indexer
   should still be loopback-only and should not require a bind/certificate
   rollback on the preferred path.
7. Revoke/rotate the OIDC client secret and
   `ALERTMIND_AUDIT_SUBJECT_HMAC_KEY` if exposure is suspected or the rollback
   drill calls for rotation. Record only the new HMAC key identifier and note
   that it begins a new subject-correlation epoch.
8. Verify Wazuh Indexer, Manager, Filebeat and Dashboard health in order.
9. Preserve sanitized failure evidence; do not alter frozen corpus or run
   artifacts.

Rollback does not require a model rerun because no accepted model artifact is
part of the live integration state.

---

## 13. Proposed implementation commits

1. **Done — `9b91a02`:**
   `docs(rbac): finalize local-first Wazuh integration plan`
2. **Done — `8ebbc1f`:**
   `docs(rbac): tighten security proof and dependency gates`
3. **Done — `d1416f4`:**
   `test(rbac): characterize offline path and scaffold inventory`
4. **Done — `f92db3d`, `fde2fe4`, `73efcd7`:** Phase 0 inventory and review
   corrections.
5. **Done — `882c465`:**
   `evidence(rbac): record phase0 owner safety gate`
6. **Done and approved — `da86617`:**
   `chore(rbac): add secret-free identity and role templates`
7. **Done and approved — `ccd5ea3`:**
   `fix(rbac): remove inherited write grant before identity mapping`
8. **Owner-executed; current review cycle:**
   `evidence(rbac): record live Indexer enforcement proof`
9. `feat(auth): add OIDC profiles and server-side authorization`
10. `feat(wazuh): add constrained read-only alert client`
11. `feat(assistant): triage live Wazuh alerts through guarded pipeline`
12. `test(rbac): cover identity, reader, audit and denial boundaries`
13. `evidence(rbac): record complete least-privilege integration proof`
14. `docs(architecture): publish implemented read-only Wazuh path`

Each commit stages explicit paths only. Never use `git add -A` in this
repository because of the known line-ending churn risk.

---

## 14. Human tasks and decision points

Before implementation, the project owner must:

1. **Done:** create and retain a clean Wazuh VM snapshot;
2. **Done for the current enrollment state:** record the current non-secret
   enrollment fingerprints for agent IDs 001 and 002; repeat that check after
   either agent is re-enrolled;
3. **Done:** approve the reviewed host-only, key-restricted SSH local-forward
   setup;
4. generate the dedicated SSH key locally and choose strong passwords, OIDC
   client secrets and an audit-subject HMAC key without pasting any secret or
   private key into an agent chat or commit;
5. approve installation of a local Keycloak instance or nominate an existing
   OIDC provider;
6. perform the privileged Wazuh/Keycloak configuration steps while the agent
   supplies reviewed commands and secret-free templates; and
7. personally exercise the final analyst login and approve the sanitized
   positive/negative evidence.

The first implementation turn must stop if the restricted SSH tunnel cannot
provide host-only access with valid TLS and a recoverable rollback path. Do not
rebind Indexer or regenerate its certificate without a separate reviewed plan.

---

## 15. Authoritative references

- [Wazuh RBAC and read-only users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html)
- [Wazuh Indexer alert-search examples](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)
- [Wazuh Indexer API configuration](https://documentation.wazuh.com/current/user-manual/indexer-api/configuration.html)
- [Securing the Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/securing-indexer-api.html)
- [Wazuh Server API RBAC](https://documentation.wazuh.com/current/user-manual/api/rbac/index.html)
- [OpenSearch access control and action groups](https://docs.opensearch.org/latest/security/access-control/index/)
- [OpenSearch document-level security](https://docs.opensearch.org/latest/security/access-control/document-level-security/)
- [OpenSearch 2.19 permissions](https://docs.opensearch.org/2.19/security/access-control/permissions/)
- [OpenSSH `authorized_keys`](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT)
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
