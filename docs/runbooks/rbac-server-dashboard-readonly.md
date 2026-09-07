# Server/Dashboard read-only implementation gate

**Status:** Local implementation package; awaiting independent review and fresh
VM inventory. No live mutation is authorized by this package. No application
runtime change is included. The authenticated analyst profile is still absent.

**Baseline:** PR #21 (`41105a9`) merged the independently approved transport and
service-credential rollback record (`32557ae`, `1850093`). Do not repeat that
drill. Its [reported results](../../evidence/rbac/phase1c-rollback-revocation-proof.md)
remain checkpoint-scoped, not proof of current availability.

## 1. Exact boundary and target

This completes the human `socanalyst` Wazuh access gate before the separate
OIDC/reader/UI implementation. The three authorization planes stay distinct:

| Plane | Target | Preserve / prohibit |
|---|---|---|
| Indexer | Existing `socanalyst` -> `alertmind_socanalyst_ro` | Existing alert namespace, agent-ID 001/002 DLS and global read-only tenant; no new grants in this package |
| Dashboard | Existing internal-user login, read-only presentation | Add the exact effective custom role to read-only UI configuration only after inventory and review; retain existing role labels |
| Wazuh Server | Dashboard authorization context for `socanalyst` -> built-in `readonly` | Separate Server mapping; no guessed numeric IDs, password duplication or direct Server user creation |
| Assistant | Existing `assistant-svc` on Indexer only | No Server identity, Dashboard grant, broker credential or new tunnel destination |

The Dashboard's Server API broker is not an Indexer identity. The existing
broker account and its run-as capability must be inventoried independently;
the Indexer `admin` password must not be assumed to authenticate to the Server.
Do not place broker credentials in the assistant or browser. Do not fabricate a
human authorization context from a browser parameter in application code.

Wazuh's documented Dashboard mapping uses `readonly` and requires `run_as` in
its Wazuh connection configuration. That does not replace Indexer enforcement.
([Wazuh mapping guide](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html))

The versioned Server role is broader than alert-only access. It can expose
system and agent information beyond the Indexer agent-001/002 alert scope;
Indexer DLS does not constrain Server responses. Record that accepted
compatibility trade-off before activation, or stop for a custom-role redesign.
Do not advertise the entire Dashboard as agent-001/002 isolated.
([4.14.7 role definitions](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/rbac/default/roles.yaml))

## 2. Implemented now: local inventory collector

[`collect_dashboard_inventory.py`](../../siem/rbac/collect_dashboard_inventory.py)
reads only the three fixed local configuration files. It emits a small set of
booleans/classifications and host ordinals, not connection URLs, usernames,
passwords, keys, raw YAML or exception bodies. Reads are size-limited; duplicate
YAML keys and unsafe tags are rejected. No HTTP, token creation, filesystem
write, package installation or service control occurs in the helper.

This is an inventory of **explicit settings**, not resolved defaults or runtime
behavior. Missing/invalid values must not be interpreted as a pass. Multiple
hosts require individual review; no "first host wins" selection is permitted.
The helper does not prove that a broker has run-as authority, that a Server role
exists or that the application is read-only.

After independent package review, stage only this public helper on the VM at
`/home/notroot/alertmind-server-dashboard-inventory/`. Compare its SHA-256 with
the committed manifest, using a console transfer; do not enable an SSH shell
or change the restricted tunnel to transfer it. No private configuration file
should leave the VM. A separate owner packet will provide the exact staging
bytes and verified digest after review.

Run the following **entire block**, not individual lines after an error:

```bash
(
set -euo pipefail
cd /home/notroot/alertmind-server-dashboard-inventory
sha256sum -c SERVER-DASHBOARD-SHA256SUMS
for svc in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$svc")
  test "$state" = active || { echo "STOP service: $svc"; exit 1; }
  printf 'PASS service health: %s=active\n' "$svc"
done
dpkg-query -W -f='${Package} ${Status} ${Version}\n' \
  wazuh-manager wazuh-indexer wazuh-dashboard
PY=/var/ossec/framework/python/bin/python3
test -x "$PY" || { echo 'STOP: packaged Python absent'; exit 1; }
sudo "$PY" -B collect_dashboard_inventory.py
printf '%s\n' 'STOP POINT: return sanitized output; no configuration or permission change.'
)
```

An import/access/shape error prints a generic STOP and returns nonzero. Do not
paste the raw files or switch to a generic YAML dump to diagnose it. Resolve
the missing dependency/access at the console without installing packages in
this gate. The fresh package versions must still support the reviewed design.

## 3. Read-only follow-up inventory before mutation

The local summary is the first packet, not the full preflight. From its output,
prepare and independently review a VM-local authenticated collector that:

1. Establishes Server API TLS separately from Indexer TLS: inspect only the
   configured public certificate/CA, SAN, issuer, validity and fingerprint.
   Do not assume the Indexer CA or its IP SAN applies to port 55000. Resolve
   missing trust/hostname coverage before sending credentials. No insecure
   bypass, listener rebind or certificate replacement is authorized here.
2. Uses a verified existing Server administrator only for inventory. JWTs and
   broker passwords stay in process memory, never command arguments, files,
   console output, shell tracing or the assistant. Error bodies are suppressed.
   Token issuance is an authentication operation, not a pure local read, and
   belongs to this later reviewed packet, not the current helper.
3. Reads all pages of Server users, roles, policies, mapping rules and their
   relationships, plus RBAC mode. Bind the unique `readonly` name to its live
   ID and resolve its policies/actions/resources; reject extra write grants,
   unexpected inheritance, ambiguous names or incomplete pagination. Require
   allowlist/default-deny mode; do not switch the global mode as a shortcut.
4. Examines the trusted Dashboard broker's existing run-as capability and all
   rules which could match `socanalyst`, not just the proposed new rule.
   Confirm the actual Dashboard auth-context shape rather than assume it.
   Reserve mapping name `alertmind_socanalyst_server_ro`; stop on collision.
5. Rechecks exact existing Indexer roles, mappings, DLS and scoped `own_index`.
   Preserve `assistant-svc` and `socanalyst` secrets. Confirm no Server user
   named `assistant-svc`; absence alone is not a tested authentication denial.
6. Captures administrator Dashboard baseline health and required saved-object
   availability, without exporting sessions, raw alert bodies or secret config.

Wazuh 4.14.7 provides run-as token issuance and a processed-current-policy read
endpoint. The future proof must inspect the policy of the **actual Dashboard
human context**, not infer it from the broker's direct administrator token.
([4.14.7 API specification](https://github.com/wazuh/wazuh/blob/v4.14.7/api/api/spec/spec.yaml))

## 4. Planned minimal change set — not executable yet

After inventory, review an exact before/after package with these boundaries:

- Link one exact `socanalyst` authorization-context rule to the observed
  built-in `readonly` role. Preserve existing rules and relationships. Do not
  add wildcard users/backend selectors or grant the broker's own role to humans.
- If already true, preserve `run_as`; otherwise change only the selected,
  verified Dashboard connection after confirming existing administrator access
  will survive. Multiple connections need an explicit selection and scope.
- If absent, add `alertmind_socanalyst_ro` to the Dashboard read-only UI role
  list, preserving its existing entries. This suppresses editing controls;
  authorization must still be enforced by the Indexer and Server.
- Preserve disabled multitenancy unless a separate reviewed need is established.
  Do not grant `kibana_user`, `all_access`, a write tenant or `.kibana*` access
  to fix UI errors without reviewing the exact necessary request.
- No monitoring-index grant is authorized. A necessary read returning 403 must
  be documented and reviewed before any additional index permission.
- Snapshot availability, console access, private root-only backups, exact
  compare-before-edit guards and a narrowly scoped rollback must precede changes.
  Restart only Dashboard if its file changes require it; no SSH/Indexer rebind.

## 5. Acceptance matrix and safe denial design

| Check | Required evidence / stop condition |
|---|---|
| Administrator continuity | Existing admin can still reach required dashboards and Server management; all four services healthy |
| Analyst login | Fresh isolated `socanalyst` session; no recycled admin cookie; authenticated positive read precedes denials |
| Alert scope | Alert views/aggregates exclude agent 000 and are labelled DLS-scoped; do not compare totals as equal to admin |
| Saved dashboards | Required two operational dashboards open without edits or broad fallback grants |
| Effective permissions | Complete Indexer and actual Server-context policy readbacks agree with the minimal change set |
| Read-only UI | Editing controls unavailable; this alone is not behavioral write-denial proof |
| Server security read | A protected read requiring security-administration access is denied to the authenticated human context; check exact request against installed API version |
| Index writes | Use only the previously reviewed fail-safe document strategy, with fresh same-principal positive read and pre/post checks; never reuse stale targets |
| Server writes/actions | Must have a version-checked, zero-state-change fallback before any request is issued; otherwise remain NOT TESTED and block the corresponding claim |
| Machine separation | No Server identity; controlled direct service-credential authentication denial plus unusable Dashboard data path, without copying the password into an agent chat |
| Existing transport | Restricted listener and existing assistant read scope unchanged; no new tunnel destination |

No active-response command, agent restart/removal, rule update, manager restart,
RBAC edit or global token revocation may be used as a "negative test" on a real
target. A non-existent ID or malformed body is not automatically safe or proof
of authorization denial: validation may precede authorization and bulk endpoints
can have partial effects. The exact later denial packet must distinguish HTTP
401, authorization 403, validation/not-found and partial results. UI-hidden and
policy-only evidence must be labelled as such, never a passing live write matrix.
If a safe behavioral probe cannot be demonstrated, report that gap for a scoped
review decision; do not fabricate success or quietly remove the criterion.

## 6. Rollback, evidence and next handoff

On a failed acceptance check, stop new analyst sessions. Revert only the newly
added Server mapping relationship/rule and exact Dashboard lines from the
private before-state; restore Dashboard and recheck administrator access and
Indexer -> Manager -> Filebeat -> Dashboard health. Do not delete either
Indexer user, reset passwords, restore the `own_index` wildcard or undo the
accepted transport. Previously issued Server tokens may remain valid: block
continued analyst use and account for token expiry/revocation using a separately
reviewed session plan rather than claiming mapping removal instantly revokes
all sessions. No global revocation is authorized by this package.

Record execution commit, installed versions, sanitized before/after, real
identity/context, exact requests/status/error classification, positive controls,
denials, broader Server-read disclosure, failures and rollback results. Unrun
rows remain NOT TESTED. Do not add a "proof" file before execution.

**Next owner action:** after Claude approves this package, run the local
inventory via its public staging packet and return only the sanitized summary.
**Next author action:** use that inventory to produce the authenticated
readback and exact mutation/denial package; do not improvise live permissions.
Then, after this gate passes, implement OIDC/named permissions, the constrained
Indexer reader, guarded live-alert triage and transactional sanitized auditing.
