# Focused review submission — human readonly transaction

Status: **awaiting-review**. Codex author implementation, not independent approval,
live release or Phase1 closure. Base main3496790; branch `feat/rbac-human-readonly-package`.

## Review scope

- [Operator](../../siem/rbac/human_readonly_operator.py): fixed Server route writer,
  full graph-delta checks, exact YAML role-list edit, private recovery journal,
  persistent inhibition and explicit secure restart/rollback/restoration.
- [Browser acceptance](../../siem/rbac/human_readonly_acceptance.js): actual scoped
  account + actual issued human policy, bounded Server read, safe duplicate-create
  and security-admin read denial; no invented run-as or exposed sessions.
- [Builder](../../siem/rbac/build_human_readonly_packet.py),
  [staging aid](../../siem/rbac/stage_human_readonly.py),
  [runbook](../runbooks/rbac-human-readonly-deployment.md),
  [tests](../../assistant/tests/test_human_readonly_package.py) and retained result.
- Reused unchanged Server reader SHA25696e64194... and compact TLS operator
  SHA2562200ccbe... are pinned as complete LF bytes. Reuse is not release of the
  earlier experimental guard/lifecycle framework. No application/Indexer change.

## Matching/context argument to approve explicitly

The [6 October result](../../evidence/rbac/dashboard-context-result-2026-10-06.md)
observes top-level string `user_name=socanalyst` through actual Dashboard-scoped
account reads. Owner confirms normal logout/no extra changes. Both current
versioned administrator FIND predicates failed; neither existing rule is changed.
The new `MATCH` examines the named field at the current object level, unlike
recursive FIND. v4.14.7 literal matching also accepts strings inside a list: the
accepted account-shape/factory boundary requires this field to be a string and
the browser acceptance rechecks it. Do not claim a general scalar-only predicate
validator for arbitrary future contexts or OIDC identities.
([v4.14.7 matcher](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/rbac/auth_context.py))

This remains owner-attested account/factory equivalence, not exact run-as wire
capture, loaded-code proof, atomic observation or cryptographic provenance. The
initial whole sanitized Server-summary digest is pinned to the observed result.
Readonly is resolved by name, its 13 policy definitions verified, existing two
admin predicates and brokerID2 checked. New IDs are returned/current, not guessed.
Policy after installation is tested through Dashboard's actual current user.

## Mutation/HTTP and duplicate-probe argument

The only writer routes are POST `/security/rules`, POST/DELETE one numeric
`/security/roles/{readonly_id}/rules?rule_ids={owned_id}`, and DELETE
`/security/rules?rule_ids={owned_id}`. No PUT, users/policies mutation, empty/all
selectors or reserved rule deletion. The creation body contains only the fixed
name and predicate. Success must be HTTP200 with one affected item, no failures;
actual graph readback is authoritative, not a returned ID blindly trusted.
TLS peer/name verification precedes bearer transmission; no redirect/proxy/DNS
fallback. The existing reader's response framing/limits and failure-body policy
remain unchanged. ([v4.14.7 API specification](https://github.com/wazuh/wazuh/blob/v4.14.7/api/api/spec/spec.yaml))

The safe write probe uses the **existing owned rule's unique name**, not a new
throwaway resource or an actual agent. `RulesManager.add_rule` commits through a
unique-name constraint; IntegrityError rolls the transaction back and returns
ALREADY_EXIST. Framework add_rule reports error4005; only Server permission
error4000/HTTP403 is a denial PASS. An unexpected duplicate/partial result stops
even though collision protects existing state. No concurrent writers and fresh
operator check are mandatory. Post-probe graph/UI check must remain identical.
([versioned ORM](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/rbac/orm.py),
[security functions](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/security.py))

`/api/request` has the fixed id/method/path/body schema and calls the scoped
current-user client. `devTools` preserves the actual upstream error/status; it is
not a credential or role selector. The already retained official package was
locally re-read: full .deb SHA25683f472d9... and installed-matched controller
SHA2566e9618c5... match; scoped request line426 and devTools error-response branch
line456 are present. This is static package comparison, not loaded-code attestation.
([versioned Dashboard route](https://github.com/wazuh/wazuh-dashboard-plugins/blob/v4.14.7/plugins/main/server/routes/wazuh-api.ts),
[controller](https://github.com/wazuh/wazuh-dashboard-plugins/blob/v4.14.7/plugins/main/server/controllers/wazuh-api.ts))

## Recovery/metadata argument

Private backups/journal are root:root0400 under0700, durable and never exported.
UI list is the only changed span, retaining unrelated YAML bytes/comments, labels,
multitenancyfalse and original UID/GID/mode. Reject aliases/duplicates/unknown
ACL/xattrs rather than losing them. The conventional trusted-administrator boundary
does not claim safety against a concurrent compromised service/root writer.

The existing inhibitor is durable before grant/UI mutation. Intents precede each
change; lost create/link/delete responses are reconciled by exact owned name,
predicate, numeric custom ID and graph projection. Unknown extra edges, admin or
policy/UI drift refuse, not a broad rollback overwrite. Rollback leaves Dashboard
stopped, keeps private backups and the secure broker patch/guard. Resume-baseline
and deliberate feature restore are separate actions; failures re-inhibit.
Existing human tokens may retain scope until normal token/session expiry; no
global revocation or instantaneous-revocation assertion is added.

## Acceptance disposition required

Approve this predicate/equivalence boundary and the duplicate-probe safety before
any live release. Separately settle P1-05's agent-action/write rows: this package
offers exact **actual human effective readonly policy**, real read positive
control, security-admin read and create denial, existing preserved Indexer proofs
and fresh manual DLS/UI/admin/two-dashboard checks. It intentionally sends no real
agent action, saved-object write or unsafe deny request. Those HTTP rows remain
NOT TESTED unless explicitly accepted by a scoped evidence decision or replaced
by a reviewed fail-safe probe. No implicit waiver or Phase1-complete output.

## Verification and unproven behavior

See [verification record](../../evidence/rbac/human-readonly-verification-2026-10-06.json)
for exact source digests/test results. New tests cover the active transaction and
documented recovery/refusal boundaries; full existing suite/evidence retained.
No root observer, real Server/Indexer/browser request, VM mutation or live review
was performed. Linux native PTY/staging, real service stop/start, permission/UI
activation, actual policy response compatibility, analyst behavior and rollback
still require the normal reviewed release/CI/owner observations. Unknown package
or changed pins refuse; future upgrades need reviewed compact-package refresh,
not suppression of security updates or automatic pin learning.
