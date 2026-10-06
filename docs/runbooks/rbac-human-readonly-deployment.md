# Scoped socanalyst mapping/UI, recovery and acceptance

6 October 2026. **Prepared for focused review; NOT a VM execution release.**
This is the finite P1-04–06 human package, not OIDC implementation or a new
runtime-attestation framework. Read the [review](../reviews/human-readonly-package-2026-10-06.md)
and [accepted owner observation](../../evidence/rbac/dashboard-context-result-2026-10-06.md).
Keep the existing H3, TLS, SSH and credential-drill results; do not replay them.

## Exact change and external conditions

The observed top-level string `user_name=socanalyst` is matched by
`{"MATCH":{"user_name":"socanalyst"}}`, not recursive `FIND`, a username guess,
role wildcard or an invented run-as body. Add one Server rule named
`alertmind_socanalyst_server_ro` and link it only to the unique **current** role
named `readonly`, whose 13 policies must match v4.14.7. Do not hardcode the
historical readonly ID2 or the future custom rule ID. Preserve both existing
administrator predicates and their links, all other users/roles/policies/rules,
the existing broker and `run_as=true`. No direct Server socanalyst or assistant
user is created.

Append `alertmind_socanalyst_ro` to
`opensearch_security.readonly_mode.roles`, retaining `kibana_read_only` and every
existing label. Only that YAML value span changes; other configuration bytes,
ownership/mode and multitenancy=false stay unchanged. Unknown aliases, duplicate
settings, unsupported encodings, extended ACLs/xattrs or drift refuse. Do not
repair permissions to make a failed check pass. No Indexer/tunnel/grant change,
saved-object write, password rotation, browser trust change or TLS rollback.

The owner accepted broader built-in Server reads for this lab; Indexer DLS still
filters alert agents001/002, **not Server data**. The assistant remains Indexer-only.
The owner-attested account/factory equivalence is not cryptographic capture of
the exact broker body. The actual issued-token effective policy is tested later.

One reviewed/released batch must explicitly confirm: original wazuh-siem (not
clone), stable host/VM/private unrecorded console, Snapshot1 and a recoverable
current before-state retained, AlertMind apps stopped, normal logout/no active
analyst session, no concurrent updates/configuration/other Dashboard instance,
and acceptance of temporary Dashboard downtime. Trust conventional lab root,
OS/systemd/shell/vendor Python3.10/PyYAML; no hostile-host attestation is claimed.
Do not run original and clone concurrently during this work.

Approve package/data/predicate/probe safety first; separately release each live
batch. Successful checkpoints within that batch do not need another review.
Any failure, changed conditions, unexplained timeout or guest freeze consumes
the batch: preserve private state and request scoped recovery, **no blind retry**.
Socket budgets do not run while a VM is suspended and are not a guest watchdog.

## M1 — public workstation build

From the repository root, using an existing workstation Python:

```powershell
$HumanReadonlyPacket = Join-Path ([IO.Path]::GetTempPath()) ('alertmind-human-readonly-' + [guid]::NewGuid() + '.json')
& {
    $ErrorActionPreference = 'Stop'
    python -B siem/rbac/build_human_readonly_packet.py --output $HumanReadonlyPacket
    if ($LASTEXITCODE -ne 0) { throw 'STOP: public build failed; retain any output' }
    "Public packet retained at: $HumanReadonlyPacket"
    'STOP POINT: obtain focused review of this exact packet and staging aid; no VM action released'
}
```

The deterministic packet contains four public sources plus SHA256SUMS. No
private config, journal, token or credential is in it. The reused Server reader
and compact TLS library are byte-pinned, unchanged. The review-submission label
remains `awaiting-focused-review`; approval/release are recorded separately.

## M2 — public stage, only after staging release

Copy the **complete reviewed** `siem/rbac/stage_human_readonly.py` as a public
heredoc command, not snippets. This preserves `/dev/tty` for public prompts while
stdin supplies source. No `input()` on heredoc stdin, remote transfer, SSH shell
or permission relaxation. From workstation PowerShell:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $PublicSource = (Get-Content -Raw -LiteralPath 'siem/rbac/stage_human_readonly.py').Replace("`r`n", "`n")
    $Command = "sudo /var/ossec/framework/python/bin/python3 -I -B - <<'ALERTMIND_HUMAN_STAGE'`n" + $PublicSource + "ALERTMIND_HUMAN_STAGE`n"
    Set-Clipboard -Value $Command
    'PASS clipboard: reviewed public staging source only; paste on the approved original console'
}
```

After pasting the whole command, type the requested release token and the exact
independently reviewed packet digest on the VM. While it waits for public Base64,
switch to the same workstation PowerShell session (retain the exact
`$HumanReadonlyPacket` from M1, assigned outside the child-scope script block):

```powershell
& {
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $HumanReadonlyPacket -PathType Leaf)) { throw 'STOP: retained packet absent' }
    $Bytes = [IO.File]::ReadAllBytes($HumanReadonlyPacket)
    $PublicBase64 = [Convert]::ToBase64String($Bytes)
    $Lines = [regex]::Matches($PublicBase64, '.{1,76}') | ForEach-Object { $_.Value }
    Set-Clipboard -Value (($Lines -join "`n") + "`nALERTMIND_PUBLIC_SOURCE_END`n")
    'PASS clipboard: wrapped public packet/end marker only; no credentials'
}
```

Paste once into the waiting VM public prompt. Expected: five exact root-private
files, syntax only, checksum recorded; no operator executed. Fixed new stage:
`/root/alertmind-broker-tls-compact/human-readonly-stage`, directory0700 and
files0400 root:root. An existing/partial stage refuses: preserve it for diagnosis,
never overwrite or chmod to replay. Existing TLS stages/backups stay untouched.

## M3 — read-only compatibility preflight

Hold until a separate one-run original-VM release. Run the **entire** block:

```bash
(
set -euo pipefail
sudo -v
sudo bash -c 'cd /root/alertmind-broker-tls-compact/human-readonly-stage && sha256sum -c SHA256SUMS'
sudo /var/ossec/framework/python/bin/python3 -I -B /root/alertmind-broker-tls-compact/human-readonly-stage/human_readonly_operator.py preflight
)
```

Enter the release token, then existing **Server** administrator credentials
privately, not Indexer admin by assumption. The helper disables core dumps before
credential prompts, verifies pinned localhost TLS and wrong-name rejection, then
authenticates once. Tokens/credentials stay in memory; cleanup is not guaranteed
secure erasure. No raw API/config/exception text leaves the process.

Two-pass catalog/context reads must match the accepted observation summary digest
`d3db272c808ddb23c7532530c096087a7b336481b6503bc783cf390111c4f046`.
The unique readonly role is resolved by name, original admin predicates/links
and empty readonly users/rules checked. Drift stops for review, not auto-repinning.
The deployed compact TLS candidate, trust, endpoint, startup guard, package4.14.7
and relevant services must remain valid. UI compatibility is checked without
writing. A PASS is configuration compatibility, not analyst behavior. Return only
PASS/STOP lines and the **public** single Server host ID printed for acceptance.

## M4 — one approved downtime/install batch

Hold until M3 is accepted and owner explicitly releases private preparation,
mapping/UI changes and downtime. Normal private snapshots in
`/root/alertmind-broker-tls-compact/human-readonly-state` remain on the VM, directory
0700/files0400. They can contain configuration secrets: **never copy, hash publicly,
print, commit or paste them**. The operator does not store passwords or tokens.

```bash
(
set -euo pipefail
sudo -v
sudo bash -c 'cd /root/alertmind-broker-tls-compact/human-readonly-stage && sha256sum -c SHA256SUMS'
sudo /var/ossec/framework/python/bin/python3 -I -B /root/alertmind-broker-tls-compact/human-readonly-stage/human_readonly_operator.py prepare
sudo /var/ossec/framework/python/bin/python3 -I -B /root/alertmind-broker-tls-compact/human-readonly-stage/human_readonly_operator.py install
)
```

`prepare` only writes private backups/journal, not grants/UI/services. `install`
uses the **existing compact maintenance inhibitor**, reloads and stops Dashboard
before any Server/UI mutation. It journals create/link/UI intents durably before
writes, reconciles the exact named rule after a lost response, verifies all
unrelated catalog bytes after every mutation, atomically replaces only the UI
list with original metadata, and leaves Dashboard stopped/inhibited. A crash
before the initial stop may leave the old active service, but no mapping/UI
mutation has begun; durable inhibition protects later starts. A later crash
retains inhibition. No automatic restart, privilege broadening or unsafe fallback.

## M5 — separately released secure restart/check

Only within the reviewed maintenance release after accepted M4:

```bash
(
set -euo pipefail
sudo -v
sudo bash -c 'cd /root/alertmind-broker-tls-compact/human-readonly-stage && sha256sum -c SHA256SUMS'
sudo /var/ossec/framework/python/bin/python3 -I -B /root/alertmind-broker-tls-compact/human-readonly-stage/human_readonly_operator.py resume
sudo /var/ossec/framework/python/bin/python3 -I -B /root/alertmind-broker-tls-compact/human-readonly-stage/human_readonly_operator.py check
)
```

Each command authenticates once, with hidden input; no authentication retry loop.
Resume checks graph/UI/TLS before removing inhibition, starts Dashboard through
its existing mandatory TLS guard, verifies active services and persists running
state. Ordinary failure re-inhibits/stops; power loss after un-inhibition still
leaves a verified secure patch and exact installed mapping/UI, not insecure bytes.
No continuous integrity or atomic-snapshot claim. Missing/changed private state
requires diagnosis/recoverable before-state; never delete the journal to proceed.

## M6 — actual analyst/admin acceptance, separately released

Use the trusted Firefox lab profile on **https://127.0.0.1:443**, no certificate
exception/warning bypass. Close old analyst sessions; fresh login as socanalyst
must acquire the new mapping. Do not capture cookies/JWTs/HAR/raw responses or
send broker credentials/direct run-as requests. Log out normally afterwards.

First verify an actual Wazuh Server read and approved alert reads, then both saved
dashboards against the retained identities/panels/data without saving. Query
agent000 versus001/002 only in the approved alerts pattern; a contemporaneous
administrator positive control must show agent000 exists before claiming DLS
exclusion. Do not add `.kibana*`, monitoring grants, `kibana_user`, `all_access` or
write tenants if a page fails. Record the denied target for scoped diagnosis.

Copy the COMPLETE reviewed `siem/rbac/human_readonly_acceptance.js` as public
source from the workstation, then paste once into Firefox **Web Console**
(`Ctrl+Shift+K`) on this authenticated origin—not the address bar or Ubuntu
terminal. Never bypass browser self-XSS protection blindly; review the source
first. Enter the requested release token and public single Server host ID printed
by M3/M5. This helper performs:

1. Actual scoped account read, exact socanalyst role/empty backend roles.
2. Actual current-user broker policy read: exact effective built-in readonly
   action/resource map, white mode and **no extra grants**.
3. Bounded real Server agent read as a positive control (ID only, no output).
4. GET security-rules denial, then one **duplicate-name** POST of the existing
   exact owned rule as a fail-safe create probe. Fresh M5/operator check must
   prove this rule exists and no concurrent maintenance is allowed. Wazuh4.14.7's
   unique rule-name constraint rolls back a duplicate rather than creating a rule
   even if permission is unexpectedly granted. Duplicate error4005 is **FAIL**,
   not authorization proof; only HTTP403 + Server error4000 passes.
5. Policy/account re-read equality. All outputs are fixed public booleans/statuses.

The Dashboard wrapper POSTs `/api/request` with a fixed method/path/body and
`devTools=true` solely to preserve upstream status. No delay/headers/impersonation
options. No real agent restart/removal, active-response, configuration/RBAC update,
bulk deletion, global token revocation, Indexer or saved-object write is sent.
HTTP401/400/404/500, generic Dashboard403 and partial/duplicate responses never
count as denial. A STOP consumes this acceptance run; do not repeat blindly.

After normal logout, run the same **M5 `check` command only**, not resume/restart,
under the released acceptance batch. It verifies the whole unrelated Server graph
and exact UI stayed unchanged after the probe. Then fresh administrator login:
repeat actual Server read, refresh, normal logout/login and both saved dashboards
without saving. Retain timings/errors and [complete the evidence template](../../evidence/rbac/human-readonly-acceptance-template.md).

Backend agent-action HTTP probes and Dashboard/saved-object write probes remain
**NOT TESTED**, not hidden behind UI PASS. Focused review must explicitly settle
whether exact actual readonly policy + versioned authorization code + the safe
create/admin denial and preserved Indexer checkpoints satisfy the finite
criterion. If not, design a scoped fail-safe probe before executing it. This
package does not silently waive a row or close P1-05. An observed UI read-only
mode is presentation evidence, not independent backend write enforcement.

## R — scoped rollback and deliberate secure restoration

Recovery needs a separate owner release with downtime and private state retained.
Normal logout/stop analyst use first. `rollback` stops/inhibits before reading
state, refuses unrelated graph/UI drift, removes ONLY our readonly edge and
exact owned custom rule ID, restores the exact private before-UI bytes/metadata
and leaves inhibition in place. It handles absent, half-installed and interrupted
owned states. Admin rules/users/policies, Indexer, TLS patch/guard and tunnel remain.
Never call the compact operator's **TLS rollback** for this human transaction.

Use the same stage checksum block, then ONE explicitly released action:

```bash
sudo /var/ossec/framework/python/bin/python3 -I -B /root/alertmind-broker-tls-compact/human-readonly-stage/human_readonly_operator.py rollback
```

After accepted rollback, separately released `resume-baseline` verifies the exact
original human graph/UI and the secure TLS patch, then starts Dashboard. Removal
of a rule is not a guaranteed immediate logout: stop analyst use and account for
existing token/session lifetime. No global revocation or claim of instant expiry.
Fresh analyst Server access should no longer have the added readonly role;
administrator/two-dashboard continuity remains to be observed.

For deliberate feature restoration after accepted rollback, separately release
`restore`, then `resume` and `check`. `restore` verifies the rolled-back baseline,
reuses private backups, resets only our intent and installs the same exact
name/predicate/UI list; the returned rule ID is newly observed. Repeat fresh
analyst/admin acceptance if required by the released recovery batch. Do not delete
state, rerun prepare, unmask/start services manually or reset unrelated roles.

P1-06 needs recorded recovery/secure restoration plus focused acceptance review;
offline interruption tests are not a live rollback result. Publish only sanitized
PASS/STOP lines, statuses/flags, accepted limitations and verdict—not private files.
