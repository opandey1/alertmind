# Security Hardening Review: AlertMind Dashboard broker TLS

Author: Codex, 9 September 2026. **Design only; awaiting independent review.**
No option is selected for live deployment. No patch, fixture or operator command
is implemented by this document.

## Evidence Basis

We have one confirmed static defect at an existing shared client boundary, not
evidence that the whole architecture needs replacing. The
[approved installed-byte review](../../reviews/dashboard-broker-control-flow-tls-2026-09-09.md)
and [provenance record](../../../evidence/rbac/dashboard-broker-code-review-2026-09-09.json)
bind nine owner-reported installed files to the official 4.14.7 package. The
[evidence inventory](context.md) records hashes, new vendor research and limits.

I reopened the matched client: human run-as authentication, ordinary user
requests, internal-user authentication and internal background reads all use
the non-verifying client. We should repair that common boundary, not only the
interactive login. Internal health/registry activity may authenticate without
an analyst opening a new session; stopping Streamlit does not stop Dashboard
background traffic.

Upstream now has host CA support, but the pinned source metadata says 5.1.0.
We have not established a compatible released upgrade or a settings-only fix
for this 4.14.7 installation. The research supports a local candidate, not
copying a development plugin or claiming vendor support for our patch.

## Constraints

We retain the frozen v1 benchmark, current Indexer roles/DLS and restricted SSH
transport. This work must not create a Server assistant-svc identity, new grant,
listener, certificate authority or secret export. The Server certificate's
known DNS SAN is `localhost`; the URL and trust anchor must be treated together.
We have no current raw broker URL, installed Node/axios identity, CA certificate
bytes or live process evidence in this task. Unknowns become implementation
preconditions, not reasons to weaken verification.

No performance budget was supplied. We assume the local lab values a small
change and recoverability over a new process boundary. All performance/resource
effects below are predictions; none were benchmarked. A failed trust or identity
check must stop authentication rather than silently fall back.

## Opportunity Portfolio

**Local remediation preferred; no additional structural opportunity qualified.**
The shared axios client already provides a suitable enforcement point. Adding
a proxy would add a service, configuration and failure mode while leaving the
first non-verifying connection to secure. A system-wide Node override would
affect unrelated traffic and obscure ownership. Neither is proportionate here.

We considered three real choices:

| Choice | Effect on the reviewed defect | When it is appropriate |
|---|---|---|
| 1. Version-bound local client fix | Proposed to address it across internal and scoped traffic; tactical patch required | Candidate recommended for offline development while retaining 4.14.7 |
| 2. Vendor-supported upgrade/backport | Unknown until an exact compatible package is identified and tested | Prefer it if support and migration cost can be established |
| 3. Explicit local-only exception | Leaves the TLS defect unchanged; restrictions only bound exposure | Only if the owner accepts residual risk, scope and expiry; not approved |

Choice 1 keeps the existing authentication/context semantics and connection
count. We would own a small patch and its drift checks. Its strongest cost is
operational: package updates can replace it, and a bad trust configuration can
make the Dashboard unavailable. We therefore need a startup hash guard,
tests of the actual client and a fail-closed recovery procedure—not just a
one-line replacement of false with true.

Choice 2 transfers ongoing patch maintenance back to the vendor. It is the
preferred long-term result, but we do not have a tested 4.14-compatible artifact.
A major upgrade can change API behavior, plugin dependencies and saved objects;
it needs its own scope approval and staging validation. Finding a feature on
`main` is insufficient reason to upgrade this lab or restart its benchmark.

Choice 3 is operationally smallest and avoids touching vendor code. It does
not authenticate the TLS peer, including during background traffic. If we
choose it later, we must state that fact, retain loopback-only scope, name an
expiry/review trigger and never reuse the custom-client TLS PASS as broker proof.
No expired exception may silently become the default deployment posture.

| Dimension | Local fix | Vendor path | Exception | Basis and validation |
|---|---|---|---|---|
| Security | Improve peer identity checks; service compromise remains | Unknown until exact implementation tested | Defect unchanged | Source-derived, high confidence for current defect; synthetic negative handshakes before credentials |
| Latency/CPU | Adds chain verification, no new hop | Unknown with wider dependency changes | Current behavior | Hypothetical, medium/low confidence; compare cold/warm auth and reads, no made-up savings |
| Memory | One bounded certificate/agent, no process | Unknown across upgrade | Current behavior | Hypothetical, medium/low confidence; compare RSS and agent/socket counts under repeated reads |
| Availability | Misconfiguration/update drift intentionally fails closed | Upgrade/regression risk | No added failure mode, existing security risk | Source-derived mechanisms, medium confidence; simulate missing trust, replacement and recovery |
| Operations | Own patch manifest, expiry and startup check | Vendor maintenance plus version migration | Own exception expiry and restrictions | Inferred, medium confidence; rehearse update/drift/recovery without silent bypass |
| Compatibility | Preserve run-as/caches/routes, restrict endpoint explicitly | Must revalidate Server/plugin/platform compatibility | Current behavior | Source-derived constraints, medium confidence; admin health, registry, saved dashboards and scoped tests |
| Developer drift/rollback | Exact hash-bound patch; no fuzzy reapply | Follow supported rollback including data compatibility | Revisit before release/scope change | Proposed, medium confidence; exercise negative drift and rollback in isolated fixture first |

## Recommendation Summary

I recommend **Choice 1 for the next offline implementation package**, subject
to Claude's design review and owner selection. We would switch to Choice 2 if
a supported compatible fix becomes available before deployment. This is a local
repair proposal, not authorization to patch the VM or accept an exception.

### Proposed client contract

- The same verified HTTPS client must serve `_authenticate`, `_request`,
  `_authenticateInternalUser` and `_requestAsInternalUser`, including 401 refresh.
  No per-request fallback or silent trust-store fallback on errors.
- Read one bounded public Server certificate from a proposed root-controlled
  path, `/etc/wazuh-dashboard/certs/alertmind-server-api.pem`. Do not read the
  private key or grant Dashboard access to `/var/ossec` private directories.
  Require one PEM certificate, expected fingerprint and validity; trust-anchor
  suitability for the installed Node/OpenSSL is tested before adoption. If the
  current self-signed cert is unsuitable, stop for a separately approved cert
  plan rather than disabling verification or issuing a new cert implicitly.
- Enable standard certificate AND hostname verification. No permissive
  `checkServerIdentity`, global `NODE_TLS_REJECT_UNAUTHORIZED`, or unrelated
  Indexer CA. Missing/changed/expired trust fails closed. A public-cert copy and
  its parent path must not be writable by the Dashboard account or others.
- Require the approved host identity `https://localhost` with port 55000; preserve
  credentials, host ID and run_as. A later owner-local transformation must
  change only a reviewed URL if necessary and never print/rewrite secret values
  gratuitously. Extra configured hosts or unexpected URLs stop the rollout.
- Enforce the final request URL's exact origin after construction, not just
  the host configuration: reject userinfo, fragments, embedded authorities,
  alternate schemes/ports/hosts and malformed paths. Keep normal API queries.
  Use a narrow loopback IPv4 resolver for localhost while retaining localhost
  for TLS identity. Its callback behavior must match the actual Node version;
  do not substitute an IP URL and assume the DNS SAN matches.
- Disable ambient HTTP(S) proxies and redirects in this broker client. Test
  every redirect class and hostile proxy environment with synthetic credentials;
  neither Basic credentials nor bearer tokens may reach a second origin.
- Load trust once during client construction, not on every alert. Trust updates
  require an intentional restart; cached tokens/agents must not conceal a broken
  trust change. Sanitize errors without serializing axios request objects.

These are proposed changes, not assertions about the current application.
Existing source maps must not misrepresent patched byte positions: the future
package must rebuild them or explicitly remove the stale mapping reference.

### Ordered implementation packages, not owner commands

**Offline candidate.** Verify the .deb and exact original broker-client hash
`d691047acfa9b9a779a94251c6b813e0296eaf53b3b202e89cb56b44eee48afb`.
Identify and pin its packaged Node version and axios dependencies. Create an
offline builder accepting only that source and producing a candidate elsewhere,
never an in-place vendor edit. Ship the transformation, expected output hash,
synthetic test fixtures and a machine-readable manifest. Unknown source/version
or a second application of the transform must stop, not fuzzy-match.

**Actual-client tests.** Load the candidate ServerAPIClient with its real axios
and Node TLS stack in an isolated test environment, not a reimplementation in
Python. Stub only logger, host/context suppliers and cookies where necessary.
Use synthetic credentials/tokens; do not import live configuration. Cover both
scoped run-as branches, internal auth/cache/401-refresh, and ordinary requests.
The original must demonstrate the negative-control failure in the same fixture;
the candidate must reject wrong-hostname, untrusted/expired peers, missing or
bad trust and unexpected origins before any application credentials arrive.
Record only pass/fail, static error codes and server request counters. Prove the
fixture detects restoring false, removing the origin gate and enabling redirects
or proxy inheritance. TLS tests are not live RBAC acceptance.

**Operator package, held.** Only after offline review, prepare one combined
sanitized preflight and apply/rollback package. It should inspect live package,
Node/dependency identities, exact source, root-controlled trust placement,
canonical endpoint and existing service unit without exporting secrets. Capture
admin/saved-object baseline. Obtain owner approval for Dashboard downtime and
a fresh recoverable checkpoint; preserve Snapshot 1. No new Server role yet.

Stop the Dashboard before modifying the shared client: background internal
traffic is in scope too. Back up only exact touched files privately, preserving
metadata. Stage/verify candidates, then atomically replace them while stopped.
Use a dedicated systemd pre-start guard to verify the candidate hash, package
identity and public trust before every start. Do not edit vendor service units
or disable automatic security updates globally. Updates that remove the patch
must produce a visible stop and require review. An offline rollback test must
include interruptions between each state transition.

**Acceptance.** Restore the Dashboard only through the reviewed guard. Confirm
real internal registry/health traffic and fresh human context with sanitized
results, then admin continuity and both saved dashboards. Bad-host/untrusted
tests with real credentials are prohibited: those legs stay in the actual-client
synthetic fixture unless a separate safe live method is approved. Do not call
this a live negative-handshake proof. Four-service health is necessary but not
sufficient; prior RBAC/context/predicate and analyst gates still follow.

### Rollback and measurement

On candidate failure, stop the Dashboard, restore exact original files/metadata
and remove only new resources verified to belong to this package. Restoring
the original non-verifying client is **not** permission to restart it: leave
Dashboard stopped until the owner approves a time-bound exception or a corrected
candidate. Preserve manager/indexer/Filebeat and restricted SSH; no broad token
revocation or credential rotation is part of rollback. This availability cost
must be accepted before rollout, not discovered during recovery.

For offline comparison, use identical synthetic cold-auth/warm-read workloads
against original and candidate: latency distributions, peak RSS, socket counts,
timeouts and descriptor growth. Required correctness threshold: zero credential
arrivals on rejected peers/origins and no insecure retry. Any persistent resource
growth or unexpected timeout blocks rollout; numerical performance tolerances
must be agreed from the baseline before acceptance, not invented after a run.

## Next Decisions

Claude reviews this derived design first. The owner then selects local offline
candidate development, further vendor investigation, or an explicit exception.
There are **no new VM commands now** and no need to rerun the nine-file inventory.
The next coding deliverable, if selected, is the offline builder/test package;
live apply scripts come only after that package passes review.

Open implementation questions: exact packaged/runtime Node and axios versions;
current Server cert suitability; safe resolver API for that Node version;
root-controlled startup-guard/trust paths; narrowly scoped URL transformation;
and acceptable Dashboard downtime on update or rollback. Those are bounded
preconditions, not permission to expand reads or weaken checks.
