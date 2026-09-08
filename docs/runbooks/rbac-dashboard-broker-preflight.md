# Dashboard context and broker preflight

**Status: local code-inventory package, awaiting independent review.** No live
authentication, browser session, permission edit or service change is authorized
by this package. Do not issue a run-as token or enter broker credentials yet.
No assistant runtime change is included. This is a prerequisite to the actual
Dashboard-context/broker proof, not completion of that proof.

The original package and diagnostic follow-up were approved and merged in
PRs #26/#27. The owner's execution then stopped with UNTRUSTED_FILE_METADATA.
Metadata-only inspection showed root:root ancestors through /usr/share, but
wazuh-dashboard:wazuh-dashboard ownership from /usr/share/wazuh-dashboard
downward (directories 0750, files 0640, no displayed symlinks). The collector's
root-only assumption was incompatible with that observation; this is not by
itself evidence of compromise. Do not change VM ownership or permissions.
This ownership correction needs independent review and a NEW hash-pinned
staging packet. Preserve the failed packet/stage; do not replay or overwrite it.

## 1. Accepted prerequisite and new safety finding

On 8 September 2026 the owner appended complete outputs to the outside-Git
`SERVER-AUTH-READERFIX-2026-09-08.md` worksheet. All three blocks completed,
including the collector's success STOP. Review of the sanitized JSON found:

- Server administrator read scope verified; two observations equal (not atomic).
- 2 users, 7 roles, 35 policies and 2 mapping rules, with reciprocal relationships.
- Role 2 is `readonly`; its 13 policy definitions and canonical digests match
  the approved collector's Wazuh 4.14.7 contract.
- The expected broker has configured `allow_run_as=true`; this does not prove
  that the Dashboard used it. Server `assistant-svc` and the proposed mapping
  name are absent. `readonly` has no linked users or rules in this observation.
- The Python collector verified the pinned Server certificate and hostname.
  The original failed packet remains unchanged; the corrected success does not
  establish the precise exception/framing in the earlier attempt.

These are owner-reported results, not independently observed live requests.
No rerun of that completed packet is requested.

The next source review found an important distinction: **the versioned Dashboard
Server API client constructs its HTTPS agent with `rejectUnauthorized: false`.**
That agent is assigned to the axios instance used by both ordinary requests and
authentication, including the credential-bearing
`POST /security/user/authenticate[/run_as]` with configured broker Basic auth.
The separate Python/curl proofs therefore cannot establish certificate
verification by the actual Dashboard broker. Loopback reduces the exposure but
does not turn an unverified connection into verified TLS. Do not claim otherwise
or silently waive the gate. Determine the installed behavior before designing
the broker execution test or any scoped remediation.

## 2. Version-pinned source trace, not installed-runtime proof

Reference: [Wazuh Dashboard plugins v4.14.7](https://github.com/wazuh/wazuh-dashboard-plugins/tree/7659dead50782307faa1c0a313b1fd29d0b2c014),
resolved commit `7659dead50782307faa1c0a313b1fd29d0b2c014`.

| Source at that commit | Reviewed relationship |
|---|---|
| [OpenSearch context factory](https://github.com/wazuh/wazuh-dashboard-plugins/blob/7659dead50782307faa1c0a313b1fd29d0b2c014/plugins/wazuh-core/server/services/security-factory/factories/opensearch-dashboards-security-factory.ts) | Reads `/_opendistro/_security/api/account` using `asCurrentUser`, returns the response as `authContext`, extracts `user_name` |
| [Factory selection](https://github.com/wazuh/wazuh-dashboard-plugins/blob/7659dead50782307faa1c0a313b1fd29d0b2c014/plugins/wazuh-core/server/services/security-factory/security-factory.ts) | Selects the OpenSearch implementation when `securityDashboards` is available; the fallback must not be assumed equivalent |
| [Scoped broker client](https://github.com/wazuh/wazuh-dashboard-plugins/blob/7659dead50782307faa1c0a313b1fd29d0b2c014/plugins/wazuh-core/server/services/server-api-client.ts) | Passes the factory context to `/security/user/authenticate/run_as` when enabled; uses configured broker Basic auth; constructs the non-verifying HTTPS agent |
| [Login controller](https://github.com/wazuh/wazuh-dashboard-plugins/blob/7659dead50782307faa1c0a313b1fd29d0b2c014/plugins/main/server/controllers/wazuh-api.ts) | Calls scoped authentication; may reuse a cached token; puts the token into cookies and a response body |
| [Browser routes](https://github.com/wazuh/wazuh-dashboard-plugins/blob/7659dead50782307faa1c0a313b1fd29d0b2c014/plugins/main/server/routes/wazuh-api.ts) | Defines `/api/login` and `/api/request`; the latter is not a generally safe read-only endpoint merely because a caller intends to read |

Use these sources to prepare the next design, not to fabricate an analyst
context JSON. `authinfo`, `account`, a broker's direct administrator token and
an actual Dashboard human session are not interchangeable. The two observed
default Server rules (`username=elastic` and `user_name=admin`) still need
matching-semantics review against the real analyst context before new mappings.
Do not infer matching semantics from predicate names or digest equality.

Selected upstream TypeScript SHA-256 values for reproducibility (not expected
hashes of transpiled installed JavaScript):

| Source | SHA-256 |
|---|---|
| Context factory | `d05b23c5a835896eb193d3ebda6339211e87b4abb0a5308ce7cb8147e18f98f5` |
| Factory selector | `b0e17aa915ba64163c71e762fdf1fe0fb1d9805fa0f4cba8e7c7bbf7e9b81c50` |
| Broker client | `1ea855c841372911a20758c84c6a609149d3509d91cef0ac5c63ccb4e8ce69e4` |
| Login controller | `a802ca6949bec9e6d9337dec83d41f3c6904bd60fdf450c8afbd002d87423665` |
| Browser routes | `c2787cc9443f3dfcec26071b38b38a7e84e58e1a02eb6649b0482ef1e45ac9e5` |

## 3. Implemented local-only collector

[`collect_broker_code_inventory.py`](../../siem/rbac/collect_broker_code_inventory.py)
reads exactly nine fixed public files under `/usr/share/wazuh-dashboard/plugins`:
three plugin manifests and six installed server-side JavaScript files. It never
imports or executes those JavaScript files. It never reads `wazuh.yml`, password
archives, certificates/private keys, application data, logs or browser storage.
It has no HTTP, credential prompts, subprocesses, file writes or custom path option.

- Root/Linux/no arguments; exactly the nine allowlisted targets, no sibling or
  traversal paths. Ancestors above /usr/share/wazuh-dashboard require root:root.
  Within that exact directory boundary allow root:root or the named
  wazuh-dashboard:wazuh-dashboard UID/GID pair, never arbitrary non-root owners
  or mixed pairs. Resolve the OS account/group, require nonzero IDs and a matching
  primary group, and recheck the same identity after both passes.
- All components remain non-symlinks and not group/world writable; directories
  and regular-file targets are type checked. No permission repair is performed.
- Each open is anchored to the preceding checked directory descriptor, with
  O_NOFOLLOW on every component (not just the final file). Compare pre-open,
  descriptor and post-read path metadata; close all handles even on failure.
  These checks reduce path-replacement risk but do not make a service-writable
  tree immutable or the observation atomic.
- Descriptor/path checks, no-follow/nonblocking open, 512 KiB/file and 3 MiB/pass
  limits, strict UTF-8, duplicate-manifest-key and nonfinite-number rejection.
- Requires `wazuh` and `wazuhCore` manifests at `4.14.7-01`, server enabled and
  the expected dependency names. Reports only the numeric security-plugin
  version; its manifest's presence does not prove that plugin is running.
- Reads the entire fixed set twice; any changed bytes stop without a partial
  inventory. Equality is not an atomic snapshot or proof that the running
  process loaded those files. Keep updates/configuration work quiescent.
- Emits known labels/relative paths, lengths, SHA-256 values, bounded version
  strings and literal indicators, never source snippets or raw error text.
- Inventory version 2 includes ownership-policy limits and resolved service
  UID/GID. Service-owned code is mutable by the service account. The allowlist
  is an observation policy, NOT package authenticity or integrity attestation;
  package_authenticity_proven and atomic_snapshot_proven are always false.
  A compromised service account can change code while preserving allowed modes.

The deployment layout is a hypothesis based on plugin IDs and server build
paths. If a file is absent, inaccessible, symlinked, unusually large or the
version differs, **stop and review metadata**. Do not broaden paths, search
private data, recursively dump code, change permissions or copy arbitrary files
into the expected paths to manufacture a pass. An installation using bundles
needs a separately reviewed adaptation.

Literal matches can occur in comments or unused code. They are discovery aids,
**not an AST/control-flow proof**. `explicit_false_text_present` requires review
of the installed client. `unresolved` means no recognized false literal; it
does not mean TLS verification is enabled. Even a true literal and all context
indicators present leave `effective_verification_proven=false`,
`broker_execution_authorized=false`, `mutation_authorized=false` and
`review_required=true`. A successful inventory exit is not an authorization pass.

## 4. Owner execution contract — after independent approval only

Expected failures now have distinct static codes, without file contents, paths
or exception text. They still stop execution with no partial inventory:

| Code | Meaning |
|---|---|
| `PUBLIC_FILE_MISSING` | A fixed file or parent was not found during the read |
| `PUBLIC_FILE_ACCESS_DENIED` | An operating-system permission check denied access |
| `PUBLIC_FILE_IS_DIRECTORY` | A filesystem operation raised an is-directory error |
| `SOURCE_ENCODING` | NUL or invalid UTF-8, consistently at all decoding entry points |
| `SERVICE_IDENTITY_UNAVAILABLE` | Named Dashboard account or group lookup was missing |
| `SERVICE_IDENTITY_INVALID` | Named account/group, nonzero IDs or primary group did not match |
| `SERVICE_IDENTITY_CHANGED` | Resolved service UID/GID differed after the observations |
| `FIXED_PATH_REQUIRED` | Requested target was outside the exact nine-file allowlist |
| `DIRECTORY_CHANGED` | Ancestor path/descriptor metadata differed during a read |

A directory rejected earlier by the regular-file metadata guard still reports
`UNTRUSTED_FILE_METADATA`. Other unexpected exceptions retain the generic STOP;
these codes are error classifications, not diagnoses of the underlying cause.
Do not relax permissions or change paths in response to a code without review.

The author will then issue a separate, dated, hash-pinned public staging packet.
Do not reuse or overwrite any prior Server collector stage. The packet must:

1. Require Snapshot 1 available, a stable VM console, apps stopped and no package
   update/configuration work in progress. No reboot or transport change.
2. Stage only this helper and `BROKER-CODE-SHA256SUMS` in a new owner-private
   directory, exact two-file set, directory 0700/files 0600, LF and digest checks.
   An existing stage must be verified, never overwritten to clear an error.
3. Verify four healthy Wazuh services and package versions 4.14.7-1. Check
   packaged Python access **as root**, then Python 3.10 syntax only. Check
   helper ownership, bytes and modes again immediately before execution.
4. Invoke the helper once via packaged Python `-I -B` at the VM console. It is
   standalone/stdlib-only, so isolated mode must not need sibling imports.
5. Return only sanitized JSON plus PASS/STOP lines. On error return the static
   STOP, not raw installed sources or a traceback; do not retry or mutate state.

No credential entry is needed. This runbook intentionally does not issue an
executable broker authentication or mutation block before the TLS decision.

## 5. Subsequent gated packages

After installed-code review, explicitly decide whether to remediate the broker
TLS path through a supportable, version-bound change or approve a documented
loopback-only exception. Neither option is authorized here. Any exception must
retain the fact that Dashboard broker TLS is not verified; it cannot inherit
the separate collector's TLS PASS. A remediation needs rollback and positive /
wrong-hostname tests on the actual broker path, not just another custom client.

Then prepare the actual Dashboard context/broker package: fresh isolated human
session, verified identity, no cached admin token substitution, exact readonly
requests and sanitized processed-current-policy output. No broker passwords,
JWTs, cookies, HAR exports, request-header captures or raw authentication bodies
may leave the browser/VM or enter the assistant. Do not add logging of credentials
or authorization contexts to the live plugin as a shortcut.

Still required before grants/acceptance: predicate semantics, fresh exact
Indexer roles/mappings/DLS and scoped `own_index`, administrator Dashboard
continuity and the two saved dashboards, explicit broader-Server-read scope
decision, minimal mapping/UI changes with rollback, and analyst acceptance /
safe denials. The broader `readonly` role includes manager/API configuration
reads; Indexer agent-001/002 DLS does not constrain it. Do not start OIDC/live
alert reader/UI integration by treating this code inventory as a closed gate.

Preserve the accepted transport/service-credential drill and all failed packets.
No drill replay, secret rotation, global token revocation or Server assistant
identity is part of this work.
