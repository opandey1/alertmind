# Dashboard broker: installed-byte control-flow and TLS review

Date: 9 September 2026. Author: Codex. **Awaiting independent review.**

## Outcome and scope

The nine public files in the owner's successful VM inventory have exact size
and SHA-256 matches in the official Wazuh Dashboard 4.14.7-1 amd64 package.
Reviewing those matching bytes confirms an executable, unconditional
`rejectUnauthorized: false` HTTPS-agent construction. The same axios client
handles broker authentication and bearer-token requests. This is no longer
only a literal-text observation or an inference from upstream TypeScript.

**The broker TLS gate is not passed.** This is a static review of bytes matching
the owner-reported installed files, not observation of the running process,
an authenticated human Dashboard session, or a negative handshake test on that
process. No VM connection, credential entry, broker execution, role change,
TLS patch, exception or application implementation was performed or authorized.

## Evidence and reproducibility

The [machine-readable record](../../evidence/rbac/dashboard-broker-code-review-2026-09-09.json)
contains all nine paths, byte lengths and SHA-256 values, plus package provenance
and three explicitly separate package-only supporting files. The owner output
was transcribed from chat, not captured independently from the VM. All three
owner packet blocks completed; preserve the original ownership failure and
the successful `BROKER-CODE-OWNERFIX-2026-09-09.md` packet separately.

Source: [official 4.14.7-1 amd64 package](https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_4.14.7-1_amd64.deb).
Downloaded package: 193,952,104 bytes; SHA-256
`83f472d9e5f59b28b1abb6260c466e77b99ae427ce8c5f76203d847f2f598b6f`.

Reproduction procedure, entirely local after download:

1. Verify the complete package length and hash above. Read the ar archive's
   `data.tar.xz` member without installing the package.
2. Select only the listed regular files under
   `usr/share/wazuh-dashboard/plugins/`, permitting an archive-leading `./`.
   Bound each file to 512 KiB; do not extract arbitrary paths or execute JavaScript.
3. Hash raw member bytes, including the inline source-map line when present;
   compare both length and digest with every record. No newline normalization.
4. Read the JavaScript body with original one-based line numbering. The inline
   source map is not needed for the trace and was not interpreted or executed.

Author comparison: **9/9 sizes and hashes match** the owner report. The package
entries also have the observed service-owned 0640 file metadata. Download via
HTTPS and hash equality are not an APT-signature or supply-chain attestation;
no repository signature was checked. Matching nine files does not attest the
whole installation, its dependency versions, or files loaded into memory.
The service account can modify its code; the owner's equal two passes are not
an atomic snapshot. Later updates invalidate this version-bound observation.

## Static control-flow trace

Paths below are relative to `/usr/share/wazuh-dashboard/plugins/`. Labels refer
to the hash-bound entries in the JSON record. These are original one-based
packaged JavaScript line numbers, not upstream TypeScript line numbers.

| Step | Evidence and interpretation |
|---|---|
| Client setup | Matched `core_plugin`, lines 39 and 71–83: chooses Dashboard security, constructs `ManageHosts` and `ServerAPIClient`, and registers `wazuh_core.api.client.asCurrentUser` using the scoped client. |
| Security implementation | Matched `factory_selector`, lines 12–18: selects the OpenSearch security factory when the `securityDashboards` plugin object is present; otherwise a different factory is used. Manifest presence alone does not prove runtime selection. |
| Human context source | Matched `context_factory`, lines 17–37: calls `/_opendistro/_security/api/account` through `context.core.opensearch.client.asCurrentUser`; passes its body as `authContext` and extracts `user_name`. This is not a caller-invented context object. |
| Login entry | Matched `login_route`, lines 46–56, and `login_controller`, lines 35–83: `/api/login` calls scoped authentication, unless the controller returns an existing unexpired matching cookie token. The token can appear in cookies and the response body; do not capture either. |
| Scoped authentication | Matched `broker_client`, lines 145–164: asks `ManageHosts` whether run-as is enabled. If true, obtains the scoped security context and requests run-as authentication; if false, calls ordinary authentication. Both branches reach the same `_authenticate`. |
| Credential-bearing request | Matched `broker_client`, lines 105–124: obtains configured host username/password, sets axios `auth`, constructs `POST /security/user/authenticate` with optional `/run_as` and optional context body, then uses `this._axios`. |
| Shared TLS policy and ordinary requests | Matched `broker_client`, lines 38–43: constructs the non-verifying HTTPS agent and assigns it to `this._axios`. Lines 62–97 use that client for a host URL plus API path with a bearer token. Neither reviewed request builder supplies a replacement HTTPS agent. |

The following connective dependencies are outside the nine-file VM inventory.
They were read from the same package and are **package-only evidence**, not
installed-byte matches:

- `wazuh/server/plugin.js`, lines 39–49: bridges `context.wazuh.api` to
  `context.wazuh_core.api` and exposes the core security service. This explains
  the controller's `context.wazuh` name but does not attest that bridge on the VM.
- `wazuhCore/server/services/manage-hosts.js`, lines 149–181 and 259–280:
  derives a registry state from host `run_as` and an internal-user read of
  `/security/users/me`. Missing, unable-to-check, user-not-allowed and unknown
  states throw; explicitly disabled states return false, enabled returns true.
  Thus configuration `run_as=true` alone is not proof of the runtime branch.
- `wazuhCore/server/services/index.js`, lines 28–59, exports ManageHosts and
  ServerAPIClient. This supporting import trace is also package-only.

The central TLS finding does not depend on which run-as branch or name bridge
is selected: the matched client constructs the agent and uses it in both
authentication branches and ordinary requests. The complete installed
dependency chain and live human-context path remain unproven.

## TLS finding and limits

The false value occurs in the constructor's executable expression, not just a
comment or source map. Node documents that certificate verification is performed
when `rejectUnauthorized` is not false; HTTPS accepts this TLS option.
See [Node TLS options](https://nodejs.org/api/tls.html) and
[Node HTTPS options](https://nodejs.org/api/https.html). These references explain
the option, not the installed Node version or runtime behavior observed in this lab.

The code supplies configured broker credentials to authentication and a bearer
token to subsequent requests over a client that does not require verified peer
identity. Encryption is not proof of the intended peer. If an attacker can
impersonate the contacted endpoint, credentials/tokens or responses could be
exposed or substituted. No interception or exploitation was attempted.

Exposure is bounded by important counterevidence: the owner configuration
classified the Server endpoint as HTTPS loopback on port 55000. This is not an
Internet-reachable interception finding. Endpoint impersonation would need an
additional foothold or redirection opportunity; for example, a local process
able to take over an unoccupied non-privileged port. That prerequisite was not
tested. A compromise of the Dashboard service identity may already permit
credential access and code modification. No CVE, CVSS score or remote exploit
claim is made.

The earlier custom-client localhost certificate/hostname success and
wrong-hostname rejection remain valid for those clients only. They cannot be
inherited by this Node client. The observed Server certificate has DNS SAN
`localhost` and fingerprint
`5037899C0818F8332B09FC144BD7BD72A3B2CA033F46DAD56C67C284D611CE87`.
The sanitized configuration output did not retain whether the actual broker URL
used `localhost` or a loopback IP. Do not assume an IP will match that DNS SAN.
The Indexer certificate/CA and SSH tunnel are separate and are not changed here.

## Decision required before broker execution

**Recommended: prepare a scoped TLS-remediation design for review.** First
establish whether a supported vendor configuration/update exists; this review
found no TLS override in the matched request builders and does not invent a
`wazuh.yml` setting. If a version-bound code change is needed, review and own its
maintenance/rollback cost explicitly before applying it.

The design must remove the explicit verification bypass, use the Server's
appropriate trust anchor and a hostname matching its certificate, and cover
both authentication and ordinary requests. Merely adding a CA while leaving
`rejectUnauthorized: false` is not a fix. Do not substitute the unrelated Indexer
CA, disable TLS globally or weaken SSH. Review endpoint, proxy and redirect
behavior as part of that design rather than assuming a direct connection.

Before any live change, test the actual client path in an isolated fixture
using synthetic credentials: trusted peer succeeds, untrusted and wrong-hostname
peers fail before credential transmission. Then plan tightly scoped live
acceptance with exact version/hash preconditions and rollback. Never direct
real broker credentials to a deliberately untrusted server. A passing custom
curl/Python client is insufficient substitute evidence.

Alternative, **not approved**: an explicitly owner-approved, time/version-bound
loopback-only TLS exception. It must disclose missing broker peer verification,
record scope and expiry/revisit conditions, and prohibit promotion to a remote
endpoint or a verified-TLS claim. Neither the collector PASS nor this review
implicitly grants that exception.

After the independent review and owner decision, the existing remaining work
is actual Dashboard context/broker proof, predicate matching, fresh Indexer and
Dashboard/saved-object baselines, the broader Server-read scope decision, then
minimal grants/UI changes and analyst acceptance/safe denials. OIDC and the
constrained assistant reader/UI follow their own implementation gates. No fixed
number of successful VM outputs is promised: remediation and exceptions have
different acceptance requirements.

## Constraints for the next proof package

- Use a fresh isolated human session; login can return a cached token without
  any fresh broker authentication. `login_controller` lines 44–56 establish that
  shortcut. Preserve administrator continuity without reusing its cookies.
- Ordinary `/api/request` dispatch reaches the scoped client (controller line
  426), but the route accepts a method/path/body and is not intrinsically
  read-only. Review exact requests, not just a route label.
- `checkStoredAPI` / `checkAPI` invoke internal-user reads (controller lines
  107 and 251); these do not establish the analyst's effective Server context.
- Do not export JWTs, cookies, HAR files, credentials, raw authentication
  bodies or unrestricted account context; do not add sensitive live logging.
- Keep Server predicate/permission semantics distinct from Indexer DLS.
  No Server `assistant-svc` identity, credential rotation, transport replay or
  new VM mutation is authorized by this review.

No further VM export is needed for this static review. Additional installed
dependency or runtime verification, if required by the chosen next package,
must be narrowly scoped rather than repeating the completed nine-file inventory.

## Author verification

- Package length/hash and all twelve extracted file records rechecked against
  the JSON record: nine owner-report matches and three package-only records.
- Source line anchors reviewed locally; no installed JavaScript was executed.
- Existing 168-test suite passed on Python 3.12; frozen-evidence verifier exited
  0 with 27 PASS lines (26 checks plus the final summary). These are regression
  checks, not new tests proving the Dashboard TLS finding or live behavior.
- No application code, collector, approved packet, frozen corpus or model-run
  artifact changed. No vendor package/source copy is committed with this review.
