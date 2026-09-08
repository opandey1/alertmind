# Server authenticated inventory — review package

**NOT EXECUTABLE UNTIL REVIEWED.** This is the first credential-bearing Server
inventory package. Independent approval and a separate owner staging packet
must precede execution. No application runtime change, role edit, Server user
creation, Dashboard edit, service operation or additional tunnel is included.

## Reader correction — replacement review required

The owner ran the previously approved `510f049` package and reached `inventory`
before a generic STOP, without a diagnostic code or accepted summary. This means
authentication/token parsing completed, not that administrator permissions were
verified. The precise live exception and HTTP framing were not captured.

Offline tests reproduced a client defect: a final fixed-length `read1()` can
close the response file and release the socket, so the old loop's next
`peer.settimeout()` touches a closed descriptor. The corrected reader stops at
the declared length without another socket operation. It rejects premature EOF
even if the bytes already form valid JSON. Chunked messages are read through
the standard-library terminal-chunk handling; bodies without length/transfer
headers remain EOF-delimited (there is no independent length to verify).

The reader rejects ambiguous/unsupported transfer framing, invalid or duplicate
Content-Length values and bodies above the existing byte cap. Deadlines and
timeouts remain enforced between reads; this does not add a hard wall-clock
deadline for trickled headers/trailers. Response files are explicitly closed on
success, errors and the credential-free 401 probe. Existing TLS, authentication,
route and permission checks are unchanged.

New static failure codes include `HTTP_FRAMING`, `TRUNCATED_RESPONSE`,
`RESPONSE_TIMEOUT` and `RESPONSE_IO`. They never include remote values or raw
exception text. Other exception types retain the generic phase-only STOP.

**Do not replay the original execution packet or overwrite its staging files.**
Keep the earlier failure as evidence. This replacement helper/manifest needs
Claude's independent approval and a newly pinned transfer/run packet before
another owner execution. No password reset or additional login is needed to
review this correction offline.

## Purpose and completed prerequisites

The owner completed the local version-2 configuration inventory and paired
credential-free Server TLS probes on Wazuh 4.14.7-1. `run_as` is explicitly true
for one expected broker connection. The Dashboard UI readonly list is valid but
lacks `alertmind_socanalyst_ro`; multitenancy is explicitly false. These are
local settings, not effective permissions.

The Server public certificate carries **DNS:localhost**, not an IP SAN. The
client connects directly to `127.0.0.1:55000` while using **localhost** for SNI,
hostname verification and the HTTP Host header. Never substitute an IP URL or
reuse the Indexer CA. The reviewed public certificate DER SHA-256 is
`5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87`.
The reported positive curl probe verified TLS and returned unauthenticated 401;
the wrong-name probe returned an explicit SAN mismatch, exit 60, HTTP 000.
These reported observations are not proof of this Python client's behavior.

## Implemented collector and security boundary

[`collect_server_inventory.py`](../../siem/rbac/collect_server_inventory.py)
and its separate `SERVER-AUTH-SHA256SUMS` manifest are additive. The earlier
local-only helper and its manifest remain unchanged.

- Fixed VM-local IPv4 socket, no DNS/proxy/redirect/environment URL or CA
  override. TLS >=1.2, certificate verification and localhost hostname checking.
- A fresh TLS context loads only the fingerprint-checked public `server.crt`.
  `--cacert`-style trust is **not itself exact peer pinning**. This implementation
  additionally hashes the actual presented DER certificate on **every connection**
  and requires the recorded digest before any HTTP header or credential is sent.
  Certificate rotation fails closed; do not replace the constant without review.
- A credential-free positive probe requires 401. A negative handshake must fail
  with OpenSSL hostname-mismatch code 62; generic trust failure is insufficient.
  Both run with this client before credential prompts.
- Root at an interactive VM console only. No arguments, stdin pipelines, password
  environment variables, password files or command-line secrets. Prompts suppress
  echo and reject getpass fallback. Independently identify an existing **Server**
  administrator; the Indexer admin identity/password is not assumed equivalent.
- One `POST /security/user/authenticate`, then fixed GET routes. No retry after
  failed login, token refresh, run-as issuance, logout/global revocation, write
  probe or arbitrary URL. No fabricated run-as context.
- Credentials and token live in process memory only. References are released on
  exit; this is **not secure erasure** of Python strings. Do not run with tracing,
  debugger, terminal recording or core-dump collection. API authentication/access
  logs may record the request; token issuance is not a side-effect-free read.
- Up to 100 requests; 100 items/page; 1,000 items/collection; 1 MiB/response;
  10-second socket timeouts and a 120-second deadline checked between network
  operations (reset after human typing, not during collection). In-progress
  HTTP header parsing uses socket timeouts; this is not a hard wall-clock kill
  of a peer that continuously trickles header bytes. Bodies must be uncompressed JSON. Non-200,
  redirects, duplicate keys, partial failures, shape errors and oversize results
  stop without printing raw errors or a partial inventory. Failures report a
  static phase and, for `InventoryError` only, its predefined source-literal
  code (for example, `SERVICE_SERVER_IDENTITY` or `PEER_CERT_CHANGED`). Other
  exception types report only the phase, never their exception text. No response
  body, username, JWT or password is emitted. Return the sanitized STOP line for
  review; do not retry authentication or change permissions based on a code alone.

## Read set and interpretation

The endpoint allowlist is derived from the [v4.14.7 API specification](https://github.com/wazuh/wazuh/blob/v4.14.7/api/api/spec/spec.yaml)
and [controllers](https://github.com/wazuh/wazuh/blob/v4.14.7/api/api/controllers/security_controller.py).
The root version response uses the [actual controller](https://github.com/wazuh/wazuh/blob/v4.14.7/api/api/controllers/default_controller.py),
not the stale version example in the specification.

| Read | Required checks |
|---|---|
| `/` after authentication | `api_version` exactly 4.14.7 |
| `/security/users/me` | One matching entered Server identity, observed administrator-role membership |
| `/security/users/me/policies` | White mode and unrestricted security read grants for user/role/policy/rule IDs plus config read; no explicit deny in those action maps |
| `/security/config` | White/default-deny mode; never switch global mode |
| `/security/{users,roles,policies,rules}` | All pages sorted by ID; reject duplicates, nonmonotonic IDs, count drift, missing/partial pages and dangling/asymmetric relationships |

The named `administrator`, `readonly` and `wazuh-wui` entries must resolve uniquely;
no numeric ID is assumed. `assistant-svc` must be absent from Server users, and
the proposed rule name `alertmind_socanalyst_server_ro` must be unused. Absence
is **not an authentication-denial test**. The broker's `allow_run_as` flag must
be true; this is configured capability, not a successfully executed broker flow.

The readonly role's complete policy-name/action/resource/effect set must match
the [4.14.7 policy defaults](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/rbac/default/policies.yaml)
and [relationships](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/wazuh/rbac/default/relationships.yaml).
Repeated action values in upstream are normalized as sets. Extra actions,
missing policies, wildcard broadening and unexpected effects stop the collector.
This role is broader than Indexer agent-001/002 DLS: it includes manager/API
configuration reads. Its suitability still requires the explicit scope decision
in the parent runbook; a matching versioned role is not deployment approval.

All collections plus config/current identity/current processed policies are read
twice. Changes fail closed. Two equal observations are **not an atomic snapshot**;
changes between reads that later revert are not detectable. Keep administration
quiescent and revalidate before any later change. Token permissions may be fixed
at issuance; a reread of processed policies does not prove token refresh.

## Sanitized output and remaining work

The version-1 output includes numeric IDs/relationship edges, collection counts,
known role labels, allow_run_as flags, exact verified readonly policies, and
canonical definition digests. Other usernames/names, arbitrary policy resource
values, rule predicates, certificate bodies and API/configuration errors are
not printed. Unknown rule bodies get `unreviewed_predicate`, never a fabricated
"does not match socanalyst" verdict. Known default predicate structure is a
classification only; it is not an evaluation of real Dashboard context.

**This package implements the Server administrator inventory slice, not all of
the parent runbook's Section 3.** Its output always says `mutation_authorized=false`
and lists the remaining gates. Before preparing any role/mapping edit:

1. Independently establish the **actual** Dashboard-provided human context and
   real broker execution, using a separately reviewed session-aware observation.
   Do not copy the broker password or fabricate a username dictionary. Review
   every potentially matching rule, including unrecognized/custom predicates.
2. Recheck exact Indexer roles/mappings/DLS/scoped own_index through its separate
   verified TLS channel. This helper has no Indexer credentials or destination.
3. Capture administrator Dashboard continuity and required saved dashboards,
   without exporting cookies or raw alert bodies. This helper opens no browser
   or analyst session and cannot claim Dashboard baseline success.
4. Review the minimal change set, rollback and safe denial matrix before mutation.

Those remaining checks are intentionally reported rather than conflated with a
Server-admin token. No new owner commands are authorized by this draft.

## Post-approval execution plan (not a staging packet)

The author supplies exact public helper/manifest bytes only after approval.
Owner keeps apps stopped, console available, Snapshot 1 available, and verifies
service health and checksums. Preserve original failed local-inventory commands.
Use the fixed packaged interpreter with **privileged** file/executable checks:
notroot cannot traverse its root:wazuh 0750 parents. Do not install packages or
change group membership/permissions to bypass that boundary.

The eventual reviewed console invocation uses `sudo .../python3 -B` on the staged
helper, without a shell pipe or redirection; `ulimit -c 0` should apply to that
execution. Enter `REVIEWED` only after the approved commit and checksum match.
Use the verified existing Server administrator and stop on any failure. Keep the
output private until its sanitized contract is checked. No credentials are to be
pasted into agent chats. The helper clears its token reference but does not revoke
other sessions. Future authenticated clients must repeat their own TLS proof.

## Offline review

Run the full unittest suite and frozen verifier. Review socket/HTTP fakes for
pre-credential TLS/pin ordering, route allowlisting, bounded pagination and token
handling; graph fixtures for complete relations, readonly drift and failure
redaction. No live endpoint, secret or model is needed. These tests do not stand
in for the post-review owner execution or later analyst acceptance matrix.
The tests also generate disposable synthetic certificates using the OpenSSL CLI
(Ubuntu runner or Git for Windows) and exercise real TLS through MemoryBIO,
without listening sockets or network access. This adds no Python dependency;
synthetic private keys exist only in a temporary test directory and are removed.
Reader regressions use real `HTTPConnection`/`HTTPResponse` with synthetic byte
streams and a peer modelling socket/file reference lifetime: no network socket.
They cover fragmented fixed-length/chunked/EOF reads, premature EOF, malformed
framing, bounds, cleanup, safe failure codes and a full synthetic inventory.
This is not a real VM/TLS socket integration test or proof of the live failure.
