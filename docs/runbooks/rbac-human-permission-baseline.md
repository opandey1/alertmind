# Human RBAC — fresh permission baseline

**Status, 4 October 2026:** diagnostic revision received owner-confirmed focused
approval; the separately released Server-only diagnostic and then ONE complete
H3 from the existing serverdiag stage succeeded and were accepted as sanitized
owner-executed evidence. Earlier failed attempts and all stages remain retained;
their exact failure causes remain unknown. Do not rerun/restage completed H3.
Next is the separately reviewed/released
[Dashboard-scoped account/context and matching-rule observation](rbac-dashboard-context-observation.md),
not a Server mapping or UI change.
No VM execution, authentication or permission change is released by this file.
This advances P1-04 preparation; it does not close P1-04 or Phase 1.

The owner accepted the built-in Server `readonly` scope for this lab: broader
system/agent reads than Indexer agent-001/002 alert DLS, no management-write
grant, assistant still Indexer-only. This external decision is recorded in
HANDOFF and the exit checklist; the collector cannot attest owner consent.

Original-VM broker installation/start checks and warning-free Firefox lab-profile
L6 administrator reads, reauthentication and both saved-dashboard comparisons
were owner-reported PASS. Actual issued-token refresh/HTTP-401 retry was **NOT
TESTED**. The owner subsequently confirmed focused reviewer acceptance of the
retained synthetic retry tests plus trusted L6 reauthentication for that remaining
criterion. P1-03 is accepted on that scoped evidence combination, not a claim of
actual issued-token HTTP-401 execution or a supplied reviewer artifact. Do not
force expiry or replay the deployment/clone/rotation drills to manufacture it.

## Scoped identity-comparison correction

The original collector compared full `authinfo` JSON across fresh TCP connections.
OpenSearch documents `remote_address` as the client's IP and TCP port:
[Authentication Information API](https://docs.opensearch.org/latest/security/api/authentication/auth-info/).
A different source port alone reproduced `IDENTITY_DRIFT` offline. The original
generic STOP did not expose its error code, so this is a demonstrated collector
bug and plausible cause, **not proof of the original run's exact failure**.

The corrected collector accepts a well-formed IPv4 or bracketed IPv6 address and
source port, then removes only that port from the in-memory comparison snapshot.
It preserves the address host, presence of the field and every other authinfo
field. The entire account response remains compared. Exact username, backend
roles, effective role, tenant/requested-tenant, attributes and unknown-field drift
are not ignored; malformed connection metadata is refused. Raw responses are not
modified or exported. TLS pins, fresh connections, read routes, DLS/positive
controls, timeouts, generic secret-free failure output and Server reader are unchanged.

The owner-reported [failed attempt and later read-only diagnostics](../../evidence/rbac/human-baseline-diagnostic-2026-10-03.md)
show current authentication, identity and count checks passing; they are not a
complete H3 result or actual Dashboard context. No password reset, grant change
or further VM diagnostic is needed to prepare this correction. After independent
approval and **renewed explicit owner release**, use the new stage below for one
corrected H2-H3 batch; a failure ends that release. Do not run the old H3 aid.

## Diagnostic-only revision, 4 October

The standalone result narrows the current failure to the Server inventory after
authentication, not a rejected password; administrator scope is still unverified.
The [retained result](../../evidence/rbac/server-inventory-diagnostic-2026-10-04.md)
does not expose the exception type or exact failed read/validation. No response
shape correction, credential reset or permission change is justified yet.

The reader now reports only fixed operation checkpoints and fixed categories
(such as `JSON_DECODE`, `MISSING_FIELD`, `TIMEOUT`) for non-check failures. Local
check codes and operation labels are allowlisted; unknown values are redacted.
No exception text, field key, raw response, private URL or token is printed.
The combined runner separately labels Server authentication, Server inventory,
final Indexer checks, enrollment comparison and summary assembly. Diagnostics
fail closed; they do not return partial inventories or change reads/validation.

Reader byte pins and checksums are refreshed explicitly for this pending revision,
not auto-learned from the VM. The new stage below preserves BOTH older stages.
The [Server-only diagnostic runbook](rbac-server-inventory-diagnostics.md) and
separately released complete H3 are now completed historical execution paths.
The diagnostic revision's original submission/failed attempts below remain
documented for reproducibility, not as current replay instructions. Neither
those results nor the accepted complete H3 prove actual Dashboard context.

## Scope and one finite result

[`collect_human_baseline.py`](../../siem/rbac/collect_human_baseline.py) performs
only fixed Indexer GETs and the unchanged, separately pinned
[`collect_server_inventory.py`](../../siem/rbac/collect_server_inventory.py).
The Server reader issues one authentication POST followed by allowlisted GETs;
it never requests run-as authentication or changes resources.

The combined result checks exact existing roles, direct-user mappings, empty
backend/direct grants, scoped seven-user `own_index`, current action-group
expansion, both effective Indexer identities, positive reads for agents 001/002
and exclusion of agent 000 with an administrator positive control. The two
existing enrollment bindings are compared locally without displaying keys.
It refreshes the full paginated Server graph and validates the unique built-in
`readonly` role/policies using the existing reader. Grants/catalogs and identities
are reread; identity equality excludes only the validated source TCP port as
described above. Equality is an observation, **not an atomic or continuous snapshot**.

TLS is separate on both planes. Indexer: numeric loopback 9200, identity
127.0.0.1, existing explicit CA and recorded leaf pin. Server: numeric loopback
55000, identity localhost and its separate recorded public certificate/peer pin.
Correct-peer and specific wrong-hostname probes precede credentials. No proxy,
redirect, external DNS, insecure fallback, arbitrary route or retry is permitted.
The indexed queries return exact count metadata with size=0, never alert sources.

Indexer account GET uses the installed factory's exact legacy
`/_opendistro/_security/api/account` path. Its result is retained only in memory.
A **direct Indexer account check is not actual Dashboard-generated context**.
The [account API reference](https://docs.opensearch.org/latest/security/api/account/get-account-details/)
describes current-user fields; the legacy path is separately anchored in the
[version-matched installed-factory review](../reviews/dashboard-broker-control-flow-tls-2026-09-09.md).
The summary always says `actual_dashboard_context_observed: false`,
`matching_server_rules_reviewed: false`, `server_mapping_payload: null` and
`mutation_authorized: false`. It does not select a Server predicate or numeric ID.
Server summary predicates may remain opaque/unreviewed; do not promote them to
reviewed matches. No raw accounts, password hashes, YAML, JWTs, enrollment keys,
cookies, HARs or exception/HTTP bodies may be exported.

Use conventional trusted lab root administration and the packaged interpreter;
this is not release of the experimental attestation/maintenance guards. No
Python/Ubuntu re-attestation, new dependencies or runtime loader project is added.

## H1 — workstation build only

Run from the repository root using an existing workstation Python. This reads
public source, checks syntax without importing/executing the collector, normalizes
LF and creates a new eight-file public packet. It refuses an existing output.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Packet = Join-Path ([System.IO.Path]::GetTempPath()) ("alertmind-human-baseline-" + [guid]::NewGuid() + '.json')
    python -B siem/rbac/build_human_baseline_packet.py --output $Packet
    if ($LASTEXITCODE -ne 0) { throw 'STOP: public build failed; preserve output' }
    "Packet retained at: $Packet"
    'STOP POINT: build only; obtain focused packet approval and separate VM execution release'
}
```

Retain the packet and digest; the digest authenticates the exact reviewed packet,
not Ubuntu or a live process. After approval, copy only its wrapped public Base64
plus `ALERTMIND_PUBLIC_SOURCE_END`; never use the clipboard for credentials here.
The packet's submission label stays `awaiting-focused-review`; later approval
must be recorded separately, not manufactured by editing that label.

## H2 — public staging, held until review and owner release

Run only on the **original** wazuh-siem console. Requires retained Snapshot 1 and
recoverable current before-state, stable host/VM, stopped AlertMind apps and no
concurrent maintenance. Approval must cover this exact packet and run. This block
stages public files only; it neither imports the collector nor authenticates.
Never overwrite an existing stage, change groups or broaden the SSH tunnel.
The new `/root/alertmind-human-baseline-serverdiag` directory preserves both
`/root/alertmind-human-baseline` and `/root/alertmind-human-baseline-identityfix`
unchanged. If the new directory already
exists, stop; do not delete or overwrite it. The old release does not authorize
this refreshed packet or another run.

```bash
(
set -euo pipefail
sudo -v
sudo /var/ossec/framework/python/bin/python3 -I -B - <<'PY'
import base64, hashlib, json, os, re, stat
from pathlib import Path

def need(ok):
    if not ok:
        raise SystemExit('STOP: public baseline staging refused; preserve any stage')

root = Path('/root/alertmind-human-baseline-serverdiag')
names = ('collect_human_baseline.py', 'collect_server_inventory.py', 'scope-contract.json',
         'indexer-role_socanalyst_ro.json', 'indexer-role_assistant_alerts_ro.json',
         'indexer-role-mapping_socanalyst_ro.json', 'indexer-role-mapping_assistant_alerts_ro.json')
with open('/dev/tty', 'r', encoding='ascii') as tty:
    print('Type REVIEWED-RELEASED-BASELINE only after packet approval, run release and all original-VM conditions:', flush=True)
    need(tty.readline(80).strip() == 'REVIEWED-RELEASED-BASELINE')
    print('Enter the independently reviewed public packet SHA-256:', flush=True)
    digest = tty.readline(80).strip().lower()
    need(re.fullmatch('[0-9a-f]{64}', digest) is not None)
    print('Paste wrapped PUBLIC Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:', flush=True)
    lines, size = [], 0
    while True:
        line = tty.readline(4097)
        need(bool(line) and len(line) <= 4096)
        if line.strip() == 'ALERTMIND_PUBLIC_SOURCE_END':
            break
        size += len(line)
        need(size <= 360000)
        lines.append(line.strip())
raw = base64.b64decode(''.join(lines), validate=True)
need(len(raw) <= 262144 and hashlib.sha256(raw).hexdigest() == digest)
packet = json.loads(raw)
need(packet['schema'] == 1 and packet['review_status'] == 'awaiting-focused-review')
need(packet['scope'] == 'human-read-only-baseline; NOT Dashboard context or mutation release')
need(len(packet['files']) == 8 and {item['name'] for item in packet['files']} == set(names) | {'SHA256SUMS'})
files = {}
for item in packet['files']:
    data = base64.b64decode(item['base64'], validate=True)
    need(0 < len(data) <= 131072 and b'\r' not in data and data.endswith(b'\n'))
    need(hashlib.sha256(data).hexdigest() == item['sha256'])
    if item['name'].endswith('.py'):
        compile(data, item['name'], 'exec')
    elif item['name'].endswith('.json'):
        json.loads(data)
    files[item['name']] = data
need(files['SHA256SUMS'] == ''.join(hashlib.sha256(files[name]).hexdigest() + '  ' + name + '\n'
                                  for name in names).encode('ascii'))
need(hashlib.sha256(files['collect_server_inventory.py']).hexdigest() ==
     '5cccc906dbf4f5470f10814f37ccc4ca849e76c36d0b45c441da95357b911e77')
need(not os.path.lexists(root))
os.umask(0o077)
root.mkdir(mode=0o700)
for name, data in files.items():
    with (root / name).open('xb') as handle:
        handle.write(data)
    os.chmod(root / name, 0o400)
    info = (root / name).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
         and stat.S_IMODE(info.st_mode) == 0o400 and (root / name).read_bytes() == data)
info = root.lstat()
need(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
print('PASS root-private public baseline stage: eight exact files; syntax only; no collector execution')
print('PASS reviewed public packet SHA-256: ' + digest)
print('STOP POINT: staging only; credentialed baseline remains separately gated')
PY
)
```

## H3 — one credentialed read-only baseline, held until separate release

Requires accepted H2 and focused review/owner release for this original-VM run.
Stable console not recorded, apps stopped, snapshots/current before-state retained,
no concurrent work. This is authentication plus reads, **not** human activation.
Root source metadata/checksum, exact package versions and all four services are
checked before helper execution. No installation, service restart or live grant.
Run the entire block; stop on any failure. Do not retry a failed authentication
or replace a pin/deadline/role expectation to obtain PASS.

```bash
(
set -euo pipefail
sudo -v
sudo bash -s <<'SH'
set -euo pipefail
ulimit -c 0
cd /root/alertmind-human-baseline-serverdiag
test "$(stat -c '%u:%g:%a' .)" = '0:0:700'
test "$(find . -mindepth 1 -maxdepth 1 | wc -l)" -eq 8
for file in SHA256SUMS collect_human_baseline.py collect_server_inventory.py scope-contract.json \
  indexer-role_socanalyst_ro.json indexer-role_assistant_alerts_ro.json \
  indexer-role-mapping_socanalyst_ro.json indexer-role-mapping_assistant_alerts_ro.json; do
  test -f "$file" && test ! -L "$file"
  test "$(stat -c '%u:%g:%a' "$file")" = '0:0:400'
done
sha256sum -c SHA256SUMS
for package in wazuh-manager wazuh-indexer wazuh-dashboard; do
  test "$(dpkg-query -W -f='${Status}|${Version}' "$package")" = 'install ok installed|4.14.7-1'
done
for svc in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  test "$(systemctl is-active "$svc")" = active
  printf 'PASS service health: %s=active\n' "$svc"
done
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root \
  /var/ossec/framework/python/bin/python3 -I -B collect_human_baseline.py </dev/tty
SH
)
```

At hidden prompts enter the existing **Indexer admin**, **socanalyst Indexer**,
current rotated **assistant-svc Indexer**, then separately the existing **Server
administrator username/password**. Do not enter SSH passphrases, old service
credentials or the broker password. Secrets are memory-only, references released
on exit; this is not guaranteed memory erasure. JWT issuance is disclosed, one
attempt, no token file. Network phases have 120s deadlines/10s socket caps and
bounded requests/1MiB responses; typing time is outside the relevant network phase.

Return only the complete sanitized summary and PASS/STOP lines. Missing/partial
counts, unexpected roles/actions, changed enrollments, duplicate/opaque Server
inventory ambiguity, TLS failure or incomplete pages stop acceptance. Private
data remains private even on failure. Retain failed attempts separately.

## Next: actual context and exact mapping package

After accepted baseline, with the scoped P1-03 decision recorded, observe the actual
fresh `socanalyst` Dashboard broker context and processed Server policy without
exporting sessions/tokens or adding sensitive logging. The installed current-user
factory/account path is a code anchor, not runtime proof. Review **every** existing
matching Server predicate/linked role; unknown predicates remain blockers.

Only then bind the unique live `readonly` name to its current ID and prepare
`alertmind_socanalyst_server_ro`, preserving other mappings. Independently review
the exact predicate, narrow read-only UI role-list addition, private backups,
compare-before-edit recovery and safe backend-denial probes before owner-approved
activation. No copied wildcard/example, guessed `username`/`user_name`, direct
Server user, assistant Server grant or permanent numeric ID is supplied here.
