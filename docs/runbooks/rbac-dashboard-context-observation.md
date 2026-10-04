# Actual socanalyst Dashboard account/context and matching-rule observation

**Status, 4 October 2026: preparation only; awaiting focused independent review.**
No VM run, browser login, permission change or UI edit is released by this file.
The complete owner-executed H3 baseline is accepted; do not rerun it or restage
its files. P1-03 is accepted on the scoped synthetic-retry/trusted-L6 combination;
actual issued-token HTTP-401 retry remains NOT TESTED. Broader built-in Server
`readonly` lab scope is already owner-accepted. P1-04/05/06 remain open.

This is one finite observation batch on the **original wazuh-siem**, not the
clone, and not another runtime-attestation project. It uses the existing trusted
Firefox lab profile and unchanged Server inventory reader. No new dependency,
broker logging/instrumentation, service restart, direct run-as impersonation,
Indexer grant, Server mapping payload or read-only UI change is included.

## What this observation proves, and what it does not

The browser script makes **two GETs only** to
`https://127.0.0.1/api/v1/configuration/account` in a fresh `socanalyst` session.
This existing Dashboard route uses `asScoped(request).callAsCurrentUser` to read
the signed-in account. Unlike H3's direct Indexer read, it traverses Dashboard's
authenticated scoped client. The installed Wazuh factory obtains its context
from the corresponding Indexer account endpoint, not `authinfo`; the field is
`user_name`, not an invented `username` browser parameter.

The [version-matched source review](../reviews/dashboard-context-observation-2026-10-04.md)
records the exact route, backend prefix, account shape and recursive-rule semantics.
The VM collector checks the four unchanged public derivation files against the
reviewed vendor bytes before and after observation. It does **not** compare the
remediated broker client against its old insecure vendor hash. Service-owned
code is still mutable; byte checks are neither loaded-code proof nor an atomic
snapshot. Conventional trusted lab root/runtime administration and no concurrent
maintenance are external assumptions, not another Linux/ELF attestation gate.

This is **owner-attested Dashboard-scoped account evidence plus a reviewed
factory-context equivalence argument**. It is not a wire capture of the exact
`run_as` body, an issued human Server token or a human effective Server-policy
read. Those remain false in the output. The challenge binds a submitted summary
to this waiting batch; it does not authenticate its origin cryptographically.
Do not promote this method to stronger broker-execution claims. Focused review
must explicitly accept the equivalence/owner-attestation boundary before using
the result to prepare a mapping. Backend human policy acceptance follows the
later exact mapping package, not a fabricated admin-token impersonation.

The VM reader issues one Server-admin authentication, then only its existing
allowlisted GETs. Complete current catalogs are observed before/after the browser
step, with each reused collection retaining its own two-pass checks. The unique
`readonly` role/policies are resolved by name/current relationships, not pinned
to historical numeric role ID 2. This supported pre-mapping state has exactly
the two reviewed administrator `FIND` predicates. Added, missing, changed,
ambiguous or unknown rules stop **before** the browser challenge. Both predicates
are evaluated, including literal matches in nested dictionaries/lists; any match
stops rather than silently accepting inherited administrator grants. Reserved
predicate behavior requires the observed `wazuh-wui` Server broker ID 2 in this
version; this is distinct from the dynamically resolved readonly role.

Only public booleans, fixed labels, rule/role IDs and fingerprints leave the
processes. No raw account, tenant names, custom attributes, password/hash,
authorization header, broker credential, cookie, JWT, HAR, network response,
console exception text or enrollment key may be exported. Tokens stay in the
Server process; normal Firefox sessions stay in the dedicated lab profile.
Reference cleanup is not guaranteed secret-memory erasure.

## C1 — workstation public build, no execution

From the repository root, using an existing workstation Python:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Packet = Join-Path ([System.IO.Path]::GetTempPath()) ("alertmind-dashboard-context-" + [guid]::NewGuid() + '.json')
    python -B siem/rbac/build_dashboard_context_packet.py --output $Packet
    if ($LASTEXITCODE -ne 0) { throw 'STOP: public build failed; preserve output' }
    "Packet retained at: $Packet"
    'STOP POINT: public build only; obtain exact-packet review and separate original-VM/browser execution release'
}
```

After focused approval, copy only this packet's wrapped PUBLIC Base64 and end
marker `ALERTMIND_PUBLIC_SOURCE_END`, using the already reviewed public-transfer
workflow. Copy the exact reviewed JavaScript file separately as **public source**
for C4; never share the clipboard with a credential record during this batch.
The `awaiting-focused-review` submission label stays unchanged after approval;
approval and the one-run release must be separately recorded.

## C2 — new public stage, held until review/release

Requires Snapshot 1 and recoverable current before-state retained, stable host/VM
and private unrecorded original console, stopped AlertMind apps, no concurrent
updates/configuration or other Dashboard session, and owner release covering
staging plus C3–C5 and one fresh browser login. Preserve all older stages/results.
If the new stage exists, stop; never overwrite it to replay a failed batch.

```bash
(
set -euo pipefail
sudo -v
sudo /var/ossec/framework/python/bin/python3 -I -B - <<'PY'
import base64, hashlib, json, os, re, stat
from pathlib import Path
def need(ok):
    if not ok:
        raise SystemExit('STOP: public context staging refused; preserve any stage')
root = Path('/root/alertmind-dashboard-context')
names = ('observe_dashboard_context.py', 'collect_server_inventory.py', 'dashboard_context_observation.js')
need(input('Type REVIEWED-RELEASED-CONTEXT after exact packet review and original-VM/browser run release: ') == 'REVIEWED-RELEASED-CONTEXT')
expected = input('Enter the independently reviewed PUBLIC packet SHA-256: ').strip()
need(re.fullmatch('[0-9a-f]{64}', expected))
print('Paste wrapped PUBLIC Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:')
parts = []
for _ in range(8192):
    line = input().strip()
    if line == 'ALERTMIND_PUBLIC_SOURCE_END':
        break
    parts.append(line)
    need(sum(map(len, parts)) <= 350000)
else:
    need(False)
raw = base64.b64decode(''.join(parts), validate=True)
need(0 < len(raw) <= 262144 and hashlib.sha256(raw).hexdigest() == expected)
packet = json.loads(raw)
need(packet['schema'] == 1 and packet['scope'] == 'dashboard-context-observation; NOT permission/UI mutation'
     and packet['review_status'] == 'awaiting-focused-review')
need(len(packet['files']) == 4 and {i['name'] for i in packet['files']} == set(names) | {'SHA256SUMS'})
files = {}
for item in packet['files']:
    data = base64.b64decode(item['base64'], validate=True)
    need(0 < len(data) <= 131072 and b'\r' not in data and data.endswith(b'\n'))
    need(hashlib.sha256(data).hexdigest() == item['sha256'])
    if item['name'].endswith('.py'):
        compile(data, item['name'], 'exec')
    files[item['name']] = data
need(files['SHA256SUMS'] == ''.join(hashlib.sha256(files[n]).hexdigest() + '  ' + n + '\n' for n in names).encode('ascii'))
need(hashlib.sha256(files['collect_server_inventory.py']).hexdigest() == '5cccc906dbf4f5470f10814f37ccc4ca849e76c36d0b45c441da95357b911e77')
need(not os.path.lexists(root))
os.umask(0o077)
root.mkdir(mode=0o700)
for name, data in files.items():
    with (root / name).open('xb') as stream:
        stream.write(data)
    os.chmod(root / name, 0o400)
    info = (root / name).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
         and stat.S_IMODE(info.st_mode) == 0o400 and (root / name).read_bytes() == data)
print('PASS public context stage: four exact root-private files; Python syntax only; no helper or browser execution')
print('PASS public packet SHA-256: ' + expected)
print('STOP POINT: stage only; C3-C5 remain subject to the separate release')
PY
)
```

## C3 — waiting Server observer, held until separate release

Only after accepted C2 and release for this exact packet/batch. Run the entire
block from the original VM terminal. No password is a command argument. Do not
pipe or redirect output, use shell tracing or record the console. Keep this
terminal open when it prints the public challenge. Do not run the old H3.

```bash
(
set -euo pipefail
sudo -v
for package in wazuh-dashboard wazuh-manager wazuh-indexer; do
    test "$(dpkg-query -W -f='${Status}|${Version}' "$package")" = 'install ok installed|4.14.7-1' || exit 1
done
for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
    test "$(systemctl is-active "$unit")" = active || exit 1
    printf 'PASS service health: %s=active\n' "$unit"
done
sudo bash -c 'cd /root/alertmind-dashboard-context && sha256sum -c SHA256SUMS'
sudo /var/ossec/framework/python/bin/python3 -I -B /root/alertmind-dashboard-context/observe_dashboard_context.py
)
```

The helper refuses non-root/non-interactive input, unexpected stage files,
metadata/manifest/reader drift, unsupported source bytes and unreviewed rules.
It verifies separate pinned Server TLS and a specific hostname rejection before
hidden Server administrator credentials. It performs one authentication only.
Browser login uses `socanalyst` **Indexer** credentials, not these Server-admin
credentials, an assistant password or an SSH passphrase.

## C4 — fresh trusted browser session and two account reads

Only while C3 is waiting, in the owner-approved Firefox lab profile **inside
the original Ubuntu VM**:

1. Close other Dashboard tabs; normally log out any previous administrator.
   At `https://127.0.0.1/app/login`, verify the warning-free origin/recorded
   Dashboard leaf. No certificate exception or warning bypass. Log in once as
   `socanalyst` with its existing Indexer password. Do not change the Firefox
   default profile, OS trust, roles or saved dashboards. If login fails, stop.
2. The Wazuh application may lack Server access before mapping. Do not add a
   role to clear that error or use its direct broker administrator checks as
   human proof. The account observation is through the authenticated security
   route, not a Wazuh token response. Any account-route refusal below stops.
3. Open Firefox Web Console, clear its displayed old entries, and paste the
   **complete reviewed public** `siem/rbac/dashboard_context_observation.js`
   source once, not an altered snippet. If browser protections block pasting,
   stop; do not disable them. Do not enable persistent network capture or open,
   copy or export cookies, storage, login responses, token values or a HAR.
4. At the script's prompt, enter only C3's public 64-hex challenge. The script
   checks the HTTPS origin, exact nine-field account shape, exact SOC role,
   empty backend/custom attributes and equality across both account responses.
   It exports a single sanitized JSON line or a static STOP, never the body.
5. Copy only that JSON line. A rejected origin, identity/grant/shape drift,
   non-200, invalid response, timeout or oversize is **not** PASS. Do not rerun
   the script or continue with a hand-edited JSON line after a STOP.

No browser-controlled context body is submitted to Server authentication. No
forced Wazuh token expiry/retry or manual `/api/login`, `/api/request`, security
edit, active response or saved-object write is part of C4.

## C5 — complete the same waiting observer, then stop

In the waiting terminal attest `FRESH-TRUSTED-SOC` only if C4 was executed in
that fresh warning-free profile exactly as reviewed, and paste only its JSON
line. The observer rereads the entire Server catalog and public source pins;
any mismatch, unexpected rule match or invalid submission ends the batch. It
prints a final summary only after all checks, with matching-rule review required,
mapping null and mutation false. Server token references are then released.
The ordinary browser session remains in the lab profile; log out normally.

Return only the final sanitized summary and PASS/STOP lines in the
[blank worksheet](../../evidence/rbac/dashboard-context-observation-template.md).
Do not claim post-run continuous service health from C3's pre-run checks. A
failure/interrupt consumes this one-run release: retain its output/stage and
seek scoped diagnosis; no automatic retry, password reset or permission repair.

Next: focused review of the actual scoped account evidence and all matching
rules. Only then prepare the exact Server mapping/read-only UI/private recovery
and safe-denial package, with another explicit owner maintenance release. This
observation cannot close P1-04/05/06 or authorize activation by itself.
