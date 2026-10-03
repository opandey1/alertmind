# Original VM — compact broker TLS maintenance and acceptance

**3 October 2026: offline preparation; awaiting focused independent review.**
No original-VM execution is released by this document. Review this package and
the reused candidate/operator/endpoint functions, then obtain explicit owner
release for the selected maintenance sequence, including Dashboard downtime and
secure restart. The [accepted clone rehearsal](../../evidence/rbac/compact-broker-clone-proof-2026-10-03.md)
is prerequisite evidence, not permission to apply clone commands to the original.

This implements Batch C's TLS deployment mechanics, not human Server grants,
OIDC or Phase 1 closure. P1-03–06 remain pending. Use the
[blank live worksheet](../../evidence/rbac/compact-broker-live-proof-template.md)
to distinguish deployment checks from real broker behavior.

## Scope and preconditions

Owner must positively select the **original wazuh-siem VM**, not the isolated
clone. Its name/identity cannot be attested by this helper. Retain Snapshot 1
and a recoverable current-original before-state; do not restore the old snapshot
over accepted RBAC/transport changes as a shortcut. Console open, host/VM stable,
all AlertMind apps stopped, no concurrent package/configuration work, no other
Dashboard instance. Confirm the current original package versions before release;
unsupported versions stop, with no automatic pin refresh or security-update freeze.

Trusted boundary: normal lab root, OS/kernel/systemd, shell/package tools and
supported vendor Python/PyYAML/Node dependencies. No hostile-root/runtime
attestation or new PID 1/ELF gate. No passwords, tokens, cookies, raw YAML,
private receipts/backups/hashes, HAR or unredacted journals may be returned.

The [facade](../../siem/rbac/broker_tls/compact_live_deployment.py) loads exact
root-private pinned operator/endpoint modules. It calls endpoint **functions**
through a new fixed interface, never that module's clone CLI or clone driver.
The clone driver/fault actions are absent from this packet. Historical sources
and pins are unchanged. Original endpoint private state is separate:
`/root/alertmind-broker-tls-compact/live-endpoint-state/`.

Only an exact `https://127.0.0.1` URL scalar may become `https://localhost`.
All other YAML bytes/credentials, 0600 UID/GID, comments/quotes/line endings are
preserved. Unknown ACL/xattrs refuse replacement. Already-compatible localhost
requires no config write or endpoint backup. Neither the facade nor endpoint
functions issue HTTP requests. Starting Dashboard does ordinary vendor traffic.

The unchanged [compact operator](rbac-broker-tls-compact-deployment.md) installs
the pinned client/public Server certificate and mandatory startup check. It
alone is the installed helper; the facade/endpoint modules stay in root-private
recovery staging. No Indexer/Server identity, role, mapping, SSH/enrollment,
saved object, password or Server configuration is changed.

## Public packet (integrity, not signature or release)

[Builder](../../siem/rbac/broker_tls/build_compact_live_packet.py),
[verification record](../../siem/rbac/broker_tls/compact-live-preparation-2026-10-03.json).
Six files, 68,159 bytes; SHA-256
`e3d0814b88252acad01944047ca922e08f163e8b51c9a97f79aede1fd9dc4cbc`.

| File | LF SHA-256 |
| --- | --- |
| candidate.cjs | fe721feb8599293853e10d33823e68ff72df001be00382e3701d5da645aba28f |
| compact_operator.py | 2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942 |
| bundle.json | 13cd780dfdffe16887a78f69aa4655f2be846485689015975b61981279615e83 |
| compact_clone_endpoint.py | e790465fbe599c697cf0ede9d19c5fbd6a84c7f5b67576647275043b80f603eb |
| compact_live_deployment.py | 13073bf64a6e5a59dc9237927218ff54c5df463cffda1d89f1ba0520071f869b |
| SHA256SUMS | 06b83ce7239174fafa2cf388416921c90371c67531d9dc5197c8a85e824ff2fc |

Envelope's `awaiting-focused-review` label is immutable submission provenance,
not a claim that a later recorded approval is absent. Retain the reviewed exact
packet and Git source revision. Never overwrite prior/partial staging or replace
old clone packets. A changed packet requires review, not editing expected hashes.

## L1 — workstation-only public build

No VM access/helper execution. A verified corrected compact bundle must exist.
This command uses the retained workstation bundle; if absent, rebuild via the
existing verified candidate/bundle builders into NEW directories, not guessed files.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    Set-Location 'C:\Users\ojasp\Desktop\project-alertmind\alertmind-main\alertmind'
    $Python = 'C:\Users\ojasp\AppData\Local\Temp\alertmind-pid1-ci-venv-20260928\Scripts\python.exe'
    $Bundle = 'C:\Users\ojasp\AppData\Local\Temp\alertmind-compact-source-cert-bundle-20261001-r1'
    $Packet = Join-Path $env:TEMP ('alertmind-compact-live-packet-' + [guid]::NewGuid() + '.json')
    & $Python -B siem/rbac/broker_tls/build_compact_live_packet.py --bundle $Bundle --output $Packet
    if ($LASTEXITCODE -ne 0) { throw 'STOP: public live packet build failed' }
    $Expected = 'e3d0814b88252acad01944047ca922e08f163e8b51c9a97f79aede1fd9dc4cbc'
    if ((Get-Item -LiteralPath $Packet).Length -ne 68159 -or
        (Get-FileHash -LiteralPath $Packet -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw 'STOP: public packet differs from reviewed bytes'
    }
    $Revision = (& git rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0) { throw 'STOP: source revision unavailable' }
    $Encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Packet))
    $Wrapped = [regex]::Matches($Encoded, '.{1,72}') | ForEach-Object { $_.Value }
    Set-Clipboard -Value (($Wrapped -join "`n") + "`nALERTMIND_PUBLIC_SOURCE_END")
    "PASS public original-VM packet: $Expected; source_revision=$Revision"
    "Packet retained at: $Packet"
    'STOP POINT: build only; VM staging/execution not released'
}
```

## L2 — original-VM public staging, syntax only

**DO NOT RUN before review and owner original-VM release.** Initial BASE must be
absent. Existing/partial state is a STOP, not authority to clean or overwrite it.
Paste only L1's public clipboard, not passwords. Run whole blocks, never continue
line by line after an exception. No `set -x`.

```bash
(
set -euo pipefail
read -r -p 'Type REVIEWED-RELEASED-ORIGINAL after review, original-VM selection and all maintenance conditions: ' consent
[ "$consent" = REVIEWED-RELEASED-ORIGINAL ] || { echo 'STOP: no original-VM release'; exit 1; }
sudo /var/ossec/framework/python/bin/python3 -I -B -c '
import base64, hashlib, json, os, pathlib, re, stat
expected = "e3d0814b88252acad01944047ca922e08f163e8b51c9a97f79aede1fd9dc4cbc"
pins = {
    "candidate.cjs": "fe721feb8599293853e10d33823e68ff72df001be00382e3701d5da645aba28f",
    "compact_operator.py": "2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942",
    "bundle.json": "13cd780dfdffe16887a78f69aa4655f2be846485689015975b61981279615e83",
    "compact_clone_endpoint.py": "e790465fbe599c697cf0ede9d19c5fbd6a84c7f5b67576647275043b80f603eb",
    "compact_live_deployment.py": "13073bf64a6e5a59dc9237927218ff54c5df463cffda1d89f1ba0520071f869b",
    "SHA256SUMS": "06b83ce7239174fafa2cf388416921c90371c67531d9dc5197c8a85e824ff2fc"}
try:
    assert os.geteuid() == 0 and os.getegid() == 0
    os.umask(0o077)
    base = pathlib.Path("/root/alertmind-broker-tls-compact")
    for parent in base.parents:
        item = parent.lstat()
        assert stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022
    assert not os.path.lexists(base)
    print("Paste wrapped PUBLIC Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:", flush=True)
    lines = []
    while True:
        line = input().strip()
        if line == "ALERTMIND_PUBLIC_SOURCE_END":
            break
        assert re.fullmatch(r"[A-Za-z0-9+/=]{1,72}", line)
        lines.append(line)
        assert len(lines) <= 5000
    raw = base64.b64decode("".join(lines), validate=True)
    assert len(raw) == 68159 and hashlib.sha256(raw).hexdigest() == expected
    packet = json.loads(raw)
    assert set(packet) == {"schema", "scope", "base_commit", "revision", "review_status", "files"}
    assert type(packet["schema"]) is int and packet["schema"] == 1
    assert packet["scope"] == "original-vm-maintenance; not execution release"
    assert packet["base_commit"] == "87d69a1d39ea728726bae599eee57682a78e10a2"
    assert packet["revision"] == "live-facade-v1" and packet["review_status"] == "awaiting-focused-review"
    assert type(packet["files"]) is list and len(packet["files"]) == 6
    values = {}
    for entry in packet["files"]:
        assert set(entry) == {"name", "sha256", "base64"}
        name = entry["name"]
        assert name in pins and name not in values and entry["sha256"] == pins[name]
        content = base64.b64decode(entry["base64"], validate=True)
        assert 0 < len(content) <= 128 * 1024 and b"\r" not in content and content.endswith(b"\n")
        assert hashlib.sha256(content).hexdigest() == pins[name]
        if name.endswith(".py"):
            compile(content, name, "exec")
        values[name] = content
    assert set(values) == set(pins)
    sums = "".join(pins[name] + "  " + name + "\n" for name in pins if name != "SHA256SUMS")
    assert values["SHA256SUMS"] == sums.encode("ascii")
    def sync(path):
        fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    base.mkdir(mode=0o700)
    sync(base.parent)
    target = base / "stage"
    target.mkdir(mode=0o700)
    sync(base)
    for name, content in values.items():
        path = target / name
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fchown(stream.fileno(), 0, 0)
            os.fsync(stream.fileno())
    sync(target)
    assert {p.name for p in target.iterdir()} == set(pins)
    for path in (base, target):
        item = path.lstat()
        assert stat.S_ISDIR(item.st_mode) and (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o700)
    for name, digest in pins.items():
        path = target / name
        item = path.lstat()
        assert stat.S_ISREG(item.st_mode) and item.st_nlink == 1
        assert (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o400)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
except Exception:
    raise SystemExit("STOP: original public stage failed; preserve partial state; no retry") from None
print("PASS original root-private public stage: exact six files; syntax only")
print("STOP POINT: stage only; no helper or live preflight executed")
'
)
```

## L3 — read-only current-original preflight

Within separate reviewed/released scope only. Return static output before any
original mutation. It checks current packages, three peer services, original
client, public certificate, unit/wiring and config metadata/endpoint prospectively.
No fresh RBAC grant or broker authentication occurs. A compatible endpoint
result is not actual TLS acceptance.

```bash
(
set -euo pipefail
sudo /bin/bash --noprofile --norc -c '
set -euo pipefail
cd /root/alertmind-broker-tls-compact/stage
printf "%s\n" "06b83ce7239174fafa2cf388416921c90371c67531d9dc5197c8a85e824ff2fc  SHA256SUMS" | /usr/bin/sha256sum -c -
/usr/bin/sha256sum -c SHA256SUMS
exec /var/ossec/framework/python/bin/python3 -I -B compact_live_deployment.py preflight
'
)
```

Only `needs-endpoint-correction` or `endpoint-compatible` is an initial passing
classification. `ready-inhibited` indicates existing applied recovery state,
not a fresh install; stop to reconcile history/release. Any failure stops the
batch. Do not restart services, edit metadata, broaden TLS, restage or replay
mutations to make preflight pass.

## L4 — explicitly released URL choice, prepare and install; remains stopped

Run only after accepted L3 and release covering the selected path. The typed
choice must match L3, not a guessed URL. One finite successful batch can continue
through L5 without a new approval at every PASS if the owner release includes
secure restart. All unexpected failures stop it. Do not use clone E3/E4/Block 4.

```bash
(
set -euo pipefail
read -r -p 'Type RELEASED-ORIGINAL-INSTALL only after accepted L3, downtime approval and release: ' consent
[ "$consent" = RELEASED-ORIGINAL-INSTALL ] || { echo 'STOP: no install release'; exit 1; }
read -r -p 'Enter accepted L3 classification (needs-endpoint-correction or endpoint-compatible): ' endpoint
case "$endpoint" in needs-endpoint-correction|endpoint-compatible) ;; *) echo 'STOP: unknown checkpoint'; exit 1 ;; esac
sudo /bin/bash --noprofile --norc -c '
set -euo pipefail
cd /root/alertmind-broker-tls-compact/stage
printf "%s\n" "06b83ce7239174fafa2cf388416921c90371c67531d9dc5197c8a85e824ff2fc  SHA256SUMS" | /usr/bin/sha256sum -c -
/usr/bin/sha256sum -c SHA256SUMS
live() { /var/ossec/framework/python/bin/python3 -I -B compact_live_deployment.py "$1"; }
if [ "$1" = needs-endpoint-correction ]; then
    live correct-endpoint
    live preflight-inhibited
fi
live prepare
live install
echo "PASS original install checkpoint: secure candidate installed; Dashboard stopped/inhibited"
echo "STOP POINT: continue only with the separately released secure restart"
' original-install "$endpoint"
)
```

## L5 — released secure restart and deployment checks

This is not credentialed broker acceptance. It does not run missing-trust or
interruption fault injection on the original. Ordinary startup failure attempts
re-inhibition. Unknown state stays stopped for explicit diagnosis/recovery.

```bash
(
set -euo pipefail
read -r -p 'Type RELEASED-SECURE-RESTART only within the approved original maintenance batch: ' consent
[ "$consent" = RELEASED-SECURE-RESTART ] || { echo 'STOP: no restart release'; exit 1; }
sudo /bin/bash --noprofile --norc -c '
set -euo pipefail
cd /root/alertmind-broker-tls-compact/stage
printf "%s\n" "06b83ce7239174fafa2cf388416921c90371c67531d9dc5197c8a85e824ff2fc  SHA256SUMS" | /usr/bin/sha256sum -c -
/usr/bin/sha256sum -c SHA256SUMS
/var/ossec/framework/python/bin/python3 -I -B compact_live_deployment.py resume
/var/ossec/framework/python/bin/python3 -I -B compact_live_deployment.py check
for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
    [ "$(/usr/bin/systemctl is-active "$unit")" = active ]
    printf "PASS original service health: %s=active\n" "$unit"
done
echo "STOP POINT: deployment checks only; actual broker and continuity acceptance pending"
'
)
```

## L6 — actual broker and continuity acceptance plan (not execution release)

Review this plan and authorize real credentialed testing only AFTER accepted L5.
Browser access to the Dashboard must itself use an accepted trusted origin;
do not bypass certificate warnings. Keep real credentials only in the normal
trusted login UI. No intentionally bad peer receives them.

- Preserve the two expected saved-dashboard identities in an owner-private
  before-state record; fresh bounded Indexer/admin/saved-object baseline remains
  part of the next acceptance package. Do not open the insecure pre-patch broker
  merely to manufacture a baseline. This helper does not mutate saved objects.
- Fresh existing administrator Dashboard login, actual Wazuh application Server
  overview/read, and normal navigation/read after browser refresh. Record static
  outcome and observed latency/errors only, no HAR, tokens/context or raw responses.
  A normal browser refresh is not proof of the broker's HTTP-401 token retry.
- Explicit fresh logout/login and repeated read proves real re-authentication.
  Actual issued-session refresh/401 behavior remains a separate unrun row until
  observed safely or focused review accepts synthetic retry coverage plus live
  re-authentication for this release. Never shorten TTL, revoke all tokens, edit
  the broker password or corrupt a real session to force it.
- Open both expected saved dashboards without saving/editing. Check administrator
  continuity and existing expected panels/data. Record only counts/static outcomes;
  no alert values, user data or saved-object exports in Git.
- Synthetic wrong-host/untrusted/expired-peer, zero-credential-arrival and actual
  client 401/forceRefresh tests run on the WORKSTATION with synthetic credentials.
  The retained 17-group fixture uses packaged axios but a workstation Node and
  adapted metadata. Never run it on the VM: it reserves TCP 55000, the real API port.
  Curl TLS proof/startup guard or an admin session is not actual analyst context.
- Only after P1-03 acceptance: refresh relevant Indexer/DLS/mapping baselines,
  observe actual `socanalyst` broker context/predicate, decide broader Server
  readonly scope, then reviewed human mapping/UI and safe backend tests (P1-04/05).
  No human mapping, credential rotation or Server action is released here.

Unrun rows remain NOT TESTED. Focused review must resolve which actual refresh/
scoped-read evidence is sufficient; this package does not claim P1-03 complete.

## Recovery — fixed actions, separately selected after diagnosis

Use the staged facade and the same public hash check as L3, with ONE explicitly
authorized action replacing `preflight`. No automatic recovery loop/force flag.

| Observed phase | Reviewed recovery direction |
| --- | --- |
| Untouched preflight failure | No mutation/retry; diagnose the concrete failure |
| Endpoint `backed-up`/`applied`, TLS not prepared | `recover-endpoint` reapplies only known corrected bytes, or `restore-endpoint` restores exact private YAML; both remain inhibited and never start |
| Endpoint partial state without valid receipt | Stop/private diagnosis, no overwrite/delete/automatic repair |
| TLS inhibition/backup before receipt | Facade preflight intentionally refuses an existing TLS backup. After private diagnosis/explicit recovery release, run the pinned staged `compact_operator.py prepare` directly (same public hash checks), using its unchanged compatible-original/identical-backup recovery. Do not replay URL correction or facade's fresh preparation. The new receipt pins the corrected whole configuration. |
| TLS prepared/partial or interrupted secure restart | `install` re-inhibits/stops before verification/editing; accepted checkpoint then separately released `resume`/`check` |
| Secure installation but maintenance/acceptance failure | `pause` inhibits/stops; not blocked by unrelated peer-health or endpoint-source checks |
| TLS rollback required | `rollback` re-inhibits/stops BEFORE state reads; restores original client, removes only matching trust/helper/guard, NEVER restarts; private state retained |
| After TLS prepare/rollback | Endpoint restore refused: TLS receipt fingerprints corrected config. Do not remove state or restore YAML independently. Secure `install` then released `resume`/`check` restores service; original URL/fully original teardown needs separate reviewed reconciliation |

Private endpoint YAML includes credentials; never return it or its hashes.
Preserve temporary files/receipts/snapshot for diagnosis. If the trusted entry or
systemctl itself fails, console recovery is required; no successful-inhibition
claim from an error alone. No original-VM fault drill, insecure restart or Phase 1
closure is authorized. P1-06 still requires accepted scoped recovery/evidence review.
