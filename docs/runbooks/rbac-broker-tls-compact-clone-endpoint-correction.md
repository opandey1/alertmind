# Compact clone — broker URL correction and inhibited preflight

**2 October 2026: preparation only; awaiting focused independent review.**
The owner approved preparing this helper, regression tests and rollback packet,
not executing the commands below. Obtain focused approval of the committed
helper/packet, then separate owner release for ONE clone-only run of E2–E4 and
the existing finite Block 4. No original-VM action is released.

Target: **Ubuntu SOC 201 - Current Isolated Clone** only. Reconfirm every clone
adapter disabled, no AlertMind app use, stable host/VM, console open, Snapshot 1
retained, no concurrent updates/configuration work, original VM untouched. Clone
selection/isolation are external owner checks, not facts the helper can attest.
Trust normal lab root/OS/systemd/shell/vendor Python/PyYAML and no concurrent
privileged writers; this is not hostile-root or whole-runtime attestation.

## Diagnosis and scope

The owner confirmed focused approval of source-reader commit `9dda08b`, merged
in PR #107 at `e5d6fb4`. Its R1/R2 build/staging passed. The corrected original
Block 3 then stopped with **CONFIG_ENDPOINT**, not a passing rehearsal. The
credential-safe diagnostic identifies the one relevant difference:

- The configured URL is exactly `https://127.0.0.1`.
- Port is integer 55000, username is `wazuh-wui`, password is a nonempty string,
  and `run_as` is boolean true. No password value was returned.
- The pinned public Server certificate has DNS SAN `localhost`; the approved
  client uses `https://localhost:55000` with fixed IPv4-loopback resolution.

Change only that URL scalar to `https://localhost`. Do not widen the origin/TLS
allowlist, alter certificates, change credentials or rewrite package permissions.
The [helper](../../siem/rbac/broker_tls/compact_clone_endpoint.py) preserves all
other YAML bytes, including quotes, comments, line endings and password text.
It resolves the named Dashboard identity and requires the existing 0600
UID/GID. Unknown ACLs/xattrs are refused, not silently discarded.

Before writing configuration, it validates the prospective strict contract,
loads persistent deny-start inhibition, stops Dashboard, saves root-private
before-state and a durable receipt, then atomically replaces/readbacks the URL.
It **never starts Dashboard**. Other three Wazuh services must remain active.
Backup and receipt are root:root 0400 beneath a 0700 directory; they contain
credentials or secret-derived hashes. Never print, upload or commit either.

The original operator, TLS candidate, five-file stage and active-service
preflight are unchanged. After E3, original Block 3 correctly refuses the
stopped service. E4 is the explicit **stopped/inhibited** preflight, not a fake
active result. It checks the pinned stage/packages/unit/client/certificate,
private endpoint receipt, exact corrected configuration and loaded inhibitor.

Prior `TOOL`, `PARENT_METADATA` and `CONFIG_ENDPOINT` failures remain separate
failed observations. No native installation/refusal/recovery acceptance exists.
P1-02 and subsequent original-VM/human RBAC work remain pending.

## Public packet binding

[Preparation record](../../siem/rbac/broker_tls/compact-clone-endpoint-preparation-2026-10-02.json).
The host-only [builder](../../siem/rbac/broker_tls/build_compact_clone_endpoint_packet.py)
compiles helper syntax only and refuses changed base sources/existing output.
The envelope records submission state, not reviewer approval or execution release.
Hashes bind bytes, not signatures. Existing stage/old stage backup stay untouched.

Packet: **14,326 bytes**, SHA-256
`8a5b7014ee8b462cb912955e5111a46f42e554d62582413402f5077d62681a71`.

| New public file | LF SHA-256 |
| --- | --- |
| compact_clone_endpoint.py | e790465fbe599c697cf0ede9d19c5fbd6a84c7f5b67576647275043b80f603eb |
| ENDPOINT-SHA256SUMS | 0b87e5b8fc0c52db446bdf13c63e75a16773960b056b39ee8af556b2493fba09 |

Run each whole block; after STOP/exception do not continue line by line or write
a PASS manually. No `set -x`, raw YAML, journal, credential or private hash output.
No more VM diagnosis is needed before this scoped packet receives review.

## E1 — workstation build only

No VM contact or helper execution. The existing five-file compact stage does
not need another R1/R2 refresh. This packet adds two public files separately.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    Set-Location 'C:\Users\ojasp\Desktop\project-alertmind\alertmind-main\alertmind'
    $Python = 'C:\Users\ojasp\AppData\Local\Temp\alertmind-pid1-ci-venv-20260928\Scripts\python.exe'
    $Packet = Join-Path $env:TEMP ('alertmind-compact-endpoint-packet-' + [guid]::NewGuid() + '.json')
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'STOP: CI interpreter absent' }
    & $Python -B siem/rbac/broker_tls/build_compact_clone_endpoint_packet.py --output $Packet
    if ($LASTEXITCODE -ne 0) { throw 'STOP: endpoint packet build failed' }
    $Expected = '8a5b7014ee8b462cb912955e5111a46f42e554d62582413402f5077d62681a71'
    if ((Get-Item -LiteralPath $Packet).Length -ne 14326 -or
        (Get-FileHash -LiteralPath $Packet -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw 'STOP: endpoint packet differs from reviewed bytes'
    }
    $Revision = (& git rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0) { throw 'STOP: source revision unavailable' }
    $Encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Packet))
    $Wrapped = [regex]::Matches($Encoded, '.{1,72}') | ForEach-Object { $_.Value }
    Set-Clipboard -Value (($Wrapped -join "`n") + "`nALERTMIND_PUBLIC_SOURCE_END")
    "PASS public endpoint packet: $Expected; source_revision=$Revision"
    "Packet retained at: $Packet"
    'STOP POINT: public build only; clone staging/execution not released'
}
```

## E2 — reviewed/released additive staging; syntax only

**DO NOT RUN before focused review and explicit owner execution release.**
The exact corrected five-file stage must already exist; no endpoint/private TLS
state or installation/inhibitor may exist. A partial new stage is a STOP, not
permission to delete or overwrite it. Nothing below reads the broker YAML.

```bash
(
set -euo pipefail
read -r -p 'Type REVIEWED-RELEASED-CLONE after review, release and all isolated-clone conditions: ' consent
[ "$consent" = REVIEWED-RELEASED-CLONE ] || { echo 'STOP: no clone release'; exit 1; }
sudo /var/ossec/framework/python/bin/python3 -I -B -c '
import base64, hashlib, json, os, pathlib, re, stat
expected = "8a5b7014ee8b462cb912955e5111a46f42e554d62582413402f5077d62681a71"
pins = {
    "compact_clone_endpoint.py": "e790465fbe599c697cf0ede9d19c5fbd6a84c7f5b67576647275043b80f603eb",
    "ENDPOINT-SHA256SUMS": "0b87e5b8fc0c52db446bdf13c63e75a16773960b056b39ee8af556b2493fba09"}
base_pins = {
    "candidate.cjs": "fe721feb8599293853e10d33823e68ff72df001be00382e3701d5da645aba28f",
    "compact_operator.py": "2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942",
    "bundle.json": "13cd780dfdffe16887a78f69aa4655f2be846485689015975b61981279615e83",
    "compact_clone_rehearsal.py": "b3f39e03dc32bd7d1de8f5a98b4f5a12dc201bc987ebcd6565c912be0da51340",
    "SHA256SUMS": "ae6442b20322ba975f57aa339c9fdc88dd0920c573320b4663832f9666c9fab1"}
def directory(path):
    item = path.lstat()
    assert stat.S_ISDIR(item.st_mode)
    assert (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o700)
def verify(path, table):
    directory(path)
    assert {p.name for p in path.iterdir()} == set(table)
    for name, digest in table.items():
        leaf = path / name
        item = leaf.lstat()
        assert stat.S_ISREG(item.st_mode) and item.st_nlink == 1
        assert (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o400)
        assert 0 < item.st_size <= 128 * 1024
        assert hashlib.sha256(leaf.read_bytes()).hexdigest() == digest
def sync(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
try:
    assert os.geteuid() == 0
    os.umask(0o077)
    base = pathlib.Path("/root/alertmind-broker-tls-compact")
    for parent in base.parents:
        item = parent.lstat()
        assert stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022
    directory(base)
    verify(base / "stage", base_pins)
    forbidden = [base / "state", base / "endpoint-state",
        pathlib.Path("/etc/alertmind/certs/alertmind-server-api.pem"),
        pathlib.Path("/usr/local/libexec/alertmind-broker-tls-compact.py"),
        pathlib.Path("/etc/systemd/system/wazuh-dashboard.service.d/00-alertmind-broker-maintenance.conf"),
        pathlib.Path("/etc/systemd/system/wazuh-dashboard.service.d/90-alertmind-broker-tls.conf")]
    assert not any(os.path.lexists(p) for p in forbidden)
    target = pathlib.Path("/root/alertmind-broker-endpoint-correction")
    assert not os.path.lexists(target)
    print("Paste wrapped PUBLIC Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:", flush=True)
    lines = []
    while True:
        line = input().strip()
        if line == "ALERTMIND_PUBLIC_SOURCE_END":
            break
        assert re.fullmatch(r"[A-Za-z0-9+/=]{1,72}", line)
        lines.append(line)
        assert len(lines) <= 300
    raw = base64.b64decode("".join(lines), validate=True)
    assert len(raw) == 14326 and hashlib.sha256(raw).hexdigest() == expected
    packet = json.loads(raw)
    assert set(packet) == {"schema", "scope", "base_commit", "revision", "review_status", "driver_sha256", "operator_sha256", "files"}
    assert type(packet["schema"]) is int and packet["schema"] == 1
    assert packet["scope"] == "isolated-clone-only; not execution release"
    assert packet["base_commit"] == "9dda08bf851e933077853be1aef21e0b95ac6135"
    assert packet["revision"] == "clone-only-url-v1" and packet["review_status"] == "awaiting-focused-review"
    assert packet["driver_sha256"] == base_pins["compact_clone_rehearsal.py"]
    assert packet["operator_sha256"] == base_pins["compact_operator.py"]
    assert type(packet["files"]) is list and len(packet["files"]) == 2
    values = {}
    for entry in packet["files"]:
        assert set(entry) == {"name", "sha256", "base64"}
        name = entry["name"]
        assert name in pins and name not in values and entry["sha256"] == pins[name]
        content = base64.b64decode(entry["base64"], validate=True)
        assert 0 < len(content) <= 128 * 1024 and b"\r" not in content and content.endswith(b"\n")
        assert hashlib.sha256(content).hexdigest() == pins[name]
        values[name] = content
    assert set(values) == set(pins)
    assert values["ENDPOINT-SHA256SUMS"] == (pins["compact_clone_endpoint.py"] + "  compact_clone_endpoint.py\n").encode("ascii")
    compile(values["compact_clone_endpoint.py"], "compact_clone_endpoint.py", "exec")
    target.mkdir(mode=0o700)
    sync(target.parent)
    for name, content in values.items():
        with (target / name).open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
    sync(target)
    verify(target, pins)
    verify(base / "stage", base_pins)
except Exception:
    raise SystemExit("STOP: endpoint staging failed; preserve existing/partial stages") from None
print("PASS additive endpoint stage: two exact root-private files; syntax only")
print("PASS original five-file compact stage unchanged")
print("NEXT: E3 only within the separately reviewed/released clone batch")
'
)
```

## E3 — private URL correction; Dashboard remains inhibited

This is the newly authorized mutation, not a read-only diagnostic. Do not use it
on the original VM or replay after an interruption. Within the ONE released
clone batch, run the whole block after E2 passes. The helper checks all relevant
compatibility inputs itself before inhibition/backup/configuration replacement.

```bash
(
set -euo pipefail
read -r -p 'Type CLONE-URL-CORRECTION to reconfirm the reviewed one-URL mutation and clone conditions: ' consent
[ "$consent" = CLONE-URL-CORRECTION ] || { echo 'STOP: correction not confirmed'; exit 1; }
sudo /bin/bash -c 'cd /root/alertmind-broker-endpoint-correction && sha256sum -c ENDPOINT-SHA256SUMS'
sudo /var/ossec/framework/python/bin/python3 -I -B \
  /root/alertmind-broker-endpoint-correction/compact_clone_endpoint.py apply
printf '%s\n' 'PASS clone-only URL correction; private backup retained; no Dashboard start'
)
```

## E4 — read-only inhibited preflight, then existing Block 4

After E3 passes in the same maintenance window, run E4. **Do not rerun original
Block 3:** its unchanged active-service check is no longer the right phase.

```bash
(
set -euo pipefail
sudo /bin/bash -c 'cd /root/alertmind-broker-endpoint-correction && sha256sum -c ENDPOINT-SHA256SUMS'
sudo /var/ossec/framework/python/bin/python3 -I -B \
  /root/alertmind-broker-endpoint-correction/compact_clone_endpoint.py preflight-inhibited
printf '%s\n' 'PASS compatibility preflight in the exact stopped/inhibited phase'
)
```

Only if E4 passes **and the owner release includes its interruption/refusal/
rollback scope**, proceed directly to [existing Block 4](rbac-broker-tls-compact-clone-rehearsal.md#block-4--single-finite-native-rehearsal).
E4 replaces its Block 3 prerequisite for this corrected attempt. The unchanged
operator `prepare` already accepts exact maintenance inhibition and binds the
corrected localhost configuration as its before-state. No extra independent
gate after every successful checkpoint in this ONE released batch. A real
failure still stops. Record failed historical runs separately in the
[worksheet](../../evidence/rbac/compact-broker-clone-proof-template.md); record
new helper/source/packet, review/release and actual output without filling
unrun rows with PASS. Review the finite rehearsal output before P1-02 closure.

## Scoped recovery — explicit direction only, never automatic replay

On any unexpected failure, preserve private state and static output. Do not
delete a stage/receipt, manually edit YAML, chmod/chown Wazuh files, remove the
inhibitor or restart the unverified Dashboard. If inhibition could not be
established, do not claim it succeeded; stop for console/state-specific diagnosis.

The following are recovery entry points, **not released routine next steps**.
Use only after the reviewer/owner selects the matching state. Reverify public
helper checksum using the same E3/E4 checksum command before either invocation.

```bash
# Before TLS prepare only; explicit completion of a known interrupted URL write.
sudo /var/ossec/framework/python/bin/python3 -I -B \
  /root/alertmind-broker-endpoint-correction/compact_clone_endpoint.py recover-apply
```

`recover-apply` requires an exact private receipt in backed-up/applied phase,
known backup, current configuration exactly original or corrected, unchanged
metadata/unit/client/certificate and no prepared TLS deployment. It reestablishes
inhibition, completes only the reviewed URL correction and leaves Dashboard
stopped. Unknown/partial receipt, ACL/permission drift or third-state YAML is a
STOP requiring specific direction, not an inferred recovery.

```bash
# Before TLS prepare only; exact private YAML restoration, NEVER a service start.
sudo /var/ossec/framework/python/bin/python3 -I -B \
  /root/alertmind-broker-endpoint-correction/compact_clone_endpoint.py restore
```

`restore` restores the entire exact original YAML backup and its original 0600
UID/GID; Dashboard remains inhibited. Its old IP URL deliberately fails the
approved endpoint contract: this is safe stopped rollback, not TLS readiness.
Private before-state is retained, not printed or removed.

**After compact TLS `prepare`, neither endpoint recovery entry is applicable.**
The helper refuses `TLS_ALREADY_PREPARED`. Use the existing compact operator's
reviewed pause/rollback/install/resume recovery. That private TLS receipt is
bound to the corrected localhost configuration: retain it. Compact TLS rollback
restores original client bytes while leaving Dashboard inhibited; it does not
restore the old URL or authorize starting the unverified original client.

No credential rotation, enrollment, SSH/reboot drill, extra OS-attestation gate
or permission rewrite is part of this correction. The helper is clone-only and
never installed as a production startup helper. Original-VM TLS deployment,
actual broker behavior and human read-only acceptance remain separately gated.
