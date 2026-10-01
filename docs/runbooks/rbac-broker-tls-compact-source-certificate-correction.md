# Compact clone — scoped source-certificate correction

**1 October 2026: offline correction prepared; awaiting focused review.**
No VM execution or stage replacement is released by this document. The owner
authorized implementation, not a retry of the failed native rehearsal. Obtain
focused approval of this correction/packet and renewed owner authorization for
ONE corrected attempt on **Ubuntu SOC 201 - Current Isolated Clone**. Confirm
all clone adapters disabled, no app use, stable host/console, Snapshot 1 retained,
no concurrent updates/configuration work and original VM untouched.

## What changed, and what did not

The owner-reported preflight recheck failed `PARENT_METADATA`. Its public API
certificate is `wazuh:wazuh` 0400, beneath root:wazuh 0770 configuration/ssl
directories. The generic root-only reader rejected that concrete layout.
The earlier `TOOL` failure remains unexplained; it is not relabelled a PASS.

Only `LinuxHost.read_source_certificate()` accepts this **fixed source path**:

| Path | Owner/group | Mode |
| --- | --- | --- |
| `/`, `/var` | root:root | 0755 |
| `/var/ossec`, `/var/ossec/api` | root:wazuh | 0750 |
| `/var/ossec/api/configuration`, its `ssl` directory | root:wazuh | 0770 |
| `/var/ossec/api/configuration/ssl/server.crt` | wazuh:wazuh | 0400 |

The named `wazuh` user/group are resolved, not assigned a guessed numeric UID.
Unknown identities/layouts, symlinks, multiple links, changed metadata, oversized
files or a different DER certificate pin fail closed. The leaf is read through
the existing bounded, no-follow, before/held/after identity checks; ancestor
identity is checked before/after too. This trusts the normal lab administration
boundary, not hostile-root containment or an atomic filesystem snapshot.

No chmod/chown of Wazuh paths. Generic readers, installed root-controlled trust,
helper/private-state/unit checks and TLS candidate are unchanged. Prepare,
install and clone preflight use the source-only accessor. Startup still reads
only the strict **installed** trust copy. The finite fault/recovery sequence is
unchanged; it has not passed natively yet.

## Corrected public packet

See the [offline correction record](../../siem/rbac/broker_tls/compact-source-cert-correction-2026-10-01.json).
Schema 2 records the approved **base** commit and an unapproved correction
revision separately. `review_status` records the submission state; later review
does not rewrite the packet. Hashes bind bytes, not independent approval.

Packet: **58,726 bytes**, SHA-256
`20d1ec0813bdf782708d7c44721820f8a3dee1c7bf976994f2465d8780e69a7c`.
Keep the old `f36ac4e7…0bc68` packet, failed output and old stage intact. Do not
rerun old Block 2, which correctly refuses an existing stage. Do not manually
erase or edit the stage. The procedure below replaces only reviewed public
staging files and retains the exact old stage under a new backup name.

## Block R1 — workstation build only

Run the whole block; no VM connection or helper execution. If the retained
candidate is absent, stop for a host rebuild, not an update to the clone.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    Set-Location 'C:\Users\ojasp\Desktop\project-alertmind\alertmind-main\alertmind'
    $Python = 'C:\Users\ojasp\AppData\Local\Temp\alertmind-pid1-ci-venv-20260928\Scripts\python.exe'
    $Candidate = 'C:\Users\ojasp\AppData\Local\Temp\alertmind-compact-candidate-20261001'
    $Bundle = Join-Path $env:TEMP ('alertmind-compact-source-cert-bundle-' + [guid]::NewGuid())
    $Packet = Join-Path $env:TEMP ('alertmind-compact-source-cert-packet-' + [guid]::NewGuid() + '.json')
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'STOP: CI interpreter absent' }
    & $Python -B siem/rbac/broker_tls/build_compact_bundle.py --candidate $Candidate --output $Bundle
    if ($LASTEXITCODE -ne 0) { throw 'STOP: corrected bundle build failed' }
    & $Python -B siem/rbac/broker_tls/build_compact_clone_packet.py --bundle $Bundle --output $Packet
    if ($LASTEXITCODE -ne 0) { throw 'STOP: corrected packet build failed' }
    $Expected = '20d1ec0813bdf782708d7c44721820f8a3dee1c7bf976994f2465d8780e69a7c'
    if ((Get-Item -LiteralPath $Packet).Length -ne 58726 -or
        (Get-FileHash -LiteralPath $Packet -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw 'STOP: corrected packet differs from reviewed bytes'
    }
    $Revision = (& git rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0) { throw 'STOP: source revision unavailable' }
    $Encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Packet))
    $Wrapped = [regex]::Matches($Encoded, '.{1,72}') | ForEach-Object { $_.Value }
    Set-Clipboard -Value (($Wrapped -join "`n") + "`nALERTMIND_PUBLIC_SOURCE_END")
    "PASS corrected public packet: $Expected; source_revision=$Revision"
    "Packet retained at: $Packet"
    'STOP POINT: public build only; no clone refresh or rehearsal released'
}
```

## Block R2 — reviewed/released clone stage refresh; syntax only

**DO NOT RUN before focused review and renewed owner release.** No operator is
executed here. The base must contain only the exact original stage: no receipt,
installation or partial refresh. New installed trust/helper/guard/inhibition
must be absent. Any other state is a STOP for specific recovery direction.

```bash
(
set -euo pipefail
read -r -p 'Type REVIEWED-RELEASED-CLONE only after approval of the correction and renewed clone release: ' consent
[ "$consent" = REVIEWED-RELEASED-CLONE ] || { echo 'STOP: no corrected clone release'; exit 1; }
sudo /var/ossec/framework/python/bin/python3 -I -B -c '
import base64, hashlib, json, os, pathlib, re, stat
expected = "20d1ec0813bdf782708d7c44721820f8a3dee1c7bf976994f2465d8780e69a7c"
old = {
    "candidate.cjs": "fe721feb8599293853e10d33823e68ff72df001be00382e3701d5da645aba28f",
    "compact_operator.py": "e9a35d66d1e8e501fbee406215d4d54da3553acededffab91064b0e0b896b05c",
    "bundle.json": "da3ced89b2e33528632e10d38b1a899fbe4119cf2cad3902b4c642d31e46cea4",
    "compact_clone_rehearsal.py": "ef9459ecf51b32dfea3ac063fa8684898d266d176f834b0a18d0b8aed425399d",
    "SHA256SUMS": "9ad02f92d10d34261ed57329b847797e698b2f00d4decad6e99c11c5b1dc64dd"}
def directory(path):
    item = path.lstat()
    assert stat.S_ISDIR(item.st_mode)
    assert (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o700)
def verify(path, pins):
    directory(path)
    assert {p.name for p in path.iterdir()} == set(pins)
    for name, digest in pins.items():
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
    for ancestor in base.parents:
        item = ancestor.lstat()
        assert stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022
    directory(base)
    assert {p.name for p in base.iterdir()} == {"stage"}
    stage = base / "stage"
    backup = base / "stage-before-source-cert-reader-v2"
    incoming = base / ".stage-source-cert-reader-v2"
    verify(stage, old)
    for target in (
        "/etc/alertmind/certs/alertmind-server-api.pem",
        "/usr/local/libexec/alertmind-broker-tls-compact.py",
        "/etc/systemd/system/wazuh-dashboard.service.d/90-alertmind-broker-tls.conf",
        "/etc/systemd/system/wazuh-dashboard.service.d/00-alertmind-broker-maintenance.conf"):
        assert not os.path.lexists(target)
    lines = []
    print("Paste wrapped PUBLIC Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:")
    while True:
        line = input().strip()
        if line == "ALERTMIND_PUBLIC_SOURCE_END":
            break
        assert re.fullmatch("[A-Za-z0-9+/=]{1,72}", line) and len(lines) < 5000
        lines.append(line)
    raw = base64.b64decode("".join(lines), validate=True)
    assert len(raw) == 58726 and hashlib.sha256(raw).hexdigest() == expected
    packet = json.loads(raw)
    assert set(packet) == {"schema", "scope", "operator_base_commit", "operator_revision", "review_status", "files"}
    assert packet["schema"] == 2 and packet["scope"] == "isolated-clone-only; not execution release"
    assert packet["operator_base_commit"] == "7e53ecdda2c4df980d93588b8193c338910bb217"
    assert packet["operator_revision"] == "source-certificate-reader-v2"
    assert packet["review_status"] == "awaiting-focused-review" and len(packet["files"]) == 5
    files, pins = {}, {}
    for entry in packet["files"]:
        assert set(entry) == {"name", "sha256", "base64"}
        name = entry["name"]
        assert name in old and name not in files
        content = base64.b64decode(entry["base64"], validate=True)
        assert 0 < len(content) <= 128 * 1024
        assert hashlib.sha256(content).hexdigest() == entry["sha256"]
        if name.endswith(".py"):
            assert b"\r" not in content and content.endswith(b"\n")
            compile(content, name, "exec")
        files[name], pins[name] = content, entry["sha256"]
    assert set(files) == set(old)
    assert not os.path.lexists(incoming) and not os.path.lexists(backup)
    os.mkdir(incoming, 0o700)
    for name, content in files.items():
        fd = os.open(str(incoming / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    sync(incoming)
    sync(base)
    verify(incoming, pins)
    verify(stage, old)
    assert {p.name for p in base.iterdir()} == {"stage", incoming.name}
    os.rename(stage, backup)
    sync(base)
    assert not os.path.lexists(stage)
    os.rename(incoming, stage)
    sync(base)
    verify(stage, pins)
    verify(backup, old)
except Exception:
    raise SystemExit("STOP: corrected stage refresh failed; preserve all directories; no helper executed") from None
print("PASS corrected public stage: exact five files; syntax only; original stage preserved")
print("PASS corrected packet SHA-256: " + expected)
print("STOP POINT: stage only; no preflight or native rehearsal PASS claimed")
'
)
```

After successful transfer, clear the public clipboard using a **nonempty**
harmless string: `Set-Clipboard -Value 'ALERTMIND_PUBLIC_TRANSFER_COMPLETE'`.
If interrupted, preserve stage/incoming/backup exactly. Do not replay R2 or
remove any directory. A missing `stage` between the two renames is recoverable
from the retained backup/incoming, but needs state-specific direction; this is
not an automatic transaction-recovery program or power-cut proof.

## Corrected rehearsal and results

Within the newly approved ONE attempt, run [original Block 3](rbac-broker-tls-compact-clone-rehearsal.md#block-3--read-only-compatibility-preflight)
against the corrected stage. If it passes, run the **unchanged Block 4** sequence
only if the renewed owner release includes that sequence. No separate gate is
added at each successful checkpoint. Any unexpected STOP holds further actions.

Use the existing worksheet, retaining the failed attempt as a separate record.
Record the corrected commit/packet, review/release, clone conditions, preflight,
exit-73 interruption, native inhibition and missing-trust refusal, inhibited
rollback, secure restoration and final stopped/inhibited state. No recalled
status, manually printed PASS or offline test substitutes for native evidence.
P1-02, original-VM deployment, actual broker TLS and human RBAC remain pending.
