# Compact broker TLS — one disposable-clone rehearsal (Batch B)

**2 October correction notice:** original preflight failed `TOOL`, then
`PARENT_METADATA`. The source-reader correction `9dda08b` is now owner-confirmed
focused-approved/merged; its R1/R2 passed, but Block 3 stopped `CONFIG_ENDPOINT`.
Its [retained public stage](rbac-broker-tls-compact-source-certificate-correction.md)
stays unchanged. The additive [clone-only URL correction packet](rbac-broker-tls-compact-clone-endpoint-correction.md)
awaits focused review and separate execution release. After its E3 correction,
Dashboard is deliberately stopped/inhibited: use E4 instead of original Block 3,
then the unchanged Block 4 sequence within ONE released batch. Do not replay
staging or relabel earlier failures. No native install/interruption/refusal/
rollback acceptance has been recorded. Historical packet pins below stay intact.

**1 October 2026: prepared for focused review; VM execution NOT RELEASED.**
The following describes the original submission state; later owner review and
one execution release are recorded in HANDOFF. It does not release a retry.
The owner confirmed focused independent approval of Batch A `7e53ecd` and its
reused TLS candidate. That does **not** approve this new fault-injection driver
or release its commands. Obtain focused approval of this packet, then separate
owner authorization for ONE run of Blocks 2–4. Record both in the
[blank worksheet](../../evidence/rbac/compact-broker-clone-proof-template.md).
Until then, only Block 1's workstation build may run; either VM may stay off.

This is P1-02 in the [finite checklist](../rbac-phase1-exit-checklist.md), not
another OS-attestation gate. Do not restore Snapshot 1 over the original VM.
Use **Ubuntu SOC 201 - Current Isolated Clone**, all its network adapters
disabled, no AlertMind app using it, a stable host and no simultaneous updates
or configuration work. Original VM remains untouched; retain Snapshot 1 and
the clone console. Confirm those conditions afresh before execution.
The program cannot reliably distinguish a clone from its original inside the
guest; correct clone selection/isolation is an **owner-verified external precondition**.

## Scope and limits

The [clone-only driver](../../siem/rbac/broker_tls/compact_clone_rehearsal.py)
uses the [compact operator](rbac-broker-tls-compact-deployment.md).
Its approved original revision and pending scoped correction are distinguished
in the correction packet; base approval does not approve new helper bytes.
Only the fixed new TLS files/private state and Dashboard service are touched.
No account, permission, SSH, enrollment, Server configuration, broker password
or saved-object operation. No new credential prompt. Operator/driver make no
API request; starting Dashboard can cause its **normal vendor loopback traffic**
using the existing broker configuration. Never claim this run is credential-free.

Trust normal lab OS/root/systemd/package tools and the supported vendor runtime;
no concurrent privileged writers. Public packet hashes bind reviewed bytes,
not package authenticity or an independent signature. No PID 1, import/ELF or
hostile-root attestation is added. Keep old guard/controller entry points blocked.

The rehearsal is finite:

| Checkpoint | Native result to obtain |
| --- | --- |
| Preflight | Exact stage, supported packages, active services, compatible unchanged client/unit/configuration/public certificate |
| Interrupted install | Abrupt **installer process exit 73** after the public trust copy's atomic write/fsync/readback; before helper/guard/client writes. Dashboard stopped; native start rejected by persistent inhibition |
| Secure recovery | Explicit `install`, `resume`, `check`; patched service active under mandatory pre-start validation |
| Missing-trust refusal | Stop/inhibit; remove only the new verified public trust copy; temporarily remove inhibition so the **TLS guard**, not `/bin/false`, must reject native startup; restore inhibition in `finally` |
| Rollback | Original client restored; guard/helper/trust removed; original service remains inhibited and its native start is rejected |
| Secure restoration and finish | Reinstall/resume/check and verify four healthy services; finally pause Dashboard, preserving secure candidate, private state and inhibition |

One selected durable checkpoint is a real abrupt process interruption, **not a
power-cut, reboot or all-checkpoint crash proof**. The existing offline tests
cover additional simulated positions. Native start failure counts only when
`ExecStartPre` identifies a FRESH exact non-ignored inhibitor/guard command with
exit 1 and MainPID is 0. Cached previous failures are refused. The pinned vendor
unit has `Restart=always`; the probe explicitly stops its automatic retries
after each native start attempt, including unexpected success. A generic
failure or unknown serialization is NOT PASS. Active service checks are
checkpoint observations, not broker readiness or continuous-health proof.
Actual broker login/read/refresh TLS, administrator/two-dashboard continuity,
human context/RBAC and safe backend denials remain P1-03–06, NOT TESTED here.

## Public artifact binding

The [host-only builder](../../siem/rbac/broker_tls/build_compact_clone_packet.py)
requires the final reviewed Batch A bundle; refuses changed payloads or helper
source and existing output; syntax-checks but never executes the driver. It
produces one flat public JSON/Base64 envelope, no tar extraction or dynamic paths.
The [preparation record](../../siem/rbac/broker_tls/compact-clone-preparation-2026-10-01.json)
pins the five files and exact packet. It is **not** live evidence or approval.

Expected packet: 55,784 bytes, SHA-256
`f36ac4e7566890162045ecf5da27b31bcda8d669ede98971272aa59f5010bc68`.
Driver LF SHA-256:
`ef9459ecf51b32dfea3ac063fa8684898d266d176f834b0a18d0b8aed425399d`.
Approved operator LF SHA-256:
`e9a35d66d1e8e501fbee406215d4d54da3553acededffab91064b0e0b896b05c`.
Candidate, bundle and checksum-file pins are in the preparation record. Retain
the committed source revision and host hash output with the worksheet.

Run each **whole** block. Do not continue line by line after STOP/throw/error,
print a PASS manually or replay a mutation after interruption. No `set -x`,
raw journal/config dumps, private receipt or configuration digest in chat/Git.

## Block 1 — workstation build/transfer preparation only

PowerShell on the physical Windows host; no VM connection. The interpreter below
is the currently verified CI venv. If it or the reviewed bundle is absent, stop
for the minimal host rebuild, not a VM/package update. Generate a NEW output;
do not reuse earlier pre-final Batch A scratch bundles.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    Set-Location 'C:\Users\ojasp\Desktop\project-alertmind\alertmind-main\alertmind'
    $Python = 'C:\Users\ojasp\AppData\Local\Temp\alertmind-pid1-ci-venv-20260928\Scripts\python.exe'
    $Bundle = 'C:\Users\ojasp\AppData\Local\Temp\alertmind-compact-bundle-20261001-final-r2'
    $Packet = Join-Path $env:TEMP ('alertmind-compact-clone-' + [guid]::NewGuid() + '.json')
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'STOP: CI interpreter absent' }
    & $Python -B siem/rbac/broker_tls/build_compact_clone_packet.py --bundle $Bundle --output $Packet
    if ($LASTEXITCODE -ne 0) { throw 'STOP: public packet build failed' }
    $Expected = 'f36ac4e7566890162045ecf5da27b31bcda8d669ede98971272aa59f5010bc68'
    if ((Get-FileHash -LiteralPath $Packet -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw 'STOP: public packet differs from reviewed artifact'
    }
    $Revision = (& git rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0) { throw 'STOP: source revision unavailable' }
    $Encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Packet))
    $Wrapped = [regex]::Matches($Encoded, '.{1,72}') | ForEach-Object { $_.Value }
    Set-Clipboard -Value (($Wrapped -join "`n") + "`nALERTMIND_PUBLIC_SOURCE_END")
    "PASS public packet: $Expected; source_revision=$Revision"
    "Packet retained at: $Packet"
    'STOP POINT: public build only; transfer/execution require packet review and owner release'
}
```

No Git push is performed. Copy only this public payload; never any certificate
private key, config, credential record or receipt. After accepted clone staging,
replace clipboard with a nonempty harmless string, e.g.
`Set-Clipboard -Value 'ALERTMIND_PUBLIC_TRANSFER_COMPLETE'`.

## Block 2 — reviewed/released clone staging, syntax only

**DO NOT RUN until this packet is approved and owner-released.** Check clone
identity/adapters in VirtualBox; a guest hostname alone cannot establish it.
At the clone console, the following creates only a NEW root-private stage. It
validates the full published packet hash before parsing/writing and compiles the
two Python files for syntax only; neither helper executes. Existing/partial
stage is a STOP, not permission to delete or overwrite it.

```bash
(
set -euo pipefail
read -r -p 'Type REVIEWED-RELEASED-CLONE only after packet approval, owner release and all clone conditions: ' consent
[ "$consent" = REVIEWED-RELEASED-CLONE ] || { echo 'STOP: no clone release'; exit 1; }
sudo /var/ossec/framework/python/bin/python3 -I -B -c '
import base64, hashlib, json, os, pathlib, re
expected = "f36ac4e7566890162045ecf5da27b31bcda8d669ede98971272aa59f5010bc68"
names = {"candidate.cjs", "compact_operator.py", "bundle.json", "compact_clone_rehearsal.py", "SHA256SUMS"}
try:
    assert os.geteuid() == 0
    os.umask(0o077)
    lines = []
    print("Paste wrapped PUBLIC Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:")
    while True:
        line = input().strip()
        if line == "ALERTMIND_PUBLIC_SOURCE_END":
            break
        assert re.fullmatch("[A-Za-z0-9+/=]{1,72}", line) and len(lines) < 5000
        lines.append(line)
    raw = base64.b64decode("".join(lines), validate=True)
    assert len(raw) == 55784 and hashlib.sha256(raw).hexdigest() == expected
    packet = json.loads(raw)
    assert set(packet) == {"schema", "scope", "operator_commit", "files"}
    assert packet["schema"] == 1 and packet["scope"] == "isolated-clone-only; not execution release"
    assert packet["operator_commit"] == "7e53ecdda2c4df980d93588b8193c338910bb217"
    assert len(packet["files"]) == 5
    files = {}
    for item in packet["files"]:
        assert set(item) == {"name", "sha256", "base64"}
        name = item["name"]
        assert name in names and name not in files
        content = base64.b64decode(item["base64"], validate=True)
        assert 0 < len(content) <= 128 * 1024
        assert hashlib.sha256(content).hexdigest() == item["sha256"]
        if name.endswith(".py"):
            assert b"\r" not in content and content.endswith(b"\n")
            compile(content, name, "exec")
        files[name] = content
    assert set(files) == names
    base = pathlib.Path("/root/alertmind-broker-tls-compact")
    assert not os.path.lexists(base)
    root = base.parent.lstat()
    import stat
    assert stat.S_ISDIR(root.st_mode) and root.st_uid == 0 and not root.st_mode & 0o022
    os.mkdir(base, 0o700)
    target = base / "stage"
    os.mkdir(target, 0o700)
    for name, content in files.items():
        fd = os.open(str(target / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    for directory in (target, base, base.parent):
        fd = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    assert all((target / name).read_bytes() == content for name, content in files.items())
    for directory in (base, target):
        item = directory.lstat()
        assert (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o700)
    for name in files:
        item = (target / name).lstat()
        assert stat.S_ISREG(item.st_mode) and item.st_nlink == 1
        assert (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o400)
except Exception:
    raise SystemExit("STOP: public clone stage failed; preserve partial state; no helper executed") from None
print("PASS exact public packet and root-private stage: five files; syntax only")
print("PASS packet SHA-256: " + expected)
print("NEXT: Block 3 preflight only; operator/driver not executed by staging")
'
)
```

## Block 3 — read-only compatibility preflight

After successful staging, run this once in the same approved clone window.
No second independent gate is required for each successful checkpoint in this
ONE released batch. Unknown version/client/endpoint/unit/trust is a concrete
STOP: return the static code for minimal correction; do not edit config or pins.

```bash
(
set -euo pipefail
sudo /bin/bash -c 'cd /root/alertmind-broker-tls-compact/stage && sha256sum -c SHA256SUMS'
sudo /var/ossec/framework/python/bin/python3 -I -B \
  /root/alertmind-broker-tls-compact/stage/compact_clone_rehearsal.py preflight
printf '%s\n' 'PASS read-only preflight; no Dashboard inhibition or broker file change'
)
```

For the endpoint-corrected attempt, E4's exact stopped/inhibited preflight
replaces this original active-service Block 3; do not execute it after E3.
The configuration is parsed privately, not printed. It must already meet the
approved `https://localhost` contract. A mismatch is not authorization to patch
credential-bearing YAML or accept a wider origin. Correct it separately with a
reviewed private backup if needed. Service start/refusal is not yet tested.

## Block 4 — single finite native rehearsal

**Clone ONLY.** This deliberately aborts one installer process and removes one
new public trust copy. Never run on the original VM. Block 3 (or E4's exact
inhibited preflight for the reviewed endpoint-corrected attempt) must have passed
in this uninterrupted maintenance window. Take all output from one run; after a
STOP/interruption other than expected exit 73, do not replay the whole block.
The clone-only driver is never installed into the production startup path.

```bash
(
set -euo pipefail
read -r -p 'Type CLONE-REHEARSAL to confirm the released interruption/missing-trust/rollback scope on the isolated clone: ' consent
[ "$consent" = CLONE-REHEARSAL ] || { echo 'STOP: rehearsal not confirmed'; exit 1; }
sudo /bin/bash -c 'cd /root/alertmind-broker-tls-compact/stage && sha256sum -c SHA256SUMS'
op() {
  sudo /var/ossec/framework/python/bin/python3 -I -B \
    /root/alertmind-broker-tls-compact/stage/compact_operator.py "$1"
}
proof() {
  sudo /var/ossec/framework/python/bin/python3 -I -B \
    /root/alertmind-broker-tls-compact/stage/compact_clone_rehearsal.py "$1"
}
op prepare
status=0
proof interrupt-install || status=$?
[ "$status" -eq 73 ] || { echo 'STOP: expected interruption exit 73 was not observed'; exit 1; }
proof prove-interruption
op install
op resume
op check
proof final
proof refuse-missing-trust
op install
op resume
op check
op rollback
proof prove-rollback
op install
op resume
op check
proof final
op pause
printf '%s\n' 'PASS finite clone rehearsal finished; secure candidate retained; Dashboard stopped/inhibited'
printf '%s\n' 'STOP POINT: return static PASS/STOP lines and expected exit 73; no original-VM release'
)
```

## Stop/recovery and acceptance

On unexpected failure, preserve output/private state and keep apps stopped.
Do not print receipt/configuration, reinstall packages, run SSH/rotation drills,
delete a partial stage or restart original unverified client bytes. At the clone
console establish the actual inhibited/stopped state before any corrective edit.
The approved staged `pause` is the normal stop/inhibit action; if it fails, stop
for console diagnosis rather than claiming successful inhibition. This is a
bounded recovery design, not protection from root interference or broken systemd.

- If exit 73 occurred, expected state is `prepared`, new public trust present,
  original client unchanged, no guard/helper, inhibition loaded and MainPID 0.
  `install` is the explicit recovery entry; **do not repeat `prepare`**.
- If interruption occurred during missing-trust proof, the intact TLS guard
  rejects the missing certificate; use `pause`, then reviewed `install`/`resume`
  recovery. Never start via another unit or remove the guard to make it work.
- Rollback retains inhibition and backup. Secure `install`/`resume`, not starting
  original bytes, is the supported restoration.
- Never substitute a recalled status, generic tool error or manually written
  PASS. Unrun/failed rows stay NOT TESTED/FAIL and P1-02 remains open.

Return only sanitized static outcomes and public hashes in the worksheet. Record
the focused reviewer and execution approval, exact committed source/packet,
clone conditions, time, all checkpoint statuses and limitations. Accept P1-02
only after output review; then move directly to Batch C's original-VM TLS and
human read-only feature, with its separate consent. No original VM action or
Phase 1 completion is authorized by a passing clone run.
