# Runbook — Phase 1C rollback and revocation drill

**Status:** Secret-free drill package; not yet executed. Every command and the
contract tests must receive independent review before the owner runs Stage 1.
Each later `STOP POINT` is a separate human/reviewer gate.

**Scope:** Exercise the rollback and restoration of the already reviewed
Phase 1C SSH transport and the `assistant-svc` Indexer credential. The drill
removes the Windows tunnel and VM SSH exposure, revokes the service mapping and
user, proves the old credentials fail, creates a distinct replacement
password, rotates the dedicated SSH client key, restores the same reviewed
least-privilege boundary, and checks Wazuh Indexer, Manager, Filebeat and
Dashboard health in that order.

This is not the future application-profile rollback. No analyst/live-Wazuh
profile, OIDC layer, constrained reader or live-alert UI exists in the current
application, so there is no implemented profile to disable or restore. The
Windows preflight combines an owner confirmation that all application
instances are stopped with a check for visible Streamlit CLI processes. This
is not proof about inaccessible or nonstandard process command lines. The full
feature must repeat the profile leg after that application layer exists. This
drill cannot establish rollback of the future OIDC/application/live-reader
layer.

## 1. Fixed boundary and exclusions

The final state must match the independently reviewed pre-drill boundary except
for two deliberately rotated secrets:

- `assistant-svc` has a new, distinct password but exactly the same direct
  mapping to `alertmind_assistant_alerts_ro`;
- the Windows SSH client uses a new passphrase-protected Ed25519 key, while the
  VM host key, dedicated known-hosts record and public Wazuh CA remain
  unchanged;
- the VM listens only on `192.168.56.102:22`, the Windows forward listens only
  on `127.0.0.1:19200`, and the only forwarding destination remains
  `127.0.0.1:9200`;
- `wazuh-indexer` remains bound to VM loopback;
- the `alertmind_assistant_alerts_ro` role, its DLS on agent IDs `001`/`002`,
  the `socanalyst` user/mapping and the scoped `own_index` mapping do not
  change; and
- the existing `openssh-server` and `openssh-sftp-server` packages remain
  installed. The disabled leg masks both SSH activation paths rather than
  removing packages.

The drill is probe-free. It must not create an index, alert, archive, sentinel
or document; request `_source`; invoke a model; or alter the frozen corpus. It
must not call `securityadmin.sh`, restore `own_index` to `users: ["*"]`, or
change `socanalyst`. The only Indexer mutations are deletion/restoration of the
one service mapping and deletion/recreation of the one service user.

Passwords, password hashes, private keys, authorization headers, raw alert
documents, verbose TLS bodies and verbose SSH logs are never pasted into chat
or committed. The human enters passwords only at interactive prompts. Record
only public fingerprints, HTTP status, exact role names, bounded hit metadata
and service states.

## 2. Recovery posture

Before starting, confirm that `Snapshot 1` remains available and that the VM
console is open. The console is the recovery channel; do not perform teardown
through the tunnel being removed.

The safe failure state is:

1. no Windows tunnel;
2. `ssh.service` and `ssh.socket` masked and inactive;
3. no TCP 22 listener and no dedicated public key in `authorized_keys`;
4. `assistant-svc` absent or present without its project mapping; and
5. the scoped `own_index` mapping unchanged.

If a restoration step fails, remain in that disabled state. Do not re-enable
the old key, reuse the old password, broaden a role, restore the `own_index`
wildcard or restore the VM snapshot merely to force a passing result. Preserve
sanitized failure evidence and obtain a new review.

## 3. Stage the reviewed helper

Create a new mode-0700 directory named
`$HOME/alertmind-rbac-phase1c-rollback` at the VM console, refusing to reuse an
existing path. Transfer these two files byte for byte into it:

- `siem/rbac/build_assistant_svc_rotation_payload.py`
- `siem/rbac/ROLLBACK-SHA256SUMS`

The helper asks for the current and replacement passwords through the terminal,
requires the replacement to be non-empty, confirmed and distinct, then emits
the replacement REST payload to standard output. The helper rejects terminal
and regular-file stdout before prompting and aborts if getpass would fall back
to an echoing prompt. Its reviewed consumer validates the complete payload in
memory before starting curl, so empty or malformed producer output cannot
initiate a request. The helper cannot prevent a different consumer from saving
the stream. That output
must never be redirected, inspected, copied or logged.

Run at the VM console:

```bash
(
set -euo pipefail
umask 077
DRILL_STAGE="$HOME/alertmind-rbac-phase1c-rollback"

if [ ! -d "$DRILL_STAGE" ] || [ -L "$DRILL_STAGE" ]; then
  echo "STOP: reviewed drill staging directory is absent: $DRILL_STAGE"
  exit 1
fi
chmod 700 "$DRILL_STAGE"
cd "$DRILL_STAGE"
python3 -c '
from pathlib import Path
expected={"build_assistant_svc_rotation_payload.py","ROLLBACK-SHA256SUMS"}
entries=list(Path(".").iterdir())
if {p.name for p in entries} != expected or any(p.is_symlink() or not p.is_file() for p in entries):
    raise SystemExit("STOP: staging must contain exactly the two reviewed regular files")
'
sha256sum -c ROLLBACK-SHA256SUMS
python3 -c 'import ast,pathlib; ast.parse(pathlib.Path("build_assistant_svc_rotation_payload.py").read_text(encoding="utf-8"))'
echo 'PASS: reviewed rotation helper is intact and syntax-valid'
)
```

Do not proceed if an unreviewed file is present in the drill directory.

## 4. Stage 1 — read-only preflight

### 4.1 Windows preflight

Run from `assistant/` in a fresh PowerShell window. The owner must stop all
application instances; the check must find no visible Streamlit CLI process
and exactly one existing tunnel process. The check reads
the process command line only to validate it and does not print it.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Secrets = Join-Path (Get-Location) '.secrets'
    $Certs = Join-Path (Get-Location) '.certs'
    $PrivateKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
    $PublicKey = "$PrivateKey.pub"
    $KnownHosts = Join-Path $Secrets 'wazuh-siem_known_hosts'
    $Ca = Join-Path $Certs 'root-ca.pem'
    $Keygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
    $OpenSsl = 'C:\Program Files\Git\usr\bin\openssl.exe'

    if ((Read-Host 'Confirm all application instances are stopped; type APP-STOPPED') -cne 'APP-STOPPED') {
        throw 'STOP: owner has not confirmed application quiescence'
    }

    $AppProcesses = @(
        Get-CimInstance Win32_Process |
          Where-Object {
              $_.CommandLine -and
              $_.CommandLine -match '(?i)\bstreamlit\b'
          }
    )
    if ($AppProcesses.Count -ne 0) {
        throw 'STOP: stop the running Streamlit process manually before the drill'
    }

    foreach ($Path in @($PrivateKey, $PublicKey, $KnownHosts, $Ca)) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "STOP: required local file is absent: $Path"
        }
    }

    $OldFingerprint = ((& $Keygen -lf $PublicKey -E sha256) -split '\s+')[1]
    if ($LASTEXITCODE -ne 0 -or
        $OldFingerprint -ne 'SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo') {
        throw "STOP: current SSH client-key fingerprint drifted: $OldFingerprint"
    }

    $HostLines = @(Get-Content -LiteralPath $KnownHosts |
        Where-Object { $_.Trim().Length -gt 0 })
    if ($HostLines.Count -ne 1 -or
        $HostLines[0] -notmatch '^(?:192\.168\.56\.102|\[192\.168\.56\.102\]:22)\s+ssh-ed25519\s+\S+$') {
        throw 'STOP: known-hosts file is not exactly one expected Ed25519 record'
    }
    $HostFingerprint = ((& $Keygen -lf $KnownHosts -E sha256) -split '\s+')[1]
    if ($LASTEXITCODE -ne 0 -or
        $HostFingerprint -ne 'SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag') {
        throw "STOP: pinned SSH host-key fingerprint drifted: $HostFingerprint"
    }

    $CaText = (& $OpenSsl x509 -in $Ca -noout -fingerprint -sha256) -join ''
    if ($LASTEXITCODE -ne 0 -or
        $CaText -notmatch 'Fingerprint=([0-9A-Fa-f:]+)') {
        throw 'STOP: Wazuh CA fingerprint calculation failed'
    }
    $CaFingerprint = ($Matches[1] -replace ':', '').ToUpperInvariant()
    if ($CaFingerprint -ne
        'EB98A4AF38CDA550D473E5659A4375905334041FAB4597F39C4F191D9E6F5E1D') {
        throw "STOP: Wazuh CA fingerprint drifted: $CaFingerprint"
    }

    $Listener = @(Get-NetTCPConnection -State Listen -LocalPort 19200)
    if ($Listener.Count -ne 1 -or $Listener.LocalAddress -ne '127.0.0.1') {
        throw "STOP: expected one loopback tunnel listener: $($Listener | Out-String)"
    }
    $TunnelProcess = Get-CimInstance Win32_Process `
        -Filter "ProcessId=$($Listener[0].OwningProcess)"
    if ($null -eq $TunnelProcess -or
        $TunnelProcess.Name -ne 'ssh.exe' -or
        $TunnelProcess.CommandLine -notmatch '127\.0\.0\.1:19200:127\.0\.0\.1:9200' -or
        $TunnelProcess.CommandLine -notmatch 'notroot@192\.168\.56\.102') {
        throw 'STOP: TCP 19200 is not owned by the reviewed SSH tunnel command'
    }

    'PASS no Streamlit CLI process observed; owner confirmed app stopped'
    "PASS current SSH client key: $OldFingerprint"
    "PASS pinned SSH host key: $HostFingerprint"
    "PASS Wazuh CA SHA-256: $CaFingerprint"
    'PASS existing tunnel: 127.0.0.1:19200 to the approved destination'
}
```

### 4.2 VM and Indexer preflight

Run at the VM console. All JSON is consumed in memory and only sanitized PASS
lines are printed. Every VM curl invocation below disables user curl
configuration and proxies; the explicit local URL and CA remain authoritative.
Health checks test each service individually: a multi-unit
`systemctl is-active` exit status alone does not prove all four are active.

```bash
(
set -euo pipefail
INDEXER_URL='https://127.0.0.1:9200'
INDEXER_CA='/etc/wazuh-indexer/certs/root-ca.pem'
IDENTITY_STAGE="$HOME/alertmind-rbac-phase1b"
SSH_STAGE="$HOME/alertmind-rbac-phase1c"
DRILL_STAGE="$HOME/alertmind-rbac-phase1c-rollback"
PRESERVED='admin,anomalyadmin,kibanaro,kibanaserver,logstash,readall,snapshotrestore'

cd "$IDENTITY_STAGE"
sha256sum -c SHA256SUMS
cd "$SSH_STAGE"
sha256sum -c SSH-SHA256SUMS
cd "$DRILL_STAGE"
sha256sum -c ROLLBACK-SHA256SUMS

sudo cmp --silent "$SSH_STAGE/sshd-alertmind.conf" \
  /etc/ssh/sshd_config.d/00-alertmind-transport.conf
python3 -c '
from pathlib import Path
import sys
expected=Path(sys.argv[1]).read_text(encoding="ascii").strip()
path=Path("/home/notroot/.ssh/authorized_keys")
if path.is_symlink() or not path.is_file():
    raise SystemExit("STOP: authorized_keys must be a regular non-symlink file")
lines=[line.strip() for line in path.read_text(encoding="ascii").splitlines() if line.strip()]
if len(lines) != 1 or not lines[0].startswith(expected+" ssh-ed25519 "):
    raise SystemExit("STOP: expected exactly one Ed25519 key with reviewed restrictions")
if path.stat().st_mode & 0o777 != 0o600:
    raise SystemExit("STOP: authorized_keys mode is not 0600")
print("PASS installed drop-in and one restricted authorized-key record")
' "$SSH_STAGE/ssh-authorized-key-options.txt"

test "$(dpkg-query -W -f='${Version}' openssh-server)" = \
  '1:10.2p1-2ubuntu3.5'
test "$(dpkg-query -W -f='${Version}' openssh-sftp-server)" = \
  '1:10.2p1-2ubuntu3.5'
test "$(systemctl is-enabled ssh.service)" = 'enabled'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
test "$(systemctl is-active ssh.service)" = 'active'
if systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH socket activation is active'; exit 1
fi
LISTENERS=$(sudo ss -ltnp | awk '$4 ~ /:22$/ {print}')
test "$(printf '%s\n' "$LISTENERS" | awk 'NF {n++} END {print n+0}')" -eq 1
printf '%s\n' "$LISTENERS" | grep -F '192.168.56.102:22' >/dev/null
INDEXER_LISTENERS=$(sudo ss -H -ltn | awk '$4 ~ /:9200$/ {print $4}')
case "$INDEXER_LISTENERS" in
  '127.0.0.1:9200'|'[::ffff:127.0.0.1]:9200') ;;
  *) echo 'STOP: Indexer is not bound to one loopback listener'; exit 1;;
esac
sudo bash -c '
set -euo pipefail
seen_001=0
seen_002=0
while read -r id name ip key; do
  case "$id" in
    001) test "$seen_001" -eq 0; seen_001=1; expected=ce6dbeeff3df5ffef33e643ea36b60ffaf4f9b73577bf8c68789c867d672a5b7; expected_name=win-victim;;
    002) test "$seen_002" -eq 0; seen_002=1; expected=483a8b3caa8e9a252aa8ea632d7a5c1ab04358c170f314ec01f1d696dfffdebf; expected_name=linux-victim;;
    *) continue;;
  esac
  digest=$(printf "%s" "$key" | sha256sum)
  digest=${digest%% *}
  test "$name" = "$expected_name"
  test "$digest" = "$expected"
  printf "PASS enrollment %s %s: %s\n" "$id" "$name" "$digest"
done < /var/ossec/etc/client.keys
test "$seen_001" -eq 1
test "$seen_002" -eq 1
'

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/roles/alertmind_assistant_alerts_ro" |
python3 -c '
import json,sys
expected=json.load(open(sys.argv[1], encoding="utf-8"))
actual=json.load(sys.stdin)["alertmind_assistant_alerts_ro"]
for key,value in expected.items():
    if actual.get(key) != value:
        raise SystemExit(f"STOP: assistant role drifted at {key}")
print("PASS exact assistant role")
' "$IDENTITY_STAGE/indexer-role_assistant_alerts_ro.json"

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_assistant_alerts_ro" |
python3 -c '
import json,sys
expected=json.load(open(sys.argv[1], encoding="utf-8"))
actual=json.load(sys.stdin)["alertmind_assistant_alerts_ro"]
for key,value in expected.items():
    if actual.get(key) != value:
        raise SystemExit(f"STOP: assistant mapping drifted at {key}")
if actual.get("and_backend_roles", []) != []:
    raise SystemExit("STOP: assistant mapping has an alternate selector")
print("PASS exact assistant mapping")
' "$IDENTITY_STAGE/indexer-role-mapping_assistant_alerts_ro.json"

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/own_index" |
python3 -c '
import json,sys
expected=sys.argv[1].split(",")
actual=json.load(sys.stdin)["own_index"]
if actual.get("users") != expected:
    raise SystemExit("STOP: scoped own_index users drifted")
for key in ("backend_roles","and_backend_roles","hosts"):
    if actual.get(key, []) != []:
        raise SystemExit(f"STOP: own_index selector is non-empty: {key}")
print("PASS scoped own_index mapping unchanged")
' "$PRESERVED"

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/internalusers/assistant-svc" |
python3 -c '
import json,sys
user=json.load(sys.stdin)["assistant-svc"]
direct=user.get("opendistro_security_roles", user.get("roles", []))
if user.get("backend_roles", []) != [] or direct != [] or user.get("attributes", {}) != {}:
    raise SystemExit("STOP: assistant-svc carries an unexpected direct grant")
if "hash" not in user:
    raise SystemExit("STOP: assistant-svc hash field is absent")
print("PASS sanitized assistant-svc record")
'

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  "$INDEXER_URL/_plugins/_security/authinfo" |
python3 -c '
import json,sys
data=json.load(sys.stdin)
if data.get("user_name") != "assistant-svc":
    raise SystemExit("STOP: service identity differs")
if data.get("roles") != ["alertmind_assistant_alerts_ro"]:
    raise SystemExit("STOP: effective service roles differ")
print("PASS assistant-svc effective role is exact")
'

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_socanalyst_ro" |
python3 -c '
import json,sys
expected=json.load(open(sys.argv[1], encoding="utf-8"))
actual=json.load(sys.stdin)["alertmind_socanalyst_ro"]
if any(actual.get(key) != value for key,value in expected.items()) or actual.get("and_backend_roles", []) != []:
    raise SystemExit("STOP: socanalyst mapping differs")
print("PASS exact socanalyst mapping; no mutation to this identity is authorized")
' "$IDENTITY_STAGE/indexer-role-mapping_socanalyst_ro.json"
sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/internalusers/socanalyst" |
python3 -c '
import json,sys
user=json.load(sys.stdin)["socanalyst"]
direct=user.get("opendistro_security_roles", user.get("roles", []))
if user.get("backend_roles", []) != [] or direct != [] or user.get("attributes", {}) != {}:
    raise SystemExit("STOP: socanalyst record differs")
print("PASS sanitized socanalyst user; password/hash neither displayed nor changed")
'

for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  if [ "$state" != 'active' ]; then
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1
  fi
  printf 'PASS service health: %s=active\n' "$unit"
done
echo 'PASS: Stage 1 VM/Indexer preflight complete'
echo 'STOP POINT: send only these sanitized PASS/service lines for review'
)
```

## 5. Stage 2 — prepare the replacement SSH key

This is a local-only preparation step. It neither changes the VM nor stops the
existing tunnel. Run from `assistant/` and enter a non-empty passphrase for the
replacement key.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Secrets = Join-Path (Get-Location) '.secrets'
    $OldKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
    $OldPublic = "$OldKey.pub"
    $ReplacementKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519.replacement'
    $ReplacementPublic = "$ReplacementKey.pub"
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if ((Test-Path -LiteralPath $ReplacementKey) -or
        (Test-Path -LiteralPath $ReplacementPublic)) {
        throw 'STOP: a replacement SSH key candidate already exists'
    }
    $OldFingerprint = ((& ssh-keygen.exe -lf $OldPublic -E sha256) -split '\s+')[1]
    if ($LASTEXITCODE -ne 0 -or
        $OldFingerprint -ne 'SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo') {
        throw 'STOP: old public-key fingerprint failed or drifted'
    }

    & ssh-keygen.exe -t ed25519 -a 100 -f $ReplacementKey `
      -C 'alertmind-wazuh-indexer-tunnel-rotation-1'
    if ($LASTEXITCODE -ne 0) { throw 'STOP: replacement ssh-keygen failed' }
    & icacls.exe $ReplacementKey /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'STOP: replacement-key ACL reset failed' }
    & icacls.exe $ReplacementKey /grant:r "${Identity}:F" 'SYSTEM:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'STOP: replacement-key ACL grant failed' }

    $NewFingerprint = ((& ssh-keygen.exe -lf $ReplacementPublic -E sha256) -split '\s+')[1]
    if ($LASTEXITCODE -ne 0 -or -not $NewFingerprint) {
        throw 'STOP: replacement public-key fingerprint failed'
    }
    if ($NewFingerprint -eq $OldFingerprint) {
        throw 'STOP: replacement SSH key did not rotate the public fingerprint'
    }
    "PASS old SSH client-key fingerprint: $OldFingerprint"
    "PASS replacement SSH client-key fingerprint: $NewFingerprint"
    'STOP POINT: send only the two public fingerprints for review'
}
```

Do not paste either public-key line into chat. The replacement public-key line
is pasted only into the VM-console prompt in Section 8.1.

## 6. Stage 3 — disable the live transport

### 6.1 Stop the Windows tunnel

Run from `assistant/`. The block refuses to stop a process unless the listener,
executable and command line all match the reviewed tunnel.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Listener = @(Get-NetTCPConnection -State Listen -LocalPort 19200)
    if ($Listener.Count -ne 1 -or $Listener.LocalAddress -ne '127.0.0.1') {
        throw 'STOP: the reviewed loopback tunnel listener is not exact'
    }
    $TunnelProcess = Get-CimInstance Win32_Process `
        -Filter "ProcessId=$($Listener[0].OwningProcess)"
    if ($null -eq $TunnelProcess -or
        $TunnelProcess.Name -ne 'ssh.exe' -or
        $TunnelProcess.CommandLine -notmatch '127\.0\.0\.1:19200:127\.0\.0\.1:9200' -or
        $TunnelProcess.CommandLine -notmatch 'notroot@192\.168\.56\.102') {
        throw 'STOP: refusing to stop an unrecognized TCP 19200 owner'
    }
    Stop-Process -Id $TunnelProcess.ProcessId -ErrorAction Stop
    Start-Sleep -Seconds 2
    if (Get-NetTCPConnection -State Listen -LocalPort 19200 `
        -ErrorAction SilentlyContinue) {
        throw 'STOP: loopback tunnel listener remains after stop'
    }
    'PASS Windows tunnel stopped; TCP 19200 has no listener'
}
```

### 6.2 Remove the VM listener and authorized key

Run at the VM console:

```bash
(
set -euo pipefail
SSH_STAGE="$HOME/alertmind-rbac-phase1c"
AUTH_KEYS='/home/notroot/.ssh/authorized_keys'
DROPIN='/etc/ssh/sshd_config.d/00-alertmind-transport.conf'

cd "$SSH_STAGE"
sha256sum -c SSH-SHA256SUMS
test -f "$SSH_STAGE/rollback/authorized_keys.pre-phase1c"
test ! -L "$SSH_STAGE/rollback/authorized_keys.pre-phase1c"
test ! -s "$SSH_STAGE/rollback/authorized_keys.pre-phase1c"

sudo systemctl disable --now ssh.service
sudo systemctl mask ssh.service ssh.socket
sudo install -o notroot -g notroot -m 600 \
  "$SSH_STAGE/rollback/authorized_keys.pre-phase1c" "$AUTH_KEYS"
sudo rm -f "$DROPIN"
sudo systemctl daemon-reload

test "$(systemctl is-enabled ssh.service 2>/dev/null || true)" = 'masked'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
if systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH is active in the disabled state'; exit 1
fi
test "$(systemctl is-enabled sshd.service 2>/dev/null || true)" = 'masked'
if systemctl list-units --type=service --state=active --no-legend \
  'sshd@*.service' | grep -q .; then
  echo 'STOP: a per-connection sshd service remains active'; exit 1
fi
test "$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$AUTH_KEYS")" -eq 0
if sudo ss -ltnp | grep -E ':(22)\b'; then
  echo 'STOP: TCP 22 remains after transport removal'
  exit 1
fi
test "$(dpkg-query -W -f='${Version}' openssh-server)" = \
  '1:10.2p1-2ubuntu3.5'
test "$(dpkg-query -W -f='${Version}' openssh-sftp-server)" = \
  '1:10.2p1-2ubuntu3.5'

for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  if [ "$state" != 'active' ]; then
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1
  fi
  printf 'PASS service health: %s=active\n' "$unit"
done
echo 'PASS transport removed: no tunnel, listener, drop-in or authorized key'
echo 'PASS OpenSSH packages retained inert and masked'
echo 'STOP POINT: preserve this output for review before service-user revocation'
)
```

At this point the old SSH client key is revoked by absence from
`authorized_keys`; retain its ignored local file temporarily for the explicit
old-key denial in Section 9.1.

## 7. Stage 4 — revoke and rotate `assistant-svc`

### 7.1 Remove the mapping, then delete the user

Run at the VM console. Enter the current `assistant-svc` password at the first
prompt and the admin password at the later prompts. This block leaves the
custom role and every other user/mapping unchanged.

```bash
(
set -euo pipefail
INDEXER_URL='https://127.0.0.1:9200'
INDEXER_CA='/etc/wazuh-indexer/certs/root-ca.pem'

status=$(sudo curl --disable --noproxy '*' --silent --show-error \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/authinfo")
test "$status" = '200'
echo 'PASS current assistant-svc credential authenticated before revocation'

status=$(sudo curl --disable --noproxy '*' --silent --show-error --fail \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  --request DELETE --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_assistant_alerts_ro")
case "$status" in 200|201) ;; *) echo "STOP mapping delete HTTP $status"; exit 1;; esac
echo "PASS assistant role mapping removed: HTTP $status"

status=$(sudo curl --disable --noproxy '*' --silent --show-error --fail \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  --request DELETE --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/api/internalusers/assistant-svc")
case "$status" in 200|201) ;; *) echo "STOP user delete HTTP $status"; exit 1;; esac
echo "PASS assistant-svc deleted: HTTP $status"

for endpoint in \
  'rolesmapping/alertmind_assistant_alerts_ro' \
  'internalusers/assistant-svc'
do
  status=$(sudo curl --disable --noproxy '*' --silent --show-error \
    --connect-timeout 5 --max-time 30 \
    --cacert "$INDEXER_CA" --user admin \
    --output /dev/null --write-out '%{http_code}' \
    "$INDEXER_URL/_plugins/_security/api/$endpoint")
  test "$status" = '404'
done
echo 'PASS service mapping and user are absent'

status=$(sudo curl --disable --noproxy '*' --silent --show-error \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/authinfo")
test "$status" = '401'
echo 'PASS old assistant-svc credential rejected after deletion: HTTP 401'

for endpoint in \
  'roles/alertmind_assistant_alerts_ro' \
  'internalusers/socanalyst' \
  'rolesmapping/alertmind_socanalyst_ro' \
  'rolesmapping/own_index'
do
  status=$(sudo curl --disable --noproxy '*' --silent --show-error \
    --connect-timeout 5 --max-time 30 \
    --cacert "$INDEXER_CA" --user admin \
    --output /dev/null --write-out '%{http_code}' \
    "$INDEXER_URL/_plugins/_security/api/$endpoint")
  test "$status" = '200'
done
echo 'PASS role, socanalyst and scoped own_index resources remain present'

for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  if [ "$state" != 'active' ]; then
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1
  fi
  printf 'PASS service health: %s=active\n' "$unit"
done
echo 'STOP POINT: service identity is now revoked; send sanitized output for review'
)
```

If any later step fails, leave the service identity absent or unmapped and the
transport disabled. Never restore the old password.

### 7.2 Recreate with a distinct password and no direct grant

Run at the VM console. The helper prompts for the old password only to reject
reuse, then asks for the replacement twice. Its standard output goes through
the validating in-memory consumer to curl; do not add `tee`, command
substitution around the helper, redirection or debug tracing. The admin prompt
occurs only after the helper finishes and the consumer validates its output.

```bash
(
set -euo pipefail
INDEXER_URL='https://127.0.0.1:9200'
INDEXER_CA='/etc/wazuh-indexer/certs/root-ca.pem'
DRILL_STAGE="$HOME/alertmind-rbac-phase1c-rollback"

cd "$DRILL_STAGE"
sha256sum -c ROLLBACK-SHA256SUMS
sudo -v

for endpoint in 'internalusers/assistant-svc' 'rolesmapping/alertmind_assistant_alerts_ro'; do
  status=$(sudo curl --disable --noproxy '*' --silent --show-error \
    --connect-timeout 5 --max-time 30 \
    --cacert "$INDEXER_CA" --user admin \
    --output /dev/null --write-out '%{http_code}' \
    "$INDEXER_URL/_plugins/_security/api/$endpoint")
  if [ "$status" != '404' ]; then
    echo "STOP: expected absent resource before recreation: $endpoint HTTP $status"; exit 1
  fi
done

status=$(
  python3 "$DRILL_STAGE/build_assistant_svc_rotation_payload.py" |
  python3 -c '
import json,subprocess,sys
try:
    payload=json.load(sys.stdin)
except (ValueError, OSError):
    raise SystemExit("STOP: rotation payload is absent or malformed; no request sent") from None
expected={"password","backend_roles","opendistro_security_roles","attributes"}
if not isinstance(payload,dict) or set(payload) != expected:
    raise SystemExit("STOP: unexpected rotation payload shape; no request sent")
if not isinstance(payload["password"],str) or not payload["password"]:
    raise SystemExit("STOP: empty replacement password; no request sent")
if payload["backend_roles"] != [] or payload["opendistro_security_roles"] != [] or payload["attributes"] != {}:
    raise SystemExit("STOP: replacement contains a grant; no request sent")
command=[
    "sudo","curl","--disable","--noproxy","*","--silent","--show-error","--fail",
    "--connect-timeout","5","--max-time","30",
    "--cacert","/etc/wazuh-indexer/certs/root-ca.pem","--user","admin",
    "--header","Content-Type: application/json",
    "--request","PUT","--data-binary","@-",
    "--output","/dev/null","--write-out","%{http_code}",
    "https://127.0.0.1:9200/_plugins/_security/api/internalusers/assistant-svc",
]
try:
    result=subprocess.run(command,input=json.dumps(payload).encode("utf-8"),check=False)
except OSError:
    raise SystemExit("STOP: rotation transport could not start") from None
raise SystemExit(result.returncode)
'
)
test "$status" = '201'
echo "PASS assistant-svc recreated through anonymous payload pipe: HTTP $status"

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/internalusers/assistant-svc" |
python3 -c '
import json,sys
user=json.load(sys.stdin)["assistant-svc"]
direct=user.get("opendistro_security_roles", user.get("roles", []))
if user.get("backend_roles", []) != [] or direct != [] or user.get("attributes", {}) != {}:
    raise SystemExit("STOP: replacement user carries an unexpected grant")
if "hash" not in user:
    raise SystemExit("STOP: replacement hash field is absent")
print("PASS sanitized replacement user: no backend/direct roles or attributes")
'

status=$(sudo curl --disable --noproxy '*' --silent --show-error \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/authinfo")
test "$status" = '401'
echo 'PASS old assistant-svc credential remains rejected after recreation: HTTP 401'

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  "$INDEXER_URL/_plugins/_security/authinfo" |
python3 -c '
import json,sys
data=json.load(sys.stdin)
if data.get("user_name") != "assistant-svc" or data.get("roles") != []:
    raise SystemExit("STOP: replacement user is not the expected unmapped identity")
print("PASS replacement credential authenticates with zero effective roles")
'
echo 'STOP POINT: replacement identity exists but remains unmapped'
)
```

The two `assistant-svc` prompts after recreation are intentionally different:
enter the old password for the expected `401`, then the new password for the
unmapped-identity proof. A mistyped old password is not revocation evidence;
the human must attest that the old value was entered accurately.

### 7.3 Restore the reviewed direct-user mapping

Run at the VM console:

```bash
(
set -euo pipefail
INDEXER_URL='https://127.0.0.1:9200'
INDEXER_CA='/etc/wazuh-indexer/certs/root-ca.pem'
IDENTITY_STAGE="$HOME/alertmind-rbac-phase1b"
MAPPING="$IDENTITY_STAGE/indexer-role-mapping_assistant_alerts_ro.json"

cd "$IDENTITY_STAGE"
sha256sum -c SHA256SUMS
status=$(sudo curl --disable --noproxy '*' --silent --show-error \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_assistant_alerts_ro")
if [ "$status" != '404' ]; then
  echo "STOP: mapping is no longer absent: HTTP $status"; exit 1
fi
sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  "$INDEXER_URL/_plugins/_security/authinfo" |
python3 -c '
import json,sys
data=json.load(sys.stdin)
if data.get("user_name") != "assistant-svc" or data.get("roles") != []:
    raise SystemExit("STOP: replacement must still authenticate with zero effective roles")
print("PASS replacement identity remains unmapped before restoration")
'
status=$(sudo curl --disable --noproxy '*' --silent --show-error --fail \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  --header 'Content-Type: application/json' \
  --request PUT --data-binary "@$MAPPING" \
  --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_assistant_alerts_ro")
test "$status" = '201'
echo "PASS reviewed assistant mapping restored: HTTP $status"

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_assistant_alerts_ro" |
python3 -c '
import json,sys
expected=json.load(open(sys.argv[1], encoding="utf-8"))
actual=json.load(sys.stdin)["alertmind_assistant_alerts_ro"]
for key,value in expected.items():
    if actual.get(key) != value:
        raise SystemExit(f"STOP: restored mapping drifted at {key}")
if actual.get("and_backend_roles", []) != []:
    raise SystemExit("STOP: restored mapping has an alternate selector")
print("PASS exact restored mapping: assistant-svc only")
' "$MAPPING"

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  "$INDEXER_URL/_plugins/_security/authinfo" |
python3 -c '
import json,sys
data=json.load(sys.stdin)
if data.get("user_name") != "assistant-svc":
    raise SystemExit("STOP: replacement identity differs")
if data.get("roles") != ["alertmind_assistant_alerts_ro"]:
    raise SystemExit("STOP: replacement effective role differs")
print("PASS replacement assistant-svc effective role is exact")
'

sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user assistant-svc \
  --header 'Content-Type: application/json' \
  --request POST \
  --data-binary '{"size":0,"query":{"terms":{"agent.id":["001","002"]}}}' \
  "$INDEXER_URL/wazuh-alerts-4.x-*/_search?filter_path=_shards.failed,hits.total" |
python3 -c '
import json,sys
data=json.load(sys.stdin)
failed=data.get("_shards",{}).get("failed")
total=data.get("hits",{}).get("total",{})
if failed != 0 or total.get("relation") not in ("eq","gte") or total.get("value",-1) < 0:
    raise SystemExit("STOP: bounded search metadata differs")
hits=total["value"]
relation=total["relation"]
print(f"PASS bounded metadata-only read: failed_shards={failed}; visible_hits={hits}; relation={relation}")
'

for path in \
  '/_cluster/health' \
  '/assistant-svc/_search'
do
  status=$(sudo curl --disable --noproxy '*' --silent --show-error \
    --connect-timeout 5 --max-time 30 \
    --cacert "$INDEXER_CA" --user assistant-svc \
    --output /dev/null --write-out '%{http_code}' \
    "$INDEXER_URL$path")
  test "$status" = '403'
done
echo 'PASS replacement credential denied cluster health and username-index read'

for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  if [ "$state" != 'active' ]; then
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1
  fi
  printf 'PASS service health: %s=active\n' "$unit"
done
echo 'STOP POINT: rotated service credential and exact mapping are restored'
)
```

## 8. Stage 5 — restore SSH with the replacement client key

### 8.1 Install only the replacement public key and reviewed drop-in

At the VM console, paste the one-line replacement **public** key only when
prompted. Type both public fingerprints from Stage 2; do not paste a private
key or either key into chat.

```bash
(
set -euo pipefail
umask 077
SSH_STAGE="$HOME/alertmind-rbac-phase1c"
DRILL_STAGE="$HOME/alertmind-rbac-phase1c-rollback"
AUTH_KEYS='/home/notroot/.ssh/authorized_keys'
DROPIN='/etc/ssh/sshd_config.d/00-alertmind-transport.conf'

cd "$SSH_STAGE"
sha256sum -c SSH-SHA256SUMS
cd "$DRILL_STAGE"
sha256sum -c ROLLBACK-SHA256SUMS
test "$(systemctl is-enabled ssh.service 2>/dev/null || true)" = 'masked'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
if systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH is active before restoration proof'; exit 1
fi
test ! -e "$DROPIN"
test "$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$AUTH_KEYS")" -eq 0

read -r -p 'Paste the one-line replacement Ed25519 PUBLIC key: ' PUBLIC_KEY
case "$PUBLIC_KEY" in ssh-ed25519\ *) ;; *) echo 'STOP: expected ssh-ed25519'; exit 1;; esac
PUBLIC_ONLY=$(mktemp "$DRILL_STAGE/replacement-public.XXXXXX")
AUTHORIZED=$(mktemp "$DRILL_STAGE/replacement-authorized.XXXXXX")
CONTROL=$(mktemp "$DRILL_STAGE/sshd-control.XXXXXX")
TARGET=$(mktemp "$DRILL_STAGE/sshd-target.XXXXXX")
trap 'rm -f "$PUBLIC_ONLY" "$AUTHORIZED" "$CONTROL" "$TARGET"' EXIT
printf '%s\n' "$PUBLIC_KEY" > "$PUBLIC_ONLY"
ACTUAL=$(ssh-keygen -lf "$PUBLIC_ONLY" -E sha256 | awk '{print $2}')
read -r -p 'Type the replacement SHA256 fingerprint from Windows: ' EXPECTED
read -r -p 'Type the revoked old SHA256 fingerprint from Windows: ' REVOKED
test "$REVOKED" = 'SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo'
test "$ACTUAL" = "$EXPECTED"
test "$ACTUAL" != "$REVOKED"

OPTIONS=$(cat "$SSH_STAGE/ssh-authorized-key-options.txt")
printf '%s %s\n' "$OPTIONS" "$PUBLIC_KEY" > "$AUTHORIZED"
sudo install -o notroot -g notroot -m 600 "$AUTHORIZED" "$AUTH_KEYS"
sudo install -o root -g root -m 644 \
  "$SSH_STAGE/sshd-alertmind.conf" "$DROPIN"

test "$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$AUTH_KEYS")" -eq 1
INSTALLED=$(ssh-keygen -lf "$AUTH_KEYS" -E sha256 | awk '{print $2}')
test "$INSTALLED" = "$EXPECTED"
test "$INSTALLED" != "$REVOKED"
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T -C \
  user=root,host=wazuh-siem,addr=192.168.56.1 > "$CONTROL"
sudo /usr/sbin/sshd -T -C \
  user=notroot,host=wazuh-siem,addr=192.168.56.1 > "$TARGET"

for line in \
  'port 22' \
  'addressfamily inet' \
  'listenaddress 192.168.56.102:22' \
  'hostkey /etc/ssh/ssh_host_ed25519_key' \
  'permitrootlogin no' \
  'pubkeyauthentication yes' \
  'passwordauthentication no' \
  'kbdinteractiveauthentication no' \
  'authenticationmethods publickey' \
  'authorizedkeysfile .ssh/authorized_keys' \
  'allowusers notroot@192.168.56.1' \
  'allowtcpforwarding local' \
  'allowstreamlocalforwarding no' \
  'permitopen 127.0.0.1:9200' \
  'gatewayports no' \
  'x11forwarding no' \
  'allowagentforwarding no' \
  'permittty no' \
  'permittunnel no' \
  'permituserrc no' \
  'forcecommand /bin/false' \
  'maxsessions 0'
do
  grep -Fxq "$line" "$TARGET" || { echo "STOP target config: $line"; exit 1; }
done
test "$(grep -c '^hostkey ' "$TARGET")" -eq 1
test "$(grep -c '^listenaddress ' "$TARGET")" -eq 1
for line in \
  'allowtcpforwarding no' \
  'permitopen none' \
  'permittty no' \
  'forcecommand /bin/false' \
  'maxsessions 0'
do
  grep -Fxq "$line" "$CONTROL" || { echo "STOP control config: $line"; exit 1; }
done

echo "PASS replacement public key installed: $INSTALLED"
echo "PASS revoked public key absent: $REVOKED"
echo 'PASS reviewed SSH target/control policy restored while units remain masked'
echo 'STOP POINT: review this pre-enable result before unmasking ssh.service'
)
```

### 8.2 Enable the one host-only listener

After review of Section 8.1, run at the VM console:

```bash
(
set -euo pipefail
fail_closed() {
  status=$?
  if [ "$status" -ne 0 ]; then
    sudo systemctl disable --now ssh.service || true
    sudo systemctl mask ssh.service ssh.socket || true
    echo 'STOP: restoration failed; verify SSH stopped and run Section 11 containment'
  fi
}
trap fail_closed EXIT
test "$(systemctl is-enabled ssh.service 2>/dev/null || true)" = 'masked'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
sudo /usr/sbin/sshd -t
sudo systemctl unmask ssh.service
sudo systemctl enable --now ssh.service

test "$(systemctl is-enabled ssh.service)" = 'enabled'
test "$(systemctl is-active ssh.service)" = 'active'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
if systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH socket activation became active'; exit 1
fi
test "$(systemctl show -p FragmentPath --value ssh.service)" = \
  "$(systemctl show -p FragmentPath --value sshd.service)"
if systemctl list-units --type=service --state=active --no-legend \
  'sshd@*.service' | grep -q .; then
  echo 'STOP: a per-connection sshd service is active'; exit 1
fi
LISTENERS=$(sudo ss -ltnp | awk '$4 ~ /:22$/ {print}')
test "$(printf '%s\n' "$LISTENERS" | awk 'NF {n++} END {print n+0}')" -eq 1
printf '%s\n' "$LISTENERS" | grep -F '192.168.56.102:22' >/dev/null
if printf '%s\n' "$LISTENERS" | grep -E \
  '0\.0\.0\.0:22|10\.0\.2\.15:22|\[::\]:22'; then
  echo 'STOP: forbidden SSH listener address'
  sudo systemctl disable --now ssh.service
  sudo systemctl mask ssh.service
  exit 1
fi

HOST_FINGERPRINT=$(ssh-keygen -lf \
  /etc/ssh/ssh_host_ed25519_key.pub -E sha256 | awk '{print $2}')
test "$HOST_FINGERPRINT" = \
  'SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag'
for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  if [ "$state" != 'active' ]; then
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1
  fi
  printf 'PASS service health: %s=active\n' "$unit"
done
echo "PASS unchanged server host key: $HOST_FINGERPRINT"
echo 'PASS one host-only SSH listener restored; ssh.socket remains masked'
echo 'STOP POINT: review listener restoration before Windows authentication tests'
trap - EXIT
)
```

## 9. Stage 6 — prove old-key denial and replacement-key success

### 9.1 Deny the old SSH key

Run from `assistant/`. This diagnostic retains no log. It requires the explicit
server-side `Permission denied (publickey)` marker and rejects any trace that
authentication succeeded; a generic nonzero exit is insufficient.

```powershell
& {
    $ErrorActionPreference = 'Continue'
    $Secrets = Join-Path (Get-Location) '.secrets'
    $OldKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
    $KnownHosts = Join-Path $Secrets 'wazuh-siem_known_hosts'
    $SshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
    $Output = & $SshExe -F none -vv -T `
      -o ConnectTimeout=10 `
      -o ConnectionAttempts=1 `
      -o KexAlgorithms=curve25519-sha256 `
      -o HostKeyAlgorithms=ssh-ed25519 `
      -o IdentitiesOnly=yes `
      -o IdentityAgent=none `
      -o StrictHostKeyChecking=yes `
      -o "UserKnownHostsFile=$KnownHosts" `
      -o NumberOfPasswordPrompts=0 `
      -i $OldKey `
      'notroot@192.168.56.102' 'true' 2>&1
    $Exit = $LASTEXITCODE
    $Text = $Output -join "`n"
    if ($Exit -eq 0 -or $Text -match '(?i)(Authenticated to|Server accepts key:)') {
        throw 'STOP: revoked SSH key was accepted'
    }
    if ($Text -notmatch 'Offering public key:.*SHA256:\+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo') {
        throw 'STOP: the reviewed old key was not offered to the server'
    }
    if ($Text -notmatch '(?i)Permission denied \(publickey\)') {
        throw 'STOP: old-key test did not reach a public-key authentication denial'
    }
    "PASS revoked SSH key denied by server: exit $Exit; no authentication"
}
```

### 9.2 Start a tunnel with the replacement key

In the first PowerShell window, run this foreground command and leave it open:

```powershell
$Secrets = Join-Path (Get-Location) '.secrets'
$ReplacementKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519.replacement'
$KnownHosts = Join-Path $Secrets 'wazuh-siem_known_hosts'
$SshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'

& $SshExe -F none -N -T `
  -o KexAlgorithms=curve25519-sha256 `
  -o HostKeyAlgorithms=ssh-ed25519 `
  -o ExitOnForwardFailure=yes `
  -o IdentitiesOnly=yes `
  -o IdentityAgent=none `
  -o StrictHostKeyChecking=yes `
  -o "UserKnownHostsFile=$KnownHosts" `
  -o ServerAliveInterval=30 `
  -o ServerAliveCountMax=3 `
  -i $ReplacementKey `
  -L '127.0.0.1:19200:127.0.0.1:9200' `
  'notroot@192.168.56.102'
```

In the second PowerShell window, repeat only the listener check, CA fingerprint
and paired TLS/metadata-only proof from Sections 9–10 of
[`rbac-wazuh-ssh-transport.md`](rbac-wazuh-ssh-transport.md). Those blocks act
on the already-running replacement tunnel and do not select a key. Enter the
new service password. The required results at this stage are:

- one listener on `127.0.0.1:19200` only;
- wrong hostname rejected with curl exit `60` and correct `127.0.0.1`
  identity accepted through the same tunnel/CA/revocation policy;
- `_shards.failed=0`, a nonnegative hit count and relation `eq` or `gte`, with
  no `_source` returned.

Do not run the original denial blocks yet: some of them independently rebuild
the canonical key path, which still refers to the old key. Run them unmodified
only after promotion and a fresh canonical-path positive proof below.

Do not treat an authentication failure as a forwarding-policy proof. The
replacement key must complete the positive local forward before its denial
matrix is accepted.

### 9.3 Promote the replacement key only after all proofs pass

Here “all proofs” means the old-key denial and replacement-key listener/paired
TLS/read proofs above. Stop the replacement tunnel with Ctrl+C, then run from
`assistant/`. This is the
point at which the revoked private key is deleted. File deletion is revocation
hygiene, not a claim of forensic erasure from the underlying storage device.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    if (Get-NetTCPConnection -State Listen -LocalPort 19200 `
        -ErrorAction SilentlyContinue) {
        throw 'STOP: stop the replacement tunnel before promoting its key'
    }
    $Secrets = Join-Path (Get-Location) '.secrets'
    $OldKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
    $OldPublic = "$OldKey.pub"
    $ReplacementKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519.replacement'
    $ReplacementPublic = "$ReplacementKey.pub"
    foreach ($Path in @($OldKey, $OldPublic, $ReplacementKey, $ReplacementPublic)) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "STOP: expected key file is absent: $Path"
        }
    }
    $OldFingerprint = ((& ssh-keygen.exe -lf $OldPublic -E sha256) -split '\s+')[1]
    if ($LASTEXITCODE -ne 0 -or
        $OldFingerprint -ne 'SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo') {
        throw 'STOP: old fingerprint calculation failed or drifted'
    }
    $NewFingerprint = ((& ssh-keygen.exe -lf $ReplacementPublic -E sha256) -split '\s+')[1]
    if ($LASTEXITCODE -ne 0 -or -not $NewFingerprint -or
        $OldFingerprint -eq $NewFingerprint) {
        throw 'STOP: replacement fingerprint is invalid or did not rotate'
    }
    if ((Read-Host 'Type the replacement fingerprint accepted in the VM proof') -cne $NewFingerprint) {
        throw 'STOP: candidate does not match the accepted replacement fingerprint'
    }
    $ResolvedSecrets = (Resolve-Path -LiteralPath $Secrets).Path
    foreach ($Path in @($OldKey, $OldPublic, $ReplacementKey, $ReplacementPublic)) {
        $Item = Get-Item -LiteralPath $Path
        if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            [System.IO.Path]::GetDirectoryName($Item.FullName) -ne $ResolvedSecrets) {
            throw 'STOP: key path is a link or outside the dedicated secrets directory'
        }
    }
    Remove-Item -LiteralPath $OldKey -Force -ErrorAction Stop
    Remove-Item -LiteralPath $OldPublic -Force -ErrorAction Stop
    Move-Item -LiteralPath $ReplacementKey -Destination $OldKey -ErrorAction Stop
    Move-Item -LiteralPath $ReplacementPublic -Destination $OldPublic -ErrorAction Stop
    $FinalFingerprint = ((& ssh-keygen.exe -lf $OldPublic -E sha256) -split '\s+')[1]
    if ($LASTEXITCODE -ne 0 -or $FinalFingerprint -ne $NewFingerprint) {
        throw 'STOP: promoted client-key fingerprint differs'
    }
    "PASS revoked local key files removed: $OldFingerprint"
    "PASS replacement key promoted to canonical path: $FinalFingerprint"
}
```

Restart the foreground tunnel using the canonical-key command in Section 9 of
the SSH transport runbook. Re-run the loopback-listener and paired TLS/read
proof with the replacement `assistant-svc` password, then all five denial
classes from Section 10: shell/command, PTY/session, remote forward, alternate
local destination and password-only authentication. The original blocks now
resolve to the replacement key at the canonical path. This final repetition
proves the restored canonical paths work and the denials are not caused by an
invalid old key. Stop every alternate-destination diagnostic tunnel afterward;
only the approved `127.0.0.1:19200` forward may remain.

## 10. Final state and evidence

First repeat the entire VM/Indexer preflight in Section 4.2 with the new
service password. It must again verify enrollment fingerprints, loopback
Indexer binding, exact role/mapping and scoped `own_index`, and the sanitized
unchanged `socanalyst` record/mapping. Existence-only HTTP `200` checks do not
establish that these policies stayed unchanged. Then run the final health
check at the VM console in the required order:

```bash
(
set -euo pipefail
test "$(systemctl is-enabled ssh.service)" = 'enabled'
test "$(systemctl is-active ssh.service)" = 'active'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
if systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH socket activation is active'; exit 1
fi
LISTENERS=$(sudo ss -ltnp | awk '$4 ~ /:22$/ {print}')
test "$(printf '%s\n' "$LISTENERS" | awk 'NF {n++} END {print n+0}')" -eq 1
printf '%s\n' "$LISTENERS" | grep -F '192.168.56.102:22' >/dev/null
for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  if [ "$state" != 'active' ]; then
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1
  fi
  printf 'PASS service health: %s=active\n' "$unit"
done
echo 'PASS final VM state: restricted SSH transport restored and Wazuh healthy'
)
```

Complete a copy of
[`evidence/rbac/phase1c-rollback-revocation-proof-template.md`](../../evidence/rbac/phase1c-rollback-revocation-proof-template.md)
using only sanitized results. Do not overwrite the template and do not call the
drill complete until the filled evidence, exact commit and contract tests have
received an independent `approve` review.

## 11. Stop conditions and containment

Stop immediately and remain fail-closed if:

- any stage directory or manifest differs;
- the current role, mapping, DLS, `own_index`, enrollment or service state has
  drifted;
- a password or private-key content appears in output, shell history, process
  arguments, an environment variable or an unintended file (the dedicated,
  ACL-protected ignored SSH private-key files are expected);
- the old service password authenticates after recreation;
- the old SSH key is accepted after replacement installation;
- the replacement identity gains any role before its reviewed mapping, or any
  role other than `alertmind_assistant_alerts_ro` afterward;
- any alert/index/document mutation occurs or a proof requires `_source`;
- SSH binds to NAT, wildcard or IPv6, or forwards outside VM
  `127.0.0.1:9200`;
- TLS requires `-k`, `--insecure`, `--ssl-no-revoke`, `verify=False` or warning
  suppression; or
- Wazuh Indexer, Manager, Filebeat or Dashboard is inactive.

Stopping a failing script does not itself undo an earlier successful
restoration step. After a failure in Sections 7–10, apply the following
containment, then report only sanitized results and await review. Do not
blindly rerun PUT/DELETE operations whose outcome is uncertain.

1. Stop the foreground Windows tunnel with Ctrl+C. If its window is
   inaccessible, use the process-identity checks in Section 6.1 to stop only
   that exact tunnel. Confirm TCP 19200 has no listener; do not kill an
   unrelated owner to obtain this result.
2. At the VM console, run the block below. It removes only this service
   mapping, not the user, custom role or any other mapping. A replacement user
   may remain unmapped while the failure is investigated.
3. If any containment check fails, do not claim a safe disabled state. Keep
   the console open, report the failed check and obtain a recovery review;
   do not broaden permissions or restore old credentials.

```bash
(
set -euo pipefail
SSH_STAGE="$HOME/alertmind-rbac-phase1c"
AUTH_KEYS='/home/notroot/.ssh/authorized_keys'
DROPIN='/etc/ssh/sshd_config.d/00-alertmind-transport.conf'
INDEXER_URL='https://127.0.0.1:9200'
INDEXER_CA='/etc/wazuh-indexer/certs/root-ca.pem'

sudo systemctl stop ssh.service ssh.socket
if [ "$(systemctl is-enabled ssh.service 2>/dev/null || true)" != 'masked' ]; then
  sudo systemctl disable ssh.service
fi
sudo systemctl mask ssh.service ssh.socket
test -f "$SSH_STAGE/rollback/authorized_keys.pre-phase1c"
test ! -L "$SSH_STAGE/rollback/authorized_keys.pre-phase1c"
test ! -s "$SSH_STAGE/rollback/authorized_keys.pre-phase1c"
sudo install -o notroot -g notroot -m 600 \
  "$SSH_STAGE/rollback/authorized_keys.pre-phase1c" "$AUTH_KEYS"
sudo rm -f "$DROPIN"
sudo systemctl daemon-reload
for unit in ssh.service ssh.socket; do
  test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = 'masked'
  if systemctl is-active --quiet "$unit"; then
    echo "STOP: containment left $unit active"; exit 1
  fi
done
test ! -s "$AUTH_KEYS"
if sudo ss -ltnp | grep -E ':(22)\b'; then
  echo 'STOP: TCP 22 remains during containment'; exit 1
fi
status=$(sudo curl --disable --noproxy '*' --silent --show-error \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  --request DELETE --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_assistant_alerts_ro")
case "$status" in 200|404) ;; *) echo "STOP containment mapping delete: HTTP $status"; exit 1;; esac
status=$(sudo curl --disable --noproxy '*' --silent --show-error \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/api/rolesmapping/alertmind_assistant_alerts_ro")
test "$status" = '404'
echo 'PASS containment: project mapping absent and SSH transport disabled'
status=$(sudo curl --disable --noproxy '*' --silent --show-error \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  --output /dev/null --write-out '%{http_code}' \
  "$INDEXER_URL/_plugins/_security/api/internalusers/assistant-svc")
case "$status" in
  404) echo 'PASS containment: service user is absent';;
  200)
    echo 'Enter the currently valid service password; a 401 is not a zero-role proof'
    sudo curl --disable --noproxy '*' --silent --show-error --fail-with-body \
      --connect-timeout 5 --max-time 30 \
      --cacert "$INDEXER_CA" --user assistant-svc \
      "$INDEXER_URL/_plugins/_security/authinfo" |
    python3 -c '
import json,sys
data=json.load(sys.stdin)
if data.get("user_name") != "assistant-svc" or data.get("roles") != []:
    raise SystemExit("STOP: contained service user still has an effective role")
print("PASS containment: service user authenticates with zero effective roles")
'
    ;;
  *) echo "STOP containment user lookup: HTTP $status"; exit 1;;
esac
for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  if [ "$state" != 'active' ]; then
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1
  fi
  printf 'PASS service health: %s=active\n' "$unit"
done
echo 'STOP POINT: no restoration retry until sanitized failure and containment are reviewed'
)
```

Before certifying containment, repeat only the scoped `own_index` readback
from Section 4.2. It must still exclude both AlertMind principals with every
alternate selector empty. A missing project mapping alone does not prove an
identity lacks access if inherited grants have drifted.

## References

- [OpenSearch Security REST API — users and role mappings](https://docs.opensearch.org/latest/security/access-control/api/)
- [OpenSearch users and roles](https://docs.opensearch.org/latest/security/access-control/users-roles/)
- [curl manual — explicit configuration, CA and proxy options](https://curl.se/docs/manpage.html)
- [Phase 1B Indexer setup and rollback gates](rbac-wazuh-read-only-setup.md)
- [Phase 1C restricted SSH transport](rbac-wazuh-ssh-transport.md)
