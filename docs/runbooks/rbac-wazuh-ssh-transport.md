# Runbook — Phase 1C restricted SSH transport

**Status:** reviewed package required; do not execute until an independent
reviewer approves the commit containing this file.

**Scope:** install OpenSSH Server on `wazuh-siem`, keep it inert throughout
installation, validate a host-only/local-forward-only policy, and only then
enable one listener at `192.168.56.102:22`. The Wazuh Indexer remains bound to
`127.0.0.1:9200`.

This runbook deliberately separates installation from enablement. A successful
package installation is not authority to start SSH. Stop after the pre-enable
proof and obtain human review of its output.

## 1. Fixed boundary

| Item | Required value |
|---|---|
| Windows host-only address | `192.168.56.1` |
| VM host-only address | `192.168.56.102` |
| SSH listener | `192.168.56.102:22` only |
| Advertised host key | existing ED25519 key only |
| Windows local endpoint | `127.0.0.1:19200` only |
| Forward destination | VM `127.0.0.1:9200` only |
| SSH principal | `notroot` |
| Authentication | dedicated, passphrase-protected Ed25519 key |
| Server package | `openssh-server=1:10.2p1-2ubuntu3.5` |
| Required companion package | `openssh-sftp-server=1:10.2p1-2ubuntu3.5` |
| Activation model | `ssh.service`; `ssh.socket` remains masked |

The server package ships both `ssh.service` and `ssh.socket` on this Ubuntu
release. Both activation paths are masked before installation. The classic
service is selected only after configuration proof so `ListenAddress` remains
the single listener authority.

Committed, secret-free inputs:

- `siem/rbac/sshd-alertmind.conf`
- `siem/rbac/ssh-authorized-key-options.txt`
- `siem/rbac/SSH-SHA256SUMS`

Never commit the generated public-key line, private key, copied Wazuh CA,
password, SSH verbose log or local runtime file.

Paste every PowerShell fence that starts with `& {` as one complete unit. The
interactive console buffers the statements until the closing brace; any
`throw` then exits that unit before later actions or PASS lines can run. Never
re-enter statements from the remainder of a block after a STOP.

## 2. Preconditions

Before any mutation, confirm all of the following:

- `Snapshot 1` remains available;
- the Phase 1B Indexer proof is merged and the live roles/mappings are
  unchanged;
- Postfix is absent, `dpkg --audit` is empty and `apt-get check` passes;
- `openssh-server` is not installed, `/usr/sbin/sshd` is absent and TCP 22 is
  not listening;
- `192.168.56.102` is assigned to `enp0s8`, and the route to `192.168.56.1`
  selects that interface and source address;
- the three existing host-key fingerprints equal the values in
  `evidence/rbac/phase1c-ssh-prerequisite-check.md`;
- `/home/notroot/.ssh/authorized_keys` contains zero key entries; and
- Wazuh Manager, Indexer, Filebeat and Dashboard are active.

Do not run `apt autoremove`. Do not regenerate or replace the existing SSH host
keys. Stop if the pinned package versions are unavailable or any precondition
has drifted.

## 3. Generate the dedicated key on Windows

Run from a fresh PowerShell at the repository root. The command moves into
`assistant/` and prompts for a passphrase; do not leave it blank.

```powershell
& {
    Set-Location .\assistant -ErrorAction Stop

    $Secrets = Join-Path (Get-Location) '.secrets'
    $PrivateKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
    $PublicKey = "$PrivateKey.pub"
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if ((Test-Path -LiteralPath $PrivateKey) -or
        (Test-Path -LiteralPath $PublicKey)) {
        throw "STOP: dedicated tunnel key already exists: $PrivateKey"
    }

    New-Item -ItemType Directory -Path $Secrets -Force -ErrorAction Stop | Out-Null
    & ssh-keygen.exe -t ed25519 -a 100 -f $PrivateKey `
      -C 'alertmind-wazuh-indexer-tunnel-2026-09-02'
    if ($LASTEXITCODE -ne 0) { throw 'STOP: ssh-keygen failed' }

    & icacls.exe $Secrets /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'STOP: secrets-directory ACL reset failed' }
    & icacls.exe $Secrets /grant:r `
      "${Identity}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'STOP: secrets-directory ACL grant failed' }
    & icacls.exe $PrivateKey /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'STOP: private-key ACL reset failed' }
    & icacls.exe $PrivateKey /grant:r "${Identity}:F" 'SYSTEM:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'STOP: private-key ACL grant failed' }

    $Fingerprint = (& ssh-keygen.exe -lf $PublicKey -E sha256)
    if ($LASTEXITCODE -ne 0) { throw 'STOP: public-key fingerprint failed' }
    $Fingerprint
}
```

Record only the `SHA256:...` public-key fingerprint. At the VM-console prompt
in Section 5, paste the single line from `$PublicKey`; never paste the private
key and never paste either key into chat or Git.

## 4. Stage the reviewed public configuration on the VM

Use the VirtualBox console/clipboard to create a new mode-`0700` staging
directory. Refuse to reuse an earlier attempt:

```bash
STAGE="$HOME/alertmind-rbac-phase1c"
if [ -e "$STAGE" ]; then
  echo "STOP: staging path already exists: $STAGE"
  exit 1
fi
install -d -m 700 "$STAGE"
```

Transfer the three committed SSH files byte for byte; do not retype or edit
the configuration. Then run:

```bash
(
set -euo pipefail
STAGE="$HOME/alertmind-rbac-phase1c"
test -d "$STAGE"
chmod 700 "$STAGE"
cd "$STAGE"
sha256sum -c SSH-SHA256SUMS
python3 -c 'import pathlib; p=pathlib.Path("sshd-alertmind.conf"); assert p.read_bytes().endswith(b"\n"); print("PASS config: LF text with final newline")'
awk 'NF {n++} END {if (n != 1) exit 1; print "PASS key-options: exactly one non-empty line"}' \
  ssh-authorized-key-options.txt
)
```

The reviewer may supply a base64 transfer envelope after approving this
package. Hash verification, not the transfer method, determines whether the
payload is acceptable.

## 5. Install the public key while SSH is still absent

Run at the VM console. This block refuses to replace an existing key entry and
requires the operator to compare the public-key fingerprint generated on
Windows.

```bash
(
set -euo pipefail
umask 077
STAGE="$HOME/alertmind-rbac-phase1c"
AUTH_KEYS='/home/notroot/.ssh/authorized_keys'
OPTIONS_FILE="$STAGE/ssh-authorized-key-options.txt"

cd "$STAGE"
sha256sum -c SSH-SHA256SUMS

entry_count=$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$AUTH_KEYS")
if [ "$entry_count" -ne 0 ]; then
  printf 'STOP: authorized_keys contains %s existing key entries\n' "$entry_count"
  exit 1
fi

install -d -m 700 "$STAGE/rollback"
cp --archive "$AUTH_KEYS" "$STAGE/rollback/authorized_keys.pre-phase1c"

read -r -p 'Paste the one-line Ed25519 PUBLIC key: ' PUBLIC_KEY
case "$PUBLIC_KEY" in
  ssh-ed25519\ *) ;;
  *) echo 'STOP: expected one ssh-ed25519 public-key line'; exit 1 ;;
esac

PUBLIC_ONLY=$(mktemp "$STAGE/public-key.XXXXXX")
AUTHORIZED=$(mktemp "$STAGE/authorized-keys.XXXXXX")
trap 'rm -f "$PUBLIC_ONLY" "$AUTHORIZED"' EXIT
printf '%s\n' "$PUBLIC_KEY" > "$PUBLIC_ONLY"
ACTUAL_FINGERPRINT=$(ssh-keygen -lf "$PUBLIC_ONLY" -E sha256 | awk '{print $2}')
read -r -p 'Type the SHA256 fingerprint shown on Windows: ' EXPECTED_FINGERPRINT
if [ "$ACTUAL_FINGERPRINT" != "$EXPECTED_FINGERPRINT" ]; then
  printf 'STOP: public-key fingerprint mismatch; VM=%s\n' "$ACTUAL_FINGERPRINT"
  exit 1
fi

OPTIONS=$(cat "$OPTIONS_FILE")
printf '%s %s\n' "$OPTIONS" "$PUBLIC_KEY" > "$AUTHORIZED"
sudo install -o notroot -g notroot -m 600 "$AUTHORIZED" "$AUTH_KEYS"

installed_count=$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$AUTH_KEYS")
test "$installed_count" -eq 1
INSTALLED_FINGERPRINT=$(ssh-keygen -lf "$AUTH_KEYS" -E sha256 | awk '{print $2}')
test "$INSTALLED_FINGERPRINT" = "$EXPECTED_FINGERPRINT"

printf 'PASS public-key fingerprint: %s\n' "$INSTALLED_FINGERPRINT"
echo 'PASS authorized_keys: one restricted Ed25519 key, mode 0600'
)
```

The committed prefix adds five cumulative controls:

```text
from="192.168.56.1",restrict,port-forwarding,permitopen="127.0.0.1:9200",command="/bin/false"
```

`restrict` disables forwarding, PTY, agent/X11 forwarding and user RC by
default. `port-forwarding` re-enables TCP forwarding generally;
`permitopen` bounds local-forward destinations; the server's
`AllowTcpForwarding local` blocks remote forwards; `from` restricts the source;
and the forced command prevents command/shell use. Server-side `PermitOpen`,
`MaxSessions 0` and `ForceCommand /bin/false` provide defense in depth. The
drop-in ends with `Match all` so its conditional context cannot leak into a
later drop-in or the remainder of the package's main configuration file.

## 6. Mask both activation paths, stage configuration and install

First run the exact read-only simulation below. It must propose the two pinned
SSH packages only (plus no new package other than a mandatory dependency that
is explicitly reviewed), with no upgrade, removal, `autoremove` or unrelated
configuration action:

```bash
(
set -euo pipefail
apt-cache policy openssh-server openssh-sftp-server
sudo apt-get --simulate install --no-install-recommends \
  openssh-server=1:10.2p1-2ubuntu3.5 \
  openssh-sftp-server=1:10.2p1-2ubuntu3.5
echo 'STOP POINT: send the complete simulation output for review'
)
```

Do not continue in the same session. After the simulation output is accepted,
the following block is the first package mutation. It intentionally creates
persistent masks before APT can install or start either unit.

```bash
(
set -euo pipefail
STAGE="$HOME/alertmind-rbac-phase1c"
DROPIN='/etc/ssh/sshd_config.d/00-alertmind-transport.conf'

cd "$STAGE"
sha256sum -c SSH-SHA256SUMS

test "$(dpkg-query -W -f='${Status}' postfix 2>/dev/null || true)" != \
  'install ok installed'
test "$(dpkg-query -W -f='${Status}' openssh-server 2>/dev/null || true)" != \
  'install ok installed'
test ! -x /usr/sbin/sshd
AUDIT=$(sudo dpkg --audit)
if [ -n "$AUDIT" ]; then
  printf '%s\n' "$AUDIT"
  echo 'STOP: dpkg audit is not empty'
  exit 1
fi
sudo apt-get check

ip -brief -4 address show dev enp0s8 | grep -F '192.168.56.102/24'
ip route get 192.168.56.1 | grep -F \
  '192.168.56.1 dev enp0s8 src 192.168.56.102'

if sudo test -e "$DROPIN"; then
  printf 'STOP: transport drop-in already exists: %s\n' "$DROPIN"
  exit 1
fi

for unit in ssh.service ssh.socket; do
  target="/etc/systemd/system/$unit"
  if [ -e "$target" ] || [ -L "$target" ]; then
    printf 'STOP: pre-existing unit override/mask: %s\n' "$target"
    exit 1
  fi
  sudo ln -s /dev/null "$target"
done
sudo systemctl daemon-reload

sudo install -d -o root -g root -m 755 /etc/ssh/sshd_config.d
sudo install -o root -g root -m 644 \
  "$STAGE/sshd-alertmind.conf" "$DROPIN"

sudo env DEBIAN_FRONTEND=noninteractive \
  apt-get install --yes --no-install-recommends \
  openssh-server=1:10.2p1-2ubuntu3.5 \
  openssh-sftp-server=1:10.2p1-2ubuntu3.5

test "$(dpkg-query -W -f='${Status}' openssh-server)" = \
  'install ok installed'
test "$(dpkg-query -W -f='${Version}' openssh-server)" = \
  '1:10.2p1-2ubuntu3.5'
test "$(dpkg-query -W -f='${Status}' openssh-sftp-server)" = \
  'install ok installed'
test "$(dpkg-query -W -f='${Version}' openssh-sftp-server)" = \
  '1:10.2p1-2ubuntu3.5'

for unit in ssh.service ssh.socket; do
  state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
  test "$state" = 'masked'
  if systemctl is-active --quiet "$unit"; then
    printf 'STOP: %s became active during installation\n' "$unit"
    exit 1
  fi
  printf 'PASS %s: masked and inactive\n' "$unit"
done

# Ubuntu ships sshd.service as a full alias of ssh.service. Prove that the
# alias resolves to the same masked unit, rather than treating it as an
# unaccounted third activation path.
test "$(systemctl is-enabled sshd.service 2>/dev/null || true)" = 'masked'
! systemctl is-active --quiet sshd.service
test "$(systemctl show -p FragmentPath --value ssh.service)" = \
  "$(systemctl show -p FragmentPath --value sshd.service)"
if systemctl list-units --type=service --state=active --no-legend \
  'sshd@*.service' | grep -q .; then
  echo 'STOP: a per-connection sshd@ service is active'
  exit 1
fi
echo 'PASS sshd.service: masked alias; no active sshd@ instance'

if sudo ss -ltnp | grep -E ':(22)\b'; then
  echo 'STOP: TCP 22 opened during installation'
  exit 1
fi

cmp --silent "$STAGE/sshd-alertmind.conf" "$DROPIN"
grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf([[:space:]]|$)' \
  /etc/ssh/sshd_config

echo 'PASS: pinned packages installed while both SSH activation paths remained inert'
)
```

If APT proposes any package other than the two pinned SSH packages and their
already reviewed mandatory dependencies, stop. `ncurses-term`, `ssh-import-id`
and any `autoremove` operation are outside this gate.

## 7. Pre-enable configuration and host-key proof

Run while both units remain masked. It validates the parser, every critical
effective setting, the `Match` scope control and the pre-existing host keys.

```bash
(
set -euo pipefail

require_line() {
  file="$1"
  expected="$2"
  if ! grep -Fxq "$expected" "$file"; then
    printf 'STOP: effective configuration lacks: %s\n' "$expected"
    exit 1
  fi
  printf 'PASS config: %s\n' "$expected"
}

for unit in ssh.service ssh.socket; do
  test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = 'masked'
  ! systemctl is-active --quiet "$unit"
done

sudo /usr/sbin/sshd -t

TARGET=$(mktemp)
CONTROL=$(mktemp)
trap 'rm -f "$TARGET" "$CONTROL"' EXIT

sudo /usr/sbin/sshd -T -C \
  user=notroot,host=wazuh-siem,addr=192.168.56.1,laddr=192.168.56.102,lport=22 \
  > "$TARGET"
sudo /usr/sbin/sshd -T -C \
  user=root,host=wazuh-siem,addr=192.168.56.1,laddr=192.168.56.102,lport=22 \
  > "$CONTROL"

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
  require_line "$TARGET" "$line"
done

mapfile -t EFFECTIVE_HOST_KEYS < <(awk '$1 == "hostkey" {print}' "$TARGET")
if [ "${#EFFECTIVE_HOST_KEYS[@]}" -ne 1 ] ||
   [ "${EFFECTIVE_HOST_KEYS[0]}" != \
     'hostkey /etc/ssh/ssh_host_ed25519_key' ]; then
  printf 'STOP: expected exactly one effective ED25519 host key; got:\n%s\n' \
    "$(printf '%s\n' "${EFFECTIVE_HOST_KEYS[@]}")"
  exit 1
fi
echo 'PASS host-key policy: exactly one effective ED25519 key'

for line in \
  'allowtcpforwarding no' \
  'permitopen none' \
  'maxsessions 0' \
  'permittty no' \
  'forcecommand /bin/false'
do
  require_line "$CONTROL" "$line"
done
if grep -Fxq 'allowtcpforwarding local' "$CONTROL"; then
  echo 'STOP: Match restriction leaked into the different-user control'
  exit 1
fi

check_host_key() {
  file="$1"
  expected="$2"
  actual=$(ssh-keygen -lf "$file" -E sha256 | awk '{print $2}')
  test "$actual" = "$expected"
  printf 'PASS host key %s: %s\n' "$(basename "$file")" "$actual"
}

check_host_key /etc/ssh/ssh_host_ecdsa_key.pub \
  'SHA256:WJ5DThrIkXPqEVqH1PBSe14Cn0+W+NX8nNANKWjy6ik'
check_host_key /etc/ssh/ssh_host_ed25519_key.pub \
  'SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag'
check_host_key /etc/ssh/ssh_host_rsa_key.pub \
  'SHA256:Feh+HT0e1W4nkFFjzd/xlbnN5qmXoFi3aaTRCMPmo0s'

if sudo ss -ltnp | grep -E ':(22)\b'; then
  echo 'STOP: TCP 22 is listening before enablement'
  exit 1
fi

sudo systemctl is-active wazuh-manager wazuh-indexer filebeat wazuh-dashboard
echo 'PASS: pre-enable proof complete; SSH remains masked and stopped'
echo 'STOP POINT: do not unmask or enable SSH until this output is reviewed'
)
```

Record only the PASS lines, package versions, public fingerprints, the target
forwarding result and the five non-matching control denials. Do not commit the
complete effective configuration.

## 8. Enable only the classic service after output review

Execute this block only after the pre-enable output is accepted. The socket
unit remains masked.

```bash
(
set -euo pipefail

test "$(systemctl is-enabled ssh.service 2>/dev/null || true)" = 'masked'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
sudo /usr/sbin/sshd -t

sudo systemctl unmask ssh.service
sudo systemctl enable --now ssh.service

test "$(systemctl is-enabled ssh.service)" = 'enabled'
test "$(systemctl is-active ssh.service)" = 'active'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
! systemctl is-active --quiet ssh.socket
test "$(systemctl is-active sshd.service)" = 'active'
test "$(systemctl show -p FragmentPath --value ssh.service)" = \
  "$(systemctl show -p FragmentPath --value sshd.service)"
if systemctl list-units --type=service --state=active --no-legend \
  'sshd@*.service' | grep -q .; then
  echo 'STOP: a per-connection sshd@ service is active'
  sudo systemctl disable --now ssh.service
  sudo systemctl mask ssh.service
  exit 1
fi

LISTENERS=$(sudo ss -ltnp | awk '$4 ~ /:22$/ {print}')
printf '%s\n' "$LISTENERS"
test "$(printf '%s\n' "$LISTENERS" | awk 'NF {n++} END {print n+0}')" -eq 1
printf '%s\n' "$LISTENERS" | grep -F '192.168.56.102:22'
if printf '%s\n' "$LISTENERS" | grep -E '0\\.0\\.0\\.0:22|10\\.0\\.2\\.15:22|\\[::\\]:22'; then
  echo 'STOP: SSH has a forbidden wildcard, NAT or IPv6 listener'
  sudo systemctl disable --now ssh.service
  sudo systemctl mask ssh.service
  exit 1
fi

sudo systemctl is-active wazuh-manager wazuh-indexer filebeat wazuh-dashboard
echo 'PASS: one host-only SSH listener active; ssh.socket remains masked'
)
```

If any check fails, execute the immediate rollback in Section 11 from the VM
console. Do not troubleshoot by broadening `ListenAddress`, `AllowUsers`,
`AllowTcpForwarding`, `PermitOpen` or an authorized-key restriction.

## 9. Pin the server host key and start the Windows-loopback tunnel

From PowerShell in `assistant/`, obtain only the advertised ED25519 public host
key, compare it to the console-established fingerprint, and promote it to the
dedicated known-hosts file only on an exact match. In the characterized Windows
host, the inbox OpenSSH 9.5 `ssh-keyscan.exe` reaches OpenSSH 10.2 but aborts
after the server selects `sntrup761x25519-sha512@openssh.com`. Use the already
installed Git for Windows OpenSSH 10.2 scanner in quiet mode; do not change the
server KEX list to accommodate the older scanner. The wrapper deliberately
does not set `$ErrorActionPreference = 'Stop'` because the scanner's native
stderr is redirected; an explicit `throw` still exits the complete block:

```powershell
& {
    $Secrets = Join-Path (Get-Location) '.secrets'
    $Candidate = Join-Path $Secrets 'wazuh-siem_known_hosts.candidate'
    $KnownHosts = Join-Path $Secrets 'wazuh-siem_known_hosts'
    $Keyscan = 'C:\Program Files\Git\usr\bin\ssh-keyscan.exe'
    $Keygen = 'C:\Program Files\Git\usr\bin\ssh-keygen.exe'

    if (-not (Test-Path -LiteralPath $Keyscan -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Keygen -PathType Leaf)) {
        throw 'STOP: compatible Git for Windows OpenSSH 10.2 tools are absent'
    }
    if ((Test-Path -LiteralPath $Candidate) -or
        (Test-Path -LiteralPath $KnownHosts)) {
        throw "STOP: known-hosts file already exists: $KnownHosts"
    }

    $ScanOutput = @(
        & $Keyscan -q -T 10 -p 22 -t ed25519 192.168.56.102 2>$null
    )
    $ScanExit = $LASTEXITCODE
    $CandidateLines = @($ScanOutput | Where-Object { $_.Trim().Length -gt 0 })
    if ($ScanExit -ne 0 -or $CandidateLines.Count -ne 1) {
        throw "STOP: expected exactly one ED25519 key record; got $($CandidateLines.Count)"
    }
    $KeyPattern = '^(?:192\.168\.56\.102|\[192\.168\.56\.102\]:22)\s+ssh-ed25519\s+\S+'
    if ($CandidateLines[0] -notmatch $KeyPattern) {
        throw 'STOP: scanner returned an unexpected host-key record'
    }
    $CandidateLines | Set-Content -LiteralPath $Candidate -Encoding ascii `
      -ErrorAction Stop
    $Observed = ((& $Keygen -lf $Candidate -E sha256) -split '\s+')[1]
    if ($Observed -ne 'SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag') {
        throw "STOP: SSH host-key mismatch: $Observed"
    }
    Move-Item -LiteralPath $Candidate -Destination $KnownHosts `
      -ErrorAction Stop
    "PASS SSH host key: $Observed"
}
```

In the first PowerShell window, start the tunnel in the foreground and leave
that window open:

```powershell
$Secrets = Join-Path (Get-Location) '.secrets'
$PrivateKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
$KnownHosts = Join-Path $Secrets 'wazuh-siem_known_hosts'
$SshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'

& $SshExe -N -T `
  -o KexAlgorithms=curve25519-sha256 `
  -o HostKeyAlgorithms=ssh-ed25519 `
  -o ExitOnForwardFailure=yes `
  -o IdentitiesOnly=yes `
  -o StrictHostKeyChecking=yes `
  -o "UserKnownHostsFile=$KnownHosts" `
  -o ServerAliveInterval=30 `
  -o ServerAliveCountMax=3 `
  -i $PrivateKey `
  -L '127.0.0.1:19200:127.0.0.1:9200' `
  'notroot@192.168.56.102'
```

The terminal should remain open silently after the key passphrase is entered.
In a second PowerShell window, prove the local listener is loopback-only.
Windows PowerShell 5.1 returns a single matching CIM instance as a scalar, so
the command must normalize the result with `@(...)` before checking `Count`.
Paste the complete invoked script block as one unit; a `STOP` invalidates the
proof and the trailing PASS must not be entered separately:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Listener = @(
        Get-NetTCPConnection -State Listen -LocalPort 19200
    )
    if ($Listener.Count -ne 1 -or $Listener.LocalAddress -ne '127.0.0.1') {
        throw "STOP: unexpected tunnel listener: $($Listener | Out-String)"
    }
    'PASS Windows tunnel listener: 127.0.0.1:19200 only'
}
```

## 10. TLS/read proof and transport denials

Copy only the public Wazuh root CA to ignored
`assistant/.certs/root-ca.pem`. Never copy an Indexer private key. Verify its
DER SHA-256 fingerprint with the installed Git for Windows OpenSSL before use.
The block keeps terminating-error behaviour for PowerShell failures but leaves
OpenSSL's native stderr unmerged, so its diagnostic remains visible and the
explicit native exit-code check remains reachable:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Ca = Join-Path (Get-Location) '.certs\root-ca.pem'
    $Expected = 'EB98A4AF38CDA550D473E5659A4375905334041FAB4597F39C4F191D9E6F5E1D'
    $OpenSsl = 'C:\Program Files\Git\usr\bin\openssl.exe'
    $Fingerprint = (& $OpenSsl x509 -in $Ca -noout -fingerprint -sha256) -join ''
    $OpenSslExit = $LASTEXITCODE
    if ($OpenSslExit -ne 0) {
        throw "STOP: Wazuh CA fingerprint calculation failed with OpenSSL exit $OpenSslExit; see native diagnostic above"
    }
    if ($Fingerprint -notmatch 'Fingerprint=([0-9A-Fa-f:]+)') {
        throw "STOP: Wazuh CA fingerprint output was not recognized: $Fingerprint"
    }
    $Actual = ($Matches[1] -replace ':', '').ToUpperInvariant()
    if ($Actual -ne $Expected) {
        throw "STOP: Wazuh CA fingerprint mismatch: $Actual"
    }
    "PASS Wazuh CA SHA-256: $Actual"
}
```

The characterized CA publishes neither a CRL distribution point nor Authority
Information Access. Windows curl 8.21 uses Schannel, whose default revocation
check therefore stops with `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`. For this
Phase 1C transport proof only, use `--ssl-revoke-best-effort`: curl documents
that this ignores revocation failures caused by missing or offline distribution
points. It does not disable peer or hostname verification. For this chain the
missing revocation locations are not a transient outage: best-effort accepts
unknown revocation status on every use for the life of the chain unless it is
replaced, so the revocation check provides no protection for this chain. Never
substitute `--ssl-no-revoke`, `--insecure` or `-k`; the final application TLS
context still requires its own reviewed certificate-chain or compatibility
decision.

First run the negative leg by connecting the tunnel to a deliberately wrong
HTTPS name. Curl exit 60 is a generic peer-certificate authentication failure;
the negative leg alone does not isolate hostname verification from another CA
or chain failure. It must be paired with the immediately following positive leg,
which uses the same tunnel, CA and revocation policy with the correct certificate
identity. This negative leg must fail before any HTTP request or credential is
sent. Do not merge native stderr into the success stream with `2>&1`: Windows
PowerShell 5.1 converts redirected native stderr into an error record, which
would terminate this invoked block before it can inspect curl's expected exit
code:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Ca = Join-Path (Get-Location) '.certs\root-ca.pem'
    $Curl = 'C:\Windows\System32\curl.exe'
    & $Curl --silent --show-error `
      --connect-timeout 5 --max-time 10 `
      --cacert $Ca --ssl-revoke-best-effort `
      --noproxy '*' `
      --resolve 'alertmind-hostname-check.invalid:19200:127.0.0.1' `
      'https://alertmind-hostname-check.invalid:19200/'
    $MismatchExit = $LASTEXITCODE
    if ($MismatchExit -ne 60) {
        throw "STOP: expected hostname mismatch exit 60; got $MismatchExit"
    }
    'PASS TLS negative leg: peer authentication rejected with curl exit 60'
}
```

Then issue a bounded, body-free search through the tunnel. Curl prompts for
the `assistant-svc` password; do not place it in the command or environment.
The first post-merge attempt on Windows PowerShell 5.1 passed the JSON literal
as an inline native-command argument. PowerShell removed its embedded field-name
quotes, and OpenSearch rejected the resulting `{size...}` body with an HTTP 400
`json_parse_exception` at column 2. Write the fixed, non-secret query to a
temporary UTF-8 file without a byte-order mark and pass curl an `@file`
argument instead. The `finally` block removes that file on both success and
failure. Paste and execute this entire invoked script block as one unit:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Ca = Join-Path (Get-Location) '.certs\root-ca.pem'
    $Curl = 'C:\Windows\System32\curl.exe'
    $Runtime = Join-Path (Get-Location) '.runtime'
    $QueryFile = Join-Path $Runtime 'wazuh-size0-query.json'
    $QueryJson = '{"size":0,"query":{"terms":{"agent.id":["001","002"]}}}'

    New-Item -ItemType Directory -Path $Runtime -Force -ErrorAction Stop | Out-Null
    if (Test-Path -LiteralPath $QueryFile) {
        throw "STOP: prior query file exists: $QueryFile"
    }

    try {
        $Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($QueryFile, $QueryJson, $Utf8NoBom)
        $BodyArgument = "@$QueryFile"
        $ResponseText = @(
          & $Curl --silent --show-error --fail-with-body `
            --connect-timeout 5 --max-time 30 `
            --cacert $Ca --ssl-revoke-best-effort `
            --noproxy '*' --user assistant-svc `
            --header 'Content-Type: application/json' `
            --request POST `
            --data-binary $BodyArgument `
            'https://127.0.0.1:19200/wazuh-alerts-4.x-*/_search?filter_path=_shards.failed,hits.total'
        ) -join "`n"
        $CurlExit = $LASTEXITCODE
        if ($CurlExit -ne 0) {
            throw "STOP: tunneled TLS/read proof failed with curl exit $CurlExit"
        }
    } finally {
        if (Test-Path -LiteralPath $QueryFile) {
            Remove-Item -LiteralPath $QueryFile -Force
        }
    }

    try {
        $Metadata = $ResponseText | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'STOP: tunneled TLS/read proof did not return valid JSON metadata'
    }
    if ($null -eq $Metadata._shards.failed -or
        $null -eq $Metadata.hits.total.value -or
        $null -eq $Metadata.hits.total.relation) {
        throw 'STOP: tunneled TLS/read proof returned incomplete metadata'
    }
    $FailedShards = [int64]$Metadata._shards.failed
    $VisibleHits = [int64]$Metadata.hits.total.value
    $HitRelation = [string]$Metadata.hits.total.relation
    if ($FailedShards -ne 0) {
        throw "STOP: tunneled search reported $FailedShards failed shards"
    }
    if ($VisibleHits -lt 0 -or $HitRelation -notin @('eq', 'gte')) {
        throw 'STOP: tunneled search returned unexpected hit-count metadata'
    }
    "PASS TLS positive leg: correct certificate identity 127.0.0.1 accepted; failed_shards=$FailedShards; visible_hits=$VisibleHits; relation=$HitRelation"
}
```

The response may contain only shard-failure and hit-count metadata. Do not
request or paste `_source`.

Only when both PASS lines are present from the unchanged tunnel, CA and
revocation-policy setup may the pair be recorded as evidence that the wrong
hostname was rejected while the correct certificate identity was accepted. If
the negative leg returns 60 but the positive leg fails, hostname verification
has not been isolated.

After that positive authentication/forwarding proof, define the same identity
and pinned host-key options in the second PowerShell window:

```powershell
$Secrets = Join-Path (Get-Location) '.secrets'
$PrivateKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
$KnownHosts = Join-Path $Secrets 'wazuh-siem_known_hosts'
$SshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
$SshOptions = @(
    '-o', 'KexAlgorithms=curve25519-sha256',
    '-o', 'HostKeyAlgorithms=ssh-ed25519',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$KnownHosts",
    '-i', $PrivateKey
)
$Destination = 'notroot@192.168.56.102'
```

Run the first three denials. Each may prompt for the dedicated key passphrase.
They must fail after the earlier positive proof established that the same key
can authenticate and open the approved local forward. These denial wrappers do
not set `$ErrorActionPreference = 'Stop'`: their expected SSH diagnostics are
captured with `2>&1`, which Windows PowerShell 5.1 represents as error records.
An explicit `throw` still exits the complete invoked block and prevents every
later denial or PASS in that block from running:

```powershell
& {
    $Marker = 'ALERTMIND_SHELL_SHOULD_NOT_RUN'
    $ShellOutput = & $SshExe @SshOptions -T $Destination "echo $Marker" 2>&1
    $ShellExit = $LASTEXITCODE
    if ($ShellExit -eq 0 -or (($ShellOutput -join "`n") -match $Marker)) {
        throw 'STOP: shell/command request was not denied'
    }
    "PASS denied shell/command: exit $ShellExit; marker absent"

    $PtyOutput = & $SshExe @SshOptions -tt $Destination "echo $Marker" 2>&1
    $PtyExit = $LASTEXITCODE
    if ($PtyExit -eq 0 -or (($PtyOutput -join "`n") -match $Marker)) {
        throw 'STOP: PTY/session request was not denied'
    }
    "PASS denied PTY/session: exit $PtyExit; marker absent"

    $RemoteOutput = & $SshExe @SshOptions -N -T `
        -o ExitOnForwardFailure=yes `
        -R '127.0.0.1:19201:127.0.0.1:9200' `
        $Destination 2>&1
    $RemoteExit = $LASTEXITCODE
    if ($RemoteExit -eq 0) {
        throw 'STOP: remote-forward request was not denied'
    }
    "PASS denied remote forward: exit $RemoteExit"
}
```

For the alternate local destination, first prove TCP 19201 is unused. Then run
this foreground command in a third PowerShell window; enter the key passphrase
and leave it open:

```powershell
& {
    $Secrets = Join-Path (Get-Location) '.secrets'
    $PrivateKey = Join-Path $Secrets 'wazuh-indexer-tunnel_ed25519'
    $KnownHosts = Join-Path $Secrets 'wazuh-siem_known_hosts'
    $SshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
    $SshOptions = @(
        '-o', 'KexAlgorithms=curve25519-sha256',
        '-o', 'HostKeyAlgorithms=ssh-ed25519',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$KnownHosts",
        '-i', $PrivateKey
    )
    $Destination = 'notroot@192.168.56.102'
    if (Get-NetTCPConnection -State Listen -LocalPort 19201 -ErrorAction SilentlyContinue) {
        throw 'STOP: diagnostic port 19201 is already in use'
    }
    $Runtime = Join-Path (Get-Location) '.runtime'
    New-Item -ItemType Directory -Path $Runtime -Force -ErrorAction Stop | Out-Null
    $AltLog = Join-Path $Runtime 'ssh-alternate-destination.log'
    if (Test-Path -LiteralPath $AltLog) {
        throw "STOP: prior diagnostic log exists: $AltLog"
    }
    & $SshExe @SshOptions -vv -N -T `
        -L '127.0.0.1:19201:127.0.0.1:443' `
        $Destination 2>&1 | Tee-Object -LiteralPath $AltLog -ErrorAction Stop
}
```

From the second window, make one connection to trigger the forwarding request:

```powershell
curl.exe --silent --show-error --connect-timeout 5 --max-time 5 `
  'https://127.0.0.1:19201/' 2>&1 | Out-Null
```

Return to the third window, stop SSH with Ctrl+C, then verify and remove the
local diagnostic log. The verifier recomputes the fixed ignored path because
variables created inside the foreground wrapper do not escape its child scope:

```powershell
& {
    $Runtime = Join-Path (Get-Location) '.runtime'
    $AltLog = Join-Path $Runtime 'ssh-alternate-destination.log'
    if (-not (Test-Path -LiteralPath $AltLog -PathType Leaf)) {
        throw "STOP: alternate-destination diagnostic log is absent: $AltLog"
    }
    $Denied = Select-String -LiteralPath $AltLog `
        -SimpleMatch 'administratively prohibited' -ErrorAction Stop
    if (-not $Denied) {
        throw 'STOP: alternate-destination denial was not observed'
    }
    Remove-Item -LiteralPath $AltLog -ErrorAction Stop
    'PASS denied alternate local destination: 127.0.0.1:443; diagnostic log removed'
}
```

Finally prove that password-only authentication is unavailable, without
allowing a password prompt:

```powershell
& {
    $PasswordOptions = @(
        '-o', 'KexAlgorithms=curve25519-sha256',
        '-o', 'HostKeyAlgorithms=ssh-ed25519',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'PasswordAuthentication=yes',
        '-o', 'NumberOfPasswordPrompts=0',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$KnownHosts"
    )
    $PasswordOutput = & $SshExe @PasswordOptions -T $Destination 'true' 2>&1
    $PasswordExit = $LASTEXITCODE
    if ($PasswordExit -eq 0) {
        throw 'STOP: password-only authentication unexpectedly succeeded'
    }
    "PASS denied password-only authentication: exit $PasswordExit"
}
```

Every forwarding/session result is non-vacuous only because the same key first completed
the positive local-forward proof. Do not treat an authentication failure as a
forwarding-policy proof.

The reviewer must see sanitized outcomes only: exit status, requested class,
expected denial and public fingerprint. Do not commit verbose SSH output.

## 11. Immediate rollback

Run from the VM console, not through the tunnel:

```bash
(
set -euo pipefail
STAGE="$HOME/alertmind-rbac-phase1c"

sudo systemctl disable --now ssh.service 2>/dev/null || true
sudo systemctl mask ssh.service ssh.socket
sudo install -o notroot -g notroot -m 600 \
  "$STAGE/rollback/authorized_keys.pre-phase1c" \
  /home/notroot/.ssh/authorized_keys
sudo rm -f /etc/ssh/sshd_config.d/00-alertmind-transport.conf
sudo systemctl daemon-reload

test "$(systemctl is-enabled ssh.service 2>/dev/null || true)" = 'masked'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
! systemctl is-active --quiet ssh.service
! systemctl is-active --quiet ssh.socket
if sudo ss -ltnp | grep -E ':(22)\b'; then
  echo 'STOP: TCP 22 still listening after rollback'
  exit 1
fi
test "$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' \
  /home/notroot/.ssh/authorized_keys)" -eq 0
sudo systemctl is-active wazuh-manager wazuh-indexer filebeat wazuh-dashboard
echo 'PASS: SSH listener/config/key access rolled back; packages remain inert'
)
```

This rollback intentionally leaves the two installed OpenSSH packages in an
inert, masked state. Package removal is a separate destructive decision and
must not use `autoremove`. Preserve the existing host keys unless the entire VM
is restored from `Snapshot 1`.

On Windows, stop every tunnel process and delete/revoke the dedicated private
key, candidate/known-hosts file, copied CA and runtime logs if the transport is
abandoned. Do not reuse the key after rollback.

## 12. Stop conditions

Stop immediately if any of these occurs:

- APT proposes an unreviewed version or unrelated package operation.
- Either SSH unit starts before the configuration proof.
- Any existing host-key fingerprint changes.
- `sshd -t` fails or target/control `sshd -T -C` output differs.
- TCP 22 listens on NAT, wildcard or IPv6 rather than only
  `192.168.56.102`.
- The key opens a shell/PTY, permits `-R`, or reaches a destination other than
  `127.0.0.1:9200`.
- The Windows forward binds outside `127.0.0.1`.
- TLS requires `-k`, `verify=False`, warning suppression or a private
  certificate key.
- Any Wazuh service becomes inactive.

Do not broaden the policy to make a failed test pass. Roll back and open a new
author/reviewer cycle.

## References

- [OpenSSH `sshd_config`](https://man.openbsd.org/sshd_config)
- [OpenSSH `authorized_keys` format](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT)
- [Ubuntu OpenSSH socket activation](https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189/5)
- [Ubuntu 26.04 `openssh-server` package files](https://packages.ubuntu.com/resolute-updates/amd64/openssh-server/filelist)
- [curl `--ssl-revoke-best-effort`](https://curl.se/docs/manpage.html#--ssl-revoke-best-effort)
