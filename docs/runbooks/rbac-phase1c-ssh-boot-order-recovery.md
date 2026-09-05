# Runbook — Phase 1C SSH boot-order recovery

**Status:** Secret-free recovery package; not yet owner-executed or independently
reviewed. It is not authority to mutate the VM until the commit containing this
file receives an independent `approve` review.

**Scope:** preserve the accepted host-only/local-forward-only SSH policy while
ordering `ssh.service` after `network-online.target`, then revalidate the
Ubuntu security-update package pair and the complete transport boundary across
one controlled reboot. This is maintenance of the implemented transport, not
Wazuh application integration and not the pending rollback/revocation drill.

## 1. Why this recovery exists

The accepted transport proof used
`openssh-server`/`openssh-sftp-server` `1:10.2p1-2ubuntu3.5`. A later system
update installed `1:10.2p1-2ubuntu3.6`. On the first observed reboot after that
update:

- `ssh.service` started at `2026-09-05 01:26:17.376 +05:30`;
- NetworkManager did not begin activating `enp0s8` until
  `01:26:17.391`;
- the DHCP lease for `192.168.56.102` was pending at `01:26:17.495` and the
  address became active at `01:26:17.669`; and
- the SSH main process exited with status `255` at `01:26:17.531`.

`ExecStartPre=/usr/sbin/sshd -t` succeeded. The package-owned unit and files
passed `dpkg --verify`, and the unit declares `RuntimeDirectory=sshd`. The
later absence of `/run/sshd` is consistent with cleanup after the failed unit,
not evidence of a missing-directory root cause at startup. Starting the
same service after `enp0s8` was active restored exactly one listener at
`192.168.56.102:22`; `ssh.socket` remained masked and all four Wazuh services
remained active.

The service currently has `After=network.target` but no dependency on
`network-online.target`. The chronology strongly supports a bind-before-address
race, although the captured journal does not contain an explicit bind error.
Do not work around it by adding a wildcard, NAT or IPv6 listener,
manually persisting `/run/sshd`, enabling socket activation, or weakening any
SSH restriction.

`network-online.target` is a startup synchronization point, not a continuing
connectivity guarantee. The enabled NetworkManager wait service waits for
startup to finish, which can include failed connections; IPv4/IPv6 profile
settings also affect when it declares completion. This minimal ordering change
must therefore pass the actual IPv4 listener and reboot proofs below; it is
not a promise of availability after network loss. No NetworkManager profile,
wait timeout, retry policy or package version is changed by this package.
See the [NetworkManager wait-online documentation](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager-wait-online.service.html)
and [systemd network-target guidance](https://systemd.io/NETWORK_ONLINE/).

## 2. Fixed boundary

| Item | Required value |
|---|---|
| Current OpenSSH packages | `1:10.2p1-2ubuntu3.6` |
| Service-ordering drop-in | `/etc/systemd/system/ssh.service.d/10-alertmind-network-online.conf` |
| Required ordering | `Wants=network-online.target`; `After=network-online.target` |
| Activation model | `ssh.service` enabled; `ssh.socket` masked |
| SSH listener | `192.168.56.102:22` only |
| Windows forward | `127.0.0.1:19200` to VM `127.0.0.1:9200` only |
| Existing SSH policy | exact accepted `00-alertmind-transport.conf` and authorized-key restriction |
| Indexer listener | one loopback listener at `127.0.0.1:9200` or its IPv4-mapped form |

Additive committed inputs:

- `siem/rbac/ssh-service-network-online.conf`; and
- `siem/rbac/SSH-BOOT-ORDER-SHA256SUMS`.

The accepted `siem/rbac/SSH-SHA256SUMS` and
`evidence/rbac/phase1c-ssh-transport-proof.md` remain historical `.3.5`
evidence and must not be edited or reinterpreted as `.3.6` proof.

## 3. Preconditions and staging

Before staging, the owner must confirm `Snapshot 1` is still available and the
VirtualBox console is open. Stop every application instance. The manually
recovered SSH listener may remain active until the controlled reboot, but the
Windows tunnel must be stopped before reboot.

Transfer only the two additive public files into a new VM directory
`$HOME/alertmind-rbac-phase1c-boot-order`. Use an exact byte transfer generated
from the independently approved commit; do not hand-edit either file on the
VM. Then run:

```bash
(
set -euo pipefail
STAGE="$HOME/alertmind-rbac-phase1c-boot-order"

test "$(id -un)" = 'notroot'
test "$(hostnamectl --static)" = 'wazuh-siem'
test ! -L "$STAGE"
test "$(stat -c '%a:%U:%G' "$STAGE")" = '700:notroot:notroot'

cd "$STAGE"
sha256sum -c SSH-BOOT-ORDER-SHA256SUMS

python3 -c '
from pathlib import Path
expected={"ssh-service-network-online.conf", "SSH-BOOT-ORDER-SHA256SUMS"}
root=Path(".")
entries=list(root.iterdir())
if {p.name for p in entries} != expected:
    raise SystemExit("STOP: boot-order stage has unexpected entries")
for path in entries:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"STOP: staged path is not a regular file: {path.name}")
    if path.stat().st_mode & 0o777 != 0o600:
        raise SystemExit(f"STOP: staged file mode is not 0600: {path.name}")
for path in entries:
    data=path.read_bytes()
    if b"\r\n" in data or not data.endswith(b"\n"):
        raise SystemExit(f"STOP: staged file is not LF text: {path.name}")
print("PASS staged boot-order package: exact files, hashes, modes and LF bytes")
'

echo 'STOP POINT: preserve this output for review before live preflight'
)
```

## 4. Read-only live preflight

Run at the VM console. It must stop if the current live transport, package
version or service state differs from the observed recovery state.

```bash
(
set -euo pipefail
SSH_STAGE="$HOME/alertmind-rbac-phase1c"
BOOT_STAGE="$HOME/alertmind-rbac-phase1c-boot-order"
SSH_DROPIN='/etc/ssh/sshd_config.d/00-alertmind-transport.conf'
SERVICE_DIR='/etc/systemd/system/ssh.service.d'
SERVICE_DROPIN="$SERVICE_DIR/10-alertmind-network-online.conf"

cd "$SSH_STAGE"
sha256sum -c SSH-SHA256SUMS
cd "$BOOT_STAGE"
sha256sum -c SSH-BOOT-ORDER-SHA256SUMS

test "$(dpkg-query -W -f='${Status}' openssh-server)" = \
  'install ok installed'
test "$(dpkg-query -W -f='${Version}' openssh-server)" = \
  '1:10.2p1-2ubuntu3.6'
test "$(dpkg-query -W -f='${Status}' openssh-sftp-server)" = \
  'install ok installed'
test "$(dpkg-query -W -f='${Version}' openssh-sftp-server)" = \
  '1:10.2p1-2ubuntu3.6'

VERIFY=$(sudo dpkg --verify openssh-server openssh-sftp-server)
test -z "$VERIFY" || { printf '%s\n' "$VERIFY"; exit 1; }

sudo cmp --silent "$SSH_STAGE/sshd-alertmind.conf" "$SSH_DROPIN"
test ! -e "$SERVICE_DROPIN"
test ! -L "$SERVICE_DROPIN"
test ! -L "$SERVICE_DIR"
if [ -e "$SERVICE_DIR" ]; then
  test -d "$SERVICE_DIR"
  test -z "$(sudo find "$SERVICE_DIR" -mindepth 1 -maxdepth 1 -print)"
fi
test -z "$(systemctl show -p DropInPaths --value ssh.service)"

test "$(systemctl is-enabled ssh.service)" = 'enabled'
test "$(systemctl is-active ssh.service)" = 'active'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
if systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH socket activation is active'; exit 1
fi

ip -brief -4 address show dev enp0s8 | grep -F '192.168.56.102/24'
ip route get 192.168.56.1 | grep -F \
  '192.168.56.1 dev enp0s8 src 192.168.56.102'
test "$(systemctl is-enabled NetworkManager-wait-online.service)" = 'enabled'
test "$(systemctl is-active NetworkManager-wait-online.service)" = 'active'
test "$(systemctl show -p Result --value NetworkManager-wait-online.service)" = 'success'

LISTENERS=$(sudo ss -H -ltnp | awk '$4 ~ /:22$/ {print $4}')
test "$(printf '%s\n' "$LISTENERS" | awk 'NF {n++} END {print n+0}')" -eq 1
test "$LISTENERS" = '192.168.56.102:22'

INDEXER_LISTENERS=$(sudo ss -H -ltn | awk '$4 ~ /:9200$/ {print $4}')
case "$INDEXER_LISTENERS" in
  '127.0.0.1:9200'|'[::ffff:127.0.0.1]:9200') ;;
  *) echo 'STOP: Indexer is not bound to one loopback listener'; exit 1;;
esac

for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  test "$state" = 'active' || {
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1;
  }
  printf 'PASS service health: %s=active\n' "$unit"
done

echo 'PASS current recovered transport and OpenSSH .3.6 boundary'
echo 'STOP POINT: review before installing the service-ordering drop-in'
)
```

## 5. Install the ordering drop-in without restarting SSH

Run only after Section 4 output is accepted. This changes one public systemd
drop-in and reloads unit metadata; it does not restart SSH.

```bash
(
set -euo pipefail
BOOT_STAGE="$HOME/alertmind-rbac-phase1c-boot-order"
SERVICE_DIR='/etc/systemd/system/ssh.service.d'
SERVICE_DROPIN="$SERVICE_DIR/10-alertmind-network-online.conf"
attempted=0
created_dir=0

fail_closed() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "$attempted" -eq 1 ]; then
    # Remove only our attempted additive file, including a partial install.
    # No daemon restart and no changes to the existing SSH access policy.
    if sudo rm -f -- "$SERVICE_DROPIN" &&
       test ! -e "$SERVICE_DROPIN" && test ! -L "$SERVICE_DROPIN" &&
       sudo systemctl daemon-reload; then
      echo 'STOP: ordering install failed; additive file removed and units reloaded'
    else
      echo 'STOP: automatic cleanup incomplete; use Section 8 containment at the console'
    fi
    if [ "$created_dir" -eq 1 ]; then
      sudo rmdir -- "$SERVICE_DIR" 2>/dev/null || true
    fi
  fi
  exit "$status"
}
trap fail_closed EXIT

cd "$BOOT_STAGE"
sha256sum -c SSH-BOOT-ORDER-SHA256SUMS
test ! -e "$SERVICE_DROPIN"
test ! -L "$SERVICE_DROPIN"
test ! -L "$SERVICE_DIR"
test -z "$(systemctl show -p DropInPaths --value ssh.service)"
test "$(systemctl is-active ssh.service)" = 'active'
test "$(systemctl is-enabled ssh.service)" = 'enabled'
BEFORE_PID=$(systemctl show -p MainPID --value ssh.service)
test "$BEFORE_PID" -gt 0
if [ -e "$SERVICE_DIR" ]; then
  test -d "$SERVICE_DIR"
  test "$(stat -c '%a:%U:%G' "$SERVICE_DIR")" = '755:root:root'
  test -z "$(sudo find "$SERVICE_DIR" -mindepth 1 -maxdepth 1 -print)"
else
  sudo install -d -o root -g root -m 755 "$SERVICE_DIR"
  created_dir=1
fi
attempted=1
sudo install -o root -g root -m 644 \
  "$BOOT_STAGE/ssh-service-network-online.conf" "$SERVICE_DROPIN"
sudo systemctl daemon-reload

sudo cmp --silent \
  "$BOOT_STAGE/ssh-service-network-online.conf" "$SERVICE_DROPIN"
test "$(stat -c '%a:%U:%G' "$SERVICE_DROPIN")" = '644:root:root'

DROPINS=$(systemctl show -p DropInPaths --value ssh.service)
case " $DROPINS " in
  *" $SERVICE_DROPIN "*) ;;
  *) echo 'STOP: ssh.service did not load the reviewed drop-in'; exit 1;;
esac
AFTER=$(systemctl show -p After --value ssh.service)
WANTS=$(systemctl show -p Wants --value ssh.service)
case " $AFTER " in *' network-online.target '*) ;; \
  *) echo 'STOP: ssh.service lacks After=network-online.target'; exit 1;; esac
case " $WANTS " in *' network-online.target '*) ;; \
  *) echo 'STOP: ssh.service lacks Wants=network-online.target'; exit 1;; esac

test "$(systemctl is-active ssh.service)" = 'active'
test "$(systemctl show -p MainPID --value ssh.service)" = "$BEFORE_PID"
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
if systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH socket activation is active'; exit 1
fi
LISTENERS=$(sudo ss -H -ltnp | awk '$4 ~ /:22$/ {print $4}')
test "$LISTENERS" = '192.168.56.102:22'

for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  test "$(systemctl is-active "$unit")" = 'active'
done

echo 'PASS reviewed ordering loaded; live listener was not restarted or broadened'
echo 'STOP POINT: review before stopping the Windows tunnel and rebooting'
trap - EXIT
)
```

## 6. Controlled reboot and boot-persistence proof

Stop the recognized Windows tunnel using Section 6.1 of the rollback drill and
confirm TCP 19200 has no listener. Do not repeat Section 4's absent-drop-in
precondition or Section 5's installation. At the VM console, record the current
boot ID in the private operator worksheet using this read-only block. Return
its output with the accepted Section 5 output before reboot approval:

```bash
(
set -euo pipefail
test "$(systemctl is-active ssh.service)" = 'active'
for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  test "$(systemctl is-active "$unit")" = 'active'
done
printf 'pre_reboot_boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
echo 'STOP POINT: record this boot ID; review before reboot'
)
```

After that output is accepted, run this command by itself:

```bash
sudo systemctl reboot
```

Wait for the VM console login prompt. Do not manually start SSH or create
`/run/sshd`. Run:

```bash
(
set -euo pipefail
BOOT_STAGE="$HOME/alertmind-rbac-phase1c-boot-order"
SERVICE_DROPIN='/etc/systemd/system/ssh.service.d/10-alertmind-network-online.conf'
read -r -p 'Paste the pre-reboot boot ID from the accepted worksheet: ' BEFORE_BOOT
[[ "$BEFORE_BOOT" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
CURRENT_BOOT=$(cat /proc/sys/kernel/random/boot_id)
test "$CURRENT_BOOT" != "$BEFORE_BOOT"
read -r -p 'Type NO-MANUAL-RECOVERY only if SSH was not manually started this boot: ' ATTESTATION
test "$ATTESTATION" = 'NO-MANUAL-RECOVERY'

cd "$BOOT_STAGE"
sha256sum -c SSH-BOOT-ORDER-SHA256SUMS
sudo cmp --silent \
  "$BOOT_STAGE/ssh-service-network-online.conf" "$SERVICE_DROPIN"

test "$(dpkg-query -W -f='${Version}' openssh-server)" = \
  '1:10.2p1-2ubuntu3.6'
test "$(dpkg-query -W -f='${Version}' openssh-sftp-server)" = \
  '1:10.2p1-2ubuntu3.6'
test "$(systemctl is-enabled ssh.service)" = 'enabled'
test "$(systemctl is-active ssh.service)" = 'active'
test "$(systemctl show -p Result --value ssh.service)" = 'success'
test "$(systemctl show -p NRestarts --value ssh.service)" = '0'
test "$(systemctl is-enabled NetworkManager-wait-online.service)" = 'enabled'
test "$(systemctl is-active NetworkManager-wait-online.service)" = 'active'
test "$(systemctl show -p Result --value NetworkManager-wait-online.service)" = 'success'
test "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = 'masked'
if systemctl is-active --quiet ssh.socket; then
  echo 'STOP: SSH socket activation is active'; exit 1
fi

DROPINS=$(systemctl show -p DropInPaths --value ssh.service)
case " $DROPINS " in *" $SERVICE_DROPIN "*) ;; \
  *) echo 'STOP: reviewed service drop-in is not loaded'; exit 1;; esac
AFTER=$(systemctl show -p After --value ssh.service)
WANTS=$(systemctl show -p Wants --value ssh.service)
case " $AFTER " in *' network-online.target '*) ;; \
  *) echo 'STOP: missing After=network-online.target'; exit 1;; esac
case " $WANTS " in *' network-online.target '*) ;; \
  *) echo 'STOP: missing Wants=network-online.target'; exit 1;; esac

ONLINE_US=$(systemctl show -p ActiveEnterTimestampMonotonic --value \
  network-online.target)
WAIT_US=$(systemctl show -p ActiveEnterTimestampMonotonic --value \
  NetworkManager-wait-online.service)
SSH_US=$(systemctl show -p ExecMainStartTimestampMonotonic --value ssh.service)
for timestamp in "$WAIT_US" "$ONLINE_US" "$SSH_US"; do
  case "$timestamp" in ''|*[!0-9]*) echo 'STOP: invalid monotonic timestamp'; exit 1;; esac
  test "$timestamp" -gt 0
done
test "$ONLINE_US" -ge "$WAIT_US"
test "$SSH_US" -ge "$ONLINE_US"

SSH_STAGE="$HOME/alertmind-rbac-phase1c"
(cd "$SSH_STAGE" && sha256sum -c SSH-SHA256SUMS)
sudo cmp --silent "$SSH_STAGE/sshd-alertmind.conf" \
  /etc/ssh/sshd_config.d/00-alertmind-transport.conf
VERIFY=$(sudo dpkg --verify openssh-server openssh-sftp-server)
test -z "$VERIFY" || { printf '%s\n' "$VERIFY"; exit 1; }
sudo /usr/sbin/sshd -t
python3 -c '
from pathlib import Path
import subprocess
import sys

def config(user):
    output = subprocess.check_output([
        "sudo", "/usr/sbin/sshd", "-T", "-C",
        f"user={user},host=wazuh-siem,addr=192.168.56.1,laddr=192.168.56.102,lport=22",
    ], text=True)
    parsed = {}
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        parsed.setdefault(key, []).append(value)
    return parsed

target = config("notroot")
control = config("root")
required = """port 22
addressfamily inet
listenaddress 192.168.56.102:22
hostkey /etc/ssh/ssh_host_ed25519_key
permitrootlogin no
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
authenticationmethods publickey
authorizedkeysfile .ssh/authorized_keys
allowusers notroot@192.168.56.1
allowtcpforwarding local
allowstreamlocalforwarding no
permitopen 127.0.0.1:9200
gatewayports no
x11forwarding no
allowagentforwarding no
permittty no
permittunnel no
permituserrc no
forcecommand /bin/false
maxsessions 0"""
for line in required.splitlines():
    key, _, value = line.partition(" ")
    if target.get(key) != [value]:
        raise SystemExit(f"STOP: effective target setting changed: {key}")
for key, value in {"allowtcpforwarding": "no", "permitopen": "none",
                   "permittty": "no", "forcecommand": "/bin/false", "maxsessions": "0"}.items():
    if control.get(key) != [value]:
        raise SystemExit(f"STOP: effective control setting changed: {key}")

options = Path(sys.argv[1]).read_text().strip()
auth = Path("/home/notroot/.ssh/authorized_keys")
lines = [s for s in auth.read_text().splitlines() if s.strip() and not s.startswith("#")]
if len(lines) != 1 or not lines[0].startswith(options + " ssh-ed25519 "):
    raise SystemExit("STOP: restricted authorized-key record changed")
for path, expected in [
    (str(auth), "SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo"),
    ("/etc/ssh/ssh_host_ed25519_key.pub", "SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag"),
]:
    fingerprint = subprocess.check_output(["ssh-keygen", "-lf", path, "-E", "sha256"], text=True).split()[1]
    if fingerprint != expected:
        raise SystemExit("STOP: public key fingerprint changed")
print("PASS post-update parser, target/control policy and both public fingerprints")
' "$SSH_STAGE/ssh-authorized-key-options.txt"

ip -brief -4 address show dev enp0s8 | grep -F '192.168.56.102/24'
LISTENERS=$(sudo ss -H -ltnp | awk '$4 ~ /:22$/ {print $4}')
test "$(printf '%s\n' "$LISTENERS" | awk 'NF {n++} END {print n+0}')" -eq 1
test "$LISTENERS" = '192.168.56.102:22'

INDEXER_LISTENERS=$(sudo ss -H -ltn | awk '$4 ~ /:9200$/ {print $4}')
case "$INDEXER_LISTENERS" in
  '127.0.0.1:9200'|'[::ffff:127.0.0.1]:9200') ;;
  *) echo 'STOP: Indexer is not bound to one loopback listener'; exit 1;;
esac

for unit in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  state=$(systemctl is-active "$unit" || true)
  test "$state" = 'active' || {
    printf 'STOP service health: %s=%s\n' "$unit" "$state"; exit 1;
  }
  printf 'PASS service health: %s=active\n' "$unit"
done

printf 'PASS new boot: before=%s after=%s\n' "$BEFORE_BOOT" "$CURRENT_BOOT"
printf 'PASS boot ordering: wait-online=%s network-online=%s ssh-start=%s\n' \
  "$WAIT_US" "$ONLINE_US" "$SSH_US"
echo 'PASS post-reboot transport: one host-only listener; socket remains masked'
echo 'STOP POINT: review before restarting the Windows tunnel'
)
```

## 7. Revalidate the complete Windows-side boundary

After Section 6 is accepted, use the existing canonical key, known-hosts file
and public CA. Do not regenerate keys, scan/promote a new known-hosts file, or
copy the CA again. From `assistant/` in PowerShell:

- Reuse the **client-public-key and known-hosts fingerprint checks only** from
  Section 4.1 of the rollback runbook (not that section's running-tunnel check
  yet). Both fingerprints must equal their accepted values.
- Start the foreground tunnel block in Section 9 of the transport runbook,
  then its second-window listener block. Do not execute Section 9's initial
  key-scan/file-creation block.
- Run Section 10's existing-CA fingerprint, paired TLS/read and denial blocks.
  No CA-copy operation or re-enrollment is needed.

Require:

1. one Windows listener at `127.0.0.1:19200` owned by the expected `ssh.exe`;
2. wrong-hostname TLS failure with curl exit `60` and no credential/query sent;
3. correct-identity metadata-only read with zero failed shards and no `_source`;
4. shell/command, PTY/session, remote-forward, alternate-local-destination and
   password-only denials using the same key that passed the positive forward;
5. removal of every diagnostic log/tunnel; and
6. all four Wazuh services still active.

Do not claim `.3.6` transport revalidation from the VM listener alone. Complete
the sanitized worksheet at
`evidence/rbac/phase1c-ssh-boot-order-proof-template.md`, preserve every failed
or aborted attempt, and obtain independent review before resuming Stage 1 of
the rollback/revocation drill.

Do not turn a partial run into a passing conclusion. The no-manual-recovery
statement is an owner attestation; the boot-ID and timestamp checks independently
verify a changed boot and service ordering, not every possible operator action.

## 8. Failure containment

If the install, reboot or revalidation fails, stop the Windows tunnel and use
the VM console. Run Section 11 of `rbac-wazuh-ssh-transport.md`, which disables
and masks SSH, removes both AlertMind drop-ins, restores the pre-transport
authorized-keys file and verifies Wazuh health. Do not broaden
`ListenAddress`, enable `ssh.socket`, create `/run/sshd` manually, downgrade a
security update, restore `own_index`, or rotate a credential while diagnosing
this maintenance failure.
