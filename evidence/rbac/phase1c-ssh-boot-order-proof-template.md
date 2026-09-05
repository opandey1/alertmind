# Phase 1C evidence template — SSH boot-order recovery

**Status:** Unexecuted template. This file is not evidence that the recovery or
revalidation ran. Copy it to `phase1c-ssh-boot-order-proof.md` only after every
reviewed stage completes. Replace each `PENDING` value with a sanitized observed
result; never overwrite this template.

**Runbook:**
[`docs/runbooks/rbac-phase1c-ssh-boot-order-recovery.md`](../../docs/runbooks/rbac-phase1c-ssh-boot-order-recovery.md)

## 1. Provenance and deviation

| Item | Sanitized value |
|---|---|
| Owner execution date/time and timezone | `PENDING` |
| Repository commit containing the approved recovery | `PENDING` |
| VM snapshot confirmed available | `PENDING` |
| Original accepted transport evidence | `PENDING` — expected PR #16 / OpenSSH `.3.5` proof unchanged |
| Current OpenSSH package pair | `PENDING` — expected `1:10.2p1-2ubuntu3.6` |
| Triggering reboot failure | `PENDING` — record the SSH status and network timing only |
| Temporary recovery | `PENDING` — expected manual service start after `enp0s8` activation |
| Raw alert, `_source`, credential or private key captured | `PENDING` — expected `no` |

The original `.3.5` evidence remains a valid historical observation. This
worksheet records the additive `.3.6` maintenance result and must not rewrite
the original evidence or imply that the earlier run occurred on `.3.6`.

## 2. Reviewed artifact integrity

| Artifact | SHA-256/result |
|---|---|
| `siem/rbac/SSH-SHA256SUMS` | `PENDING` |
| `siem/rbac/SSH-BOOT-ORDER-SHA256SUMS` | `PENDING` |
| `ssh-service-network-online.conf` | `PENDING` |
| Installed SSH policy matches `sshd-alertmind.conf` | `PENDING` |

## 3. Pre-apply recovered boundary

| Check | Result |
|---|---|
| `enp0s8` address and route | `PENDING` — expected `192.168.56.102/24` and host-only route |
| `ssh.service` / `ssh.socket` | `PENDING` — expected enabled+active / masked+inactive |
| Existing SSH listener | `PENDING` — expected only `192.168.56.102:22` |
| Existing systemd SSH drop-ins | `PENDING` — expected none |
| OpenSSH package integrity | `PENDING` |
| Indexer listener | `PENDING` — expected one loopback listener |
| Wazuh health: Indexer → Manager → Filebeat → Dashboard | `PENDING` |

## 4. Ordering installation

| Check | Result |
|---|---|
| Installed service drop-in path, owner and mode | `PENDING` — expected root:root `0644` |
| Installed bytes match reviewed artifact | `PENDING` |
| Effective `Wants=network-online.target` | `PENDING` |
| Effective `After=network-online.target` | `PENDING` |
| SSH listener unchanged without restart | `PENDING` |
| Wazuh health unchanged | `PENDING` |

## 5. Controlled-reboot proof

| Check | Result |
|---|---|
| Reboot date/time and timezone | `PENDING` |
| Pre-reboot and post-reboot boot IDs differ | `PENDING` |
| No manual `/run/sshd` creation or SSH start after reboot | `PENDING` — expected `yes` |
| NetworkManager wait-online enabled, active and successful | `PENDING` |
| Wait-online monotonic activation not later than network-online | `PENDING` |
| `network-online.target` monotonic activation | `PENDING` |
| `ssh.service` monotonic main-process start | `PENDING` |
| SSH start not earlier than network-online | `PENDING` |
| `ssh.service` result | `PENDING` — expected enabled, active, `success` |
| `ssh.socket` state | `PENDING` — expected masked and inactive |
| VM SSH listener after reboot | `PENDING` — expected only `192.168.56.102:22` |
| Indexer listener after reboot | `PENDING` — expected one loopback listener |
| Post-update parser, target/control policy and restricted key | `PENDING` |
| Post-update OpenSSH package integrity | `PENDING` |
| Wazuh health: Indexer → Manager → Filebeat → Dashboard | `PENDING` |

## 6. Post-update transport revalidation

| Check | Result |
|---|---|
| Existing client public fingerprint | `PENDING` |
| VM host-key fingerprint unchanged | `PENDING` |
| Wazuh public CA SHA-256 unchanged | `PENDING` |
| Windows tunnel | `PENDING` — expected only `127.0.0.1:19200` |
| Wrong-hostname TLS leg | `PENDING` — expected curl exit `60` before HTTP/credentials |
| Correct-identity TLS/read leg | `PENDING` — metadata only; no `_source` |
| Shell/command denial | `PENDING` |
| PTY/session denial | `PENDING` |
| Remote-forward denial | `PENDING` |
| Alternate-local-destination denial | `PENDING` |
| Password-only denial | `PENDING` |
| Diagnostic tunnels and logs removed | `PENDING` |
| Wazuh health after denial matrix | `PENDING` |

## 7. Claim boundary

**Allowed conclusion after independent approval:** the Ubuntu `.3.6` OpenSSH
pair retained the previously reviewed SSH restrictions, and the additive
systemd ordering made the single host-only listener survive one controlled
reboot without manual service recovery while Wazuh remained healthy.

The no-manual-recovery statement is an owner attestation. Different boot IDs
and the three monotonic timestamps support a new-boot ordering observation;
they do not independently prove absence of every operator action.

**Not established:** general availability across multiple reboots or network
failures, future package compatibility, Wazuh application integration,
rollback/revocation-drill success, OIDC, Dashboard/Server RBAC, production
readiness or certificate-revocation availability.

## 8. Deviations and failures

`PENDING` — include the aborted rollback Stage 1 attempt, the first post-update
reboot failure, temporary manual recovery, and every later failed or aborted
step. Do not turn a partial run into a passing conclusion.

## 9. Independent review

| Item | Value |
|---|---|
| Reviewer | `PENDING` |
| Reviewed commit | `PENDING` |
| Verdict | `PENDING` |
| Required corrections | `PENDING` |
