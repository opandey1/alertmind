# Phase 1C evidence — SSH boot-order recovery

**Status:** Owner-executed checks completed; consolidated by Codex and awaiting
independent evidence review. This is not an approved rollback/revocation result.

**Observed date:** 5 September 2026, Asia/Kolkata (UTC+05:30), from the owner's
VM-console and Windows PowerShell reports. Consolidated on 6 September 2026.
Exact wall-clock times for each execution, including the controlled reboot,
were not printed in the returned outputs and are not reconstructed here.

**Runbook:** [SSH boot-order recovery](../../docs/runbooks/rbac-phase1c-ssh-boot-order-recovery.md).
The [blank worksheet](phase1c-ssh-boot-order-proof-template.md) and
[original OpenSSH .3.5 transport evidence](phase1c-ssh-transport-proof.md)
remain unchanged.

## 1. Provenance and deviation

The executable recovery package was independently approved as `fc5d1a8` and
`b6d9083`, then merged through PR #19 at
`32496af4dc4dbab5b8845f7ebae5ed0282194969`. That merge supplied the reviewed
scripts and configuration used for this execution; this later evidence commit
did not produce those earlier observations.

The owner executed the gated steps, returning sanitized results after each
stop point. Codex checked those outputs against the approved scripts; it did
not operate the VM, collect live credentials or independently observe the
absence of manual intervention. Some exact assertions run silently: a reached
final PASS/STOP under the complete fail-closed block is the evidence for those
checks, not a separately captured dump of each value.

The dated, outside-Git operator packets covered staging/preflight, tunnel stop,
controlled reboot, Windows reconnect, paired TLS/read and SSH denials. They
retained the approved command bodies with directory/error-handling wrappers;
the denial packet additionally checked diagnostic cleanup and each service's
health. They are coordination aids, not new benchmark runs.

| Item | Recorded value |
|---|---|
| Snapshot / console / apps | Owner confirmed Snapshot 1 available, console open and apps stopped before staging; later supplied APP-STOPPED |
| Current OpenSSH pair | `openssh-server` and `openssh-sftp-server`: `1:10.2p1-2ubuntu3.6`, checked in preflight and after reboot |
| Original accepted transport | PR #16, evidence commits `af571b1` / `0767a89`, OpenSSH `.3.5`; preserved as historical evidence |
| Trigger | First observed post-update boot left SSH failed with main-process exit 255 before the host-only IPv4 address became active |
| Temporary recovery | Owner manually started SSH after the address was available, restoring the restricted listener; this preceded the controlled maintenance reboot |
| Sensitive content | No password, private key, token, authorization header, raw alert or `_source` in this record or the accepted returned outputs |

The existing Phase 1B Indexer roles/DLS remain the previously accepted
authorization baseline. This maintenance did not change them or rerun the
full Indexer authorization/write-denial matrix.

## 2. Reviewed artifact integrity

The owner returned successful checksums for both SSH inputs and the ordering
input. Staging also passed exact-file, permission and LF-byte checks. The
manifest-file digests below are calculated from the committed LF bytes; they
are provenance bindings, not claims that the VM printed those manifest digests.

| Artifact under `siem/rbac/` | SHA-256 |
|---|---|
| `SSH-SHA256SUMS` | `ed05758753b7cb278a84c591dd03e55af6d57cedb6b534f97271bff23a7a8d3c` |
| `sshd-alertmind.conf` | `6b18ac0de80ac6490bdebbeaa5ac0a50040f6ec0ba9c379c4b0fbe3e8d3fe640` |
| `ssh-authorized-key-options.txt` | `90c23d007a9f04588d4e9bf0b264b27641361224e0d46d57cecd68c81ef3394c` |
| `SSH-BOOT-ORDER-SHA256SUMS` | `8d7f4c3533bb2b4432bd28d52d006d8839f2f3241863c6c053bcc454aca39ba1` |
| `ssh-service-network-online.conf` | `574b9a8bf1d224f71b7a2a88c36bd50c45ec9e82b105f38d4ad38d28912b5855` |

The ordering artifact contains only:

```ini
[Unit]
Wants=network-online.target
After=network-online.target
```

The preflight and post-reboot blocks compared the installed SSH policy with
`sshd-alertmind.conf`. The post-reboot block also checked the restricted
authorized-key prefix, target/control effective policy and public fingerprints.

## 3. Pre-apply recovered boundary

The owner reached Section 4's final recovered-transport PASS and review STOP.
Its checks established:

| Check | Reported/guarded result |
|---|---|
| Host-only interface and route | `enp0s8`, `192.168.56.102/24`; route to `192.168.56.1` through that interface/source |
| SSH activation | `ssh.service` enabled and active; `ssh.socket` masked and not active |
| SSH listener | Exactly one, `192.168.56.102:22` |
| Existing SSH service drop-ins | None before the ordering install |
| OpenSSH package integrity | No modified package-owned files reported by the verification guard |
| Indexer listener | One loopback listener; guard accepts `127.0.0.1:9200` or `[::ffff:127.0.0.1]:9200` |
| NetworkManager wait-online | Enabled, active and successful |
| Indexer / Manager / Filebeat / Dashboard | All four explicitly reported active |

## 4. Ordering installation

The owner's first Section 5 execution reached:

> PASS reviewed ordering loaded; live listener was not restarted or broadened

The complete block verified:

- installed path `/etc/systemd/system/ssh.service.d/10-alertmind-network-online.conf`,
  owner `root:root`, mode `0644`, exact reviewed bytes;
- loaded `Wants=network-online.target` and `After=network-online.target`;
- SSH remained active with the same main-process ID and host-only listener;
- socket activation remained masked/inactive; and
- all four Wazuh services remained active.

No service restart was part of the ordering install. A subsequent accidental
Section 5 rerun is excluded from success evidence; see Section 8.

## 5. Controlled-reboot proof

Before reboot, the owner reported the recognized Windows tunnel stopped and
no TCP 19200 listener. The VM baseline block recorded the first ID below.
After reboot, the complete proof reached its final review STOP.

| Check | Result |
|---|---|
| Controlled-reboot wall-clock timestamp | Not captured in returned output; observed date 2026-09-05, UTC+05:30 |
| Pre-reboot boot ID | `7463f15f-0c87-4f03-94d8-c71adc722a9d` |
| Post-reboot boot ID | `4e283a22-f60e-44c1-9470-1f9636126a2b` |
| No manual SSH recovery | Owner supplied `NO-MANUAL-RECOVERY` under instructions not to start SSH or create `/run/sshd`; this is an attestation |
| Wait-online | Enabled, active, successful; monotonic activation `17048323` microseconds |
| Network-online | Monotonic activation `17051573` microseconds |
| SSH main-process start | Monotonic start `17302430` microseconds |
| Ordering comparisons | `17048323 <= 17051573 <= 17302430`; SSH started `250857` microseconds (`0.250857 s`) after network-online |
| SSH service | Enabled, active, result `success`, `NRestarts=0` checked by the block |
| Socket activation | Masked and not active |
| VM SSH listener | Exactly one host-only listener: `192.168.56.102:22` |
| Indexer listener | One loopback listener under the unchanged loopback guard |
| Post-update configuration | Parser, target/control settings, restricted key and both public fingerprints PASS |
| OpenSSH integrity | Post-update verification guard passed |
| Wazuh health | Indexer, Manager, Filebeat and Dashboard each explicitly active |

The distinct boot IDs and positive monotonic timestamps support a new-boot
ordering observation. They do not independently prove the absence of every
possible operator action.

## 6. Post-update transport revalidation

The owner confirmed apps stopped; the Windows baseline observed no Streamlit
CLI process and checked the listener's process/command identity. This is not
a comprehensive process inventory or a continuously monitored availability claim.

| Trust input | Unchanged value |
|---|---|
| Client public key | `SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo` |
| Pinned VM host key | `SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag` |
| Public CA DER SHA-256 | `EB98A4AF38CDA550D473E5659A4375905334041FAB4597F39C4F191D9E6F5E1D` |

| Check | Owner-reported result |
|---|---|
| Windows forward | Recognized foreground SSH process; only `127.0.0.1:19200`, forwarding to VM `127.0.0.1:9200` |
| Wrong-hostname TLS control | curl exit `60`; Schannel explicitly failed to match `alertmind-hostname-check.invalid` against certificate names |
| Correct-identity TLS/read | `127.0.0.1` accepted; `failed_shards=0; visible_hits=10000; relation=gte` |
| Shell/command | Windows wrapper exit `-1`; test marker absent |
| PTY/session | Windows wrapper exit `-1`; test marker absent |
| Remote forward | SSH exit `255`; denial PASS |
| Alternate local destination `127.0.0.1:443` | Denial marker found; diagnostic log removed |
| Password-only authentication | SSH exit `255`; denial PASS; command permits zero password prompts |
| Diagnostic cleanup | No TCP 19201 listener, alternate-destination log or TLS query file |
| Final service health | Indexer, Manager, Filebeat and Dashboard each active; final review STOP reached |

The TLS pair used the same tunnel, CA and revocation policy. The negative
control had no credentials/query and failed at certificate authentication;
the positive request authenticated as `assistant-svc` and returned metadata
only. `10000 / gte` means at least 10,000 matching alerts, not an exact total.
No `_source` was requested. The fixed non-secret JSON request used UTF-8
without a BOM and curl's `@file` form, with `finally` cleanup.

For this curl proof only, `--ssl-revoke-best-effort` tolerated unavailable
revocation data while CA and hostname verification remained enabled. This
private CA chain publishes no revocation location, so this proof provides
**no effective certificate-revocation protection**. No `--ssl-no-revoke`,
`--insecure` or `-k` was used. The application TLS decision remains separate.

The key-authenticated denials used the same existing key/policy as the preceding
successful forward. Password-only testing deliberately disabled public-key
authentication. The alternate-destination verifier required
`administratively prohibited` before deleting its local diagnostic log.
The approved TCP 19200 tunnel was not the diagnostic tunnel being removed.

The `-1` values are preserved as observed Windows wrapper results, not portable
SSH exit-code claims. The shell/PTY/remote-forward summaries alone are not
server-side proof of successful authentication on each new connection: their
wrappers check nonzero exits (plus marker absence for shell/PTY). Acceptance
for review also relies on the preceding positive same-key proof, unchanged
effective policy and the owner's execution sequence; no connection or
authentication error was reported. Such an error would invalidate a policy
denial inference even if a wrapper printed PASS. Verbose SSH logs are not
retained or published.

## 7. Claim boundary

**Conclusion proposed for independent approval:** the observed Ubuntu `.3.6`
OpenSSH pair retained the reviewed restrictions, and the additive systemd
ordering was followed by one successful controlled reboot with the host-only
SSH listener available without owner-reported manual service recovery.
Wazuh remained healthy at the recorded checkpoints.

The evidence supports the ordering intervention but does not establish a
universal causal guarantee. The original failure chronology strongly supports
a bind-before-address race; no explicit bind-error line was captured.

**Not established:** availability across multiple reboots or network failures,
future package compatibility, new Indexer authorization proof, Wazuh application
integration, rollback/revocation-drill success, OIDC, Dashboard/Server RBAC,
production readiness or certificate-revocation availability. No live alert was
submitted to an LLM during this maintenance.

## 8. Deviations and failures

1. The attempted rollback Stage 1 packet stopped at its obsolete OpenSSH
   `.3.5` version guard after Windows checks. It did not complete a renewed
   baseline or any subsequent revocation leg; the packet was superseded.
2. The first observed post-update boot was at 2026-09-05 01:26:01 +05:30.
   SSH started at 01:26:17.376, exited 255 at 01:26:17.531, and the host-only
   address became active at 01:26:17.669. `ExecStartPre` succeeded. Later
   `sshd -t` reported absent `/run/sshd` after failure; that later condition
   is not proof of the startup cause. Package integrity and
   `RuntimeDirectory=sshd` were intact. An early zero-listener observation
   also preceded a later active, loopback-bound Indexer observation; it is
   not the final transport boundary.
3. The owner manually started SSH after the address was available, restoring
   the restricted listener and service health. This was temporary recovery,
   not a successful boot-order proof.
4. After the first successful ordering install, the owner mistakenly reran
   Section 5 and returned only its checksum line. The owner confirmed the
   repeat. The existing-file guard occurs before `attempted=1`, explaining
   the early exit without a second install or cleanup of the original file.
   This is not counted as another successful installation.
5. Coordination initially confused the Windows tunnel prerequisite with the
   install stage. It was clarified that Section 5 required active VM SSH,
   not an active Windows tunnel. The tunnel was later explicitly stopped
   for reboot and restarted only after the VM proof was accepted.

No later failure was reported in the accepted reboot/reconnect/TLS/denial
sequence. A session interruption delayed consolidation, not execution of a
new live test. Earlier `.3.5` keyscan, clipboard, listener and inline-JSON
failures remain recorded in the unchanged original transport evidence and are
not repurposed as successful `.3.6` observations.

## 9. Independent review

| Item | Value |
|---|---|
| Evidence reviewer | Pending — Claude requested through HANDOFF |
| Evidence commit | To be identified by the author entry in HANDOFF; the execution/package commit is pinned above |
| Verdict | Awaiting independent review; not approved |
| Required corrections | Not yet assessed |

Do not resume the rollback/revocation drill or claim Phase 1C completion from
this author consolidation. Independent approval of this separate evidence
record is the next gate.
