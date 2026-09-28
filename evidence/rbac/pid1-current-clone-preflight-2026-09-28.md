# PID 1 image candidate — owner-reported isolated-clone preflight

Status: **owner-reported isolation context and Gate 1 observations; not independently
reviewed, package-authenticated or approved as an installed-image reference**.
The user supplied the sanitized console output on 2026-09-28. This record
transcribes only that report; Codex did not access either VM.

## Operator context

- VirtualBox entry: `Ubuntu SOC 201 - Current Isolated Clone`.
- Source: original VM's `Current State (changed)` at clone creation, **not**
  historical `Snapshot 1`. The original VM was reported untouched.
- The user reports every clone network adapter disabled and no updates or
  configuration changes on the clone after cloning. A disabled-adapter setting
  is an operator report, not a shell-verifiable ongoing isolation guarantee.
- Whether any AlertMind app was running against the clone was **not reported**.
  On the next turn, the owner confirmed no AlertMind app **is** running
  against the clone. That resolves current app-state uncertainty but does
  not retroactively prove the state at the Gate 1 instant. Recheck before
  any further clone execution.

## Reported Gate 1 result

| Check | Reported value |
| --- | --- |
| OS and architecture | Ubuntu `26.04`, `amd64` |
| PID 1 executable link | `/usr/lib/systemd/systemd` |
| Running/disk UID:GID, mode | `0:0`, `755` for both |
| Running/disk size | `141776` bytes for both |
| Running/disk device and inode | `2050:1471799` for both |
| Running and disk SHA-256 | `3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3` |
| Local dpkg claim | `systemd`, `amd64`, `install ok installed`, version `259.5-0ubuntu3.4` |
| Local dpkg path claim | `systemd: /usr/lib/systemd/systemd` |
| Script terminator | `STOP: read-only clone preflight complete; return output for review.` |

The output also showed root-owned path components from `/` through the
candidate binary. The running and on-disk digest, device and inode matched
in this one owner-reported read. The `systemd` version and file ownership are
**local dpkg claims**, not independently authenticated package provenance.
The pre-hash 32 MiB size gate does not make `sha256sum` race-proof if a
privileged writer changes the file during hashing.

No authenticated binary package, signed Release/package-index chain,
independent image comparison, native Python observer run, intended-host
attestation or current original-VM liveness check was supplied. This digest
is **not an approved pin**; do not insert it into the PID 1 reference, a
guard, admission policy or the original VM's configuration. No VM command is
released by this record.
