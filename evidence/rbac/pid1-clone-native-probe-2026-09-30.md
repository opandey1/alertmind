# PID 1 clone Gate 2A — owner-reported compatibility diagnostic

Status: **completed owner-executed checkpoint; independent review pending**.
The owner supplied the following sanitized output on 2026-09-30 after reporting
the probe branch merged. The local checkout confirms `bca00b4` was merged in
PR #94 at `9f13df5`. Codex checked the transcript against the
[Gate 2A packet](../../docs/runbooks/rbac-pid1-clone-native-compatibility.md);
Codex did not access either VM.

## Operator context and source

- The owner reconfirmed the clone's identity, disconnected network adapters,
  unchanged state and that no AlertMind application uses it.
- The previously identified VirtualBox entry is
  `Ubuntu SOC 201 - Current Isolated Clone`, created from the original VM's
  `Current State (changed)`. This remains distinct from historical `Snapshot 1`.
- The packet runs the fixed `/usr/bin/python3.14` with `-I -S -B` as an
  unprivileged user, under a 20-second shell timeout. These are the packet's
  checks; no raw interpreter identity, boot ID or execution timestamp was
  printed. The date above is the date the output was received.
- The output contains no packet digest or Git commit. The merge establishes
  repository history, not independent attestation of the pasted console code.

## Reported output

```text
PASS isolated unprivileged Python 3.14 feature probe
PASS visible procfs mount and PID 1 stat/status candidate shapes
PASS bounded local dpkg status and systemd file-list candidate shapes
PASS no AlertMind module imported; no privileged observer executed
STOP POINT: return only these PASS/STOP lines; do not run the PID 1 observer
```

All four PASS lines and the final STOP POINT match the committed packet.
The checkpoint is accepted as an owner-reported successful diagnostic. No
retry or additional Gate 2A output is needed for this recorded run.

## Meaning and remaining work

This reports compatibility of selected Python features and procfs/dpkg input
shapes in one unprivileged clone run. It does not execute the actual PID 1
observer, compare its running/disk image output, authenticate Python imports
or installed package origin, or establish the original VM's current state.
It does not provide a reviewed PID 1 reference or maintenance/startup authority.

The next work is to prepare a verified source/runtime launch for the actual
bounded observer on this disposable clone and retain its sanitized result for
comparison with the existing image/archive candidate. That launch still needs
separate review; Gate 2A is complete and should not be repeated to substitute
for it. Earlier deferred review obligations remain open.
