# PID 1 clone Gate 2B — root-private source staging checkpoint

Status: **Block 2 completed as owner-reported staging; root observation pending;
independent review deferred, not self-approved**.
The owner supplied the following results on 2026-09-30 after reporting
`evidence/rbac-pid1-clone-host-packet` merged. The local checkout confirms
`e62e421` was merged in PR #97 at `0d95aa2`, retaining the host checkpoint.
The executable staging packet and source candidate came from `277f27b`,
merged in PR #96 at `81fdd88`. Codex compared the results with the
[Gate 2B staging packet](../../docs/runbooks/rbac-pid1-clone-source-launch.md)
and the standalone entry's verification-mode output. Codex did not access a VM.
The date above records receipt, not an independently observed execution time.

## Operator confirmation and reported results

The owner returned `CLONE-ONLY` at the prompt requiring clone identity,
disconnected adapters, no app use and no intervening updates to be checked.
The packet identifies `Ubuntu SOC 201 - Current Isolated Clone`, not the
original VM or historical Snapshot 1. This is operator confirmation, not
independent machine or isolation attestation.

The result lines below retain the reported checks. The sudo password prompt
and public Base64 prompt are omitted; the owner's `xxxxxxxxxxxxxxxxxxxxxxxxx`
transfer placeholder immediately before the first path is also omitted.
No transfer bytes or credentials are recorded here.

```text
/home/notroot/alertmind-pid1-clone-2b-public/pid1_clone_entry.py: OK
PASS held source hashes and syntax: 8 modules; none executed
PASS verification mode complete; observer was not executed
/root/alertmind-pid1-clone-2b/pid1_clone_entry.py: OK
PASS root-private staged source: exact checksum, root:root, directory 0700, file 0400
PASS clone source stage: source_count=8; no bundled observer executed
STOP POINT: return staging output; do not run observation mode
```

All expected checksum, verification, metadata and final STOP results are
present, with no reported failure. The checkpoint is accepted as successful
owner-executed staging. The packet binds both source copies to 121691 bytes
and SHA-256 `5b15151c91c3f6a2eb0e473489df1d70485cbe7c03cb1d8ffa22b7dc21c98106`;
its root-private checks require root:root, directory 0700, file 0400 and one
file link. The transcript reports those checks passing but does not print
the digest or individual metadata values independently. Merge history does
not attest the exact console code used.

Verification mode ran the standalone entry's standard-library bootstrap and
compiled all eight held sources as an unprivileged user. It did not execute
any bundled source or the PID 1 observer. The privileged staging operations
copy/check public files only; no root Python or service change is requested.

## Next work and limits

Do not repeat either Block 1 or Block 2, overwrite the existing stage, change
permissions or run `--observe` manually. Preserve both staged copies. No further
VM output is needed for this completed staging checkpoint.

The next work is to prepare and review the separate bounded clone-only
observation command against the installed source and candidate runtime
conditions. External runtime/launch trust remains outstanding; staging is not
approval of that boundary. The observer's native behavior, running/disk image
comparison, independent archive-chain review and approved versioned reference
remain pending. This record grants no original-VM maintenance, deployment,
startup or Phase 1/OIDC authority. All earlier deferred review obligations
remain open.
