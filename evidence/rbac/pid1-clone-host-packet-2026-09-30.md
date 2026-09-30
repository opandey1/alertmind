# PID 1 clone Gate 2B — host packet rendering checkpoint

Status: **Block 1 completed; clone staging and root observation pending;
independent review deferred, not self-approved**.
The owner supplied the following output on 2026-09-30 after reporting the
branch merged. The local checkout confirms implementation `277f27b` was merged
in PR #96 at `81fdd88`. Codex checked the output against the
[Gate 2B packet](../../docs/runbooks/rbac-pid1-clone-source-launch.md).
The receipt date is not an independently observed execution timestamp.

## Reported output

```text
PASS host packet SHA-256: 5b15151c91c3f6a2eb0e473489df1d70485cbe7c03cb1d8ffa22b7dc21c98106
PASS host packet: bytes=121691 source_count=8; observer not executed
PASS clipboard: wrapped public Base64 and end marker only
STOP POINT: retain the output; transfer to the isolated clone only after review
```

All four lines match Block 1. A read-only check of the existing Windows-host
artifact `%TEMP%\alertmind-pid1-clone-2b-20260930.py` confirmed 121691 bytes and
the same SHA-256. A separate in-memory rendering matched that size and digest
and contained eight source entries. Neither check executed bundled observer
code. Codex did not read or alter the clipboard, connect to a VM, transfer
the packet or run privileged observation.

The clipboard line records the owner's Block 1 result, not its current contents.
Copying Block 2 can replace that public Base64. The runbook now provides a
separate refresh snippet that checks the existing artifact's exact bytes and
restores only wrapped public Base64 and its end marker. Do not rerun Block 1
over the existing artifact or paste Base64 into the chat.

## Next checkpoint and limits

Block 1 needs no rerun. Block 2 staging may proceed only on the console of
`Ubuntu SOC 201 - Current Isolated Clone`, with its fresh clone-only
prerequisites confirmed: disconnected adapters, no AlertMind app use, no
intervening updates/configuration work and the original VM untouched.
It creates new staging directories, performs unprivileged verification and
copies the checked public source to a root-private location. It does not run
any bundled observer or root Python. Return its PASS/STOP output before any
further action; preserve a partial stage and stop if a check fails.

Root observation, external runtime/launch review, independent archive-chain
review and an approved PID 1 reference remain outstanding. This host checkpoint
does not establish native observer compatibility, package authenticity,
production deployment authority or Phase 1/OIDC completion. All earlier
deferred independent-review obligations remain open.
