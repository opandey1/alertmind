# Operator safety core — offline, not an installer

This is the first implementation slice of the approved design's operator
package. `operator_core.py` implements byte-integrity checks for a future
pre-start guard and conservative rollback decisions. It has no command-line
entry point, process execution, network access, filesystem writes or service
operations. **No startup guard is installed or operational on the VM.**

The candidate and existing contract remain unchanged. The core repeats the
reviewed pins deliberately; a CI test requires equality with `contract.json`.
Do not refresh either pin set automatically after a failed check.

## Implemented

`installed_checks(manifest_bytes)` accepts the pinned builder manifest only.
It rejects malformed/duplicate JSON, unrecognized pins, changed file inventory,
unsafe paths and invalid sizes. It translates the candidate to the installed
broker-client path and the packaged dependency files to their installed paths.
The original client is **not** an acceptable installed replacement. The primary
packaged Node binary and version header are added as pinned targets. The real
approved manifest yields 270 targets; deriving these paths does not read them.

`verify_installed_bytes(...)` rejects an unexpected package version or selected
Node path before calling its reader. It verifies sizes and hashes on two full
passes, including the candidate, dependencies and primary Node binary/header.
Missing/read-error/changed/oversized bytes fail with fixed diagnostic codes.
It returns `startup_authorized: false` even when byte checks pass.

The injected reader and version/runtime observations are an **unimplemented
privileged-adapter boundary**, not trusted evidence because a caller supplies
them. A caller can fake them; this library is not a security boundary against
its caller. Production wiring must use fresh, independently verified observations
and bounded reads before allocation, not owner-entered paths or a saved JSON
receipt. Tests currently use miniature synthetic manifests/readers. No native
root/no-follow filesystem proof or packaged Linux execution is claimed.

`recovery_step(observation)` returns one next action from fresh observations:

| Observation | Next action |
|---|---|
| Startup inhibition absent or unknown | Inhibit startup, then re-observe |
| Dashboard stop not established | Stop Dashboard, then re-observe |
| Installed client missing/unrecognized | Hold; investigate, never overwrite unknown bytes |
| Exact private backup/metadata unverified | Hold; do not restore |
| Candidate still installed | Restore original atomically while inhibited and stopped |
| Original bytes restored, metadata not proven | Restore original metadata while inhibited and stopped |
| Original bytes and metadata restored | Keep Dashboard stopped and inhibited |

This implements rollback decision logic, **not atomic replacement, durable
journaling, power-loss recovery or service inhibition itself**. A transaction
journal may assist an operator, but cannot establish current file/service state.
Tests model interruptions before and after each observation transition, replay
the same observation and confirm deterministic decisions. They are not disk
crash simulations. Each physical action, once implemented, must have fresh
readback and independently tested interruption handling.

There is no restart, unmask, cleanup or delete action in this core. Restoring the
known non-verifying original never authorizes its execution. Exact original
bytes alone do not prove restoration of original owner/group/mode metadata.
Unknown state stays held; no backup, journal or success result is invented.

## Verification

Twenty network-free tests run in the ordinary regression suite. Eight deliberately
removed controls were additionally checked during author verification: manifest
inventory pin, second pass, package/runtime identity, startup inhibition,
private-backup validation, unknown-client hold and no-restart terminal state.
These mutation runs are author checks, not additional unittest methods.

The September 13 test-only follow-up pins exact parser error codes (including
nested duplicate keys and all three non-finite JSON constants) and independently
exercises expected length versus maximum length. The upper-bound case uses the
runtime header target, whose exact size is intentionally unspecified, with all
preceding reads valid. Removing any of those four guards must now fail the
corresponding error-code assertion rather than pass on a later hash/contract
error. The suite still contains twenty operator methods; production core and
candidate bytes are unchanged. See
[follow-up verification](operator-test-verification-2026-09-13.json).

Historical TLS fixture verification files remain unchanged. Claude's September
12 approval records the updated 16-group fixture passing on Linux Node 22.22.2
with inherited proxy settings; it does not close the native operator gates.

## Required next adapter package — not released here

1. Establish selected packaged Linux runtime and real Server certificate
   suitability without broker credentials; agree the 30-second timeout and
   performance acceptance criteria. Preserve the current public fingerprints.
2. Implement/review native descriptor-relative no-follow traversal, ownership,
   mode and bounded-read checks for guard/manifest/trust/vendor paths. Preserve
   the distinction between root-controlled trust and service-mutable vendor code.
   Two equal byte passes cannot prevent edits after checking or attest running
   code. Verify the installed dependency resolution/file set too: matching listed
   files alone does not exclude an extra module or a changed resolution path.
3. Derive effective package, runtime, launch/environment and single broker host
   settings privately. No arbitrary executable override, fallback Node or
   `NODE_OPTIONS` preload may bypass the intended guard. Do not export secrets.
4. Build the root-controlled pre-start adapter and exact service drop-in from
   observed unit settings. Do not invent a unit override or silently overwrite
   existing drop-ins. A guard failure must prevent background/internal broker
   authentication as well as interactive requests.
5. Implement/rehearse durable inhibition, exact private backups, atomic installs,
   metadata preservation and recovery from interruption after every write.
   Do not remove the inhibitor on rollback to the original. Unknown file content
   or partially written state requires inspection, not unconditional replay.
6. Obtain explicit owner downtime/checkpoint approval and independent package
   review **before** any staging/apply/restart instructions. Preserve Snapshot 1.
   Then perform real internal/scoped broker, admin and saved-object acceptance;
   these do not follow from a core or fixture PASS.

No VM command is requested by this deliverable. No role, grant, credential,
certificate, SSH transport, benchmark, dependency or live Dashboard change is
included. The larger operator package and subsequent application work remain
incomplete until those separately reviewed steps are implemented and accepted.
