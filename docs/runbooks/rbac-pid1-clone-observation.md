# PID 1 clone Gate 2C — bounded observation launch candidate

Status: **owner-reported Gate 2C diagnostic completed on 2026-09-30;
independent review pending; reference not approved**.
The [retained result](../../evidence/rbac/pid1-clone-observation-2026-09-30.md)
contains both wrapper PASS lines, the matching two-pass JSON and both STOP
POINT lines, with no reported failure. The single-run release has been used.
**Do not rerun this packet.** Its unchanged Bash block below is retained as
execution provenance, not permission for another run.
Gate 2A and [Gate 2B source staging](../../evidence/rbac/pid1-clone-source-stage-2026-09-30.md)
are complete as owner-reported checkpoints. Do not repeat them, regenerate
the source artifact or overwrite either staged copy.

This is one read-only diagnostic on **Ubuntu SOC 201 - Current Isolated Clone**.
It is not a production launcher, installation transaction, maintenance guard,
approved PID 1 reference or Phase 1/OIDC completion. No original-VM command
is authorized. The held-source entry and its external checksum stay unchanged.

## Release and external trust boundary

The owner separately answered **“Approve and confirm all conditions”** on
2026-09-30, approving one read-only Gate 2C run on the named clone and accepting
the diagnostic assumptions below. This is the execution release for the exact
packet merged in PR #99 (`7fcc211`, `5c4dbb2`; merge `40e8abb`), not independent
review or evidence that it has run. The Bash block is unchanged by this release.
Merge or successful offline tests alone do not release privileged observation.

For that single run, these conditions had to be reconfirmed at execution:

- The exact clone entry is selected in VirtualBox, every network adapter is
  disconnected, no AlertMind app uses it and the original VM remains untouched.
- No update, configuration work or concurrent privileged operation has intervened
  since staging. The host/VM are stable; do not run while an update or sleep,
  overheating or recovery condition is in progress.
- The operator trusts this clone's OS/kernel, root shell, sudo, coreutils,
  interpreter, stdlib and native libraries sufficiently for a disposable
  diagnostic. Earlier local hashes/package checks are supporting observations,
  not authenticated origin or loaded-code proof. Root code cannot bootstrap
  that trust with self-checks. This does not waive independent review before
  any approved reference or production use.
- The owner-directed temporary review deferral remains recorded in HANDOFF.
  Typing a confirmation below does not independently review this packet or
  close any deferred obligation.

No further VM output is needed for this completed diagnostic. For any later
separately authorized operation, an unknown condition or changed digest must
stop for review; do not install
packages, repair paths or auto-learn an updated pin to make the diagnostic pass.

## Packet — historical single-run diagnostic; do not repeat

The owner ran this entire subshell as `notroot` at the clone's console under
the single-run release. The original instructions were: enter `CLONE-ONLY`, `TRUSTED-DIAGNOSTIC` and
`LAUNCH-RELEASED` at their respective confirmation prompts, not as standalone
shell commands. Enter the normal sudo password only at sudo's password prompt;
do not paste it into chat. These confirmations do not grant production authority.
No additional branch merge was required for this unchanged, already merged block.
The root shell reads fixed public instructions from a quoted heredoc. Its
outer timeout starts after sudo authentication; the observer has a separate
40-second timeout/2-second kill grace and a 30-second BOOTTIME collection window.
Fixed hash reads have 5-second timeouts. These are process timeouts, not a
guarantee across host sleep, kernel failure or a hostile privileged actor.
Only the outer timeout creates a process group. Nested hash/observer timeouts
use `--foreground` to stay in that group rather than escaping the outer
monitor's group signal. This follows the [GNU timeout implementation](https://github.com/coreutils/coreutils/blob/master/src/timeout.c):
foreground mode omits the separate group and signals its direct child.
The fixed observer does not spawn children; this is not a containment promise
for arbitrary code that changes groups or sessions. The upstream source is
semantic guidance, not authentication of the clone's installed tool.

```bash
(
set -euo pipefail
trap 'printf "%s\n" "STOP: CLONE_LAUNCH_FAILED"; exit 1' ERR
read -r -p 'Type CLONE-ONLY after checking clone identity, disconnected adapters, no app use, stable host and no intervening changes: ' clone
[ "$clone" = CLONE-ONLY ] || { printf '%s\n' 'STOP: clone conditions not confirmed'; exit 1; }
read -r -p 'Type TRUSTED-DIAGNOSTIC only after accepting the external clone/runtime/toolchain trust assumptions for this diagnostic: ' trust
[ "$trust" = TRUSTED-DIAGNOSTIC ] || { printf '%s\n' 'STOP: external diagnostic trust not confirmed'; exit 1; }
read -r -p 'Type LAUNCH-RELEASED only after this exact packet has received separate explicit execution release: ' release
[ "$release" = LAUNCH-RELEASED ] || { printf '%s\n' 'STOP: observation release not confirmed'; exit 1; }
if sudo /usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/timeout --signal=TERM --kill-after=2s 60s \
    /bin/bash --noprofile --norc -s <<'ALERTMIND_CLONE_ROOT'
set -euo pipefail
trap 'printf "%s\n" "STOP: CLONE_ROOT_CHECK_FAILED"; exit 1' ERR
trap 'printf "%s\n" "STOP: CLONE_LAUNCH_INTERRUPTED"; exit 130' INT
trap 'printf "%s\n" "STOP: CLONE_LAUNCH_INTERRUPTED"; exit 143' TERM
umask 077
ulimit -S -c 0
ulimit -H -c 0
cd /
[ "$(/usr/bin/id -u)" = 0 ] && [ "$(/usr/bin/id -g)" = 0 ] || { printf '%s\n' 'STOP: root identity mismatch'; exit 1; }
entry='/root/alertmind-pid1-clone-2b/pid1_clone_entry.py'
python='/usr/bin/python3.14'
source_sha='5b15151c91c3f6a2eb0e473489df1d70485cbe7c03cb1d8ffa22b7dc21c98106'
python_sha='52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'
fail() { printf 'STOP: %s\n' "$1"; exit 1; }
check_files() {
    local parent
    for parent in / /usr /usr/bin; do
        [ "$(/usr/bin/stat -c '%F:%u:%g:%a' -- "$parent")" = 'directory:0:0:755' ] || fail CLONE_PARENT_METADATA
    done
    case "$(/usr/bin/stat -c '%F:%u:%g:%a' -- /root)" in
        directory:0:0:700|directory:0:0:750|directory:0:0:755) ;;
        *) fail CLONE_PARENT_METADATA ;;
    esac
    [ "$(/usr/bin/stat -c '%F:%u:%g:%a' -- /root/alertmind-pid1-clone-2b)" = 'directory:0:0:700' ] || fail CLONE_STAGE_METADATA
    [ "$(/usr/bin/stat -c '%F:%u:%g:%a:%h:%s' -- "$entry")" = 'regular file:0:0:400:1:121691' ] || fail CLONE_SOURCE_METADATA
    [ "$(/usr/bin/stat -c '%F:%u:%g:%a:%h:%s' -- "$python")" = 'regular file:0:0:755:1:7477160' ] || fail CLONE_PYTHON_METADATA
}
check_hashes() {
    [ "$(/usr/bin/timeout --foreground --signal=TERM --kill-after=2s 5s /usr/bin/sha256sum -- "$entry")" = "$source_sha  $entry" ] || fail CLONE_SOURCE_DIGEST
    [ "$(/usr/bin/timeout --foreground --signal=TERM --kill-after=2s 5s /usr/bin/sha256sum -- "$python")" = "$python_sha  $python" ] || fail CLONE_PYTHON_DIGEST
}
check_files
source_stamp=$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$entry")
python_stamp=$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$python")
check_hashes
[ "$source_stamp" = "$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$entry")" ] || fail CLONE_SOURCE_CHANGED
[ "$python_stamp" = "$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$python")" ] || fail CLONE_PYTHON_CHANGED
printf '%s\n' 'PASS pre-launch staged source and candidate interpreter: exact metadata, digests and stable identity'
# Clear again: Bash exports PWD/SHLVL; the entry requires exactly these three keys.
if /usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/timeout --foreground --signal=TERM --kill-after=2s 40s \
    /usr/bin/python3.14 -I -S -B -X pycache_prefix=/dev/null/alertmind-pid1-clone \
    "$entry" --observe
then
    :
else
    status=$?
    case "$status" in
        124|137) fail CLONE_OBSERVATION_TIMEOUT ;;
        *) fail CLONE_OBSERVATION_FAILED ;;
    esac
fi
check_files
check_hashes
[ "$source_stamp" = "$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$entry")" ] || fail CLONE_SOURCE_CHANGED
[ "$python_stamp" = "$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$python")" ] || fail CLONE_PYTHON_CHANGED
printf '%s\n' 'PASS post-launch staged source and interpreter: metadata, digests and identity unchanged'
ALERTMIND_CLONE_ROOT
then
    printf '%s\n' 'STOP POINT: return the complete diagnostic output for review; no reference or maintenance approval'
else
    status=$?
    case "$status" in
        124|137) printf '%s\n' 'STOP: CLONE_LAUNCH_TIMEOUT' ;;
        *) printf '%s\n' 'STOP: CLONE_LAUNCH_FAILED; no result accepted' ;;
    esac
    exit 1
fi
)
```

## Accepting the output

The retained owner report satisfies the diagnostic contract below. This is
not independent result review or reference approval; do not request another
run to reconfirm the completed checkpoint.

A successful packet must have the pre-launch PASS, the entry's sanitized JSON
and diagnostic STOP, the post-launch PASS and the final review STOP, with
exit zero and no failure line. A JSON result followed by a timeout, drift or
other failure is **not accepted**, even if the entry itself returned zero.
Return the whole sanitized result, not only its candidate-match field.

The entry verifies Linux/root/x86_64, Python 3.14.4, exact argv/search path,
environment, cache-prefix and core limits, then loads the eight verified sources
into its empty-path synthetic package. Only `observe_pid1_image_inventory()`
is called. Its two-pass record must match the earlier image/version candidate
and retain all false trust/authority claims. Imports execute bundled module
definitions; this is no longer verification-only mode.

The wrapper performs no file creation, chmod/chown, package installation,
service query/reload/restart, credential access, network request or persistent
pin update. Reads may advance access times. Root-private source/metadata checks
exclude ordinary-user substitution, not hostile root/kernel changes or an
atomic guarantee across every named-path read and execution. The fixed runtime
checks are not authentication of shell/tools, stdlib/native origins or loaded
code. Independent native-result/archive review remains before any reference.

On failure or interruption, preserve the staged source and complete sanitized
failure. Stop for review before any retry; this single-run release does not
authorize retries or changing the launch flags, selecting
another interpreter, refreshing hashes, elevating a writable checkout or
repairing the clone to satisfy the candidate. No live result is recorded by
this offline packet and no privileged execution has occurred in its tests.
