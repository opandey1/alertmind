# PID 1 clone Gate 2C — bounded observation launch candidate

Status: **offline candidate; not executed or released for VM execution**.
Gate 2A and [Gate 2B source staging](../../evidence/rbac/pid1-clone-source-stage-2026-09-30.md)
are complete as owner-reported checkpoints. Do not repeat them, regenerate
the source artifact or overwrite either staged copy.

This is one read-only diagnostic on **Ubuntu SOC 201 - Current Isolated Clone**.
It is not a production launcher, installation transaction, maintenance guard,
approved PID 1 reference or Phase 1/OIDC completion. No original-VM command
is authorized. The held-source entry and its external checksum stay unchanged.

## Release and external trust boundary

**Do not run this candidate yet.** Merge or successful offline tests alone do
not release privileged observation. Obtain a separate explicit release for
this packet and acknowledge the following diagnostic assumptions first:

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

No new VM inventory output is needed merely to prepare this candidate. If a
condition is unknown or a digest has changed, stop for review; do not install
packages, repair paths or auto-learn an updated pin to make the diagnostic pass.

## Packet — held pending explicit release

Once separately released, run this entire subshell as `notroot` at the clone's
console. The three prompts are confirmations, not secret input or shell commands.
The root shell reads fixed public instructions from a quoted heredoc. Its
outer timeout starts after sudo authentication; the observer has a separate
40-second timeout/2-second kill grace and a 30-second BOOTTIME collection window.
Fixed hash reads have 5-second timeouts. These are process timeouts, not a
guarantee across host sleep, kernel failure or a hostile privileged actor.

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
    [ "$(/usr/bin/timeout --signal=TERM --kill-after=2s 5s /usr/bin/sha256sum -- "$entry")" = "$source_sha  $entry" ] || fail CLONE_SOURCE_DIGEST
    [ "$(/usr/bin/timeout --signal=TERM --kill-after=2s 5s /usr/bin/sha256sum -- "$python")" = "$python_sha  $python" ] || fail CLONE_PYTHON_DIGEST
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
    /usr/bin/timeout --signal=TERM --kill-after=2s 40s \
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
failure. Stop for review; do not retry by changing the launch flags, selecting
another interpreter, refreshing hashes, elevating a writable checkout or
repairing the clone to satisfy the candidate. No live result is recorded by
this offline packet and no privileged execution has occurred in its tests.
