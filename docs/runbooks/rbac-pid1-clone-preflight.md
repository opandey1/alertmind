# PID 1 installed-image preflight — disposable clone only

Status: **Gate 1 owner-executed on 2026-09-28; independently unreviewed**.
The owner identified `Ubuntu SOC 201 - Current Isolated Clone` as a clone of
the original VM's **Current State (changed)**, not a clone of historical
`Snapshot 1`. The owner reports every adapter disabled in the clone's
VirtualBox settings, the original VM untouched, and no clone update or
configuration change after cloning. The reported output and limits are in
[the sanitized evidence record](../../evidence/rbac/pid1-current-clone-preflight-2026-09-28.md).
This packet does not authorize the dormant Python PID 1 observer,
the Dashboard guard, a package change, or any command on the original
`wazuh-siem` VM. It gathers the first native candidate observations needed to
review an installed `systemd` reference; it is not that reference.

## Gate 0 — distinguish and isolate the clone

Before booting or using its console on any future repetition, identify the
**clone** by its VirtualBox VM entry and settings, not by its hostname or IP
address (both can be copied from the original). In the clone's VirtualBox
network settings, disconnect **every** virtual adapter from NAT, host-only,
bridged and other networks
(`Not attached` or cable disconnected). Do not change the original VM's
settings. Confirm the clone is disposable, its console is open, no AlertMind
application is running against it, and no update or configuration work is in
progress. If it is already booted and adapter isolation is uncertain, stop;
verify isolation in VirtualBox before running Gate 1. Do not copy or paste
credentials, secrets, raw alerts or configuration values into the packet.

The operator must explicitly attest these facts before Gate 1. The shell
output below cannot prove that the console belongs to the clone or that a
disconnected adapter cannot be reconnected later. A failed or uncertain
check is a stop, not a reason to try the original VM.

## Gate 1 — bounded, read-only candidate inventory

On the **isolated clone's console only**, run the block once. It executes
`bash`, `readlink`, `stat`, `sha256sum`, `namei` and `dpkg-query`. It reads
local OS/architecture metadata, the fixed PID 1 executable link and disk
image, path metadata and local dpkg status/file-list claims. It does not
execute the image, Python, `systemctl`, a generator
or an installer/updater, connect to a network, write a file or change a service.
The `sudo` prompt is for the clone operator's local account; do not record or
paste that password. Stop on any error or unexpected output; do not change a
path, use a fallback image or repair the clone as part of this gate.

```bash
sudo bash <<'ALERTMIND_PID1_CLONE_PREFLIGHT'
set -euo pipefail
export LC_ALL=C

image=/usr/lib/systemd/systemd
printf '%s\n' '=== Candidate and local operating-system claim ==='
grep -E '^(ID|VERSION_ID)=' /etc/os-release
printf 'architecture=%s\n' "$(dpkg --print-architecture)"

printf '%s\n' '=== Running PID 1 image link ==='
if ! running_target=$(readlink -- /proc/1/exe); then
    printf '%s\n' 'STOP: PID 1 executable link could not be read'
    exit 1
fi
printf 'pid1_executable_link=%s\n' "$running_target"
if [ "$running_target" != "$image" ]; then
    printf '%s\n' 'STOP: PID 1 executable is not the fixed candidate'
    exit 1
fi
if [ -L "$image" ] || [ ! -f "$image" ]; then
    printf '%s\n' 'STOP: fixed disk image is not a regular non-symlink file'
    exit 1
fi
namei -l -- "$image"

printf '%s\n' '=== Running and on-disk identity ==='
running_identity=$(stat -Lc '%d:%i' -- /proc/1/exe)
disk_identity=$(stat -Lc '%d:%i' -- "$image")
running_size=$(stat -Lc '%s' -- /proc/1/exe)
disk_size=$(stat -Lc '%s' -- "$image")
stat -Lc 'running uid=%u gid=%g mode=%a bytes=%s device=%d inode=%i' -- /proc/1/exe
stat -Lc 'disk    uid=%u gid=%g mode=%a bytes=%s device=%d inode=%i' -- "$image"
if [ "$running_identity" != "$disk_identity" ]; then
    printf '%s\n' 'STOP: running and disk image device/inode differ'
    exit 1
fi
if (( running_size < 1 || running_size > 33554432 || disk_size != running_size )); then
    printf '%s\n' 'STOP: image size is outside the fixed 32 MiB bound or differs'
    exit 1
fi
running_hash=$(sha256sum -- /proc/1/exe)
running_hash=${running_hash%% *}
disk_hash=$(sha256sum -- "$image")
disk_hash=${disk_hash%% *}
printf 'running_sha256=%s\ndisk_sha256=%s\n' "$running_hash" "$disk_hash"
if [[ ! $running_hash =~ ^[0-9a-f]{64}$ ]] || [ "$running_hash" != "$disk_hash" ]; then
    printf '%s\n' 'STOP: running and disk image digests differ or are malformed'
    exit 1
fi

printf '%s\n' '=== Local dpkg claim ==='
if ! claim=$(dpkg-query -W -f='${Architecture}|${Status}|${Version}' systemd); then
    printf '%s\n' 'STOP: systemd package claim unavailable'
    exit 1
fi
printf 'systemd_claim=%s\n' "$claim"
case "$claim" in
    'amd64|install ok installed|'?*) ;;
    *) printf '%s\n' 'STOP: systemd package claim is not installed amd64'; exit 1 ;;
esac
if ! dpkg-query --search -- "$image"; then
    printf '%s\n' 'STOP: local package file-list claim unavailable'
    exit 1
fi
printf '%s\n' 'STOP: read-only clone preflight complete; return output for review.'
ALERTMIND_PID1_CLONE_PREFLIGHT
```

Return only the Gate 0 operator attestation (clone entry identified, all
adapters disconnected, original VM untouched) and the complete sanitized
Gate 1 output, including a STOP if one occurred. No package archives, raw
`/proc` content, environment, credentials or configuration files are
requested. The command toolchain, filesystem and dpkg database are themselves
clone-local observations: matching inodes/hashes and a dpkg file-list entry
are **not** package-source authentication, an independently pinned baseline,
proof of the intended host, or proof of loaded manager code. These shell reads
are not atomic against privileged writes. The 32 MiB size check is a
**pre-hash gate**, not a hard I/O cap if the file changes during `sha256sum`;
only the separately reviewed native reader can enforce its own read bound.

The reported running and disk image observations agree, and the local package
record names the same path; this remains only a clone-local candidate. The
owner has not yet confirmed the separate Gate 0 condition that no AlertMind
app was running against the clone; this must be checked before any further
clone execution.
The [next-gate plan](rbac-pid1-clone-provenance-plan.md) separates
independent package-source comparison from native compatibility testing of
the existing dormant observer. A locally clean `dpkg --verify` would compare
against the same local database, not authenticate the installed package. No
pin may be auto-learned from Gate 1 or copied into admission policy. The
original VM remains untouched and Phase 1/OIDC acceptance remains open.
