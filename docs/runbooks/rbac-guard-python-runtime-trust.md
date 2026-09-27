# Guard Python runtime trust — offline inventory boundary

Status: **not selected, not installed, not approved for startup**. Gates A,
B1, B2, C1, C2 and C3 below are completed owner-reported diagnostics. No VM
output or rerun is requested for the current offline policy work. Historical
command blocks are retained for provenance, not instructions to replay them.
None authorizes the dormant held-code loader or a Dashboard change.

The 13 source files in the proposed pre-start capsule have an exact, CI-checked
direct-import contract. Their module bodies import these 16 standard-library
roots: `base64`, `binascii`, `contextlib`, `dataclasses`, `errno`, `hashlib`,
`json`, `os`, `pathlib`, `re`, `selectors`, `stat`, `subprocess`, `sys`, `time`,
and `types`. `operator_fs._identity()` later imports `pwd` and `grp`, making
**18 direct roots in the full possible call path**. Relative project imports
refer only to earlier, pinned modules. The contract also catches recognized
`__import__`, `eval`, `exec` and `importlib`/`runpy`-style calls in these
sources. This is static source coverage, not a Python sandbox: aliasing,
transitive imports, C extensions and runtime-loaded modules are not proven.

Before executing the dormant loader in any pre-start path, an independent
review must settle all of the following from a **selected host runtime**:

1. The exact interpreter executable and its resolved target, version,
   installation/package provenance, bytes and non-service-writable ownership
   chain. The historical Wazuh-packaged Python path is only a candidate, not
   a selected or trusted interpreter.
2. The exact launch command and environment, including `-I -S -B`, linker
   inputs and path-related variables. An observed `sys.flags` value is a
   post-start tripwire, not authentication of what ran before the guard's
   first line. The unit policy must establish these inputs externally.
3. The selected runtime's effective `sys.path`, `sys.meta_path`, preloaded
   `sys.modules`, extension-module origins and standard-library provenance,
   including transitively imported code for all 18 direct roots. A source
   import list alone is not a full dependency closure.
4. An independently approved pin/update policy for those runtime artifacts
   and a recovery plan for package upgrades. A manifest derived from the
   running interpreter's own report cannot by itself attest that interpreter.
5. Native Linux/Python-version tests of the exact candidate, plus review of
   import side effects and startup latency. Existing Windows Python 3.12
   tests establish only the offline source contract.

Python's [isolated mode and site flags](https://docs.python.org/3.14/using/cmdline.html)
exclude several common injection paths, but do not certify the interpreter
or standard-library files. Python's [import system](https://docs.python.org/3.10/reference/import.html)
uses cached modules and finders; these also need review. Until the above is
accepted, `operator_guard_entry.py` must continue to **compile only**, exit 1,
and remain absent from the Dashboard service. Human `socanalyst` and broker
acceptance remain separate later gates.

## Gate A — metadata-only host candidate inventory

Run this **on the Wazuh VM console**, only with Snapshot 1 available, a stable
VM, all AlertMind apps stopped, and no simultaneous update/configuration work.
It reads two fixed candidate paths: the historical Wazuh-packaged Python and
the Ubuntu system Python. Neither is selected by this packet. Do not paste
credentials or raw configuration. Do not use an SSH tunnel for this step.

The block invokes `bash`, `readlink`, `namei`, `stat`, `sha256sum` and
`dpkg-query`; it **never invokes either Python candidate**, imports modules,
opens a network connection, writes a file, or changes a service. Its command
toolchain and package registry are host observations, not independent trust
anchors. A nonzero dpkg lookup is reported as unresolved, **not** as proof that
a package or owner is absent. If any other command fails unexpectedly, stop and
send the sanitized error without changing permissions or choosing a different
interpreter.

```bash
sudo bash <<'ALERTMIND_PYTHON_INVENTORY'
set -eu
export LC_ALL=C

for candidate in /var/ossec/framework/python/bin/python3 /usr/bin/python3; do
    printf '\n=== candidate %s ===\n' "$candidate"
    if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
        printf 'ABSENT: fixed candidate path\n'
        continue
    fi
    if ! resolved=$(readlink -e -- "$candidate"); then
        printf 'STOP: candidate path does not resolve cleanly\n'
        exit 1
    fi
    if [ ! -f "$resolved" ]; then
        printf 'STOP: resolved target is not a regular file\n'
        exit 1
    fi
    printf 'resolved=%s\n' "$resolved"
    namei -l -- "$candidate"
    stat -c 'entry: type=%F uid=%u gid=%g mode=%a size=%s mtime=%y' -- "$candidate"
    stat -Lc 'target: type=%F uid=%u gid=%g mode=%a size=%s mtime=%y' -- "$candidate"
    sha256sum -- "$resolved"
    printf 'package ownership for entry:\n'
    if ! dpkg-query --search -- "$candidate"; then
        printf 'UNRESOLVED: no successful dpkg ownership lookup\n'
    fi
    printf 'package ownership for resolved target:\n'
    if ! dpkg-query --search -- "$resolved"; then
        printf 'UNRESOLVED: no successful dpkg ownership lookup\n'
    fi
done

printf '\n=== installed package identities ===\n'
for package in wazuh-manager python3 python3-minimal python3.14-minimal; do
    if ! dpkg-query --show --showformat='${Package}\t${Version}\t${Status}\n' "$package"; then
        printf 'UNRESOLVED: package identity lookup for %s\n' "$package"
    fi
done
printf 'STOP: metadata-only candidate inventory complete; no Python executed.\n'
ALERTMIND_PYTHON_INVENTORY
```

Return only the output of this block. Public path metadata, package names and
binary digests are sufficient; no package archive, stdlib file contents,
environment values, tokens, passwords or private keys are requested. The
inventory is **not** runtime approval. After review, choose one candidate and
design a separate, bounded provenance/import-origin test for that exact
runtime; do not wire `_loaded_verified_bundle` or install the guard on the
strength of this output.

## Gate A owner result and provisional probe target (25 September 2026)

The owner reported the complete Gate A output. Both candidates resolved and
both entry/target paths were listed in dpkg's file ownership database:

| Candidate | Resolved binary | Owner/mode | SHA-256 | Package |
|---|---|---|---|---|
| Wazuh-packaged | `/var/ossec/framework/python/bin/python3.10` | root:wazuh, 0750 | `9447e8fd458492a1736238b429d5f5ead106fd5ac47fccc2cd83d0e4489ee7b6` | wazuh-manager 4.14.7-1 |
| Ubuntu system | `/usr/bin/python3.14` | root:root, 0755 | `52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41` | python3.14-minimal 3.14.4-1ubuntu0.2 |

The Wazuh path's shown ancestors are root-owned with group `wazuh` and mode
0750, **not group-writable**. The Ubuntu path's shown ancestors and binary are
root:root, with no group/other write bit. The symlink's 0777 mode is not a
claim that its root-owned parent is writable by the service. The owner did not
report `UNRESOLVED` or an early STOP. This is owner-reported metadata, not an
independent package-authenticity or ACL/mount proof.

For the **next diagnostic only**, `/usr/bin/python3.14` is the provisional
target: it is outside the Wazuh-managed tree and has the simpler root-owned
chain. This does **not** select it for the root-run pre-start guard or reject
the packaged Python. No interpreter was executed in Gate A. Package updates
can invalidate the observed digest; never auto-refresh a pin on mismatch.

## Gate B1 — system-Python package and direct ELF preflight

At the stable VM console, with Snapshot 1, stopped AlertMind apps and no
concurrent updates, run this **read-only** block. It rechecks the exact
Gate A target/digest, installed Python package identities and package-file
drift, selected stdlib path metadata, and the executable's directly declared
ELF loader/libraries. It never executes Python, Node or `ldd`, and does not
change services. If it stops, return the output; do not repair a package or
continue to Gate B2. Package verification compares files to the VM's own
dpkg database and is **only a drift check**, not a signed provenance proof.

```bash
sudo bash <<'ALERTMIND_SYSTEM_PY_PREFLIGHT'
set -euo pipefail
export LC_ALL=C

target=$(readlink -e -- /usr/bin/python3)
if [ "$target" != /usr/bin/python3.14 ]; then
    printf 'STOP: system Python target changed: %s\n' "$target"
    exit 1
fi
actual=$(sha256sum -- "$target")
actual=${actual%% *}
if [ "$actual" != 52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41 ]; then
    printf 'STOP: system Python binary digest changed: %s\n' "$actual"
    exit 1
fi
printf 'PASS pinned system Python target/digest: %s %s\n' "$target" "$actual"
namei -l -- /usr/bin/python3
stat -Lc 'binary: type=%F uid=%u gid=%g mode=%a size=%s' -- "$target"

for package in python3.14-minimal libpython3.14-minimal libpython3.14-stdlib; do
    status=$(dpkg-query --show --showformat='${Status}' "$package")
    version=$(dpkg-query --show --showformat='${Version}' "$package")
    printf 'package=%s version=%s status=%s\n' "$package" "$version" "$status"
    if [ "$status" != 'install ok installed' ]; then
        printf 'STOP: package not fully installed: %s\n' "$package"
        exit 1
    fi
    if verify_output=$(dpkg --verify "$package" 2>&1); then
        if [ -n "$verify_output" ]; then
            printf '%s\n' "$verify_output"
            printf 'STOP: package verification had output: %s\n' "$package"
            exit 1
        fi
        printf 'PASS local dpkg drift check: %s\n' "$package"
    else
        printf '%s\n' "$verify_output"
        printf 'STOP: package verification failed: %s\n' "$package"
        exit 1
    fi
done

for path in /usr/lib/python3.14/encodings/__init__.py /usr/lib/python3.14/os.py; do
    printf '=== selected stdlib file %s ===\n' "$path"
    namei -l -- "$path"
    stat -Lc 'file: type=%F uid=%u gid=%g mode=%a size=%s' -- "$path"
    dpkg-query --search -- "$path"
    sha256sum -- "$path"
done

if ! command -v readelf >/dev/null 2>&1; then
    printf 'STOP: readelf unavailable; do not substitute ldd\n'
    exit 1
fi
printf '=== direct ELF loader ===\n'
readelf -lW -- "$target" | grep -F 'Requesting program interpreter:'
printf '=== direct ELF needed libraries ===\n'
readelf -dW -- "$target" | grep -F '(NEEDED)'
printf 'STOP: Gate B1 metadata only; do not run Gate B2 yet.\n'
ALERTMIND_SYSTEM_PY_PREFLIGHT
```

Return only Gate B1 output. The two stdlib files are **samples**, not a complete
closure. `readelf` gives direct ELF declarations, not resolved/transitive
loader input. Review B1 before any Python execution. The [dpkg manual](https://manpages.debian.org/testing/dpkg/dpkg.1.en.html)
explicitly distinguishes `--verify` from a security verification; the
[Linux `ldd` manual](https://man7.org/linux/man-pages/man1/ldd.1.html)
warns against running it on an untrusted executable.

## Gate B2 — completed unprivileged import-origin diagnostic; do not rerun

The owner ran this block after review of Gate B1. It executed only the
provisionally selected system Python as the unprivileged
console user, with only three explicit environment values and `-I -S -B`;
its script contained no guard, network or Wazuh call. The JSON reported
version, flags, import finders, search paths and every module loaded after
importing the guard's eighteen direct stdlib roots. It does not print
environment values or module contents. Module origins are *self-reported
diagnostic data*, not independent
attestation of what the interpreter or linker executed.

```bash
(
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then
    printf 'STOP: run B2 as the unprivileged console user, not root\n'
    exit 1
fi
cd /
if [ "$(readlink -e -- /usr/bin/python3)" != /usr/bin/python3.14 ]; then
    printf 'STOP: system Python target changed since Gate B1\n'
    exit 1
fi
actual=$(sha256sum -- /usr/bin/python3.14)
actual=${actual%% *}
if [ "$actual" != 52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41 ]; then
    printf 'STOP: system Python digest changed since Gate B1\n'
    exit 1
fi
/usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/timeout 30s /usr/bin/python3.14 -I -S -B - <<'ALERTMIND_IMPORT_ORIGINS'
import sys
startup_modules = len(sys.modules)
import base64
import binascii
import contextlib
import dataclasses
import errno
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import selectors
import stat
import subprocess
import time
import types

flags = sys.flags
required_flags = ('isolated', 'ignore_environment', 'no_site',
                  'dont_write_bytecode')
if (sys.platform != 'linux' or os.geteuid() == 0 or
        sys.executable != '/usr/bin/python3.14' or
        sys.version_info[:2] != (3, 14) or
        any(getattr(flags, name, None) != 1 for name in required_flags)):
    raise SystemExit('STOP: unexpected diagnostic Python launch')

def finder_name(finder):
    kind = finder if isinstance(finder, type) else type(finder)
    return kind.__module__ + '.' + kind.__qualname__

modules = []
for name, module in sorted(sys.modules.items()):
    spec = getattr(module, '__spec__', None)
    modules.append({
        'name': name,
        'origin': getattr(spec, 'origin', None),
        'file': getattr(module, '__file__', None),
        'cached': getattr(module, '__cached__', None),
    })

print(json.dumps({
    'scope': 'unprivileged diagnostic, not guard/runtime attestation',
    'executable': sys.executable,
    'version': list(sys.version_info[:3]),
    'flags': {name: getattr(flags, name) for name in required_flags},
    'startup_module_count': startup_modules,
    'sys_path': sys.path,
    'meta_path': [finder_name(finder) for finder in sys.meta_path],
    'modules': modules,
}, sort_keys=True, indent=2))
ALERTMIND_IMPORT_ORIGINS
printf 'STOP: Gate B2 diagnostic only; no guard authorization.\n'
)
```

Passing B2 does not prove root-run behavior, cached-bytecode integrity,
dynamic-loader resolution, all function-local imports, package authenticity or
an immutable future systemd environment. No guard deployment is authorized.

### B1/B2 owner observations (25 September 2026)

Gate B1 reported the pinned `/usr/bin/python3.14` digest, all three Python
packages fully installed at `3.14.4-1ubuntu0.2` with clean local
`dpkg --verify` output, package-owned root:root samples for
`encodings/__init__.py` and `os.py`, and direct ELF declarations for the
interpreter. This is a local drift check, not package authenticity or resolved
loader proof. Gate B2 reported Python 3.14.4, the four expected isolation
flags, `startup_module_count=20`, the three standard import finders and the
exact diagnostic STOP. Its 104 module rows comprise 36 built-ins, 17 frozen,
50 paths under `/usr/lib/python3.14`, and the `<stdin>` module. The 50 paths
include one native extension, `_hashlib`; 49 source rows reported a bytecode
cache *path*, which does not prove that a cache file exists or was loaded.
The reported search path was `/usr/lib/python314.zip`,
`/usr/lib/python3.14`, `/usr/lib/python3.14/lib-dynload`. No non-standard
origin appeared in the owner-supplied JSON. This was an unprivileged,
self-reported diagnostic, not an independently attested runtime. Preserve the
original owner output outside Git; do not rerun B1/B2 to collect more data.

## Gate C1 — B2 file-origin and cache-candidate metadata, no Python execution

After reviewing this exact block and confirming Snapshot 1, stable VM console,
stopped AlertMind apps and no concurrent update/configuration work, run it at
the VM console. It is a **read-only inventory** of the fixed 50 file-backed
origins from B2, not a complete import or dynamic-linker closure. The list is
the ordered B2 `origin` values; its LF-separated SHA-256 is
`0648932e6294710318bba50f9c829327a7f1fff3be030606174fd44822c06497`.
The block fails closed on interpreter/package drift, missing or symlinked
origins, a service-writable path component, unexpected package ownership, or
an active `/usr/lib/python314.zip` path. It records source and existing cache
digests, not their contents. `__cached__` is a proposed cache path, not proof
that bytecode supplied the running module. An absent cache is normal; a
present cache is inspected for path ownership/mode but not assumed authentic.

```bash
sudo bash <<'ALERTMIND_PYTHON_ORIGIN_C1'
set -euo pipefail
export LC_ALL=C
export PATH=/usr/bin:/bin
cd /

stop() {
    printf 'STOP: Gate C1 %s\n' "$1"
    exit 1
}

check_chain() {
    local path=$1 expected_kind=$2 component meta uid gid mode kind
    [ "$(readlink -e -- "$path")" = "$path" ] || stop "non-canonical or symlinked path: $path"
    component=$path
    while :; do
        meta=$(stat -c '%u %g %a %F' -- "$component") || stop "stat failed: $component"
        read -r uid gid mode kind <<< "$meta"
        [ "$uid" = 0 ] && [ "$gid" = 0 ] || stop "non-root path component: $component"
        (( (8#$mode & 8#022) == 0 )) || stop "group/other-writable path component: $component"
        if [ "$component" = "$path" ]; then
            [ "$kind" = "$expected_kind" ] || stop "unexpected path type: $component"
        else
            [ "$kind" = directory ] || stop "non-directory ancestor: $component"
        fi
        [ "$component" = / ] && break
        component=${component%/*}
        [ -n "$component" ] || component=/
    done
}

[ "$(readlink -e -- /usr/bin/python3)" = /usr/bin/python3.14 ] || stop 'interpreter target drift'
binary_hash=$(sha256sum -- /usr/bin/python3.14)
[ "${binary_hash%% *}" = 52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41 ] || stop 'interpreter digest drift'
for package in python3.14-minimal libpython3.14-minimal libpython3.14-stdlib; do
    [ "$(dpkg-query --show --showformat='${Status}' "$package")" = 'install ok installed' ] || stop "package status drift: $package"
    [ "$(dpkg-query --show --showformat='${Version}' "$package")" = '3.14.4-1ubuntu0.2' ] || stop "package version drift: $package"
    verify_output=$(dpkg --verify "$package" 2>&1) || stop "local package drift: $package"
    [ -z "$verify_output" ] || stop "local package drift output: $package"
done
printf 'PASS pinned interpreter and three local package records\n'

check_chain /usr/lib/python3.14 directory
check_chain /usr/lib/python3.14/lib-dynload directory
if [ -e /usr/lib/python314.zip ] || [ -L /usr/lib/python314.zip ]; then
    stop 'active or symlinked python314.zip search-path candidate; review separately'
fi
printf 'PASS B2 search roots: canonical root-owned directories; zip candidate absent\n'

mapfile -t origins <<'ALERTMIND_B2_FILE_ORIGINS'
/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so
/usr/lib/python3.14/_opcode_metadata.py
/usr/lib/python3.14/_py_warnings.py
/usr/lib/python3.14/_weakrefset.py
/usr/lib/python3.14/annotationlib.py
/usr/lib/python3.14/ast.py
/usr/lib/python3.14/base64.py
/usr/lib/python3.14/collections/__init__.py
/usr/lib/python3.14/contextlib.py
/usr/lib/python3.14/copy.py
/usr/lib/python3.14/copyreg.py
/usr/lib/python3.14/dataclasses.py
/usr/lib/python3.14/dis.py
/usr/lib/python3.14/encodings/__init__.py
/usr/lib/python3.14/encodings/aliases.py
/usr/lib/python3.14/encodings/utf_8.py
/usr/lib/python3.14/enum.py
/usr/lib/python3.14/fnmatch.py
/usr/lib/python3.14/functools.py
/usr/lib/python3.14/glob.py
/usr/lib/python3.14/hashlib.py
/usr/lib/python3.14/importlib/__init__.py
/usr/lib/python3.14/inspect.py
/usr/lib/python3.14/json/__init__.py
/usr/lib/python3.14/json/decoder.py
/usr/lib/python3.14/json/encoder.py
/usr/lib/python3.14/json/scanner.py
/usr/lib/python3.14/keyword.py
/usr/lib/python3.14/linecache.py
/usr/lib/python3.14/locale.py
/usr/lib/python3.14/opcode.py
/usr/lib/python3.14/operator.py
/usr/lib/python3.14/pathlib/__init__.py
/usr/lib/python3.14/pathlib/_os.py
/usr/lib/python3.14/re/__init__.py
/usr/lib/python3.14/re/_casefix.py
/usr/lib/python3.14/re/_compiler.py
/usr/lib/python3.14/re/_constants.py
/usr/lib/python3.14/re/_parser.py
/usr/lib/python3.14/reprlib.py
/usr/lib/python3.14/selectors.py
/usr/lib/python3.14/signal.py
/usr/lib/python3.14/struct.py
/usr/lib/python3.14/subprocess.py
/usr/lib/python3.14/threading.py
/usr/lib/python3.14/token.py
/usr/lib/python3.14/tokenize.py
/usr/lib/python3.14/types.py
/usr/lib/python3.14/warnings.py
/usr/lib/python3.14/weakref.py
ALERTMIND_B2_FILE_ORIGINS

[ "${#origins[@]}" -eq 50 ] || stop 'origin-list count drift'
declare -A seen_paths=()
declare -A seen_cache_dirs=()
source_records=()
source_count=0
cache_present=0
cache_absent=0
for path in "${origins[@]}"; do
    case "$path" in /usr/lib/python3.14/*.py|/usr/lib/python3.14/lib-dynload/*.so) ;; *) stop "unexpected origin path: $path" ;; esac
    [ -z "${seen_paths[$path]+x}" ] || stop "duplicate origin: $path"
    seen_paths[$path]=1
    check_chain "$path" 'regular file'
    owner_line=$(dpkg-query --search -- "$path") || stop "package lookup failed: $path"
    owner=${owner_line%%: *}
    listed=${owner_line#*: }
    [ "$listed" = "$path" ] || stop "ambiguous package lookup: $path"
    case "$owner" in libpython3.14-minimal|libpython3.14-minimal:amd64|libpython3.14-stdlib|libpython3.14-stdlib:amd64) ;; *) stop "unexpected package owner: $path" ;; esac
    digest_line=$(sha256sum -- "$path")
    digest=${digest_line%% *}
    source_records+=("$digest  $path  $owner")
    source_count=$((source_count + 1))
    printf 'ORIGIN %s  %s  %s\n' "$digest" "$owner" "$path"

    case "$path" in
        *.py)
            cache_dir=${path%/*}/__pycache__
            if [ -z "${seen_cache_dirs[$cache_dir]+x}" ]; then
                seen_cache_dirs[$cache_dir]=1
                if [ -e "$cache_dir" ] || [ -L "$cache_dir" ]; then
                    check_chain "$cache_dir" directory
                fi
            fi
            cache=${cache_dir}/${path##*/}
            cache=${cache%.py}.cpython-314.pyc
            if [ -e "$cache" ] || [ -L "$cache" ]; then
                check_chain "$cache" 'regular file'
                cache_digest=$(sha256sum -- "$cache")
                printf 'CACHE_PRESENT %s  %s\n' "${cache_digest%% *}" "$cache"
                cache_present=$((cache_present + 1))
            else
                cache_absent=$((cache_absent + 1))
            fi
            ;;
    esac
done

[ "$source_count" -eq 50 ] && [ "$((cache_present + cache_absent))" -eq 49 ] || stop 'origin/cache count drift'
printf '%s\n' "${source_records[@]}" | sha256sum | awk '{print "ORIGIN_MANIFEST_SHA256 " $1}'
printf 'PASS C1 metadata: origins=%s cache_present=%s cache_absent=%s\n' "$source_count" "$cache_present" "$cache_absent"
printf '=== _hashlib direct ELF dynamic entries (not resolved libraries) ===\n'
elf_dynamic=$(readelf -dW -- /usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so) || stop 'extension dynamic-entry inspection failed'
case "$elf_dynamic" in *'(NEEDED)'*) ;; *) stop 'extension lacks expected direct dependency entries' ;; esac
printf '%s\n' "$elf_dynamic" | grep -E '\((NEEDED|RPATH|RUNPATH)\)'
printf 'STOP: Gate C1 metadata only; no guard or root-run Python authorization.\n'
ALERTMIND_PYTHON_ORIGIN_C1
```

Return the `PASS`/`STOP` lines, the `ORIGIN_MANIFEST_SHA256`, the `_hashlib`
dynamic entries and the `CACHE_PRESENT` lines, if any. Retain the 50
`ORIGIN` lines locally; they contain only public paths and hashes, but the
summary is enough for initial review. If any check stops, send the STOP/error
without rerunning or changing VM files. This gate does not test ACLs beyond
mode bits, loaded bytecode versus reported cache paths, resolved/transitive
ELF dependencies, package signatures, atomicity across the many reads,
root-run behavior, future updates or
the guard decision. Do not install or invoke the guard.

### C1 owner observations (25 September 2026)

The owner reported `PASS C1 metadata: origins=50 cache_present=49
cache_absent=0` and `ORIGIN_MANIFEST_SHA256
6625b3d3dd24b51ceb4f4396d3eb21eada5fa2a7f87e8951cc3b7ceaded61c1d`.
The 50 origin records were recomputed into that manifest from the reported
lines. `_hashlib` declared `libcrypto.so.3` and `libc.so.6` as direct ELF
dependencies; no `RPATH`/`RUNPATH` entry was reported. This is owner-supplied
host metadata. The 49 present `.pyc` files were *not* established as the
bytecode actually loaded or equivalent to their source. Do not rerun C1,
delete caches, or treat local dpkg drift checks as package authenticity.

## Gate C2 — unprivileged cache-redirection and mapped-file diagnostic

Run this block **only on the VM console as `notroot`**, after reviewing it,
with Snapshot 1 available, a stable VM, stopped AlertMind apps, and no
concurrent updates/configuration work. C2 is read-only; it neither runs the
guard nor changes a file, role, service or package. It rechecks the pinned
interpreter before launching a fresh, unprivileged Python process under an
empty inherited environment and `-I -S -B`. `-X
pycache_prefix=/dev/null/alertmind-c2` points Python's cache lookup at a
path that cannot be traversed because `/dev/null` is a character device;
`-B` prevents cache writes. Python [documents that a non-`None`
`sys.pycache_prefix` redirects cache **reads and writes** away from source-tree
`__pycache__` directories](https://docs.python.org/3.14/library/sys.html#sys.pycache_prefix).
The command checks the reported prefix and all 49 source-backed cache
candidates, then imports the same 18 direct roots as B2. It reports only the
unique absolute pathname fields from `/proc/self/maps`, which [describes
currently mapped memory regions](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html),
not future loads or package authenticity. Unexpected mapped paths are not
printed; the script stops with their SHA-256 instead.

This diagnostic tests the intended *cache-bypass launch shape*, but its
in-process checks and mapped-file report are still observations from the
interpreter being assessed. They do not independently attest its startup,
prove all transitive/native loads, or authorize root-run use. No `ldd`,
`LD_TRACE_LOADED_OBJECTS`, `strace`, root-run Python or guard invocation is
part of this block. The C2 origin-path digest below uses **lexicographic
order**, unlike C1's ordered B2 path list, so its expected value is distinct.
C2 does not rehash the 50 source/extension files or the 49 existing caches;
their byte stability since C1 remains unproven.

```bash
(
set -euo pipefail
export LC_ALL=C
cd /
if [ "$(id -u)" -eq 0 ]; then
    printf 'STOP: Gate C2 must run as the unprivileged console user\n'
    exit 1
fi
if [ "$(readlink -e -- /usr/bin/python3)" != /usr/bin/python3.14 ]; then
    printf 'STOP: Gate C2 interpreter target drift\n'
    exit 1
fi
binary_hash=$(sha256sum -- /usr/bin/python3.14)
if [ "${binary_hash%% *}" != 52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41 ]; then
    printf 'STOP: Gate C2 interpreter digest drift\n'
    exit 1
fi
if [ -e /usr/lib/python314.zip ] || [ -L /usr/lib/python314.zip ]; then
    printf 'STOP: Gate C2 zip search-path candidate appeared\n'
    exit 1
fi
if /usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/timeout 30s /usr/bin/python3.14 -I -S -B \
    -X pycache_prefix=/dev/null/alertmind-c2 - <<'ALERTMIND_CACHE_LOADER_C2'
import base64
import binascii
import contextlib
import dataclasses
import errno
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import selectors
import stat
import subprocess
import sys
import time
import types

def stop(message):
    raise SystemExit('STOP: Gate C2 ' + message)

prefix = '/dev/null/alertmind-c2'
flags = sys.flags
if (sys.platform != 'linux' or os.geteuid() == 0 or
        sys.executable != '/usr/bin/python3.14' or
        sys.version_info[:3] != (3, 14, 4) or
        any(getattr(flags, name, None) != 1 for name in
            ('isolated', 'ignore_environment', 'no_site', 'dont_write_bytecode')) or
        sys.pycache_prefix != prefix):
    stop('unexpected unprivileged Python launch')
device = os.stat('/dev/null')
if not stat.S_ISCHR(device.st_mode) or os.path.lexists(prefix):
    stop('cache prefix is traversable or /dev/null is not a character device')
if sys.path != ['/usr/lib/python314.zip', '/usr/lib/python3.14',
                '/usr/lib/python3.14/lib-dynload']:
    stop('search path differs from B2')

origins = set()
source_caches = []
for module in sys.modules.values():
    spec = getattr(module, '__spec__', None)
    origin = getattr(spec, 'origin', None)
    if not isinstance(origin, str) or not origin.startswith('/'):
        continue
    if not origin.startswith('/usr/lib/python3.14/'):
        stop('unexpected origin path digest=' +
             hashlib.sha256(origin.encode()).hexdigest())
    origins.add(origin)
    if origin.endswith('.py'):
        source_caches.append(getattr(spec, 'cached', None))
if len(origins) != 50 or len(source_caches) != 49:
    stop('origin or source-cache count differs from B2/C1')
if any(not isinstance(path, str) or not path.startswith(prefix + '/')
       for path in source_caches):
    stop('a source-backed cache path is outside the redirected prefix')
origin_manifest = hashlib.sha256(
    ('\n'.join(sorted(origins)) + '\n').encode()).hexdigest()
if origin_manifest != '41fe4f2680be2f097dcfd240ab15f6334957a629d822533212821364c5aacfeb':
    stop('sorted origin path-list digest differs from B2/C1')

mapped = set()
with open('/proc/self/maps', encoding='utf-8') as stream:
    for line in stream:
        fields = line.rstrip('\n').split(None, 5)
        if len(fields) < 6 or not fields[5].startswith('/'):
            continue
        path = fields[5]
        if (path.endswith(' (deleted)') or len(path) > 512 or
                not path.startswith(('/usr/', '/lib/', '/lib64/'))):
            stop('unexpected mapped pathname digest=' +
                 hashlib.sha256(path.encode()).hexdigest())
        mapped.add(path)
if ('/usr/bin/python3.14' not in mapped or
        '/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so'
        not in mapped or not any(path.endswith('/libcrypto.so.3') for path in mapped)):
    stop('expected interpreter, _hashlib or libcrypto mapping absent')
if len(mapped) > 64:
    stop('mapped-path count exceeds diagnostic cap')

print('C2_ORIGIN_PATHS_SHA256 ' + origin_manifest)
for path in sorted(mapped):
    print('C2_MAPPED ' + path)
print(f'PASS C2 diagnostic: source_cache_candidates={len(source_caches)} '
      f'mapped_files={len(mapped)} prefix=/dev/null/alertmind-c2')
ALERTMIND_CACHE_LOADER_C2
then
    printf 'STOP: Gate C2 diagnostic only; no guard or root-run Python authorization.\n'
else
    status=$?
    printf 'STOP: Gate C2 diagnostic failed (exit=%s); do not retry with altered flags.\n' "$status"
    exit 1
fi
)
```

Return the complete `C2_MAPPED` list, the origin-path digest, `PASS` and
final `STOP` lines. If the diagnostic fails, send only the STOP/error without
retrying or repairing the host. **Do not run it as root** and do not start,
install or wire the guard into the Dashboard service. The mapped paths still
need an independent, bounded host metadata and package-ownership review
before any root-run decision. A later launch policy must externally pin the
interpreter, flags, empty environment, cache redirection and all relevant
loader inputs; the diagnostic cannot substitute for that policy.

### C2 owner observations (25 September 2026)

The owner reported the expected sorted-origin digest
`41fe4f2680be2f097dcfd240ab15f6334957a629d822533212821364c5aacfeb`,
49 redirected cache candidates, nine unique mapped file paths, and the
required diagnostic STOP. Those nine paths are fixed in Gate C3 below. They
include `libzstd.so.1.5.7`; C2 does not show which object required it. The
reported result is consistent with C2 passing for **one unprivileged launch**.
It is neither independently observed host state nor a root-run guard permit.
Do not rerun C2 to collect more output.

## Gate C3 — fixed mapped-file metadata and direct ELF declarations

Run this **at the VM console as `notroot`**, only after reviewing the committed
block, with Snapshot 1 available, a stable VM, stopped AlertMind apps, and no
concurrent updates/configuration work. Its mapped-file set is exactly the nine
paths in the owner's C2 output. It rechecks that `/dev/null` is a root-owned character
device, the redirected child cache path cannot exist, the Python zip-search
candidate is absent, and `/etc/ld.so.preload` is absent. For each mapped path,
it requires a canonical, non-symlinked root:root chain with no group/other
write bit, a bounded regular ELF file, one exact dpkg file-owner record and a
fully installed package with no *local* `dpkg --verify` drift. It prints the
file SHA-256, package version and only sanitized `NEEDED`/`SONAME` dynamic
entries; any `RPATH`/`RUNPATH` entry stops for separate review. It also prints
the metadata/digest of `/etc/ld.so.cache`, a loader input, without assuming
that this generated cache is package-owned. The fixed nine-path list has an
LF-delimited SHA-256 of
`0b112d9d770034238714593a83cc70c81cf232c2c7601d917e736b28e452e9ba`.

`readelf -d` [reports ELF dynamic entries](https://sourceware.org/binutils/docs/binutils/readelf.html);
it does not run the mapped object or establish which dependency selected a
particular path. The dynamic linker can consult RPATH/RUNPATH, the environment
and its cache [when resolving libraries](https://man7.org/linux/man-pages/man8/ld.so.8.html).
`dpkg --verify` is [only a local database integrity check, not a security
verification](https://manpages.debian.org/unstable/dpkg/dpkg.1.en.html).
This block neither invokes Python/`ldd` nor creates or changes a file,
package, service, role or dashboard. An early STOP is a finding; do not
repair the VM, follow a symlink, loosen a permission, or substitute another
command to make it pass. A non-exact package-owner lookup (including a
different merged-`/usr` registry spelling), or an unreadable package file
during the unprivileged drift check, requires review rather than a `sudo` retry.

```bash
/usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin \
    /bin/bash <<'ALERTMIND_MAPPED_FILE_C3'
set -euo pipefail
cd /

stop() {
    printf 'STOP: Gate C3 %s\n' "$1"
    exit 1
}

[ "$(id -u)" -ne 0 ] || stop 'must run as the unprivileged console user'
[ "$(readlink -e -- /usr/bin/python3)" = /usr/bin/python3.14 ] || stop 'interpreter target drift'
[ -c /dev/null ] && [ ! -L /dev/null ] || stop '/dev/null is not a direct character device'
[ "$(stat -c '%u:%g' -- /dev/null)" = 0:0 ] || stop '/dev/null owner changed'
[ ! -e /dev/null/alertmind-c2 ] && [ ! -L /dev/null/alertmind-c2 ] || stop 'cache prefix became traversable'
[ ! -e /usr/lib/python314.zip ] && [ ! -L /usr/lib/python314.zip ] || stop 'zip search-path candidate appeared'
[ ! -e /etc/ld.so.preload ] && [ ! -L /etc/ld.so.preload ] || stop 'global loader preload requires separate review'

check_chain() {
    local path=$1 kind=$2 component uid gid mode
    [ "$(readlink -e -- "$path")" = "$path" ] || stop "non-canonical path: $path"
    component=$path
    while :; do
        uid=$(stat -c '%u' -- "$component") || stop "stat failed: $component"
        gid=$(stat -c '%g' -- "$component") || stop "stat failed: $component"
        mode=$(stat -c '%a' -- "$component") || stop "stat failed: $component"
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] || stop "invalid mode: $component"
        [ "$uid" = 0 ] && [ "$gid" = 0 ] || stop "non-root path component: $component"
        (( (8#$mode & 8#022) == 0 )) || stop "writable path component: $component"
        if [ "$component" = "$path" ] && [ "$kind" = file ]; then
            [ -f "$component" ] && [ ! -L "$component" ] || stop "non-regular file: $component"
        else
            [ -d "$component" ] && [ ! -L "$component" ] || stop "non-directory ancestor: $component"
        fi
        [ "$component" = / ] && break
        component=${component%/*}
        [ -n "$component" ] || component=/
    done
}

mapfile -t mapped <<'ALERTMIND_C2_MAPPED_FILES'
/usr/bin/python3.14
/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so
/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
/usr/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/x86_64-linux-gnu/libcrypto.so.3
/usr/lib/x86_64-linux-gnu/libexpat.so.1.11.2
/usr/lib/x86_64-linux-gnu/libm.so.6
/usr/lib/x86_64-linux-gnu/libz.so.1.3.1
/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7
ALERTMIND_C2_MAPPED_FILES

[ "${#mapped[@]}" -eq 9 ] || stop 'mapped-file count drift'
list_hash=$(printf '%s\n' "${mapped[@]}" | sha256sum)
[ "${list_hash%% *}" = 0b112d9d770034238714593a83cc70c81cf232c2c7601d917e736b28e452e9ba ] || stop 'mapped-file list drift'
printf 'PASS fixed C2 path list: count=9 sha256=%s\n' "${list_hash%% *}"

declare -A checked_packages=()
for index in "${!mapped[@]}"; do
    path=${mapped[$index]}
    check_chain "$path" file
    size=$(stat -c '%s' -- "$path") || stop "size lookup failed: $path"
    [[ "$size" =~ ^[0-9]+$ ]] && (( size > 0 && size <= 33554432 )) || stop "file size outside 1..33554432: $path"
    digest_line=$(sha256sum -- "$path") || stop "hash failed: $path"
    digest=${digest_line%% *}
    if [ "$path" = /usr/bin/python3.14 ] &&
       [ "$digest" != 52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41 ]; then
        stop 'pinned interpreter digest drift'
    fi
    if [ "$path" = /usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so ] &&
       [ "$digest" != f57bc22cc1b6f3b48c43778634af1a7e79c5ae0632350fa5144d050c7848112c ]; then
        stop 'C1 _hashlib digest drift'
    fi
    owner_line=$(dpkg-query --search -- "$path") || stop "package lookup failed: $path"
    [[ "$owner_line" != *$'\n'* ]] || stop "ambiguous package lookup: $path"
    owner=${owner_line%%: *}
    listed=${owner_line#*: }
    [ "$owner" != "$owner_line" ] && [ "$listed" = "$path" ] || stop "non-exact package lookup: $path"
    status=$(dpkg-query --show --showformat='${Status}' "$owner") || stop "package status lookup failed: $owner"
    version=$(dpkg-query --show --showformat='${Version}' "$owner") || stop "package version lookup failed: $owner"
    [ "$status" = 'install ok installed' ] || stop "package not fully installed: $owner"
    if [ -z "${checked_packages[$owner]+x}" ]; then
        verify_output=$(dpkg --verify "$owner" 2>&1) || stop "local package drift: $owner"
        [ -z "$verify_output" ] || stop "local package drift output: $owner"
        checked_packages[$owner]=1
    fi
    header=$(readelf -hW -- "$path") || stop "ELF header read failed: $path"
    printf '%s\n' "$header" | grep -Eq 'Class:[[:space:]]+ELF64' || stop "not ELF64: $path"
    dynamic=$(readelf -dW -- "$path") || stop "ELF dynamic read failed: $path"
    [[ "$dynamic" != *'(RPATH)'* && "$dynamic" != *'(RUNPATH)'* ]] || stop "ELF search-path tag requires review: $path"
    printf 'FILE %02d sha256=%s bytes=%s package=%s version=%s path=%s\n' "$index" "$digest" "$size" "$owner" "$version" "$path"
    while IFS= read -r line; do
        if [[ "$line" == *'(NEEDED)'* || "$line" == *'(SONAME)'* ]]; then
            if [[ "$line" =~ \((NEEDED|SONAME)\).*\[([A-Za-z0-9._+-]+)\] ]]; then
                printf 'ELF %02d %s %s\n' "$index" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
            else
                stop "unparseable ELF dependency entry: $path"
            fi
        fi
    done <<< "$dynamic"
done

check_chain /etc/ld.so.cache file
cache_size=$(stat -c '%s' -- /etc/ld.so.cache) || stop 'loader cache size lookup failed'
[[ "$cache_size" =~ ^[0-9]+$ ]] && (( cache_size > 0 && cache_size <= 33554432 )) || stop 'loader cache size outside bound'
cache_hash=$(sha256sum -- /etc/ld.so.cache) || stop 'loader cache hash failed'
printf 'LOADER_CACHE sha256=%s bytes=%s path=/etc/ld.so.cache\n' "${cache_hash%% *}" "$cache_size"
printf 'PASS C3 metadata: mapped_files=9 packages=%s no_rpath_runpath=yes\n' "${#checked_packages[@]}"
printf 'STOP: Gate C3 metadata only; no native-closure, package-authenticity or root-run guard authorization.\n'
ALERTMIND_MAPPED_FILE_C3
```

Return `PASS`, `FILE`, `ELF`, `LOADER_CACHE` and final `STOP` lines only. If a
check stops, send that STOP and do not rerun with altered code or privileges.
The package names/versions and hashes are public metadata, not credentials.
C3's sequential reads are not an atomic snapshot, a signed-package proof or
an exhaustive dependency graph. The exact root-run launch environment,
other loader inputs, import machinery and durable update/recovery policy
remain separate gates. Do not run or install the guard.

## C3 accepted owner report and offline policy (26 September 2026)

The [retained sanitized transcript](../../evidence/rbac/python-runtime-c3-owner-report-2026-09-26.txt)
is a transcription of the owner's chat output, not an independently captured
VM artifact. It reports all nine files across seven packages, matching Python
and `_hashlib` pins, no RPATH/RUNPATH and the final metadata-only STOP. The
35 lines retain public values and ordering; only text line endings may differ.
The producer was Gate C3 at `795b7a062771fb0bb001a45aaf66f860d4c79183`.
The report's date is its receipt/recording date, not a proven VM execution time.

The declared graph has 15 `NEEDED` edges. Every name has a matching `SONAME`
among the nine files; `libcrypto.so.3` explicitly needs `libzstd.so.1`. This
accounts for a declared dependency consistent with the C2 mapping, not proof
of which loader path was selected, runtime `dlopen` coverage or complete
native closure. C3's path/mode/package checks were sequential and reported
by the owner. No root-runtime authorization follows.

`siem/rbac/broker_tls/operator_python_policy.py` now implements an **offline
comparison contract**, deliberately outside the thirteen-module guard capsule:

- `check_c3_report(raw)` requires the complete bounded transcript, validates
  its grammar/counts/order and compares every file/cache value with explicit
  pins. Truncation, duplicate/unknown records, drift, missing final STOP and
  extra output fail with fixed diagnostic codes. LF and CRLF are equivalent;
  other text normalization is not performed.
- `compare_metadata(files, cache)` compares caller-supplied immutable records
  for the nine mapped files, package versions, ELF declarations and generated
  loader cache. It does not read current files, repeat dpkg checks or validate
  current metadata/ownership. The 49 source origins are not covered by this
  mapped-file-only contract.
- `check_candidate_launch(argv, environment)` checks **proposed data only**:
  the fixed Python target, `-I -S -B`, explicit `-X` cache redirection using
  C2's `/dev/null/alertmind-c2` prefix, and the proposed guard script path.
  The environment must contain exactly HOME=/nonexistent, LC_ALL=C and
  PATH=/usr/bin:/bin. Missing/extra options or variables are rejected, including
  empty `LD_*`/`PYTHON*` entries. This is not an executable launcher or unit.

All results keep runtime trust/startup authorization false. The metadata
result also keeps live-host, package-authenticity and native-resolution proof
false; the launch result keeps effective-environment proof false. A perfectly
matching historical transcript is replayable and cannot authorize startup.

Python documents [cache redirection](https://docs.python.org/3.14/library/sys.html#sys.pycache_prefix)
and the [isolation flags](https://docs.python.org/3.14/using/cmdline.html#cmdoption-I).
These explain the candidate shape, not its deployment safety. A separately
trusted launcher must establish the environment before interpreter/ELF startup;
checking or clearing it inside Python is too late. The launch helper and its
own loader inputs must also be trusted. No implementation here does that.

### Dormant native read/compare adapter (updated 27 September 2026)

`siem/rbac/broker_tls/operator_python_runtime.py` now implements the fixed-file
read/compare slice separately from the pure policy and the guard. It reads the
nine C3-pinned files, generated loader cache and 49 C1 source files twice, and
the fixed dpkg status database three times. The existing root-only no-follow reader bounds
each read and rechecks metadata/ancestors; the adapter checks mapped/cache exact
sizes, all SHA-256 values and seven selected amd64 package versions/installed
states. C1 source sizes were not recorded; source reads use a 1 MiB per-file
ceiling rather than an invented exact size. There are 121 reads per observation.
An unchanged fully installed `hold` selection is allowed; selection drift
between reads is not. No commands, transcript replay, writes or pin refresh
are used. The [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#python-fixed-file-reader--dormant-not-a-runtime-trust-decision)
describes the 21 adapter tests, including two Linux-only temporary-file cases,
and seven additional source-pin tests.

The module is **not deployed or wired into the guard**. Package status is not
package-file ownership or signed authenticity. The 49 source paths' byte pins
are now covered, but their actual selection and remaining loader inputs are
not; the reader does not prove actual
resolution, loaded code, an atomic snapshot or a trusted launch environment.
Its runtime/startup flags remain false. This is an offline implementation,
not a new live gate or authorization to execute root-run Python on the VM.

### C1 source-pin provenance (recorded 26–27 September 2026)

The [retained C1 transcript](../../evidence/rbac/python-runtime-c1-owner-report-2026-09-26.txt)
copies the owner's earlier attachment, removing only the leading empty sudo
password prompt and normalizing CRLF to LF. It contains 107 public-metadata
lines, including all 50 ORIGIN records, 49 CACHE_PRESENT records, the summary
and diagnostic STOP. Its filename records the start of transcription, not a
VM execution timestamp. Producer: the Gate C1 block at
`d79875b2ef327095b49719315dc6fb0a6fc56fd3`. The LF-normalized transcript SHA-256 is
`b67be416f452f7ca3159195a2632bada396c8c509439d22171d08a917ba3d187`.

Tests re-derive the already accepted origin-record manifest
`6625b3d3dd24b51ceb4f4396d3eb21eada5fa2a7f87e8951cc3b7ceaded61c1d`
and ordered B2/sorted C2 path sets. The 49 source pins in
`operator_python_policy.py` version 2 reproduce the source rows exactly;
the extension row matches the existing C3 `_hashlib` pin. All source rows
report libpython3.14-minimal:amd64; its version is from the accepted B1/C1
package preflight, not a new observation or a version field invented in ORIGIN.

The observer never loads this transcript, imports/executes these source files,
or uses the `.pyc` hashes as approved bytecode. Matching source bytes cannot
prove Python did not use a cache, frozen code or a shadowing module. Python's
[cache-prefix documentation](https://docs.python.org/3.14/library/sys.html#sys.pycache_prefix)
describes redirection of source cache lookups; this does not establish complete
import resolution or make the existing launch-data check an actual launcher.

### Dormant fixed-name input observer (27 September 2026)

`siem/rbac/broker_tls/operator_python_paths.py` implements the next bounded
offline slice. Two fixed-name passes reject any `/usr/lib/python314.zip` or
`/etc/ld.so.preload` object and inspect `/dev/null` through an `O_PATH`
metadata-only descriptor. Trusted ancestors, root ownership, character-device
1:3 identity and before/open/after/name comparisons are required. Ordinary
0666 null-device permissions are allowed, not treated as a writable code file.
These are candidate requirements, not additional C3 observations.

The [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#python-fixed-name-inputs--dormant-observations-only)
documents the fifteen tests, two Linux-only, and precise limitations. The
observer neither reads/writes the device payload nor opens the cache prefix.
It does not prove that cache redirection took effect, exclude every import or
loader input, establish loaded-code provenance, or prevent injection before
Python starts. Its trust/startup flags remain false. It is separate from the
byte reader and is not a complete snapshot or a deployed guard component.

### Dormant in-process import-state observer (27 September 2026)

`siem/rbac/broker_tls/operator_python_import_state.py` checks current reported
interpreter/argv/isolation/search-path/cache-prefix settings and the 50
selected file-backed modules' origin/loader/cache/package metadata twice.
It requires those subjects already loaded, never preloads them, and invokes
no finder/loader or lazy cache property. Dotted names follow C1 source paths
and agree with B2; this is not a new VM observation. The candidate's full
combined launch/call point still requires review and selected-runtime testing.

The [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#python-in-process-import-state--selected-metadata-only)
describes seventeen portable synthetic tests and the limitations. Mutable
metadata and matching current finder identities cannot authenticate loaded
code. Other modules, path hooks/importer caches, native resolution and initial
environment are not attested. The observer is not installed or wired into the
guard; runtime/startup authority stays false.

### Dormant path-hook/importer-cache observer (27 September 2026)

`siem/rbac/broker_tls/operator_python_path_importers.py` now checks the proposed
default hook/closure structure and bounded cached FileFinder metadata twice,
without invoking import machinery or filling/clearing caches. It accepts only
the two stdlib roots, six selected package paths and an optional negative ZIP
entry; absent cache entries are not failures. The proposed suffix/loader policy
comes from the version-matched implementation shape, not new VM evidence.

The [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#python-path-hooks-and-cached-importers--candidate-metadata-only)
describes the twenty synthetic tests, exact checks and limitations. In particular,
matching hook identities cannot authenticate mutable bootstrap code, directory
caches are not filesystem inventory, and the default `.pyc`/extension loaders
do not prove source-only imports. The earlier selected-module observer still
does not check path hooks itself; these remain separate observations, not a
combined trust decision. The new observer is neither installed nor wired into
the guard, and all runtime/startup authority remains false.

### Dormant selected filesystem-candidate observer (27 September 2026)

`siem/rbac/broker_tls/operator_python_candidates.py` adds fixed-name checks for
the 50 selected module origins and 514 alternate import names. It holds eleven
root-owned no-follow directory descriptors across two metadata passes, requires
the selected regular files, rejects every alternate object and checks directory
and origin drift. It never lists directories, opens candidate payloads, invokes
import machinery, changes caches or writes. These are proposed constraints,
not additional observations from B2/C1/C2/C3.

The [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#selected-python-filesystem-candidates--dormant-fixed-name-checks)
describes twenty tests (two Linux-only) and its conservative rejection of both
earlier and later alternate candidates. Existing `__pycache__` files and unrelated
modules are outside this policy. Byte pins, effective import state, cache-prefix
use and native loading remain separate controls. This is not complete import
resolution, loaded-code attestation or an atomic combined observation. The
module is dormant, outside the capsule, with trust/startup flags still false.

### Dormant built-in/frozen metadata observer (27 September 2026)

`siem/rbac/broker_tls/operator_python_embedded.py` covers the selected 36 built-in
and 17 frozen B2 keys, with explicit bootstrap/collections/os aliases, current
loader identities, parent bindings and separate module/spec names. It requires
preloaded subjects and compares two observations without invoking subject
imports, finders/loaders or file I/O. The
[operator contract](../../siem/rbac/broker_tls/OPERATOR.md#built-in-and-frozen-python-modules--dormant-selected-metadata-checks)
describes twenty synthetic tests and source-based candidate constraints.

The [B2 projection](../../evidence/rbac/python-runtime-b2-embedded-modules-2026-09-27.tsv)
is a lossless field projection of the owner's earlier diagnostic, **not a new
VM run**. Source attachment: `Pasted text.txt`, attachment identifier
`35fee2f5-e3e0-4542-9d2e-b90fc6caaf15`; raw SHA-256
`8ab9d68c038774fbf62b15f08e739177ec40cf924e02aa731016335143f96a7f`.
Parse the initial JSON object, select `modules` rows with origin `built-in` or
`frozen`, preserve their order, emit `name`, `origin`, `file`, `cached` as TSV
with one header and final LF; `-` encodes JSON null. Normalized projection hash:
`496131f4994debb5b56767bcf7478b404a699cd1a0b916ce0f5d6753dc6ada3e`.
The other 51 rows (50 file-backed and diagnostic `__main__`) are not in this
projection. No previously retained evidence was changed. The observer never
uses this file as current runtime evidence.

B2 recorded none of the extra alias/loader/package identity fields. Those
constraints are proposed from CPython 3.14.4 source and need native acceptance;
Windows Python 3.12 fixtures do not validate the selected Ubuntu build. Even
matching live metadata would not authenticate embedded or bootstrap code. This
observer is dormant and outside the capsule, with runtime/startup flags false.

### Entry/private-module and closed-table policy (27 September 2026)

The existing `operator_guard_entry.py` now includes dormant pure validation
for explicitly supplied prepared (104-key) and fully held (118-key) tables.
The base stdlib keys match the prior 50 file-backed and 53 built-in/frozen
selections. Only direct-script `__main__`, the fixed private package and the
thirteen pinned child modules are added. No wildcard private-prefix exception,
partial bundle, automatic imports, auto-learning or phase inference is allowed.

The [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#entryprivate-modules-and-closed-table--dormant-pure-policy)
documents entry/loader/import bindings, explicit phase-dependent meta finders,
private registry identity, alias rules and twenty-three tests. Entry code adds
no imports; the thirteen capsule sources and their pins are unchanged. The
checker is not called by startup or the held loader and returns no permit.
Its direct-script metadata is candidate policy, not the B2 `<stdin>` report.

This completes the offline declared-table/entry/private-metadata policy slice,
not trusted initialization, complete executable-code coverage or a fresh
process observation. The exact sets still need a reviewed real call point and
selected-runtime acceptance. Before-load observers and the four-finder held
state cannot be naively composed. No check may temporarily remove the deny
finder or silently expand the allowlist to pass. No new VM output is requested.

### Native mapped backing objects (27 September 2026)

`operator_python_native.py` now adds the dormant, no-argument self-process
mapping observer. The [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#python-native-mappings--dormant-current-process-observer)
describes the strict maps policy, held canonical/backing descriptors, exact
C3 byte pins, four maps reads and two hashing passes, plus thirty regressions.
Unknown mappings and inaccessible proc magic links fail without a fallback.

This implements selected current mapping/backing-object verification, not
pre-execution library resolution or memory/symbol attestation. The parser's
4-KiB segment/kernel-name rules are candidate constraints, not additional
owner evidence. Native Ubuntu compatibility and procfs access remain unverified.
The interpreter, kernel and procfs must already be trusted; this observer cannot
bootstrap that trust. It is outside the capsule and not invoked by the entry.
No A-C3 evidence/pin, dependency, service or VM setting changed.

### Fixed standard-library preparation (27 September 2026, original slice)

The entry now defines a dormant `_prepare_stdlib()` routine for the original
eighteen B2 roots, with no root-list/callback/authorization input. It checks the
proposed launch settings and existing entry/module/finder identities before
imports, brackets each root with state checks and finishes at the exact 104-key
prepared-table policy. Failure stops without retries or attempted import rollback.
See the [operator contract](../../siem/rbac/broker_tls/OPERATOR.md#fixed-stdlib-preparation--dormant-entry-routine)
for its twenty-five tests and explicit trust prerequisites.

This is import-time execution, not another metadata-only observer. The routine
must not be invoked until a separate trusted launch boundary has established
interpreter, source and native-loader inputs. It is not called by the entry or
held loader today. Synthetic local fixtures establish neither an actual Ubuntu
preparation run nor bootstrap trust. No new VM diagnostic or execution block is
released. The guard continues to compile only and exit nonzero.

### Next work and VM availability

**27 September connected-contract update:** the offline launcher/phase-composition
candidate is described in the [current operator section](../../siem/rbac/broker_tls/OPERATOR.md#current-launchcomposition-work-27-september-2026).
It connects preparation, a 21-child held capsule, phase-aware Python observers
and broker observations, while retaining an always-nonzero exit. A separate
offline renderer supplies pre-exec shell checks and a clean fixed Python launch;
it assumes the trusted OS/supervisor rather than authenticating itself. Native
execution and installation remain unverified. The owner explicitly approved
the scoped test-contract change; the old disconnected-only assertions now have
phase-specific replacements and additional refusal/cleanup tests. All exits
remain nonzero. This is not approval to install, start a broker or run a VM block.

The owner may shut down the VM normally after stopping the Windows tunnel.
No more VM output is needed **for this offline slice**. Do not rerun A–C3.
The mapped/cache/source byte adapter, fixed optional-path/null-anchor observer
and selected in-process import-state, path-hook/importer-cache metadata,
selected filesystem-candidate and built-in/frozen metadata observers are
implemented and composed in the fixed candidate phases. The entry/private-module
and declared complete-table policy brackets observer execution. The launcher
proposes pre-exec constraints but does not authenticate its OS/supervisor trust
anchor. Remaining work includes validating those assumptions on the selected
runtime and implementing the final observation-to-startup decision, installation
and recovery transaction. Matching selected mutable metadata does not complete
those controls. Neither an observer nor composition may use a stored C3 report
as a substitute for fresh reads or auto-refresh pins after package drift.
A changed generated loader cache also needs review; it is not automatically
evidence of compromise. The owner-requested
[upgrade/revalidation workflow](../../siem/rbac/broker_tls/OPERATOR.md#upgrade-and-revalidation-requirement--open-before-deployment)
is now an explicit prerequisite before deployment: versioned baselines, reviewed
fresh evidence, native compatibility tests and interruption-safe maintenance;
no automatic pin acceptance or indefinite suppression of security updates.

Independent review, native Linux/version tests, externally established launch
trust, durable installation/recovery and actual broker acceptance still precede
deployment. Later live checks will need the VM again and must be separately
released. The connected guard candidate always exits 1 and is not installed.

**27 September result-policy follow-up:** the connected entry now checks every
returned result against the [explicit non-authorizing contract](../../siem/rbac/broker_tls/OPERATOR.md#connected-observation-result-policy-27-september-2026).
Missing/unknown/unsuitable results, coerced types, incorrect coverage or changed
package snapshots stop later observations. No result is treated as a startup
permit. Service state/login-variable visibility remains distinct from stopped
service/complete-environment proof. Future service-hook wiring must explicitly
reconcile the current no-auxiliary-command/no-drop-in and non-transitioning
service baseline. The operational upgrade/maintenance workflow remains required
before deployment; no new VM output is needed for this offline slice.

**Maintenance planning follow-up:** [UPGRADES.md](../../siem/rbac/broker_tls/UPGRADES.md)
defines the three lifecycle boundaries and the pure versioned-baseline/one-step
planner. It refuses missing prerequisites, stale/rebooted observations, partial
upgrades and unreviewed drift; even a matching target stays inhibited. It does
not collect or authenticate inputs, install a service hook, execute an upgrade
or authorize startup. Trusted collection, durable execution/recovery and native
acceptance are the next work, not further repetition of accepted A–C3 gates.
