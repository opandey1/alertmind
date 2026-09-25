# Guard Python runtime trust — offline inventory boundary

Status: **not selected, not installed, not approved for startup**. Gates A,
B1 and B2 below are completed owner-reported diagnostics. Gate C1 is the next
read-only, metadata-only inventory; none authorizes the dormant held-code
loader or a Dashboard change.

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
