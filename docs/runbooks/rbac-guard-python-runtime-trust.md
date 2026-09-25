# Guard Python runtime trust — offline inventory boundary

Status: **not selected, not installed, not approved for startup**. This records
the next evidence required for the dormant held-code loader. The metadata-only
candidate inventory below asks for one owner-executed VM command; it does not
authorize interpreter execution or a Dashboard change.

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

## Gate B2 — held, unprivileged import-origin diagnostic

**Do not run this block yet.** It is prepared for review after B1 passes. It
will execute only the provisionally selected system Python as the unprivileged
console user, with only three explicit environment values and `-I -S -B`;
its script contains no guard, network or Wazuh call. The JSON would report
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

Passing B2 later would not prove root-run behavior, cached-bytecode integrity,
dynamic-loader resolution, all function-local imports, package authenticity or
an immutable future systemd environment. No guard deployment is authorized.
