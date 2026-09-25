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

Python's [isolated mode and site flags](https://docs.python.org/3.10/using/cmdline.html)
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
