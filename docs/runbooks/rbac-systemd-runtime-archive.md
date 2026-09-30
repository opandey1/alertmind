# Host-only systemd runtime-artifact provenance

Status: offline author implementation; Windows-host smoke completed, independent
review deferred. No approved library reference, VM command or maintenance release.

The previous [PID 1 image candidate](../../evidence/rbac/pid1-image-reference-candidate-v1.md)
covers the executable, not all code it loads. The matching archived manager's
ELF metadata declares `libsystemd-core-259.so`, `libsystemd-shared-259.so` and
`libc.so.6`, with RUNPATH `/usr/lib/x86_64-linux-gnu/systemd`. Ubuntu describes
[`libsystemd-shared`](https://packages.ubuntu.com/en/resolute/libsystemd-shared)
as its private shared-library package. The host check below authenticates the
two exact package artifacts and inspects three fixed images without loading them.

## Implemented checks

[`verify_systemd_runtime_archive.py`](../../siem/rbac/verify_systemd_runtime_archive.py)
uses the existing archive verifier's candidate format and tool contract, still
pending independent review:

1. Verify local `resolute-updates` InRelease with the pinned Ubuntu archive
   signer, then check its exact amd64 `Packages.xz` size and SHA-256.
2. Require one indexed `systemd` and one `libsystemd-shared` record, both
   `259.5-0ubuntu3.4`/amd64 with exact filenames/source identity, bounded sizes
   and hashes. Refuse duplicates, missing records and folded critical fields.
3. Check **both** package hashes before extraction. Hold these verified bytes
   in memory rather than reopening downloaded paths for extraction.
4. Use bsdtar stdout-only extraction for exactly:
   `usr/lib/systemd/systemd`,
   `usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-259.so`, and
   `usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-259.so`.
   Refuse missing/duplicate members. No filesystem extraction, shell, ldd,
   ctypes library loading, package install or downloaded executable is used.
5. Match manager bytes against the supplied image candidate. Parse each object's
   bounded ELF64 little-endian amd64 program headers and selected dynamic
   strings. Check manager interpreter/declared private libraries and each
   private library's expected SONAME. Report dependencies and search strings,
   not resolved paths or a complete dependency closure.
6. Count fixed NUL-terminated **suffixes** for the eight candidate generator
   directory strings and two override names in each image. These are byte
   observations only; even a suffix in an unrelated string is counted. They
   do not identify the calling function, ordering, build macro use or current
   getenv state. Do not promote them into effective-path proof.

The pure [`inspect_systemd_elf.py`](../../siem/rbac/inspect_systemd_elf.py) reader
uses program headers, not section names. The [ELF ABI](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.dynamic.html)
defines DT_NEEDED string offsets, SONAME, RPATH/RUNPATH and DT_NULL termination.
The first DT_NULL ends the array; its value and following padding are ignored.
Bounds, unambiguous file-backed string/dynamic mappings, unique relevant tags,
bounded strings and a terminator are required. This is **not** full ELF, symbol,
relocation, constructor or code-safety validation.

Limits inherited from the archive verifier include 16 MiB per package, 32 MiB
per extracted image and 30 seconds per gpgv/bsdtar call. Output limits are
checked after tools exit, not hard streaming memory caps. The ELF reader bounds
program headers to 256, dynamic entries to 4096, string table to 2 MiB and
individual strings to 4096 bytes. The CLI refuses Unix root execution; run
only on an already trusted physical host with reviewed local tools. Input-file
metadata checks are not an atomic snapshot or defense against a privileged
host writer. Toolchain and trust-anchor provenance still require review.

## Host-only reproduction, not a new VM gate

The [completed host report](../../evidence/rbac/systemd-runtime-archive-host-smoke-2026-09-30.md)
records Codex's run, not an owner-executed clone gate. No extra output is needed
from the owner now; both VMs may remain off. Preserve the old public archive
bundle unchanged. This module uses a **new** bundle containing its four public
files plus the exact library `.deb`, never package discovery or installation.
The library package comes from Ubuntu's archive; its authoritative checksum
is taken from the same signed index, not trusted solely from a web listing.

If separately reproducing on the trusted Windows host, from the repository root:

```powershell
& "$env:TEMP\alertmind-pid1-ci-venv-20260928\Scripts\python.exe" -B `
    -m siem.rbac.verify_systemd_runtime_archive `
    --bundle "$env:TEMP\alertmind-systemd-runtime-archive-20260930" `
    --gpgv 'C:\Program Files (x86)\GnuPG\bin\gpgv.exe' `
    --bsdtar 'C:\Windows\System32\tar.exe' `
    --candidate-sha256 3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3 `
    --candidate-bytes 141776
if ($LASTEXITCODE -ne 0) { throw 'STOP: runtime-artifact candidate verification failed' }
```

These are observed host paths, not trusted tool pins. Missing tools/bundle or
changed versions require review, not arbitrary substitution. The module does
not download files or create a reference. CI uses synthetic data and no network.
Thirty-four [tests](../../assistant/tests/test_systemd_runtime_archive.py) cover
the parser/chain, tampering, exact extraction, CLI refusal and retained public
report. A real bsdtar fixture runs only when libarchive is available; GNU tar
is not substituted. CI neither redownloads nor reattests historical artifacts.

## What this closes, and what remains

This completes host-side candidate provenance and static loader metadata for
the two private library artifacts. The original image-only comparison did not
cover these bytes. The retained report records ten literal suffix observations
in the shared-library image, not proof of compiled or effective search paths.

No downloaded artifact is an approved runtime pin. Historical signed metadata
is not a freshness assertion. The report keeps trust-anchor approval, archive
freshness, installed/loaded state, loader resolution, complete dependency
closure, compiled/effective path semantics, override state, reference approval
and mutation/startup authorization false. All older review debt remains open.

Next review Ubuntu's exact source/build path construction against these
artifact candidates, then establish installed loaded-library/current-path
facts and selected generator/link/dependency/effect baselines under the
outstanding maintenance boundaries. Do not execute either library to obtain
those facts. No controller, guard capsule or held clone source is changed;
completed clone checkpoints must not be repeated.
