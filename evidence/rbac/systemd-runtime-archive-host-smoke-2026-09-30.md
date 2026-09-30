# systemd runtime archive — Windows-host candidate smoke

Status: **host check passed; independent review pending** under the owner's
offline review deferral. No library reference or live maintenance is approved.
This is Codex's physical-Windows-host run, not owner execution on a VM.
Neither VM was contacted, updated or used to execute a package image.

The new [host-only verifier](../../docs/runbooks/rbac-systemd-runtime-archive.md)
reused copies of the public InRelease, Packages.xz, keyring and systemd `.deb`
from the preserved 28 September host bundle. It downloaded only the exact
public `libsystemd-shared_259.5-0ubuntu3.4_amd64.deb` from
`https://archive.ubuntu.com/ubuntu/pool/main/s/systemd/` into a fresh temporary
bundle on 30 September. The old bundle and all clone source/evidence were
unchanged. No package, library or key material was committed.

Gpgv reverified the InRelease signature with archive signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C`. Both package records, hashes and
sizes were checked against that signed index before stdout-only extraction.
Ubuntu's [archive-integrity documentation](https://documentation.ubuntu.com/security/software-integrity/archive-verification/)
describes this signature/checksum chain. Historical metadata was used; current
archive freshness, independent trust-anchor approval and installed state are
not established. The keyring's recorded SHA-256 identifies its bytes only.

| Artifact | SHA-256 | Bytes |
| --- | --- | ---: |
| InRelease | `c16f5e1a367bd64dbac6153facf06868e4f290483dbb4297799f71e9cce161f7` | 137401 |
| Packages.xz | `a6345fd9e9a35aa81d0f058537ca44dae79ae9e50a23a40a3c6f8696453d8f3e` | 679268 |
| public keyring | `aff7b0bd431039349cfd2b8e97e722f360f61dd02f1c2087f911d80c5bd57614` | 3413 |
| systemd .deb | `1b2eca56c5cfdbc1aca78591a68f94b7e1c996abd52095587069776b816b9dca` | 3128676 |
| libsystemd-shared .deb | `9b30b1e96cc8b48f94a2df5c1cbee7690e16f727d71b40c458a64aabe15db35f` | 2462336 |
| manager image | `3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3` | 141776 |
| core library | `8fcb08373177707996567006be35737e408d9ede3b0a2ca08fdd130182012754` | 2488904 |
| shared library | `c733810400659bf34b5d46f77b801507a384ebc36392c5fe48fedc72388bae3e` | 5001176 |

Both packages are version `259.5-0ubuntu3.4`, amd64, source systemd. The
manager image matches the [retained PID 1 candidate](pid1-image-reference-candidate-v1.md).
The libraries came from two fixed members of the libsystemd-shared package;
they were never loaded or executed. Static metadata:

- Manager: interpreter `/lib64/ld-linux-x86-64.so.2`; needed
  `libsystemd-core-259.so`, `libsystemd-shared-259.so`, `libc.so.6`;
  RUNPATH `/usr/lib/x86_64-linux-gnu/systemd`; no RPATH or SONAME.
- Core: SONAME `libsystemd-core-259.so`; needed `libsystemd-shared-259.so`,
  `libm.so.6`, `libc.so.6`; no interpreter or RPATH/RUNPATH.
- Shared: SONAME `libsystemd-shared-259.so`; needed `libcrypt.so.1`,
  `libcrypto.so.3`, `libm.so.6`, `libc.so.6`, `ld-linux-x86-64.so.2`;
  no interpreter or RPATH/RUNPATH.

Each of the eight candidate generator-directory strings and two override names
has one NUL-terminated suffix occurrence in the shared-library bytes and zero
in manager/core. This is not function/call-site identification, proof of
compiled macro use, ordering, current getenv or effective path semantics.
No complete loader/dependency closure or installed loaded-library match exists.

The first smoke attempt stopped at `ELF_DYNAMIC`: the initial reader wrongly
required all padding after DT_NULL to be zero. The authenticated core library
contains a nonzero padding value (53140). The reader was corrected to the
[ELF ABI's DT_NULL termination rule](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.dynamic.html),
with regression coverage for ignored terminal values/tail bytes and refusal of
unterminated arrays. No provenance or authorization condition was relaxed.
The corrected CLI exited 0 using Python 3.12.14, gpgv 2.4.8 and Windows
bsdtar/libarchive 3.8.8. ELF metadata was read by the pure reader, not by ldd.

The complete sanitized [JSON result](systemd-runtime-archive-host-smoke-2026-09-30.json)
is 3678 LF bytes, SHA-256
`043da749e885132c2e110beaedbf99b5cf22b4fa2ef5b31eb9863c36515b32a2`.
Offline tests pin that historical record, shapes and non-authorizing flags;
they do not rerun signature verification or establish present VM state.
Source/build equivalence, installed loaded code, current path sources, selected
generator effects and independent review remain open. No VM action is needed
for this host checkpoint; leave the isolated clone powered off.
