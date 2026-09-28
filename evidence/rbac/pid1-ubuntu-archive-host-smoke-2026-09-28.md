# PID 1 Ubuntu archive chain — Codex Windows-host smoke test

Status: **host-side candidate comparison passed; independent review pending**.
This is not an owner-executed clone gate or an approved installed-image pin.
Codex used a fresh temporary folder on the physical Windows host. Neither
the isolated clone nor the original VM was contacted, changed, or executed.
No downloaded package or key material was committed to the repository.

On 2026-09-28, the host fetched the public Ubuntu 2018 archive key from
`keyserver.ubuntu.com` and `resolute-updates` `InRelease`, amd64 `Packages.xz`
and the exact `systemd` `.deb` from `archive.ubuntu.com`. The key fingerprint
was checked against Ubuntu's [published fingerprint](https://wiki.ubuntu.com/Security/FAQ)
before a local keyring was produced. `gpgv` verified the signed Release with
signer `F6ECB3762474EDA9D21B7022871920D1991BC93C`; the verifier checked
the signed index hash/size, indexed package hash/size, and extracted image.

| Checked artifact | SHA-256 / size |
| --- | --- |
| `InRelease` | `c16f5e1a367bd64dbac6153facf06868e4f290483dbb4297799f71e9cce161f7` / 137,401 bytes |
| `Packages.xz` | `a6345fd9e9a35aa81d0f058537ca44dae79ae9e50a23a40a3c6f8696453d8f3e` / 679,268 bytes |
| `systemd_259.5-0ubuntu3.4_amd64.deb` | `1b2eca56c5cfdbc1aca78591a68f94b7e1c996abd52095587069776b816b9dca` / 3,128,676 bytes |
| extracted `usr/lib/systemd/systemd` | `3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3` / 141,776 bytes |

The extracted image digest and size equal the [owner-reported Current-State
clone candidate](pid1-current-clone-preflight-2026-09-28.md). The host check
used Python 3.12.14, GnuPG/gpgv 2.4.8, and Windows bsdtar/libarchive 3.8.8;
`verify_pid1_ubuntu_archive.py` exited 0. This comparison does **not** prove
that the clone's running image came from this package, that the downloaded key
or host toolchain were independently trusted, that either VM is currently in
the reported state, or that future archive metadata will retain this version.
The verifier explicitly reported `reference_approved=false`,
`mutation_authorized=false`, and `review_required=true`. A separate reviewed
clone-native compatibility check is still required before any reference pin.
