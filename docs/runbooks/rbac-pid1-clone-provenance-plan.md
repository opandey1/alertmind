# PID 1 clone follow-up — provenance and native compatibility plan

Status: **package-provenance candidate recorded; owner-reported Gate 2A and
Gate 2B staging and Gate 2C native diagnostic completed;
independent result/reference approval remains pending**.
The owner-reported [Gate 1 result](../../evidence/rbac/pid1-current-clone-preflight-2026-09-28.md)
is a candidate for Ubuntu 26.04 / `systemd` 259.5-0ubuntu3.4 on an isolated
Current-State clone. It is not a trusted baseline. Keep the original VM
untouched and the clone isolated; it may remain powered off during this review.

1. **Confirm the missing operator prerequisite.** Before another clone run,
   establish that no AlertMind application is running against that clone and
   that its network adapters remain disconnected. Recheck the exact clone
   identity and that no update/configuration change intervened. A new package
   version, executable digest, boot image or connected adapter invalidates
   this candidate and requires a new review, not an automatic pin update.
   For the Gate 2A result received 2026-09-30, the owner reconfirmed clone identity,
   disconnected adapters, unchanged state and no app use. That completes
   the reported prerequisites for this run; earlier Gate 1-time app state
   remains unknown.
2. **Establish package-source provenance independently of the clone's dpkg
   database.** Use a separately trusted Ubuntu archive signing key and the
   corresponding authenticated Release/InRelease → Packages checksum → exact
   `systemd` `.deb` checksum chain for this architecture and version. In a
   disposable verification environment, extract that authenticated package's
   `/usr/lib/systemd/systemd` and compare its SHA-256 with the owner-reported
   running/disk candidate. Record the distribution, repository pocket,
   signing-key fingerprint, metadata/package hashes, extracted-image hash,
   verification tool/version and retrieval time. If the installed version is
   no longer in a current package index, use Ubuntu's signed historical
   [snapshot metadata](https://documentation.ubuntu.com/security/software-integrity/archive-verification/#validating-old-versions)
   rather than treating an arbitrary archived `.deb` as authenticated. A
   `dpkg-query` or `dpkg --verify` result alone only checks local records and
   cannot do this.
   Do not fetch packages on, alter or update the clone/original VM to complete
   this step. Codex's [host-side smoke result](../../evidence/rbac/pid1-ubuntu-archive-host-smoke-2026-09-28.md)
   matches the reported image, but remains a candidate pending independent
   review of the trust anchor, toolchain and extraction contract.
3. **Review native observer compatibility separately.** Review the installed
   Ubuntu/Python/procfs assumptions and a trusted, bounded launch packet for
   `operator_maintenance_pid1_image.py` on the isolated clone. The Gate 1
   shell script is not an authorization to execute that module. The native
   result must be sanitized and compared with the reviewed candidate, with
   failures stopping rather than falling back to a different path. Do not
   import project code as root from an unverified writable checkout. A
   [Gate 2A unprivileged diagnostic](rbac-pid1-clone-native-compatibility.md)
   checks selected interpreter/procfs/dpkg input shapes without running
   project code. The [owner-reported result](../../evidence/rbac/pid1-clone-native-probe-2026-09-30.md)
   includes all expected PASS lines and the final STOP POINT. Gate 2A is
   complete; proceed with designing the trusted launch and actual native
   collector test rather than repeating the probe. Its result is not native
   collector acceptance or a trusted root launch.
   The [Gate 2B source/launch package](rbac-pid1-clone-source-launch.md) now
   renders eight exact sources into one externally hash-checked script, with
   separate non-executing verification and root-only observation modes.
   The [host Block 1 checkpoint](../../evidence/rbac/pid1-clone-host-packet-2026-09-30.md)
   is complete: 121691 bytes, eight sources and the expected external checksum.
   Do not rerun the exclusive-creation builder over its existing output.
   The [clone Block 2 checkpoint](../../evidence/rbac/pid1-clone-source-stage-2026-09-30.md)
   is also complete: both checksums, eight-source non-executing verification,
   root-private metadata and final STOP results were reported, with fresh
   `CLONE-ONLY` confirmation. Preserve the staged copies; do not repeat Block 2.
   The separate [Gate 2C bounded launch candidate](rbac-pid1-clone-observation.md)
   now implements source/interpreter pre/post checks, cleared runtime environment,
   disabled core dumps and nested timeouts. Its offline tests use synthetic
   tools plus a Linux-only unprivileged timeout check, not a root observer.
   On 2026-09-30 the owner separately approved one read-only run of the exact
   merged Gate 2C packet and confirmed its isolation/no-change conditions and
   external diagnostic runtime trust. The owner subsequently returned the
   [complete Gate 2C result](../../evidence/rbac/pid1-clone-observation-2026-09-30.md):
   pre/post checks PASS, eight sources, two matching passes, candidate digest
   and version match, 61 ms, all trust/authority claims false and both review
   STOP lines. This completes the owner-reported native diagnostic only.
   The release has been used; do not repeat Gate 2A/2B/2C. No further VM output
   is needed for these checkpoints; the clone can remain off and isolated.
   Independent archive/native-result review and reference approval remain
   pending. The staging packet itself never released root observation.
4. **Only then consider an exact reference.** An independent reviewer must
   approve both the authenticated package comparison and native result before
   producing a versioned, retained reference. The pure comparator can check
   matching candidate fields; it cannot attest the source of either input.
   Even an approved match would not prove loaded manager code, the current
   generator paths, host identity, exclusion of concurrent privileged writes,
   safe reload or Phase 1/OIDC completion.

Ubuntu documents [archive signature and checksum verification](https://documentation.ubuntu.com/security/software-integrity/archive-verification/)
and [APT's signed Release-to-package chain](https://manpages.ubuntu.com/manpages/resolute/man8/apt-secure.8.html).
The [dpkg manual](https://manpages.ubuntu.com/manpages/resolute/man1/dpkg.1.html)
explicitly distinguishes its local `--verify` check from a security
verification. Ubuntu's [resolute-updates amd64 download listing](https://packages.ubuntu.com/resolute-updates/amd64/systemd/download)
currently identifies `systemd_259.5-0ubuntu3.4_amd64.deb` (3,128,676 bytes)
with SHA-256 `1b2eca56c5cfdbc1aca78591a68f94b7e1c996abd52095587069776b816b9dca`.
That is a **candidate archive-artifact checksum**, not the extracted PID 1
binary hash, proof of which pocket installed the clone's package, or a
substitute for verifying signed metadata. This plan intentionally has no
VM executable provenance command. A separate [host-only, unexecuted archive
verification packet](rbac-pid1-ubuntu-archive-verification.md) now supplies
an exact local bundle check for review. No VM package manager, systemd
command, credential read or service change is requested by that packet.
