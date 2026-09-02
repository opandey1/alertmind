# Phase 1C SSH transport prerequisite evidence

**Status:** prerequisite complete; OpenSSH transport not yet installed or
enabled.

**Captured:** 2 September 2026, from the `wazuh-siem` VM console.

This record contains package state and public fingerprints only. It contains
no password, enrollment key, private key, authorization header or alert body.

## Baseline

- VM: Ubuntu 26.04 (`resolute`), amd64, kernel `7.0.0-30-generic`.
- `openssh-client`: `1:10.2p1-2ubuntu3.5`, installed.
- `openssh-server`: dpkg state `un` (`unknown/not-installed`).
- `/usr/sbin/sshd`: absent.
- `ssh.service` and `ssh.socket`: inactive and no installed unit file.
- TCP 22: no listener.
- Host-only path: Windows `192.168.56.1` to VM `192.168.56.102` on
  `enp0s8`; the VM route selected `192.168.56.102` as its source.
- Existing host-key fingerprints to preserve:
  - ECDSA: `SHA256:WJ5DThrIkXPqEVqH1PBSe14Cn0+W+NX8nNANKWjy6ik`
  - ED25519: `SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag`
  - RSA: `SHA256:Feh+HT0e1W4nkFFjzd/xlbnN5qmXoFi3aaTRCMPmo0s`
- `/home/notroot/.ssh` was mode `0700`; `authorized_keys` was mode `0600`
  and contained zero key entries.
- All four Wazuh services were active before and after this prerequisite work.

## Package-manager blocker and owner decision

The first OpenSSH simulation exposed `postfix` `3.10.6-4ubuntu2.1` in dpkg
state `iF` (half configured). Read-only diagnosis established:

- Postfix was automatically installed and had no installed reverse-dependent
  package;
- Wazuh email notification was `no`;
- no SMTP listener existed;
- active, deferred, incoming and maildrop queues were empty, and hold was
  absent;
- `/etc/postfix/main.cf` and `/etc/mailname` were absent; and
- `postconf` failed because `main.cf` was absent.

An exact `apt-get --simulate purge postfix` proposed removing only `postfix`.
It listed `libnsl2` and `networkd-dispatcher` as no-longer-required but did not
remove them. The owner explicitly approved purging Postfix only, without
`autoremove`.

The owner then purged Postfix. Verification established:

- Postfix is absent;
- `dpkg --audit` produced no finding and `apt-get check` passed;
- `openssh-server` remains not installed and `/usr/sbin/sshd` remains absent;
- no TCP 22, 25, 465 or 587 listener exists; and
- Wazuh Manager, Indexer, Filebeat and Dashboard remain active.

The `.list.migrate` notices emitted by APT concern ignored migration remnants
with invalid filename extensions. They did not block dependency resolution or
the consistency check and were not changed in this gate.

## Stop point

No OpenSSH package, key, daemon configuration or listener has been installed
or enabled. The next mutation is blocked until the exact Phase 1C transport
package, pre-enable proof and rollback receive independent review.
