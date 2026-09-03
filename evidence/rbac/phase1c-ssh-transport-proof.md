# Phase 1C evidence — restricted SSH transport proof

**Captured:** 2–3 September 2026 (owner-executed on the Windows host and
`wazuh-siem` VM)

**Status:** Sanitized owner-executed live proof, awaiting independent review.
The host-only SSH local forward, verified-TLS metadata read and transport
denial matrix completed successfully. This record closes only the owner-proof
portion of the Phase 1C transport gate; it does not claim application
integration or independent approval.

This record contains public fingerprints, configuration hashes and sanitized
outcomes only. It contains no password, private key, authorization header,
enrollment key, raw alert, `_source`, verbose SSH log or unrestricted error
body.

## Provenance and unchanged authorization boundary

- The accepted final proof was run from merged `main` at `7d0d6dc`. The later
  documentation-only merge at `153654b` did not change the SSH package,
  runbook, Indexer roles or mappings.
- Wazuh Manager, Indexer, Filebeat and Dashboard were active before and after
  the accepted transport and denial checks.
- The Wazuh Indexer remained bound to VM loopback at `127.0.0.1:9200`.
- The previously reviewed Phase 1B authorization boundary remained in force:
  `assistant-svc` had only `alertmind_assistant_alerts_ro`, limited to search
  and get on `wazuh-alerts-4.x-*` with DLS for agent IDs `001` and `002`.
- `Snapshot 1` remained available. No rollback was executed during this proof.

## Reviewed server configuration and activation

Only the pinned packages `openssh-server` and `openssh-sftp-server`, both
version `1:10.2p1-2ubuntu3.5`, were installed. Both SSH activation paths were
masked during installation. After the target and control parser checks passed,
only `ssh.service` was unmasked and enabled; `ssh.socket` remained masked.

The accepted effective configuration established:

- one IPv4 listener at `192.168.56.102:22`, with no wildcard, NAT-interface or
  IPv6 SSH listener;
- the existing ED25519 host key as the only advertised host key;
- root, password and keyboard-interactive authentication disabled;
- public-key authentication limited to `notroot` from `192.168.56.1`;
- local forwarding only, with `PermitOpen 127.0.0.1:9200`;
- remote, stream-local, agent, X11 and tunnel forwarding disabled;
- no TTY or user RC, `ForceCommand /bin/false`, and `MaxSessions 0`; and
- a non-matching control context with forwarding disabled and
  `PermitOpen none`.

The two committed public configuration inputs matched
`siem/rbac/SSH-SHA256SUMS` before use:

| Input | SHA-256 |
|---|---|
| `sshd-alertmind.conf` | `6b18ac0de80ac6490bdebbeaa5ac0a50040f6ec0ba9c379c4b0fbe3e8d3fe640` |
| `ssh-authorized-key-options.txt` | `90c23d007a9f04588d4e9bf0b264b27641361224e0d46d57cecd68c81ef3394c` |

The installed authorized-key entry combined server policy with the reviewed
key options: source `192.168.56.1`, restricted mode, port forwarding enabled
only so the approved local forward could operate, destination
`127.0.0.1:9200`, and command `/bin/false`.

## Pinned client trust material and tunnel

- Dedicated passphrase-protected client-key public fingerprint:
  `SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo`.
- Pinned VM ED25519 host-key fingerprint:
  `SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag`.
- Public Wazuh CA DER SHA-256:
  `EB98A4AF38CDA550D473E5659A4375905334041FAB4597F39C4F191D9E6F5E1D`.
  The copied file contained exactly one public certificate and no private key.
- The Windows endpoint had exactly one listener at `127.0.0.1:19200`, owned
  by the foreground SSH process. The approved path was
  `127.0.0.1:19200` → host-only SSH → VM `127.0.0.1:9200`; no wildcard local
  listener was present.
- Git for Windows OpenSSH 10.2 performed the ED25519 host-key scan because the
  Windows inbox scanner could not negotiate the server's preferred KEX. The
  inbox SSH client then used the pinned host key and explicitly selected the
  reviewed mutually supported KEX.

The process ID was deliberately not retained because it is ephemeral. The
forward is a foreground process, so its listener, owning process and pinned
inputs must be rechecked before every later use.

## Paired certificate and read proof

Both legs used the same unchanged tunnel, public CA and revocation policy.
Only the requested HTTPS hostname changed during the certificate-verification
control. The negative leg deliberately failed before HTTP and sent no
credential or query; after the correct certificate identity passed, the
positive leg authenticated as `assistant-svc` and issued the bounded query:

| Leg | Certificate identity | Result |
|---|---|---|
| Negative control | `alertmind-hostname-check.invalid` | curl exit `60`; diagnostic explicitly reported that the name did not match the server certificate |
| Positive read | `127.0.0.1` | accepted; `failed_shards=0`, `visible_hits=10000`, `relation=gte` |

The positive query requested only hit-count metadata (`size: 0`) for the two
DLS-approved agent IDs. It requested no `_source` and returned no raw alert.
Because the relation was `gte`, `10000` is a lower bound, not an exact corpus
or Indexer total.

The Wazuh private CA publishes neither a CRL distribution point nor Authority
Information Access. For this PowerShell/curl proof only,
`--ssl-revoke-best-effort` tolerated the unavailable revocation status while
the exact CA and hostname verification remained enabled. This chain therefore
received no effective revocation protection. No `--ssl-no-revoke`,
`--insecure` or `-k` bypass was used. This compatibility decision does not
approve or settle the later Python application's TLS context or certificate
chain.

## Same-key transport denial matrix

The same client key and unchanged server configuration that completed the
positive local forward were used for every denial:

| Attempt | Sanitized result |
|---|---|
| Shell/command execution | denied; Windows wrapper exit `-1`; marker absent |
| PTY/session allocation | denied; Windows wrapper exit `-1`; marker absent |
| Remote forwarding | denied; SSH exit `255` |
| Local forwarding to alternate destination `127.0.0.1:443` | denied; the diagnostic log was removed only after its denial marker was observed |
| Password-only authentication | denied; SSH exit `255`; zero password prompts allowed |

The `-1` values are recorded as the observed Windows process-wrapper results,
not generalized as portable SSH exit codes. Marker absence is part of those
two checks. Because the same key had already established the approved local
forward and positive read, the matrix is not a vacuous authentication-failure
test. All four Wazuh services remained active after the matrix.

## Excluded and superseded attempts

The following attempts are not accepted as evidence:

- the Windows inbox `ssh-keyscan` attempt that failed KEX negotiation;
- an initial listener proof that raised `STOP` after treating one CIM result
  as a scalar, including its manually entered trailing PASS line;
- an initial positive TLS request that returned HTTP `400` /
  `json_parse_exception` after Windows PowerShell 5.1 stripped quotes from
  inline JSON, including all null-derived statements entered after that stop;
- the earlier Schannel revocation-unknown exit `60`, which did not isolate a
  hostname mismatch; and
- interrupted CA clipboard/candidate-path attempts before the final public CA
  fingerprint and no-private-key checks passed.

The accepted positive query used a temporary UTF-8, no-BOM file with curl's
`@file` form and removed it in `finally`. The accepted listener, CA, negative
TLS and positive TLS checks were rerun as atomic blocks, so a `STOP` could not
fall through to a later PASS.

## Stop point and remaining work

This evidence demonstrates a host-only, public-key-only, local-forward-only
transport to the loopback-bound Indexer, a verified-hostname metadata read and
denial of five unapproved transport/authentication paths. It awaits independent
review and does not yet close Phase 1C as reviewed evidence.

It does **not** implement or prove Wazuh Server/Dashboard read-only
configuration, OIDC/application authentication or authorization, the
constrained Python reader and normalizer, the live-alert Streamlit UI,
transactional sanitized audit logging, or the rollback/revocation drill. The
rollback commands remain documented in the runbook but were not exercised.
No live alert was sent through the LLM assistant.
