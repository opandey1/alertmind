# Compact Dashboard broker TLS package — Batch A candidate

**1 October 2026: offline implementation, awaiting focused independent review.**
This is not a VM execution packet. Clone staging/execution will be released
separately after review and owner approval. P1-01 remains open; P1-02 rehearsal,
actual broker TLS and human `socanalyst` activation are NOT TESTED. Follow the
[finite checklist](../rbac-phase1-exit-checklist.md), not the deferred guard work.

## Supported scope and trust

The [standalone operator](../../siem/rbac/broker_tls/compact_operator.py) touches
only the fixed broker client, one public certificate, a startup helper, two
additive systemd drop-ins and private recovery state. No identities, mappings,
enrollment, SSH, saved objects, Server configuration or broker passwords change.
No network request, alternate root or arbitrary command/path is exposed.
Neither experimental guard/controller is called or made deployable.

Supported packages: `wazuh-dashboard` and `wazuh-manager` **4.14.7-1**. The
[existing candidate/contract](../../siem/rbac/broker_tls/README.md) pins original
and patched client bytes. Normal vendor dependencies, packaged Python/PyYAML,
Node, OS/root, systemd and administrative tools are trusted lab inputs. No
concurrent updates/configuration work or other Dashboard instance is allowed.
Applications must be stopped, console available and recovery snapshot retained
for the separately approved maintenance window. This is not hostile-root
containment, whole-runtime attestation or continuous integrity monitoring.

One configured broker host must have `url: https://localhost`, integer
`port: 55000`, `run_as: true`, username `wazuh-wui` and a nonempty password.
Duplicate YAML keys and anchors/aliases are refused. Values are never printed;
configuration is not copied or edited. Its whole-byte digest is retained
privately and must match on later starts. Changed credentials/configuration
need a reviewed stopped re-baseline, not automatic acceptance of a new hash.
Earlier inventory proved only HTTPS loopback, not this exact spelling. Current
VM compatibility is unproven: if it differs, stop and review the minimal endpoint
correction with backup, rather than broadening the allowed origin.

Public trust comes from `/var/ossec/api/configuration/ssl/server.crt`, NOT the
Indexer CA. Accepted DER SHA-256:
`5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87`.
The unchanged [Node policy](../../siem/rbac/broker_tls/policy.cjs) verifies SAN
`localhost`, validity and connections, with no proxy/redirect/insecure fallback.
The startup helper checks the exact pin and expiry; it does not perform TLS traffic.

## Fixed files and startup

| Location | Purpose / permissions |
| --- | --- |
| `/root/alertmind-broker-tls-compact/stage/` | Reviewed public candidate/helper/bundle/checksums; root:root directory 0700, files 0400 |
| `/root/alertmind-broker-tls-compact/state/` | Original-client backup and private receipt; root:root directory 0700, files 0400 |
| `/etc/alertmind/certs/alertmind-server-api.pem` | Exact public certificate; root:root 0644, root-controlled traversable parents |
| `/usr/local/libexec/alertmind-broker-tls-compact.py` | Helper; root:root 0400, read by Python, not directly executed |
| `/etc/systemd/system/wazuh-dashboard.service.d/00-alertmind-broker-maintenance.conf` | Durable additive `ExecStartPre=/bin/false` inhibition |
| `/etc/systemd/system/wazuh-dashboard.service.d/90-alertmind-broker-tls.conf` | Mandatory additive startup check; vendor `ExecStart` unchanged |

The startup check uses `ExecStartPre=+` with fixed packaged Python and `-I -B`.
Only that command runs with root privileges, to traverse packaged Python and
read private state; Dashboard is not made root. Failure is not ignored and
prevents service startup. These are documented systemd semantics, **not native
acceptance for this package**. ([upstream v259 service contract](https://github.com/systemd/systemd/blob/v259/man/systemd.service.xml))

Use a deny-start drop-in, not a mask that might collide with a regular packaged
unit under `/etc/systemd/system`. Reload, stop and verify MainPID 0 plus
inactive/failed state and exact loaded drop-ins precede broker file edits.
Reboot loads persistent inhibition. Unknown extra drop-ins are not overwritten.
Initial fragment must be root-controlled `/etc/systemd/system/wazuh-dashboard.service`
or `/usr/lib/systemd/system/wazuh-dashboard.service`, with `KillMode=control-group`.
Its private fingerprint must remain unchanged. Startup checks package versions,
client/metadata, helper, configuration, trust and loaded wiring. Missing Python,
helper or imports refuse startup. No system-wide census or live login is performed.

## Public bundle — workstation only

The [bundle builder](../../siem/rbac/broker_tls/build_compact_bundle.py) takes a
fresh verified output of the existing candidate builder. It checks contract and
candidate bytes, normalizes helper CRLF to LF, syntax-checks without execution,
and emits `candidate.cjs`, `compact_operator.py`, `bundle.json`, `SHA256SUMS` in
a NEW directory. No download, install, live-config read or vendor/operator execution.
Do not reuse partial output or commit extracted vendor files/runtime/packages.

Workstation-only invocation from the repository root:

```text
python -B siem/rbac/broker_tls/build_compact_bundle.py --candidate /scratch/verified-candidate --output /new/scratch/compact-bundle
```

The later clone packet must bind exact reviewed published bytes before root
execution and verify root-private staging. Bundle/checksums provide integrity,
not an independent signature or self-issued approval. No private receipt or
live configuration is transferred.

## Actions — contract, not released commands

All actions require Linux/root. Keep the reviewed staged helper as the recovery
entry even if installation is partial or the installed helper is removed.

| Action | Behavior / checkpoint |
| --- | --- |
| `prepare` | Check compatible untouched baseline/stage; inhibit/stop; preserve original client/metadata and private receipt. Retry pre-receipt interruption using identical backup only. |
| `install` | Inhibit/stop first; recheck private baseline/backup/stage/trust; atomically replace only known absent/before/after bytes; verify and save `installed`, retaining inhibition. Also explicit recovery after interrupted start. |
| `check` | Read-only mandatory pre-start refusal on maintenance, incompatible phase or package/client/trust/config/helper/unit/wiring drift. No mutation or HTTP. |
| `resume` | Re-establish inhibited/stopped checkpoint; validate installation; remove inhibition only after verification; reload/check/start; save `running`. Ordinary failure attempts re-inhibition/stop. |
| `pause` | Supported maintenance entry: durable inhibition/reload/stop; no approval or automatic re-baseline for an update. |
| `rollback` | Inhibit/stop first; verify backup and known targets; restore original client/metadata and remove matching added guard/helper/trust. Keep inhibition/backup. NEVER restart original unverified broker. |

| Interruption / refusal | Recovery after stable-host preflight |
| --- | --- |
| Before preparation changes anything | Diagnose static refusal; never bless unknown inputs. |
| Inhibition/directory/backup but no receipt | Retry `prepare` only with compatible original baseline and identical backup. A damaged/partial receipt is not accepted. |
| `prepared`, any subset of known installed files | Retry `install`; remain inhibited during edits. |
| `installed` | Review checkpoint, then `resume`; no mixed-installation restart. |
| During removal of inhibition/start/final receipt | Security inputs were verified before start release; reboot may start that SECURE installation, still requiring `check`. Explicit `install` stops/re-inhibits/reverifies; then review and `resume`. Downtime after start release is not guaranteed. |
| During rollback | Retry `rollback`; inhibition precedes restoration. Secure `install` then reviewed `resume` can restore service. |
| Unknown bytes, damaged/missing state, extra drop-ins or tool failure | Leave/restore stopped inhibition where possible; diagnose at console. No unknown-file deletion, automatic state repair or bypass. |

Writes compare before replacement, use same-directory temporary files and atomic
replacement, fsync files/parent directories, then verify readback. This is local
filesystem recovery, not an atomic multi-file snapshot. Unreferenced temporary
files can survive interruption; retain privately for diagnosis, not execution
or automatic deletion. Stop/reload failure is not successful inhibition: confirm
state at console. The operator cannot defeat concurrent privileged changes.

The receipt contains a configuration digest, not raw credentials. **Never
paste/commit the receipt or its configuration digest**: it fingerprints
credential-bearing configuration. Console output is static PASS/action or
STOP/code only. Root CLI/startup checks disable core dumps before reading it;
Python cannot guarantee erasure of those in-memory credentials. Vendor HTTP
response bodies are outside this output guarantee.

## Verification and finite next step

The [retained offline verification record](../../siem/rbac/broker_tls/compact-verification-2026-10-01.json)
binds the public bundle hashes, local checks and explicit non-acceptance fields.

Twenty-five tests cover success/refusal, interruption after every completed fake
mutation, stopped recovery, failed restart, original rollback and secure reinstall.
Two disposable Linux filesystem tests cover actual no-follow/atomic replacement/
FD handling and skip on Windows. No root observer, real systemd action, live
credential or alert is used. Fake-host behavior is not native startup evidence.

The pinned Dashboard package was rebuilt and the actual-client synthetic fixture
rerun: **17 groups passed**, including negative TLS, proxy/redirect mutants and
refresh semantics. Packaged axios 1.12.2, workstation Node v24.19.0/Windows,
synthetic pin/adapted Linux metadata — not VM packaged Node or live broker proof.

Next: focused review of this package plus reused candidate, then one separately
authorized clone deployment/recovery packet. Prove mandatory pre-start refusal,
secure restart, interrupted recovery and rollback remaining stopped; preserve
admin/saved dashboards. Actual broker login/read/refresh TLS acceptance precedes
human mapping/UI. Completed SSH, rotation and PID 1 diagnostics are not repeated.
P1-02–06 stay pending; broader Server `readonly` scope needs owner decision.

For updates, `pause` and preserve recovery state before normal vendor maintenance;
review/rebuild the compact contract on a clone before secure restart. Unknown
versions/replacement bytes refuse startup. Certificate renewal and credential
changes also require reviewed stopped re-baselining. No auto-pins, indefinite
security-update freeze or general upgrade-engine claim.
