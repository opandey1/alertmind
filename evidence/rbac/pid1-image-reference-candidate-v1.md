# PID 1 image reference candidate v1 — retained, not approved

Status: **offline candidate retained; independent review deferred; no live wiring**.

On 2026-09-30 the owner confirmed Claude was not yet available and authorized
offline continuation without that review for now. This permits retaining the
candidate and testing recorded agreement; it is **not independent approval**
of the archive chain, collector, launch packet or reference. All older review
debt remains open. Neither VM was contacted for this step.

## Retained data and content addresses

The [234-byte JSON candidate](pid1-image-reference-candidate-v1.json) uses the
existing six-field schema of `operator_maintenance_pid1_reference.py`. It
contains only the fixed path, `systemd`/`amd64` identity, expected executable
SHA-256 and expected local dpkg-claimed version. No boot ID, start tick,
timestamp, approval Boolean, credential or manager permission is retained in
the reference. `v1` names this artifact version; `schema: 1` names its format.

| Content | SHA-256 |
| --- | --- |
| JSON file, exact LF bytes including final newline | `ae4d461b5666c1afc7ba59f0d24809ca2a3d42ea0debef3e7e525163c34e5978` |
| Comparator canonical reference fingerprint, no final newline | `4d70f472c30b25dc3626dd3d27688cbc1327c6ebb7e0e9bf83842e96d0064c70` |
| Archive smoke record, UTF-8 after CRLF-to-LF normalization | `59bcbfda06525fe65f5ce605718b1cfdb127a16f85e75a6de491162766eedf91` |
| Gate 2C record, UTF-8 after CRLF-to-LF normalization | `6d2d6e0ecb3099430a0b4e11e53df5b30bd63a329dca506e98c387be31d31c3f` |

These hashes bind content, **not authenticity or approval**. The new JSON
file alone has an LF checkout rule. Historical evidence bytes are unchanged;
their normalized hashes tolerate Windows checkout line endings, not edits.

## Evidence basis

- [Host archive comparison](pid1-ubuntu-archive-host-smoke-2026-09-28.md),
  retained by `dec7a77` (test portability correction `523995c`): an Ubuntu
  signed metadata/package comparison reported the extracted image as
  141,776 bytes with SHA-256
  `3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3`.
  The exact package is `systemd_259.5-0ubuntu3.4_amd64.deb`, not a package hash
  substituted for an executable hash. Distribution/pocket and key/toolchain
  details remain in that record; independent trust review is still pending.
- [Gate 2C native result](pid1-clone-observation-2026-09-30.md), retained by
  `7f7c6d5`: the owner-reported running/disk image and dpkg claim match that
  path/digest/version in two passes under the external diagnostic runtime
  assumptions. The 61-ms collection and boot/start identity are observations,
  not freshness, loaded-code, intended-host or package-origin proof.
- Pure comparison (`430c436`) rejects candidate digest/version drift. A
  recorded match keeps reference provenance, observation authenticity and
  freshness, package authenticity, effective generator paths, mutation and
  startup claims false. No caller-supplied Boolean can promote this artifact.

## Offline checks and remaining boundary

From `assistant/`, run:

```powershell
python -m unittest discover -s tests -p "test_pid1_reference_candidate.py" -v
```

The seven tests pin the artifact and both historical records, parse the
complete retained Gate 2C shape/flags before comparison, verify agreement and
refusal of drift or added approval fields, and check the pending/no-live-wiring
contract. They read committed local files only; they do **not** reverify archive
signatures, fetch packages, execute the native observer, inspect either VM or
independently approve evidence. Full CI includes these checks automatically.

The candidate is **not connected to the guard or maintenance controller** and
is not installed on the clone or original VM. File existence, a matching hash,
green CI and an owner-merged branch cannot admit a mask, reload, install or
startup. Do not auto-learn or refresh it during any such operation. A future
upgrade must retain a separate candidate and evidence instead of overwriting
this artifact or historical observations.

Before a trusted reference or live gate is accepted, a focused independent
review still needs the archive verifier/trust anchor/toolchain, held-source
observer/launch contract and reported result, with its exact scope recorded.
That narrow review does not approve unused maintenance operations or close
the older deferred scopes. Current effective generator paths, dependency/effect
review and the external maintenance/host/writer boundaries also remain open.
The [maintained provenance plan](../../docs/runbooks/rbac-pid1-clone-provenance-plan.md)
records the owner's offline-review deferral separately from live acceptance.

No further Gate 2A/2B/2C output or rerun is requested. Preserve the isolated
clone and stages; the clone may remain powered off. Phase 1 human access and
Phase 2 OIDC are not completed by this candidate.
