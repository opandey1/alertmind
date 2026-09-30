# PID 1 clone Gate 2C — owner-reported native observation

Status: **completed owner-reported diagnostic; candidate matched;
independent review pending; reference not approved**.

The owner returned this sanitized output on 2026-09-30 after explicitly
approving one read-only Gate 2C run on **Ubuntu SOC 201 - Current Isolated Clone**
and accepting its external diagnostic runtime trust assumptions. Receipt date
is not an independently observed execution timestamp. Codex did not access
either VM or execute the observer.

## Packet provenance and confirmations

The [bounded observation packet](../../docs/runbooks/rbac-pid1-clone-observation.md)
was implemented in `7fcc211`/`5c4dbb2`, merged in PR #99 at `40e8abb`.
Release-record commit `aefa3e9` on `docs/rbac-pid1-clone-observation-release`
was **not merged** when the owner ran it. That does not invalidate this result:
the executable block is unchanged from PR #99; the separate human release
preceded execution. Codex rechecked that equality locally after receiving the
output. Git history cannot independently attest the exact console bytes used.

The owner returned all three required confirmations. They reaffirm clone
identity/isolation/no-app/no-change conditions and external diagnostic trust;
they are operator attestations, not independent host or runtime authentication.
The original VM remains outside this diagnostic's authority.

## Supplied output

Console line-ending/paste artifacts are removed below; values, result lines
and their order are retained. No password or private key is included.

```text
Type CLONE-ONLY after checking clone identity, disconnected adapters, no app use, stable host and no intervening changes: CLONE-ONLY
Type TRUSTED-DIAGNOSTIC only after accepting the external clone/runtime/toolchain trust assumptions for this diagnostic: TRUSTED-DIAGNOSTIC
Type LAUNCH-RELEASED only after this exact packet has received separate explicit execution release: LAUNCH-RELEASED
PASS pre-launch staged source and candidate interpreter: exact metadata, digests and stable identity
{"candidate_fields_match": true, "inventory": {"atomic_snapshot_proven": false, "boot_id": "23419e71-1a7f-48c1-a8f9-dce98a1565c4", "candidate_path": "/usr/lib/systemd/systemd", "collection_elapsed_ms": 61, "continuous_control_proven": false, "current_generator_paths_proven": false, "dpkg_claimed_version": "259.5-0ubuntu3.4", "executable_sha256": "3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3", "independently_pinned_image_verified": false, "intended_host_proven": false, "loaded_code_proven": false, "local_dpkg_status_and_list_claim_matched": true, "mutation_authorized": false, "package_authenticity_proven": false, "passes": 2, "pid1_start_ticks": 145, "review_required": true, "running_and_disk_bytes_matched": true, "startup_authorized": false}, "reference_approved": false, "runtime_authenticity_proven": false, "scope": "isolated-clone native diagnostic; not maintenance admission", "source_count": 8}
STOP POINT: native diagnostic only; no reference or maintenance approval
PASS post-launch staged source and interpreter: metadata, digests and identity unchanged
STOP POINT: return the complete diagnostic output for review; no reference or maintenance approval
```

## Validation and limits

All expected prompts, wrapper PASS lines, sanitized JSON and both STOP POINT
lines are present in order; no failure or timeout is reported. Under the
committed packet, the final review STOP is reachable only after a zero-status
root-shell result and successful post-checks. The owner did not separately
print a numeric shell exit status; this record does not invent one.

The JSON matches the entry/collector contract: eight sources; two passes;
running/disk bytes and local dpkg status/list matched; `/usr/lib/systemd/systemd`;
version `259.5-0ubuntu3.4`; expected SHA-256
`3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3`.
Collection elapsed 61 ms, below the collector's 30-second window. Boot ID and
start ticks are observation fields, not proof of the intended host or freshness.
The wrapper reports source/interpreter metadata, digest and identity unchanged
afterward. These checks are reported success, not a separate disk attestation.

All nine inventory trust/authority claims and both summary authority claims
remain false; `review_required=true`. This is a successful native diagnostic
under the acknowledged external clone/runtime trust assumption, **not**
package authenticity, loaded-code proof, an approved PID 1 reference, production
maintenance/startup permission, fresh original-VM health or completed RBAC/OIDC.
It does not test timeout cancellation or hostile concurrent mutation merely
because the successful collection was fast.

## Next step

The single-run release has been used. Do not rerun Gate 2C or repeat Gate 2A/2B
staging. Preserve the staged sources and this report; the clone may remain
powered off and isolated. No further VM output is needed for this checkpoint.

Next independently review this native result together with the
[host-side authenticated archive comparison candidate](pid1-ubuntu-archive-host-smoke-2026-09-28.md)
before approving any versioned reference. All earlier deferred review remains
open. The [provenance plan](../../docs/runbooks/rbac-pid1-clone-provenance-plan.md)
still separates observed compatibility from reference/production authority.
