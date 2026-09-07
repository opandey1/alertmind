# Phase 1C evidence — rollback and revocation drill

**Status:** Owner-executed checkpoints completed; author consolidation awaiting
independent review. This record is not an independent approval.

**Runbook:** [Rollback and revocation drill](../../docs/runbooks/rbac-phase1c-rollback-revocation-drill.md).
The [blank template](phase1c-rollback-revocation-proof-template.md) remains unchanged.

## 1. Provenance and scope

| Item | Sanitized value |
|---|---|
| Reports and consolidation | Reports recorded across 6–7 September 2026; consolidated 7 September 2026, Asia/Kolkata (UTC+05:30). Exact per-command wall-clock timestamps were not captured and are not reconstructed. |
| Reviewed execution commit | `ea37cd89caac8858652317803386df85f01760bb` (merged PR #20); this later evidence commit did not produce the live observations. |
| Prior maintenance | [OpenSSH .3.6 boot-order evidence](phase1c-ssh-boot-order-proof.md), `a1022fb` with `b136a29` guards; Claude's final approval and PR #20 merge are recorded in HANDOFF. The immutable author-submission record retains its then-pending verdict. |
| Recovery point | Owner confirmed Snapshot 1 available and VM console open; reconfirmed stable host/VM after interruption. |
| Application state | Apps stopped; no live analyst/Wazuh profile existed. Application-profile disable/restore was not applicable. |
| Scope retained | Existing custom roles, DLS, scoped `own_index`, `socanalyst`, frozen artifacts and model runs; no intended mutation to them. Final exact/sanitized checks are scoped in Section 7. |
| Sensitive content | No raw alert, `_source`, credential value, password hash, authorization header or private-key content in this record. Reviewed searches requested metadata only. |
| Test data | No probe/index/document was created by this drill. No live alert was submitted to a model. |

The owner ran VM-console and Windows commands, returning sanitized outcomes
after gates. Codex compared them with the reviewed command bodies; it did not
operate the VM or independently inspect credentials, private keys or each SSH
connection. A completed block's final PASS/STOP supports its preceding silent
guards on that execution, not an independently collected dump of every value.

This was an **interrupted, checkpoint-reconciled drill**, not one uninterrupted
passing script. Stages 4A/4B required separate read-only reconciliation; those
failures remain in Section 8. Dated outside-Git Stage 1–6F packets and the
append-only HANDOFF preserve the coordination sequence. Those local packets
are not prerequisites for running repository CI; the reviewed runbook is
committed, and the exceptional diagnostic outcomes are disclosed here.

## 2. Reviewed artifact integrity

The owner returned all ten payload checksum successes before and after the
drill, plus the final ordering checksum. The manifest digests below bind the
committed LF content; the VM printed payload verification results, not these
manifest-file digests. The helper was staged with syntax-only validation,
exact files, permissions and LF checks before its later authorized execution.

| Artifact under `siem/rbac/` | SHA-256 | Owner result |
|---|---|---|
| `SHA256SUMS` | `70a354bfb6877304c108f85b155aed290c56f5e300cb320d60c21e82130f33a1` | Six identity payloads OK |
| `SSH-SHA256SUMS` | `ed05758753b7cb278a84c591dd03e55af6d57cedb6b534f97271bff23a7a8d3c` | Two SSH payloads OK |
| `SSH-BOOT-ORDER-SHA256SUMS` | `8d7f4c3533bb2b4432bd28d52d006d8839f2f3241863c6c053bcc454aca39ba1` | Ordering payload OK |
| `ROLLBACK-SHA256SUMS` | `99293f97e06eb3fec73d619beb5c8eb11f3719734d3a012209203062ccb82fa7` | Rotation helper OK |
| `build_assistant_svc_rotation_payload.py` | `7dbe717ad1863c548d4065390db82229b3400da875c4159514b14499e9ba1028` | Syntax check before execution; checksum reverified |

## 3. Pre-drill boundary

| Check | Owner-reported/guarded result |
|---|---|
| Stopped apps | Owner confirmed APP-STOPPED; no Streamlit CLI process observed. Not a complete inventory of inaccessible or nonstandard processes. |
| Windows tunnel | Recognized existing forward, `127.0.0.1:19200` only, to approved VM destination |
| Old client fingerprint | `SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo` |
| Server host fingerprint | `SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag` |
| Public CA DER fingerprint | `EB98A4AF38CDA550D473E5659A4375905334041FAB4597F39C4F191D9E6F5E1D` |
| OpenSSH pair | `openssh-server` / `openssh-sftp-server`: `1:10.2p1-2ubuntu3.6` |
| SSH boundary | One `192.168.56.102:22` listener; service active/enabled, socket masked; reviewed SSH/key restrictions and Wants/After `network-online.target` |
| Indexer | One loopback listener at `127.0.0.1:9200` or its IPv4-mapped loopback representation |
| Assistant role/mapping | Exact reviewed role and direct-user mapping; only effective role `alertmind_assistant_alerts_ro` |
| Other authorization | Scoped `own_index` unchanged; exact `socanalyst` mapping and sanitized no-extra-grants user record |
| Enrollment bindings | IDs 001/win-victim and 002/linux-victim matched the committed enrollment-fingerprint guards |
| Health order | Indexer → Manager → Filebeat → Dashboard: each individually active |

## 4. Disabled and revoked state

| Check | Result |
|---|---|
| Windows TCP 19200 | No listener after stopping the recognized tunnel |
| VM transport removal | No TCP 22 listener, active per-connection instance, authorized key or AlertMind SSH/order drop-in |
| Activation paths | `ssh.service`, `ssh.socket` and `sshd.service` masked/inactive on fresh readback; OpenSSH packages retained inert |
| Indexer listener | Loopback only on fresh readback |
| Admin authentication | HTTP `200` on fresh readback |
| Assistant mapping absence | HTTP `404` on fresh readback |
| Assistant user absence | HTTP `404` on fresh readback |
| Old credential after deletion | HTTP `401` on fresh readback |
| Preserved resources | Assistant custom role, `socanalyst` user/mapping and scoped `own_index`: HTTP `200` presence on fresh readback; not exact-content proof at this stage |
| Wazuh health | All four active during removal and fresh readback |

The first deletion run was interrupted. Exact mapping/user DELETE response
codes are **unknown**; later 404/401 checks establish current revoked state,
not the missing historical response codes or an uninterrupted first run.

## 5. Service-credential rotation and restoration

| Check | Result |
|---|---|
| Replacement creation | HTTP `201`; reviewed helper output flowed through an anonymous pipe, not a password file or command-line value |
| Password difference | Helper required a nonempty confirmed replacement different from the supplied comparison value. Known-old `401` and new `200` were subsequently reported separately; no secret was inspected. |
| Initial replacement grants | Sanitized user had no backend/direct roles or attributes |
| Positive credential recheck | Fresh read-only HTTP `200`, exact `assistant-svc`, effective roles `[]`, backend roles `[]` |
| Negative credential recheck | Fresh known-OLD test HTTP `401`; owner-reported selection of the old saved record, not proof of an earlier clipboard value |
| Mapping restoration | HTTP `201`, exact mapping to `assistant-svc` only |
| Restored effective role | Exactly `alertmind_assistant_alerts_ro` |
| Bounded read | `failed_shards=0; visible_hits=10000; relation=gte` |
| Restricted reads | Cluster health `403`; username-index search `403` |
| Wazuh health | Indexer, Manager, Filebeat, Dashboard individually active |

The helper comparison alone does not identify the real old credential if the
operator entered a different comparison value. The separate positive and
known-old negative observations are retained as owner-reported evidence.
The initial new-password check failed before these successful rechecks; its
cause was not established. No permission broadening was used to bypass it.

## 6. SSH-key rotation and transport restoration

| Check | Result |
|---|---|
| Revoked client fingerprint | `SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo` |
| Replacement client fingerprint | `SHA256:RAmkB1Xh5VLXel/ezCNgQRrl54HnnuUoQmlEY/XIb1c` |
| Key difference / passphrase | Fingerprints differ; owner explicitly confirmed nonempty replacement passphrase, not independently inspected encryption |
| VM key installation | One restricted Ed25519 record; replacement fingerprint installed, old fingerprint absent; pre-enable target/control parser checks passed while SSH masked |
| Service restoration | Reviewed SSH/order configuration restored; one host-only listener, socket masked, unchanged server host key, four services active |
| Old-key live denial | Exact old fingerprint offered; explicit public-key rejection; exit `255`; no acceptance/authentication marker under Section 9.1 guards |
| Replacement-path tunnel | `127.0.0.1:19200` only; paired TLS/read passed before promotion |
| Local promotion | Old private/public files removed; replacement pair renamed to canonical paths; final fingerprint matched. Not forensic erasure. |
| Canonical-path tunnel | Fresh loopback-only listener and paired TLS/read passed after promotion |
| Public CA / server identity | Unchanged pinned CA fingerprint and server host key from Section 3 |
| Wrong-hostname control | Explicit Schannel name mismatch for `alertmind-hostname-check.invalid`; curl exit `60` |
| Correct-identity read | `127.0.0.1` accepted; `failed_shards=0; visible_hits=10000; relation=gte` on replacement and canonical paths |
| Final shell/command | Windows wrapper exit `-1`; marker absent |
| Final PTY/session | Windows wrapper exit `-1`; marker absent |
| Final remote forward | Exit `255`; denial PASS |
| Final alternate destination | `127.0.0.1:443` denied; verifier required `administratively prohibited`; diagnostic log removed |
| Final password-only authentication | Exit `255`; password prompts disabled |
| Diagnostic cleanup | No TCP 19201 listener, alternate-destination log or TLS query file |

The final denials followed the successful **same canonical-key positive
forward**. The `-1` values are Windows-wrapper observations, not portable
native SSH exit-code meanings. Shell/PTY/remote-forward summaries alone do not
establish successful authentication on every fresh connection. Interpretation
also relies on the prior positive forward, unchanged policy and reported
sequence; no connectivity/authentication failure was reported in that final
sequence. Such a failure would invalidate a policy-denial inference even if
a wrapper printed PASS. Verbose SSH logs are not published.

Each TLS pair used the same tunnel, CA and revocation policy. The negative
control supplied no credential and failed at certificate authentication;
the positive request returned only metadata. `10000 / gte` is a **lower bound**,
not an exact count. The fixed non-secret query file used UTF-8 without BOM
and was removed by finally cleanup; no raw alert was requested.

The reviewed curl `--ssl-revoke-best-effort` exception retained peer/hostname
verification but supplies **no effective certificate-revocation protection**
for this private CA, which publishes no revocation location. No insecure TLS
bypass is established or authorized; application TLS remains a separate gate.

## 7. Final state and claim boundary

| Check | Result |
|---|---|
| Final exact preflight | Section 4.2 repeated with new service password; all ten payload checksums, installed restrictions, enrollment bindings and final STOP passed |
| Assistant authorization | Exact role/mapping; exact effective service role; sanitized no-extra-grants user record |
| `own_index` | Exact preserved seven-user selector; excludes both AlertMind principals; alternate selectors empty |
| `socanalyst` | Exact mapping and sanitized backend/direct-role/attribute checks unchanged; password/hash was neither displayed nor compared for equality |
| Final VM check | Section 10 ordering checksum/comparison, OpenSSH `.3.6` pair, service active/enabled, socket masked/inactive, loaded ordering and one host-only listener passed |
| Final health order | Indexer → Manager → Filebeat → Dashboard: each individually active; final restored-state PASS |
| Frozen artifacts | No accepted model-run/corpus/timing artifact changed in this evidence patch; offline frozen verifier is required before submission |

Final owner line: **PASS final VM state: boot-ordered restricted SSH transport
restored and Wazuh healthy**.

**Conclusion proposed for independent approval:** the currently implemented
restricted transport and `assistant-svc` identity were disabled/revoked,
rotated and restored through gated, reconciled checkpoints on OpenSSH `.3.6`.
Observed final authorization and transport checks retained the reviewed
boundary and all four Wazuh services were healthy. This is not proof of no
transient service change between checkpoints, future availability, another
reboot, or a fresh complete Phase 1B DLS/write-denial matrix.

**Not established:** application-profile rollback, OIDC, Dashboard/Server RBAC,
live alert ingestion, model-path execution, production readiness, certificate
revocation availability or forensic erasure. The current app has no live
analyst/Wazuh profile; those later implementation and acceptance gates remain.

## 8. Deviations and failures

1. The obsolete `.3.5` rollback baseline attempt and subsequent `.3.6`
   boot-order repair/reboot belong to the linked maintenance record. They
   are preserved there, not counted as another passing rotation or reboot.
2. Stage 4A deletion was interrupted after owner-recalled authentication,
   mapping/user deletion, absence and old-credential-rejection PASS lines.
   The owner reported overheating/sleep; Codex did not diagnose that cause.
   Exact DELETE codes and the original final tail were not retained. A rerun
   exited at the old assistant credential prompt; no exact rerun response
   was captured. Fresh read-only admin `200`, user/mapping `404`, old `401`,
   preserved-resource presence and health reconciled the revoked state.
   Repeated pasted copies are one checkpoint, not independent observations.
3. Stage 4B created the replacement (201) and verified no grants. Its initial
   old-password checkpoint returned 401, then the attempted new-password
   checkpoint also returned 401; curl exit 22 caused a secondary JSON parse
   traceback. No final success was reached in that original block. The owner
   suspected a clipboard/password mix-up but could not confirm it. Cause
   remains unknown; no successful retry erases that failure.
4. Separate read-only rechecks established new-credential 200/empty roles
   and known-old 401. Their selected secrets were not independently inspected;
   they do not reconstruct the earlier clipboard. Restoration continued
   only after these distinct observations, without resetting the identity
   again or adding extra permissions.
5. Agent usage-limit interruptions delayed packet preparation/consolidation.
   They do not establish VM/tunnel continuity or new live observations.
   Canonical-path positive proof preceded the final denial results. No
   further live failure was reported in the accepted Stage 5A–6F sequence.

## 9. Independent review

| Item | Value |
|---|---|
| Reviewer | Pending — Claude requested through HANDOFF |
| Evidence commit | Identified by the author submission in HANDOFF; execution source is pinned in Section 1 |
| Verdict | Awaiting independent review; not approved |
| Required corrections | Not yet assessed |

This author-submission review table records its submission state. A subsequent
independent verdict must identify the reviewed commit in HANDOFF; this document
must not imply prior approval. Do not advance the Server/Dashboard or application
integration gates on this author consolidation alone.
