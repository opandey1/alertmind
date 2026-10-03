# Server inventory — diagnostic revision held for review

**4 October 2026: NOT EXECUTABLE UNTIL REVIEWED AND SEPARATELY RELEASED.**
This revision identifies the operation/category of a failure; it does not fix
an assumed live response shape or close the human baseline. No credentials,
VM run, permission change or service restart is authorized by this document.

The [owner's Server-only result](../../evidence/rbac/server-inventory-diagnostic-2026-10-04.md)
reached `inventory`, so authentication/token parsing completed. The generic STOP
exposed no cause. Administrator scope was not accepted. A missing field, malformed
JSON, transport problem or interruption can give that same old STOP; do not infer
which occurred or reset credentials.

## Diagnostic contract

The reader retains the explicit certificate/name/peer pin and wrong-hostname
probe before credentials, one ordinary authentication POST, allowlisted GETs,
same ordered/short-circuit rechecks, byte/request/time/page limits, complete
graph/readonly validation and fail-closed cleanup. No new dependency or raw log.

Failures report the static `authentication`/`inventory` phase and a fixed
operation checkpoint (e.g. `READ_USERS`, `VALIDATE_GRAPH`, `COMPARE_CONTEXT`).
An allowlisted local check has `code=...`; other exceptions have a fixed category
(e.g. `JSON_DECODE`, `MISSING_FIELD`, `FIELD_ACCESS`, `TIMEOUT`, `IO_ERROR`).
Unknown check/operation values are redacted. No exception text, field name,
class name, raw response, private URL, token or username is emitted.
Checkpoints narrow the location; they are not a traceback or a proven root cause.
No partial inventory is accepted or printed on failure.

The combined runner also separates Server authentication/inventory from final
Indexer baseline/identity/enrollment rechecks and summary assembly. A final
Indexer failure is no longer mislabeled `Server inventory`. This is diagnostic
bookkeeping, not changed permissions, validation or authorization.

## One finite next run — still held

1. Focused independent review must cover the changed reader, connected baseline,
   byte pins, tests and exact new public packet. Submission labels stay unchanged;
   approval is recorded separately. The new verification record is
   `siem/rbac/server-inventory-diagnostics-verification-2026-10-04.json`.
2. The owner then separately authorizes ONE new-stage H2 plus the Server-only
   diagnostic below on the original VM. Reconfirm Snapshot 1/current before-state,
   stable private/unrecorded console, apps stopped and no concurrent maintenance.
3. Build with the existing [H1 builder](rbac-human-permission-baseline.md#h1--workstation-build-only)
   only if a new reviewed packet is needed. Otherwise retain the exact review
   packet/digest. No helper is executed by a public build. Transfer only public
   wrapped Base64/end marker; never credentials.
4. Use the corrected canonical [H2 public stage](rbac-human-permission-baseline.md#h2--public-staging-held-until-review-and-owner-release).
   It targets NEW `/root/alertmind-human-baseline-serverdiag`, refuses an existing
   target and preserves `/root/alertmind-human-baseline` and
   `/root/alertmind-human-baseline-identityfix`. No overwrite, deletion or reuse.
5. Only after H2 PASS in that separately approved batch, execute the following
   Server-only block once. Do NOT run combined H3 as an additional diagnostic.
   Any failure/interruption/changed condition ends the run; no automatic retry.

```bash
(
set -euo pipefail
test -t 0 && test -t 1
read -r -p 'Type REVIEWED-RELEASED-SERVER-DIAGNOSTIC only after new-packet review and original-VM release: ' ready
test "$ready" = REVIEWED-RELEASED-SERVER-DIAGNOSTIC
sudo -v
sudo bash -s <<'SH'
set -euo pipefail
ulimit -c 0
cd /root/alertmind-human-baseline-serverdiag
test "$(stat -c '%u:%g:%a' .)" = '0:0:700'
test "$(find . -mindepth 1 -maxdepth 1 | wc -l)" -eq 8
for file in SHA256SUMS collect_human_baseline.py collect_server_inventory.py scope-contract.json \
  indexer-role_socanalyst_ro.json indexer-role_assistant_alerts_ro.json \
  indexer-role-mapping_socanalyst_ro.json indexer-role-mapping_assistant_alerts_ro.json; do
  test -f "$file" && test ! -L "$file"
  test "$(stat -c '%u:%g:%a' "$file")" = '0:0:400'
done
sha256sum -c SHA256SUMS
printf '%s  %s\n' '5cccc906dbf4f5470f10814f37ccc4ca849e76c36d0b45c441da95357b911e77' \
  collect_server_inventory.py | sha256sum -c -
for package in wazuh-manager wazuh-indexer wazuh-dashboard; do
  test "$(dpkg-query -W -f='${Status}|${Version}' "$package")" = 'install ok installed|4.14.7-1'
done
for svc in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
  test "$(systemctl is-active "$svc")" = active
  printf 'PASS service health: %s=active\n' "$svc"
done
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root \
  /var/ossec/framework/python/bin/python3 -I -B collect_server_inventory.py </dev/tty
SH
)
```

At the reader guard enter `REVIEWED` only after approval/release. Wait for the
credential-free TLS PASS, then enter the existing **Server API administrator**
username/password at the hidden prompts, not Indexer/broker/SSH credentials.
Login issues one token and may produce normal Server logs; no token file or
guaranteed secure memory erasure. Do not enable shell tracing, recording,
debuggers, raw HTTP logging or output redirection to diagnose.

Return only sanitized checksum/PASS/STOP and, on success, the complete sanitized
JSON. Stop even on PASS for assessment. It is a current Server observation, not
acceptance of the failed old run, full combined H3, actual Dashboard context,
matching predicates or a permission-mutation release. Subsequent complete H3
requires separate review of this result and explicit release; don't restage again
or automatically replay prior tests/drills. Human activation remains held.
