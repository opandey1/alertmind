# Runbook — RBAC and read-only Wazuh integration

**Status:** Phase 0, the Phase 1A package and the inherited-role correction are
independently approved and merged. The owner has now applied the live
`own_index` correction and both direct-user mappings, then completed the
Indexer declarative, DLS/read-scope and fail-safe write-denial checks. The
sanitized proof awaits independent review. SSH, network, Wazuh
Server/Dashboard, identity-provider and application configuration remain
unchanged.

**Applies to:** the post-v1 local-first analyst profile described in
[`docs/rbac-wazuh-read-only-implementation-plan.md`](../rbac-wazuh-read-only-implementation-plan.md).

**Safety boundary:** Do not begin the SSH transport or any later integration
step until the completed Phase 1B Indexer enforcement proof receives
independent approval. Do not repeat a write-denial request unless this matrix
is still fail-safe and the role/mapping preconditions are rechecked.

---

## 1. Phase 0 checkpoint

| Item | Status | Evidence / note |
|---|---|---|
| Submitted v1 preserved | Complete | Existing `v1.0` tag remains immutable. |
| Fresh implementation branch | Complete | `feat/rbac-wazuh-phase0`, created from merged `main`. |
| Pre-feature regression baseline | Complete | 78 assistant tests and frozen-evidence verifier passed before planning. |
| Paste/provider characterization | Complete | Eight additive tests bring the branch to 86 tests without changing the frozen evidence path. |
| Recoverable Wazuh snapshot | Owner reported complete | Powered-off snapshot `Snapshot 1`, 1 September 2026 19:41 IST. A descriptive local rename is recommended. |
| Wazuh recovery gate | Owner reported complete | Manager, Indexer, Filebeat and Dashboard returned `active` on 1 September 2026. |
| Read-only Wazuh inventory | Complete | Sanitized results are recorded in Section 6. |
| Canonical namespace check | Complete | Both planned roles/mappings and both planned users returned 404. |
| Agent enrollment fingerprints | Complete and approved | Sanitized ID/name/SHA-256 bindings for 001/002 are in `evidence/rbac/phase0-owner-checklist.md`. |
| Corrected Phase 0 documents | Complete and approved | Commits `f92db3d`, `fde2fe4` and `73efcd7`; Claude approved the final correction cycle. |
| Secret-free owner checklist | Complete and approved | Snapshot, no-re-enrollment, transport approval and no-secret confirmations are in the sanitized evidence record. |
| Secrets in Git | Prohibited | Local secrets, certificate copies, runtime state and Keycloak data paths are ignored. |

Phase 0 closed when Claude approved `882c465`; the owner subsequently merged
it to `main` at `de4b6a5`. The Phase 1A identity package was subsequently
approved and merged at `76246e8`; its custom roles and users were created as
recorded in Section 8. The current stop point is independent review of the
completed Indexer enforcement proof before the SSH transport gate.

## 2. Rules for collecting inventory

- Run VM commands on `wazuh-siem`; endpoint VMs do not need to be started.
- Every command below is observational. The HTTP `POST` is a bounded search and
  cannot create or update state.
- Never paste a password, enrollment key, private key, bearer token,
  authorization header or unredacted alert into chat, a worksheet or Git.
- Use `sudo curl --user admin` without a password in the command. Curl prompts
  interactively, keeping the password out of shell history. `sudo` is required
  because `notroot` cannot traverse the protected Indexer certificate path.
  A separately installed user-readable copy of the **public CA only** is an
  acceptable later alternative; do not relax `/etc/wazuh-indexer/certs`.
- Never point `openssl x509` at a file whose name contains `key`.
- Do not add `-k`/`--insecure` or suppress certificate verification.
- Python 3.13+ may reject this lab's older Wazuh CA under its newly enabled
  `VERIFY_X509_STRICT` default because the CA lacks a key-usage extension.
  Disabling that flag relaxes a broader bundle of strict RFC 5280 checks; it is
  not a targeted exception for one missing extension. Prefer a reviewed
  certificate-chain replacement. Any compatibility context must explicitly
  accept that broader reduction while retaining the configured CA,
  `CERT_REQUIRED` and hostname verification. Never use an unverified context
  or `verify=False`.
- Stop if any command would mutate state or unexpectedly returns credentials or
  raw alert bodies.

## 3. Host, service, certificate and identity inventory

These commands do not require an Indexer password:

```bash
hostnamectl --static
ip -brief -4 address
sudo systemctl is-active wazuh-manager wazuh-indexer filebeat wazuh-dashboard
sudo systemctl is-active ssh
sudo ss -ltnp | grep -E ':(22|443|9200|55000|1514|1515)\b'
sudo /var/ossec/bin/agent_control -l
dpkg-query -W -f='${Package}\t${Version}\n' wazuh-indexer
sudo grep -E '^(name|version|opensearch.version)=' \
  /usr/share/wazuh-indexer/plugins/opensearch-security/plugin-descriptor.properties
sudo find /etc/wazuh-indexer/certs -maxdepth 1 -type f \
  ! -iname '*key*' -printf '%f\n'
```

Inspect the public Indexer node certificate and public CA. Never select a
private-key file:

```bash
sudo openssl x509 -in /etc/wazuh-indexer/certs/wazuh-indexer.pem \
  -noout -subject -issuer -serial -dates -fingerprint -sha256 \
  -ext subjectAltName

sudo openssl x509 -in /etc/wazuh-indexer/certs/root-ca.pem \
  -noout -subject -issuer -serial -dates -fingerprint -sha256
```

Before creating a DLS role, record a non-secret SHA-256 fingerprint of each
current enrollment key. This command emits only ID, name and digest; it never
prints the key:

```bash
sudo bash -c '
  printf "agent_id\tagent_name\tenrollment_sha256\n"
  while read -r id name ip key; do
    case "$id" in
      001|002)
        digest=$(printf "%s" "$key" | sha256sum)
        digest=${digest%% *}
        printf "%s\t%s\t%s\n" "$id" "$name" "$digest"
        ;;
    esac
  done < /var/ossec/etc/client.keys
'
```

Store only the emitted digests in sanitized evidence. Re-run this check and
review DLS after either agent is re-enrolled; an ID alone is not a permanent
endpoint identity.

On the Windows host, confirm the host-only adapter without exposing unrelated
network configuration:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -like '192.168.56.*' } |
  Format-Table InterfaceAlias, IPAddress, PrefixLength
```

## 4. Read-only Indexer inventory

The current certificate validates VM loopback only:

```bash
export INDEXER_URL='https://127.0.0.1:9200'
export INDEXER_CA='/etc/wazuh-indexer/certs/root-ca.pem'
```

Use `sudo curl` for every request while the CA remains in the protected
directory:

```bash
sudo curl --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/?filter_path=name,cluster_name,cluster_uuid,version.number,version.distribution"

sudo curl --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_cluster/health?filter_path=cluster_name,status,number_of_nodes,active_primary_shards,unassigned_shards"

sudo curl --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_cat/shards?h=index,shard,prirep,state,unassigned.reason&s=state,index"

sudo curl --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_cat/indices/wazuh-alerts-*?format=json&h=index,health,status,docs.count,store.size&s=index"

sudo curl --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/wazuh-alerts-*/_field_caps?fields=agent.id,agent.name,rule.id,rule.level,rule.mitre.id,timestamp,@timestamp"

sudo curl --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert "$INDEXER_CA" --user admin \
  -H 'Content-Type: application/json' -X POST \
  --data-binary '{"size":0,"aggs":{"agent_ids":{"terms":{"field":"agent.id","size":20}},"agent_names":{"terms":{"field":"agent.name","size":20}}}}' \
  "$INDEXER_URL/wazuh-alerts-*/_search?filter_path=aggregations"
```

Inventory composable templates, legacy templates, aliases and ISM separately:

```bash
sudo curl --silent --show-error --fail-with-body \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_index_template?filter_path=index_templates.name,index_templates.index_template.index_patterns,index_templates.index_template.priority,index_templates.index_template.template.settings,index_templates.index_template.template.aliases"

sudo curl --silent --show-error --fail-with-body \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_template?filter_path=*.index_patterns,*.order,*.settings.index.plugins.index_state_management.policy_id,*.settings.index.opendistro.index_state_management.policy_id,*.aliases"

sudo curl --silent --show-error --fail-with-body \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_cat/aliases/wazuh-alerts-*?format=json&h=alias,index&s=alias,index"

sudo curl --silent --show-error --fail-with-body \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_plugins/_ism/policies?size=100&filter_path=policies._id,policies.policy.policy_id,policies.policy.description,policies.policy.ism_template,policies.policy.default_state,policies.policy.states.name,policies.policy.states.actions,policies.policy.states.transitions"
```

Confirm the canonical role, mapping and internal-user namespaces. Every result
must be 404 on a clean start:

```bash
for name in alertmind_socanalyst_ro alertmind_assistant_alerts_ro; do
  sudo curl --silent --show-error --cacert "$INDEXER_CA" --user admin \
    -o /dev/null -w "role $name: HTTP %{http_code}\n" \
    "$INDEXER_URL/_plugins/_security/api/roles/$name"
  sudo curl --silent --show-error --cacert "$INDEXER_CA" --user admin \
    -o /dev/null -w "mapping $name: HTTP %{http_code}\n" \
    "$INDEXER_URL/_plugins/_security/api/rolesmapping/$name"
done

for name in socanalyst assistant-svc; do
  sudo curl --silent --show-error --cacert "$INDEXER_CA" --user admin \
    -o /dev/null -w "internal user $name: HTTP %{http_code}\n" \
    "$INDEXER_URL/_plugins/_security/api/internalusers/$name"
done
```

Before any optional index-level DELETE denial test, record the effective
destructive-action setting. Do not run the test unless every returned value
resolves to `true`:

```bash
sudo curl --silent --show-error --fail-with-body \
  --cacert "$INDEXER_CA" --user admin \
  "$INDEXER_URL/_cluster/settings?include_defaults=true&filter_path=transient.action.destructive_requires_name,persistent.action.destructive_requires_name,defaults.action.destructive_requires_name"
```

The 2 September 2026 capture returned the effective default as `false`.
Accordingly, the optional index-level DELETE proof is prohibited in this lab.
Do not change this cluster safety setting merely to enable a test.

## 5. Lifecycle cross-check and prohibited probe

`POST /_index_template/_simulate_index/<name>` evaluates composable templates
only. It does not model legacy templates or ISM auto-attachment. In this lab it
returned `{}` for `wazuh-alerts-rbacprobe-000001` even though the live ISM
policy's `ism_template.index_patterns` is `wazuh-alerts-*` and would adopt that
index. Simulation alone is therefore an unsafe approval check.

The required three-part decision is:

1. inspect composable templates;
2. inspect legacy `_template` patterns and aliases; and
3. inspect every relevant ISM `ism_template.index_patterns` value and action.

The completed inventory found no safe disposable name inside the former
service-role namespace. Do not create `wazuh-alerts-rbacprobe-000001`, any
replacement alert probe, or a sentinel document. Phase 1 uses the fail-safe,
zero-state-change denial matrix in the implementation plan against existing
and guaranteed-nonexistent literal IDs.

## 6. Sanitized inventory record

| Field | Non-secret value |
|---|---|
| Snapshot name and time | `Snapshot 1`; powered off; 2026-09-01 19:41 IST (owner-reported) |
| SIEM host-only IPv4 | `enp0s8` — `192.168.56.102/24` |
| Windows host-only IPv4 | `Ethernet 2` — `192.168.56.1/24` |
| Indexer bind scope | `127.0.0.1:9200` only |
| SSH state | Inactive; no TCP 22 listener |
| Server API bind scope | TCP 55000 on all IPv4 and IPv6 interfaces |
| Dashboard bind scope | TCP 443 on all IPv4 interfaces |
| Agent state | `000 wazuh-siem` active/local; `001 win-victim` and `002 linux-victim` disconnected because endpoint VMs remained off |
| DLS allowlist | `agent.id` values `001`, `002`; ID `000` excluded |
| Agent value counts | `001=7,890`; `002=16,667`; `000=11,445`; ID 000 spans names `wazuh-siem=11,030` and `Ubuntu=415` |
| Enrollment fingerprints | `001 win-victim`: `ce6dbeeff3df5ffef33e643ea36b60ffaf4f9b73577bf8c68789c867d672a5b7`; `002 linux-victim`: `483a8b3caa8e9a252aa8ea632d7a5c1ab04358c170f314ec01f1d696dfffdebf` |
| Live Indexer version | `wazuh-indexer 4.14.7-1`; OpenSearch/OpenSearch Security `2.19.5`/`2.19.5.0` |
| Submitted-v1 version | Wazuh 4.14.5; preserved separately and not retro-edited |
| Node certificate | SAN `IP:127.0.0.1`; expires 2036-06-19; SHA-256 `BC:90:AA:A9:18:88:39:41:65:A3:3F:C8:BE:9F:C6:67:CA:6F:0A:08:F5:DE:20:2C:62:A0:E0:89:26:23:32:FB` |
| Public CA | Expires 2036-06-19; SHA-256 `EB:98:A4:AF:38:CD:A5:50:D4:73:E5:65:9A:43:75:90:53:34:04:1F:AB:45:97:F3:9C:4F:19:1D:9E:6F:5E:1D` |
| Validated TLS URL | VM-local `https://127.0.0.1:9200` passes with CA and hostname verification. Python 3.14 compatibility testing disabled `VERIFY_X509_STRICT` wholesale after the older CA's missing key-usage extension triggered rejection; `CERT_REQUIRED` and hostname verification remained enabled. Proposed Windows `https://127.0.0.1:19200` tunnel is not yet configured. |
| Alert indices | 25 open/green `wazuh-alerts-4.x-*` indices; 35,992 documents; no aliases |
| Cluster health | Yellow, one node, 132 active primaries; four unassigned replica shards belong to OpenDistro system indices |
| Relevant composable templates | None for `wazuh-alerts-*` |
| Relevant legacy template | `wazuh`: `wazuh-alerts-4.x-*`, `wazuh-archives-4.x-*` |
| Relevant ISM policy | `wazuh-alert-retention-policy`; auto-attach `wazuh-alerts-*`; retain 90 days then delete |
| Required DLS/query fields | Present with usable keyword/long/date mappings |
| Canonical roles/mappings (Phase 0 baseline) | Both planned role and mapping names returned 404 before creation |
| Planned internal users (Phase 0 baseline) | `socanalyst` and `assistant-svc` returned 404 before creation |
| Disposable alert probe | Prohibited: broad ISM auto-attachment makes the former candidate unsafe |
| Preferred transport | Reviewed design: host-only, key-restricted SSH local forward; not implemented |
| `action.destructive_requires_name` | Effective default `false`; optional index-level DELETE proof prohibited |

Phase 1B delta on 2 September 2026: sanitized pre-mapping authinfo exposed the
inherited wildcard `own_index` role, so work first stopped before project
mappings. After independent approval, the owner applied the scoped correction,
proved both users had no effective role, applied both direct-user mappings and
completed the Indexer allow/deny matrix. See the historical finding in
[`evidence/rbac/phase1b-inherited-access-check.md`](../../evidence/rbac/phase1b-inherited-access-check.md)
and the completed live result in
[`evidence/rbac/phase1b-indexer-enforcement-proof.md`](../../evidence/rbac/phase1b-indexer-enforcement-proof.md).

Unset the convenience variables when finished:

```bash
unset INDEXER_URL INDEXER_CA
```

## 7. Phase 0 exit gate

Phase 0 passes only when:

- the full automated regression and frozen-evidence checks pass on the branch;
- the Wazuh snapshot can be identified and restored;
- the sanitized inventory above is complete;
- enrollment fingerprints for IDs 001/002 are recorded without exposing keys;
- the restricted SSH tunnel design and fail-safe denial matrix are documented;
- no disposable alert/probe index or sentinel is created; and
- an independent reviewer approves the correction and owner-evidence commits.

If any condition fails, leave the offline profile unchanged and do not begin
RBAC or SSH configuration.

## 8. Phase 1 identity package and inherited-role gate — live Indexer gate complete

The normative files are:

- `siem/rbac/scope-contract.json`;
- `siem/rbac/indexer-role_socanalyst_ro.json`;
- `siem/rbac/indexer-role_assistant_alerts_ro.json`;
- `siem/rbac/indexer-role-mapping_socanalyst_ro.json`;
- `siem/rbac/indexer-role-mapping_assistant_alerts_ro.json`;
- `siem/rbac/indexer-role-mapping_own_index_scoped.patch.json`;
- `siem/rbac/indexer-role-mapping_own_index_rollback.patch.json`;
- `siem/rbac/SHA256SUMS`; and
- `siem/rbac/negative-test-matrix.md`.

The two role files and two project mapping files are exact OpenSearch Security
REST request bodies. The two `.patch.json` files are JSON Patch documents for
the existing editable `own_index` mapping. The scope contract pins all six
executable payloads to the approved inventory and distinguishes the normal
correction from the rollback-only wildcard restore.

Live work completed before the inherited-role correction:

- both enrollment fingerprints and all four original payload hashes matched;
- `alertmind_socanalyst_ro` and `alertmind_assistant_alerts_ro` were created
  and exactly read back;
- `socanalyst` and `assistant-svc` were created with owner-entered passwords;
  sanitized user readback showed no backend role, direct security role or
  attribute; and
- no AlertMind project mapping had yet been applied.

The pre-mapping authinfo check then showed `own_index` as the sole effective
role for both users. Its reserved/static role grants `cluster_composite_ops`
and `indices_all` on `${user_name}`; its editable mapping uses `users: ["*"]`.
Permissions are additive, so the planned narrower mappings would not remove
that write path. Security-plugin private-tenant metadata does not change this
conclusion; Wazuh Dashboard multitenancy is disabled in the live configuration.

### 8.1 Pre-apply invariant check

Immediately before any correction, stop unless all of the following remain
true:

1. the internal-user set is exactly `admin`, `anomalyadmin`, `assistant-svc`,
   `kibanaro`, `kibanaserver`, `logstash`, `readall`, `snapshotrestore` and
   `socanalyst`;
2. both new user records still have empty backend roles, direct security roles
   and attributes;
3. only basic internal HTTP authentication is enabled; all other HTTP authc
   and both LDAP authz domains remain disabled;
4. the complete `own_index` mapping has `users: ["*"]` and every other
   `own_index` selector is empty (`backend_roles`, `and_backend_roles`,
   `hosts`);
5. the `own_index` role definition is unchanged: `cluster_composite_ops`,
   `${user_name}`, `indices_all`, reserved/static; and
6. all six files in `siem/rbac/SHA256SUMS` match the reviewed bytes transferred
   to the VM.

Any mismatch invalidates the payload. Preserve sanitized output and return to
review; do not broaden a selector or edit the preserved-user list ad hoc.

### 8.2 Normal correction and effective-role gate

Apply the reviewed `own_index` mapping correction only after this commit is
approved. From the verified VM staging directory, use the JSON Patch endpoint
with certificate verification and an interactively entered admin password:

```bash
sudo curl --silent --show-error --fail-with-body \
  --connect-timeout 5 --max-time 30 \
  --cacert /etc/wazuh-indexer/certs/root-ca.pem --user admin \
  --header 'Content-Type: application/json' --request PATCH \
  --data-binary '@indexer-role-mapping_own_index_scoped.patch.json' \
  'https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/own_index'
```

Read back the complete mapping as administrator. Require the `users` selector
to equal, without duplicates, `admin`, `anomalyadmin`, `kibanaro`,
`kibanaserver`, `logstash`, `readall` and `snapshotrestore`; require the
wildcard and both new principals to be absent and every other selector empty.

Before project mappings, authenticate separately as `socanalyst` and
`assistant-svc`. Require the correct username, no backend/direct role,
`own_index` absent, no unexpected effective role and an empty effective-role
list. Private-tenant metadata may still appear, but it is not a role grant.
For each identity, issue only a read-only search against its username-named
index (`/socanalyst/_search` or `/assistant-svc/_search`) and require `403`.
Do not issue a write or create either index.

Apply the two AlertMind direct-user mappings only after every preceding check
passes. Read back each mapping, then repeat authinfo and username-index search:

- `socanalyst` must have only `alertmind_socanalyst_ro` at the Indexer stage;
- `assistant-svc` must have only `alertmind_assistant_alerts_ro`; and
- both username-named searches must still return `403`.

Only then proceed to transport and the fail-safe denial matrix. If a required
fixed client request later returns a missing-permission 403, stop and review
the exact action before editing the role. Do not add a wildcard action group or
broaden the index/DLS scope for convenience.

There is no password-bearing user template and no custom Wazuh Server role
payload. The human user is later mapped to Wazuh's built-in `readonly` Server
role after current Server role/mapping and Dashboard `run_as` state are read
back. Record that the Server role is broader than alert-only access.
`assistant-svc` receives no Server API identity or Dashboard tenant.

The Indexer DLS also filters the human dashboards to agent IDs 001/002. Any
evidence captured as `socanalyst` must be labelled **DLS-scoped**; its counts
will exclude the inventoried agent-000 documents and need not match admin
screenshots.

### 8.3 Executed Indexer enforcement result

The owner executed the approved sequence on 2 September 2026 and stopped
before transport:

- the live action-group expansion confirmed that `cluster_composite_ops`
  included `indices:data/write/bulk` and `indices:data/write/reindex`, while
  `indices_all` expanded to `indices:*`; this enumerates the prevented
  inherited write path without claiming that alert data was copied;
- the scoped patch left exactly the seven preserved users in the `own_index`
  mapping and left every alternate selector empty;
- before direct mapping, both new users had no effective role and their
  username-index searches returned `403`;
- after direct mapping, each user had only its intended AlertMind role and both
  username-index searches still returned `403`;
- `assistant-svc` could search/get one DLS-visible agent-002 alert, saw zero of
  the `11,816` current agent-000 documents visible to admin, and was denied
  cluster-health, Security-index and Dashboard-index reads; and
- both random IDs returned `404`, not `403`, in the same positively read
  concrete index before the write attempts, proving index read access and
  isolating the later action denials; fail-safe `_create`, non-upserting
  `_update` and DELETE attempts all returned `403`/`security_exception`, the
  original canonical source hash was unchanged and both random IDs remained
  absent.

No concrete `wazuh-archives-*` index existed. The archive wildcard's empty
`200` had zero shards and zero hits and is therefore vacuous, not evidence of
access. A literal archive-namespace control returned `403`; rerun against a
concrete archive index if one later exists. Do not create one for this test.

The Python 3.14 evidence harness disabled `VERIFY_X509_STRICT` wholesale after
the older Wazuh CA's missing key-usage extension triggered rejection. The flag
gates a broader bundle of strict RFC 5280 checks; this was not a targeted
key-usage exception. It retained the configured CA, `CERT_REQUIRED` and
hostname verification. The later client must preserve those properties and
prefer a reviewed certificate-chain replacement; unverified TLS remains
prohibited.

The complete sanitized result, identifiers and hashes are in
[`evidence/rbac/phase1b-indexer-enforcement-proof.md`](../../evidence/rbac/phase1b-indexer-enforcement-proof.md).

### 8.4 Rollback-only wildcard restore

The rollback patch is **Rollback-only** and is unsafe while either new
identity can authenticate. Before restoring `users: ["*"]`:

1. remove both AlertMind project mappings;
2. revoke or delete `socanalyst` and `assistant-svc`;
3. prove both credentials fail authentication; and
4. obtain separate approval for the wildcard restore.

Only after all four conditions may the rollback patch be applied and read back.
Restoring the wildcard first recreates the inherited write grant and is a
security regression, not a rollback.

## 9. Approved Phase 1 transport constraints — not yet executed

The preferred transport keeps Indexer on VM loopback and forwards Windows
`127.0.0.1:19200` over SSH on the host-only adapter to VM
`127.0.0.1:9200`. Before enabling SSH, capture and review the effective
configuration. The dedicated public-key line must include:

```text
restrict,port-forwarding,permitopen="127.0.0.1:9200",command="/bin/false"
```

`restrict` disables forwarding as well as PTY, agent/X11 forwarding and
`~/.ssh/rc`; the explicit `port-forwarding` option re-enables TCP forwarding
generally, and `permitopen` limits only local (`-L`) forwarding to Indexer
loopback. `PermitOpen` neither disables remote (`-R`) forwarding nor blocks a
shell. Therefore the server configuration must also include:

```text
Match User notroot
    AllowTcpForwarding local
```

The `Match` directive denies remote forwarding for this account, while the
key-level `restrict`, `permitopen` and forced command deny the remaining
facilities and shell access. Before enabling the service, evaluate the
connection-specific configuration and a different-user control:

```bash
sudo sshd -T -C user=notroot,host=wazuh-siem,addr=192.168.56.1,laddr=192.168.56.102,lport=22 \
  | grep '^allowtcpforwarding '
sudo sshd -T -C user=root,host=wazuh-siem,addr=192.168.56.1,laddr=192.168.56.102,lport=22 \
  | grep '^allowtcpforwarding '
```

The first result must be `allowtcpforwarding local`. The second must reflect
the global/different-user value and must not become `local` merely because of
the `Match User notroot` block. Record both outputs as scope evidence. Do not
substitute a plain `sshd -T`: without `-C` connection parameters it does not
evaluate the `Match` rule.

The corresponding private key is the fifth analyst-profile secret. Store it
only under ignored `assistant/.secrets/`, protect it with a Windows ACL, and
include it in generation, rotation, revocation and rollback records. The key
must not open an interactive shell, request a PTY, use agent/X11 forwarding,
enable gateway ports or reach any destination other than `127.0.0.1:9200`.
Do not enable SSH until the Phase 1 transport configuration and rollback
commands receive their own independent approval.
