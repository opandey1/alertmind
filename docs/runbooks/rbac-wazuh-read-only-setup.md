# Runbook — RBAC and read-only Wazuh integration

**Status:** Phase 0 characterization and owner-supplied live inventory are
complete. Review corrections are in progress; no Wazuh, SSH, network,
identity-provider or application configuration has been changed.

**Applies to:** the post-v1 local-first analyst profile described in
[`docs/rbac-wazuh-read-only-implementation-plan.md`](../rbac-wazuh-read-only-implementation-plan.md).

**Safety boundary:** Phase 0 is read-only. Do not create users, roles, mappings,
indices, documents, templates, policies, firewall rules, SSH listeners or
certificates while following this section.

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
| Agent enrollment fingerprints | Pending owner capture | Record only SHA-256 digests for IDs 001/002 before role creation. |
| Corrected Phase 0 documents | Awaiting review | The unsafe disposable probe has been removed. |
| Secrets in Git | Prohibited | Local secrets, certificate copies, runtime state and Keycloak data paths are ignored. |

Phase 1 must not start until the enrollment fingerprints are recorded and the
correction commit receives independent approval.

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
| Enrollment fingerprints | `<pending owner capture before role creation>` |
| Live Indexer version | `wazuh-indexer 4.14.7-1`; OpenSearch/OpenSearch Security `2.19.5`/`2.19.5.0` |
| Submitted-v1 version | Wazuh 4.14.5; preserved separately and not retro-edited |
| Node certificate | SAN `IP:127.0.0.1`; expires 2036-06-19; SHA-256 `BC:90:AA:A9:18:88:39:41:65:A3:3F:C8:BE:9F:C6:67:CA:6F:0A:08:F5:DE:20:2C:62:A0:E0:89:26:23:32:FB` |
| Public CA | Expires 2036-06-19; SHA-256 `EB:98:A4:AF:38:CD:A5:50:D4:73:E5:65:9A:43:75:90:53:34:04:1F:AB:45:97:F3:9C:4F:19:1D:9E:6F:5E:1D` |
| Validated TLS URL | VM-local `https://127.0.0.1:9200` passes; proposed Windows `https://127.0.0.1:19200` tunnel is not yet configured |
| Alert indices | 25 open/green `wazuh-alerts-4.x-*` indices; 35,992 documents; no aliases |
| Cluster health | Yellow, one node, 132 active primaries; four unassigned replica shards belong to OpenDistro system indices |
| Relevant composable templates | None for `wazuh-alerts-*` |
| Relevant legacy template | `wazuh`: `wazuh-alerts-4.x-*`, `wazuh-archives-4.x-*` |
| Relevant ISM policy | `wazuh-alert-retention-policy`; auto-attach `wazuh-alerts-*`; retain 90 days then delete |
| Required DLS/query fields | Present with usable keyword/long/date mappings |
| Canonical roles/mappings | Both planned role and mapping names return 404 |
| Planned internal users | `socanalyst` and `assistant-svc` return 404 |
| Disposable alert probe | Prohibited: broad ISM auto-attachment makes the former candidate unsafe |
| Preferred transport | Reviewed design: host-only, key-restricted SSH local forward; not implemented |
| `action.destructive_requires_name` | `<pending before optional index-level DELETE proof>` |

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
- an independent reviewer approves the correction commit.

If any condition fails, leave the offline profile unchanged and do not begin
RBAC or SSH configuration.

## 8. Approved Phase 1 transport constraints — not yet executed

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
Do not enable SSH until the correction commit is approved.
