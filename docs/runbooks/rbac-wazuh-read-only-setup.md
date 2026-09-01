# Runbook — RBAC and read-only Wazuh integration

**Status:** Phase 0 inventory only; no Wazuh, network, identity-provider or
application configuration has been changed.

**Applies to:** the post-v1 local-first analyst profile described in
[`docs/rbac-wazuh-read-only-implementation-plan.md`](../rbac-wazuh-read-only-implementation-plan.md).

**Safety boundary:** Phase 0 is read-only. Do not create users, roles, mappings,
indices, templates, policies, firewall rules or certificates while following
this section.

---

## 1. Phase 0 checkpoint

| Item | Status | Evidence / note |
|---|---|---|
| Submitted v1 preserved | Complete | Existing `v1.0` tag remains immutable. |
| Fresh implementation branch | Complete | `feat/rbac-wazuh-phase0`, created from merged `main`. |
| Pre-feature regression baseline | Complete | 78 assistant tests and frozen-evidence verifier passed before planning. |
| Paste/provider characterization | Complete | Eight additive tests lock the offline UI and guarded Paste/provider behavior. |
| Recoverable Wazuh snapshot | Owner reported complete | Snapshot was taken while the VM was powered off; record its local name/time below. |
| Wazuh recovery gate | Owner reported complete | Manager, Indexer, Filebeat and Dashboard returned `active` on 1 September 2026. |
| Read-only Wazuh inventory | Pending | Follow Sections 2–5; sanitize the returned text before review. |
| Secrets in Git | Prohibited | The local secret, certificate-copy, runtime database and Keycloak-data paths are ignored. |

Snapshot identifier: `<record locally; no credentials>`

Snapshot UTC/local time: `<pending>`

Phase 1 must not start until the inventory is reviewed and the snapshot
identifier is recorded.

## 2. Rules for collecting inventory

- Run these commands on `wazuh-siem`; keep the VM on until collection is done.
- Every command below is observational. The two HTTP `POST` calls are search or
  template simulation operations and do not create or update state.
- Never paste a password, private key, bearer token, authorization header or
  unredacted alert into chat, a worksheet or Git.
- Use `curl --user admin` without a password in the command. Curl prompts for
  the password interactively, keeping it out of shell history.
- Never point `openssl x509` at a file whose name contains `key`.
- Do not add `-k`/`--insecure` to work around certificate validation. A failure
  to validate the current certificate is itself an inventory finding.
- Stop if any command would mutate state or if its output unexpectedly contains
  credentials or raw alert bodies.

## 3. Host, service and certificate inventory

These commands do not require an Indexer password:

```bash
hostnamectl --static
ip -brief -4 address
sudo systemctl is-active wazuh-manager wazuh-indexer filebeat wazuh-dashboard
sudo ss -ltnp | grep -E ':(443|9200|55000|1514|1515)\b'
sudo /var/ossec/bin/agent_control -l
sudo find /etc/wazuh-indexer/certs -maxdepth 1 -type f ! -iname '*key*' -printf '%f\n'
```

Inspect the public Indexer node certificate selected from the final command.
Replace the placeholder with that public certificate path; do not select a
private-key file.

```bash
sudo openssl x509 -in <INDEXER_PUBLIC_CERT_PATH> -noout \
  -subject -issuer -serial -dates -fingerprint -sha256 -ext subjectAltName
```

Record only:

- the host-only IPv4 address and interface;
- which ports are bound to loopback, host-only or all interfaces;
- agent IDs/names and active/disconnected state;
- certificate subject, issuer, validity dates, SHA-256 fingerprint and SANs;
- whether a SAN name/IP is reachable from the planned Windows assistant host.

## 4. Read-only Indexer inventory

Choose an Indexer URL whose host exactly matches a certificate SAN and the
public root CA path. If no current URL validates, record that fact and stop this
section rather than disabling verification.

```bash
export INDEXER_URL='https://<SAN-NAME-OR-IP>:9200'
export INDEXER_CA='/etc/wazuh-indexer/certs/root-ca.pem'

curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin "$INDEXER_URL/"

curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin \
  "$INDEXER_URL/_cluster/health?filter_path=cluster_name,status,number_of_nodes,active_primary_shards"

curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin \
  "$INDEXER_URL/_cat/indices/wazuh-alerts-*?format=json&h=index,health,status,docs.count,store.size&s=index"

curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin \
  "$INDEXER_URL/wazuh-alerts-*/_field_caps?fields=agent.id,agent.name,rule.id,rule.level,rule.mitre.id,timestamp,@timestamp"

curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin \
  "$INDEXER_URL/_index_template?filter_path=index_templates.name,index_templates.index_template.index_patterns,index_templates.index_template.priority"

curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin \
  "$INDEXER_URL/_template?filter_path=*.index_patterns,*.order"

curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin "$INDEXER_URL/_plugins/_ism/policies?size=100"
```

The final response may be long. Retain only policy IDs, index patterns,
priorities and retention/rollover action summaries in the sanitized inventory.

Confirm the two planned roles and mappings do not already exist. `404` is the
expected clean-start result:

```bash
for name in socanalyst_ro assistant_alerts_ro; do
  curl --silent --show-error --cacert "$INDEXER_CA" --user admin \
    -o /dev/null -w "role $name: HTTP %{http_code}\n" \
    "$INDEXER_URL/_plugins/_security/api/roles/$name"
  curl --silent --show-error --cacert "$INDEXER_CA" --user admin \
    -o /dev/null -w "mapping $name: HTTP %{http_code}\n" \
    "$INDEXER_URL/_plugins/_security/api/rolesmapping/$name"
done
```

## 5. Candidate probe pre-check

This simulation is read-only: it asks which composable template would match
the proposed disposable index name without creating the index.

```bash
curl --silent --show-error --fail-with-body --cacert "$INDEXER_CA" \
  --user admin -X POST \
  "$INDEXER_URL/_index_template/_simulate_index/wazuh-alerts-rbacprobe-000001"
```

Compare the simulated match with the legacy-template and ISM patterns from
Section 4. Do not approve that probe name if any Wazuh/Filebeat ingestion,
rollover, retention or dashboard-evidence policy would attach to it.

## 6. Sanitized inventory record

Return or record only this summary:

| Field | Non-secret value |
|---|---|
| Snapshot name and time | `<pending>` |
| Wazuh host-only IPv4 | `<pending>` |
| Indexer bind scope | `<pending>` |
| Server API bind scope | `<pending>` |
| Dashboard bind scope | `<pending>` |
| Active agent IDs/names | `<pending>` |
| Indexer version | `<pending>` |
| Public certificate SANs and expiry | `<pending>` |
| Validated TLS URL from assistant host | `<pending>` |
| Existing alert index patterns | `<pending>` |
| Relevant composable templates | `<pending>` |
| Relevant legacy templates | `<pending>` |
| Relevant ISM patterns/actions | `<pending>` |
| Required alert/DLS fields present | `<pending>` |
| Planned role/mapping name conflicts | `<pending>` |
| Candidate probe template match | `<pending>` |
| Candidate probe ISM match | `<pending>` |

Unset the convenience variables when finished:

```bash
unset INDEXER_URL INDEXER_CA
```

## 7. Phase 0 exit gate

Phase 0 passes only when:

- the full automated regression and frozen-evidence checks pass on the branch;
- the Wazuh snapshot can be identified and restored;
- the non-secret inventory above is complete;
- the Indexer exposure/TLS path has a feasible host-only design;
- an isolated probe name can be selected without lifecycle or ingestion side
  effects; and
- an independent reviewer approves the Phase 0 commit and inventory decision.

If any condition fails, leave the offline profile unchanged and do not begin
RBAC configuration.
