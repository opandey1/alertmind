# Runbook — Wazuh all-in-one recovery

**Applies to:** `wazuh-siem` (Wazuh 4.14.5 all-in-one: indexer + manager + dashboard + Filebeat on one Ubuntu host)
**Purpose:** bring the stack back to a healthy, verified state after an unclean shutdown, host crash, or a service that won't start.

> **Why this exists.** During the Week-1 build the Windows host crashed with `CLOCK_WATCHDOG_TIMEOUT (0x101)` while the SIEM VM was running. The VM came back but the Wazuh services were in a failed/half-started state. This is the repeatable procedure that recovered them; follow it in order rather than restarting services ad hoc, because the three components have a strict startup dependency (indexer → manager → Filebeat → dashboard).

---

## 1. When to use this

Any of:
- Dashboard returns `502/503`, "Server is not ready yet", or won't load after a reboot.
- `systemctl status wazuh-indexer | wazuh-manager | wazuh-dashboard` shows `failed` or `activating`.
- Agents show **Disconnected** in the dashboard but the endpoints are up.
- The VM was force-stopped, snapshotted-while-running, or the host crashed.

## 2. Pre-flight checks (30 seconds, do these first)

A surprising number of "Wazuh is down" cases are actually disk or memory exhaustion — check before restarting anything.

```bash
df -h /var                # indexer refuses to start / goes read-only when disk is low
free -h                   # indexer JVM needs headroom; OOM-kill leaves it failed
date                      # clock skew breaks agent TLS + indexer security
```

If `/var` is above ~85%, free space first (old archives/logs) — restarting into a full disk just fails again.

## 3. Recovery procedure

### Step 1 — Stop everything in reverse dependency order
```bash
sudo systemctl stop wazuh-dashboard
sudo systemctl stop filebeat
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
```

### Step 2 — Clear any stragglers and failed states
```bash
# confirm nothing is still holding the ports / running
sudo ss -tlnp | grep -E ':(9200|1514|1515|55000|443)'
ps -ef | grep -E 'wazuh|opensearch|filebeat' | grep -v grep

# if a lingering indexer/JVM remains after stop, end it, then:
sudo systemctl reset-failed wazuh-indexer wazuh-manager filebeat wazuh-dashboard
```

### Step 3 — Start the indexer first, and WAIT for it to be healthy
The manager's Filebeat and the dashboard both depend on the indexer being up. Starting them too early is the most common cause of a recovery that "half works".
```bash
sudo systemctl start wazuh-indexer
sleep 30

# health must return before continuing (single-node "yellow" is normal — no replicas)
curl -sk -u admin:<ADMIN_PASSWORD> "https://localhost:9200/_cluster/health?pretty"
# look for: "status" : "green"  or  "yellow"
```
If health does not respond, do **not** proceed — see Troubleshooting §5.

### Step 4 — Start the manager, then Filebeat
```bash
sudo systemctl start wazuh-manager
sleep 15
sudo systemctl start filebeat

# verify Filebeat can reach the indexer
sudo filebeat test output
# expect: connection ... OK  and  talk to server ... OK
```

### Step 5 — Start the dashboard last
```bash
sudo systemctl start wazuh-dashboard
sleep 20
```

## 4. Verification (the recovery isn't done until all of these pass)

```bash
# 1. all four services active
sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard --no-pager | grep -E 'Active:'

# 2. all key ports listening
sudo ss -tlnp | grep -E ':(1514|1515|55000|9200|443)'

# 3. indexer cluster healthy
curl -sk -u admin:<ADMIN_PASSWORD> "https://localhost:9200/_cluster/health?pretty" | grep status

# 4. agents reconnect (give them a minute)
sudo /var/ossec/bin/agent_control -l
# expect 001 win-victim and 002 linux-victim → Active

# 5. fresh alerts flowing — trigger one and confirm it lands
#    e.g. on linux-victim:  sudo cat /etc/shadow   → search rule.id:100100 in dashboard
```

Reach the dashboard at `https://<host-only-IP>` and confirm login + recent events.

## 5. Troubleshooting common failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Indexer won't start; log shows disk watermark | `/var` low; indexer set indices read-only | Free space, then clear the block: `curl -sk -u admin:<pw> -XPUT "https://localhost:9200/_all/_settings" -H 'Content-Type: application/json' -d '{"index.blocks.read_only_allow_delete":null}'` |
| Indexer `failed`, OOM in `journalctl -u wazuh-indexer` | JVM heap vs. VM RAM | Give the VM more RAM, or lower heap in `/etc/wazuh-indexer/jvm.options` |
| Dashboard 503 / "not ready" | Started before indexer was healthy | Stop dashboard, confirm indexer health (Step 3), start dashboard again |
| `filebeat test output` fails | Indexer down or cert/credential mismatch | Confirm indexer health first; re-check `/etc/filebeat/filebeat.yml` output block |
| Agents stay Disconnected | Clock skew or manager not fully up | Fix time (`timedatectl`), confirm 1514/1515 listening, restart agent on the endpoint |
| Everything "active" but no new alerts | Filebeat not running / manager not writing | Confirm `filebeat` active and `/var/ossec/logs/alerts/alerts.json` is growing |

## 6. Post-recovery checklist

- [ ] All four services `active (running)`.
- [ ] Ports 1514/1515/55000/9200/443 listening.
- [ ] Indexer health green/yellow.
- [ ] Both agents Active.
- [ ] A test alert fired and is visible in the dashboard.
- [ ] **Take a fresh snapshot** of `wazuh-siem` now that it's healthy, so the next recovery starts from a known-good point.

## 7. Notes

- Replace `<ADMIN_PASSWORD>` with the generated admin password (from `wazuh-install-files.tar` → `wazuh-passwords.txt`). Never commit it.
- Prevention: snapshot the SIEM VM while it is **shut down** (not running) for the cleanest restore point, and shut VMs down gracefully rather than force-stopping the host.
- This is single-node behaviour; the `yellow` cluster status is expected and not an error.
