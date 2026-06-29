# Rebuild Guide — AlertMind

**Purpose:** let a reviewer reproduce the AlertMind mini-SOC from this repository and reach a verified, alert-firing state **in under an hour, without troubleshooting** — the project's reproducibility criterion. Every step ends with a check; if a check fails, the fix is in §9 or the recovery runbook.

> **Read this first — two rebuild paths.** The Windows endpoint runs **Sysmon, a Windows kernel driver that cannot run in a Linux container**, so the lab cannot be fully containerised. Therefore:
>
> - **Path A — Full lab (authoritative):** VirtualBox, from the provided **OVA exports** (fast) or from the manual steps below (from scratch). Covers all four roles including Windows/Sysmon. *This is the path graded against.*
> - **Path B — Containerised subset (convenience, planned):** a `docker-compose` bringing up the Wazuh manager + Linux victim + cloud-sample ingestion. Faster for a reviewer who only needs to see ingestion and the Linux detection pack; it does **not** include the Windows endpoint. Status: planned (`docker/` directory).
>
> Use Path A for a complete grade-ready rebuild; Path B is a quick way to see the Linux pipeline.

## Time budget (Path A, importing the provided OVAs)

| Step | Task | Time |
|---|---|---|
| 1 | Host requirements check | 2 min |
| 2 | Import + start VMs (OVAs) | 15 min |
| 3 | Network setup (NAT Network + Host-Only) | 5 min |
| 4 | Wazuh services up + dashboard reachable | 5 min |
| 5 | Confirm agents onboarded | 5 min |
| 6 | Confirm/deploy rules | 5 min |
| 7 | Run verification commands | 8 min |
| 8 | Review expected output vs. evidence | 5 min |
| | **Total** | **~50 min** |

*From bare-OS installs (no OVAs) this exceeds an hour, mostly OS + Wazuh install time; the OVA import path is the intended <1 hr route.*

> **Note on the Windows endpoint.** The <1 hr target assumes the evaluator uses the provided Linux/Kali OVAs **and** either already has a Windows 11 evaluation VM ready or validates the Windows path from the documented evidence (§8). A fully fresh Windows installation from Microsoft evaluation media will exceed the one-hour target.

## Rebuild success criteria

The rebuild is successful when **all** of these hold:

- Wazuh dashboard login works.
- Ports 1514, 1515, 55000, 9200, 443 are listening.
- `win-victim` and `linux-victim` show **Active** in Wazuh.
- A Windows service-creation test produces **rule 61138 / T1543.003**.
- A Linux `/etc/shadow` access test produces **rule 100100 / T1003.008**.
- Evidence IDs EVID-WAZUH-001, EVID-WIN-001, EVID-WIN-002, EVID-LIN-001, EVID-LIN-002, EVID-RULES-001 are reproducible (§8).

## Artifacts & credentials (read before Step 2)

**OVA files are not in Git** (large, and the Windows image carries a licensed OS). Two supported ways to obtain a runnable lab:

1. **Recommended — minimise binaries.** Rebuild the Linux side (`wazuh-siem`, `linux-victim`, `attacker`) from this repo's documented steps (or the planned `docker/` subset), and build `win-victim` from a **free Microsoft Windows 11 Enterprise Evaluation VM** (90-day, no licensing concern) following §5. Nothing large needs hosting.
2. **Convenience — provided OVAs.** Hosted out-of-band (e.g. a private Google Drive folder shared with the program team), with links + checksums recorded in [`docs/artifacts.md`](artifacts.md). On import, choose **"Keep all MAC addresses"** to preserve the documented DHCP IPs; if MACs are regenerated, re-check the manager IP and update each agent's manager address.

Add to `.gitignore`: `*.ova`, `*.ovf`, `*.vdi`, `*.vbox-prev`, `*wazuh-passwords.txt`, `wazuh-install-files.tar`.

**Credentials.** No password is stored in Git. The cleanest path for an evaluator is to **reset the admin password to your own value on first use** — see [`docs/runbooks/wazuh-password-reset.md`](runbooks/wazuh-password-reset.md). (If a working password is provided instead, it is shared out-of-band in the submission notes, never committed.)

---

## 1. Host requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Hypervisor | VirtualBox 7.x | OVAs exported from 7.x |
| Host RAM | 16 GB (32 GB comfortable) | All VMs at once ≈ 16 GB of VM RAM; stagger on 16 GB hosts |
| Host disk | ~80 GB free | Four VMs + snapshots |
| Host OS | Any VirtualBox-supported | Build was on Windows 11 (hypervisor only — never a monitored endpoint) |

**Check:** VirtualBox installed (`VBoxManage --version`), ≥16 GB RAM, ≥80 GB free.

## 2. VM requirements

Four roles. Import the matching OVA for each (or build from scratch per the linked architecture doc).

| Role | VM | OS | RAM | OVA |
|---|---|---|---|---|
| SIEM host | `wazuh-siem` | Ubuntu 24.04.4 LTS | 6–8 GB | `wazuh-siem.ova` |
| Windows endpoint | `win-victim` | Windows 11 | 4–6 GB | Not shipped; build from MS Win11 Eval VM (§5) |
| Linux endpoint | `linux-victim` | Ubuntu 24.04.4 LTS | 2 GB | `linux-victim.ova` |
| Attacker | `attacker` | Kali | 2–4 GB | `attacker.ova` |

**Stagger on a 16 GB host:** bring up `wazuh-siem` + one endpoint at a time. **Snapshot** each VM after a clean start.

**Check:** all four VMs import without error and boot to a login.

## 3. Network setup

All VMs share one VirtualBox **NAT Network** named `LabNet` (`10.0.2.0/24`) for inter-VM traffic + internet, isolated from the physical LAN. The SIEM host has a **second Host-Only adapter** for dashboard access from the host browser.

1. VirtualBox → **Tools → Network → NAT Networks** → create `LabNet`, CIDR `10.0.2.0/24`, DHCP on.
2. Each VM → **Settings → Network → Adapter 1** → *NAT Network* → `LabNet`.
3. `wazuh-siem` only → **Adapter 2** → *Host-Only Adapter* (`vboxnet0`).

**Check (from any endpoint VM):** `ping 10.0.2.15` (the manager) succeeds.
Expected IPs: manager `10.0.2.15`, `win-victim` `10.0.2.4`, `linux-victim` `10.0.2.7` (DHCP may differ; adjust agent configs to match the manager IP).

## 4. Wazuh install

If using the `wazuh-siem` OVA, Wazuh 4.14.5 is already installed — skip to the check. From scratch:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

The installer prints the dashboard URL and `admin` credentials (also in `wazuh-install-files.tar` → `wazuh-passwords.txt`; **never committed**). If you imported the OVA and don't have the password, reset it to your own value — see [`docs/runbooks/wazuh-password-reset.md`](runbooks/wazuh-password-reset.md).

**Check:**
```bash
sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard --no-pager | grep Active
sudo ss -tlnp | grep -E ':(1514|1515|55000|9200|443)'
```
Open `https://<wazuh-siem Host-Only IP>` and log in. → **EVID-WAZUH-001**

## 5. Agent onboarding

The Linux agent is pre-configured in the provided OVA; the Windows agent is configured if using a prepared internal VM, otherwise follow the fresh Windows eval VM steps below. Confirm they report **Active**. From scratch, deploy via the dashboard's *Agents → Deploy new agent* wizard (pointed at `10.0.2.15`), then apply the config blocks below.

**Windows (`win-victim`)** — Sysmon + the three channels. Add to `C:\Program Files (x86)\ossec-agent\ossec.conf`:
```xml
<localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>
<localfile><location>System</location><log_format>eventchannel</log_format></localfile>
<localfile><location>Security</location><log_format>eventchannel</log_format></localfile>
```
Sysmon is installed with the repo's `siem/wazuh/sysmonconfig.xml` (the SwiftOnSecurity config with the EID 10 / LSASS include populated). Then `Restart-Service WazuhSvc`.

**Linux (`linux-victim`)** — auditd ingestion. Add to `/var/ossec/etc/ossec.conf`:
```xml
<localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
```
Then `sudo systemctl restart wazuh-agent`.

**Fresh Windows eval VM (`win-victim` from scratch).** Since the Windows VM is not shipped, build it from a Microsoft Windows 11 Enterprise Evaluation VM:
1. Rename the host to `win-victim`.
2. Attach Adapter 1 to the `LabNet` NAT Network.
3. Install Sysmon with the repo's `siem/wazuh/sysmonconfig.xml` (`Sysmon64.exe -accepteula -i sysmonconfig.xml`).
4. Deploy the Wazuh agent pointed at manager `10.0.2.15`, agent name `win-victim`.
5. Add the three `<localfile>` channel blocks above to the agent `ossec.conf`.
6. `Restart-Service WazuhSvc`.

**Check:**
```bash
sudo /var/ossec/bin/agent_control -l     # expect 001 win-victim + 002 linux-victim → Active
```
Trigger telemetry: `whoami` on Windows (→ **EVID-WIN-001**); on Linux, a self-cleaning user-creation test (→ **EVID-LIN-001**):
```bash
TESTUSER="alertmindtest$(date +%s)"
sudo useradd "$TESTUSER"        # → user-creation alert (rule 5902 / T1136)
sudo userdel -r "$TESTUSER" 2>/dev/null || sudo userdel "$TESTUSER"   # cleanup
```

## 6. Rule deployment

**auditd ruleset (`linux-victim`):**
```bash
sudo cp detections/auditd/alertmind.rules /etc/audit/rules.d/alertmind.rules
sudo augenrules --load
sudo auditctl -l          # rules listed, no errors
```

**Wazuh detection rules (`wazuh-siem` / manager):**
```bash
xmllint --noout siem/wazuh/local_rules.xml                       # must pass
sudo cp siem/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo tail -50 /var/ossec/logs/ossec.log                          # no rule/XML errors
```
→ **EVID-RULES-001**

## 7. Verification commands

The rebuild is done only when these pass.

```bash
# Service + port health (wazuh-siem)
sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard --no-pager | grep Active
sudo ss -tlnp | grep -E ':(1514|1515|55000|9200|443)'

# Indexer health (yellow is normal for single-node)
curl -sk -u admin:<ADMIN_PASSWORD> "https://localhost:9200/_cluster/health?pretty" | grep status

# Agents active
sudo /var/ossec/bin/agent_control -l
```

**End-to-end detection — the key proof.** Both tests clean up after themselves.

On `win-victim` (PowerShell, elevated):
```powershell
sc.exe create AlertMind7045Test binPath= "C:\Windows\System32\cmd.exe /c timeout /t 60" start= demand
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 3 |
  Select-Object TimeCreated, ProviderName, Id, Message
sc.exe delete AlertMind7045Test          # cleanup
# → dashboard: rule.id:61138 (T1543.003)  → EVID-WIN-002
```

On `linux-victim`:
```bash
sudo cat /etc/shadow                      # read leaves no residue
# → dashboard: rule.id:100100 (T1003.008, level 12)  → EVID-LIN-002
```

Validate a rule offline without re-attacking:
```bash
sudo /var/ossec/bin/wazuh-logtest    # paste a real SYSCALL+PATH block; confirm 100100 fires
```

## 8. Expected output / screenshots

Each verified state maps to a captured artifact in `evidence/week1/` (same IDs used in the README and report).

| Step | Expected result | Evidence ID |
|---|---|---|
| 4 | Four services `active`; ports 1514/1515/55000/9200/443 listening; dashboard login | EVID-WAZUH-001 |
| 5 | `whoami` → Sysmon EID 1 alert in Wazuh | EVID-WIN-001 |
| 5 | `useradd` → user-creation alert (T1136) | EVID-LIN-001 |
| 6 | `local_rules.xml` validates + manager loads it cleanly | EVID-RULES-001 |
| 7 | `sc create` → rule 61138, T1543.003 | EVID-WIN-002 |
| 7 | `cat /etc/shadow` → rule 100100, T1003.008, level 12 | EVID-LIN-002 |

If your run matches these six, the lab is reproduced correctly.

## 9. Known issues & gotchas (read before troubleshooting)

These are the exact friction points found during the original build — pre-empting them is the difference between a clean rebuild and an hour of debugging.

| Symptom | Cause | Fix |
|---|---|---|
| auditd events don't reach Wazuh; only journald-style alerts appear | Agent has no `audit` `localfile` block | Add the block in §5; restart agent. Confirm `decoder.name:auditd`, `location:/var/log/audit/audit.log` |
| auditd events decode but never alert | Custom keys hit base rule 80700 (level 0) only | The child rules in `local_rules.xml` (100100–100115) raise the level; ensure the file deployed and the manager restarted |
| No LSASS / credential-access alerts | SwiftOnSecurity Sysmon `ProcessAccess` (EID 10) is an empty `include` by default | Use the repo's `sysmonconfig.xml` (EID 10 include populated for `lsass.exe`); reload with `Sysmon64.exe -c` |
| Service-creation (T1543.003) not firing | System/Security channels not forwarded | Ensure both `<localfile>` channel blocks in §5. Note: System **EID 7045** is emitted by Service Control Manager and needs no audit policy; Security **EID 4697** requires the "Audit Security System Extension" policy enabled via `auditpol` |
| auditd `No buffer space available` | Over-heavy ruleset | Use the lean `alertmind.rules` (already scoped); raise `-b` if it recurs |
| Dashboard not reachable from host | Missing Host-Only adapter | Add Adapter 2 (Host-Only) to `wazuh-siem` (§3). Note it binds `0.0.0.0:443` by default |
| Agents `Disconnected` though VMs up | Clock skew breaks TLS, or manager not fully up | `timedatectl` to fix time; confirm 1514/1515 listening; restart agent |
| Rule file won't load | `--` (double hyphen) inside an XML comment | Run `xmllint --noout` before deploy; keep XML comments hyphen-free |

## 10. If a service won't start

For an unclean shutdown, host crash, or a Wazuh service stuck in `failed`/`activating`, follow the ordered recovery procedure — **do not** restart services ad hoc (the components have a strict startup dependency): see [`docs/runbooks/wazuh-recovery.md`](runbooks/wazuh-recovery.md).

---

## Appendix — repo file → deploy location

| Repo path | Deploys to | On |
|---|---|---|
| `detections/auditd/alertmind.rules` | `/etc/audit/rules.d/alertmind.rules` | `linux-victim` |
| `siem/wazuh/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | `wazuh-siem` (manager) |
| `siem/wazuh/sysmonconfig.xml` | Sysmon config (`Sysmon64.exe -c`) | `win-victim` |
| `siem/wazuh/*ossec.conf` snippets | agent `ossec.conf` `<localfile>` blocks | each endpoint |

*Replace `<ADMIN_PASSWORD>` with the value from `wazuh-passwords.txt`. Never commit it.*
