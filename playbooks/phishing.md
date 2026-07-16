# IR Playbook — Phishing

**Framework:** NIST SP 800-61 incident-response lifecycle (Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity).
**Scope:** email-borne phishing that delivers a malicious attachment or link leading to code execution on a workstation. Business email compromise and pure credential-harvesting pages are handled by *account-compromise.md* once credentials are confirmed used.
**Primary AlertMind detections:** `100200` (Office app spawns a shell — T1566/T1059), `100201` (encoded PowerShell — T1059.001), `100202` (LOLBin execution — T1218), and, on payload callback, `100206` (DNS tunnelling/C2 — T1048/T1071.004).

## Roles

| Role | Responsibility in this playbook |
|---|---|
| **Tier-1 analyst** | First triage of the alert or user report; validate, classify severity, execute short-term containment, escalate. |
| **Tier-2 / IR lead** | Deep analysis, host isolation decision, eradication, recovery sign-off. |
| **SOC manager** | Business communication, decision on user notification, post-incident review owner. |
| **System/asset owner** | Approves isolation/reimage of the affected endpoint. |

---

## Phase 1 — Preparation

- User-reportable phishing button / mailbox is live; users know to report rather than delete.
- Wazuh detections `100200–100202` and `100206` deployed and verified on `win-victim`; Sysmon EID 1 + DNS (EID 22) flowing.
- Endpoint isolation method agreed (host-only network detach / disable NIC / EDR isolate).
- Contact list current (mail admin, asset owner, comms).
- Known-good baselines and clean VM snapshots available for rebuild.

## Phase 2 — Detection & Analysis *(Tier-1)*

1. **Entry points:** a user report, or an AlertMind alert firing (`100200/100201/100202`) indicating a document or LOLBin spawned execution.
2. **Validate the alert** in the Daily SOC Briefing / Discover:
   - `agent.name:"<host>" AND rule.id:(100200 OR 100201 OR 100202)`
   - Confirm the parent→child chain (e.g. `winword.exe → cmd.exe`, or `powershell.exe -EncodedCommand …`). A benign match is unlikely for these rules but confirm the `parentImage`/`commandLine`.
3. **Scope the user/host:** identify the user (`data.win.eventdata.user`), the host, and the delivering email (subject/sender) from the user report or mail logs.
4. **Determine if code executed:** the presence of `100200/100201/100202` means execution already occurred — treat as a confirmed compromise attempt, not just a suspicious email.
5. **Check for follow-on activity** (pivot the same host/time window): persistence (`100205` Run-key), credential access (`100203` LSASS), C2 (`100206` DNS). Any of these raises severity.
6. **Classify severity:** *High* if execution + persistence/cred-access/C2; *Medium* if execution only; *Low* if the email was reported and no execution alert exists.
7. **(Week 3) LLM assistant:** produces a 5-line summary, the ATT&CK tag, suggested investigation queries, and a draft user-notification — **human-reviewed before use; the assistant takes no action and receives no secrets.** Record the assistant's tag vs. ground truth for the measurement log.
8. **Escalate** High/Medium to the Tier-2 / IR lead with the alert IDs and scoped host/user.

## Phase 3 — Containment, Eradication & Recovery *(Tier-2 / IR lead)*

**Short-term containment (minutes):**
- Isolate the affected endpoint from `LabNet` (detach NIC / EDR isolate) — Tier-1 may do this immediately for High.
- Reset the affected user's password and revoke active sessions.
- Quarantine the phishing email; ask mail admin to search-and-purge the same message from other mailboxes (block sender/domain/URL).

**Evidence preservation (before eradication):**
- Snapshot the VM; export the triggering alerts and the raw Sysmon events; collect the malicious attachment/URL, process tree, and any dropped files (hash them).

**Eradication:**
- Kill the malicious process tree; remove dropped payloads.
- Remove persistence if present: Run-key (`100205` target), scheduled tasks/services (System 7045), any new local account.
- Run a full AV/EDR scan on the host.

**Recovery:**
- Restore from a known-good snapshot if persistence/rootkit is suspected or eradication confidence is low.
- Re-enable the account with a forced password change; re-image or rejoin the host to the network.
- Monitor the host for 24–72h for re-infection or C2 (`100206`).

## Phase 4 — Post-Incident Activity *(SOC manager)*

- **Lessons learned** within a week: timeline (attack → `100200/…` fire → analyst → contained), what worked, what didn't.
- **Metrics:** record the four MTTD/MTTR timestamps (see `measurement/`).
- **Detection improvements:** tune FPs, add IOCs (sender, URL, hashes) to blocklists, and consider new rules for any technique that wasn't detected.
- **User awareness:** targeted retraining for the affected user/team; feed the sample into awareness campaigns.

---

## Appendix — key queries & evidence

```text
# Execution chain on the host
agent.name:"<host>" AND rule.id:(100200 OR 100201 OR 100202)
# Follow-on activity, same host, widen the time window
agent.name:"<host>" AND rule.id:(100205 OR 100203 OR 100206)
# Everything from the host during the incident window
agent.name:"<host>" AND rule.mitre.id:*
```
**Evidence to collect:** triggering alert IDs + raw events, email (headers, attachment/URL), process tree, dropped-file hashes, isolation/containment timestamps, VM snapshot ID.
