# IR Playbook — Account Compromise

**Framework:** NIST SP 800-61 lifecycle (Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity).
**Scope:** a legitimate account is used by an adversary — via stolen credentials, pass-the-hash, a stolen SSH key, or a newly created rogue account — typically to move laterally and establish persistence. (If the account was compromised by malware/credential-dumping, cross-link *malware.md*; if by phishing, *phishing.md*.)
**Primary AlertMind detections:** `92652` (successful NTLM remote logon / possible pass-the-hash), `100204` + built-ins `92218/92307/92650` (PsExec-style lateral movement — T1021.002/T1569.002), `100101` (new local account — T1136), `100116` (SSH `authorized_keys` persistence — T1098.004), `100113` (SSH key access — T1552.004), `100100` (`/etc/shadow` read — T1003.008), `100102` (sudoers — T1548.003).

## Roles

| Role | Responsibility |
|---|---|
| **Tier-1 analyst** | Validate the suspicious logon/account activity, scope the account's footprint, execute immediate account containment, escalate. |
| **Tier-2 / IR lead** | Trace lateral movement, hunt persistence, coordinate credential resets, recovery sign-off. |
| **SOC manager** | Business decision on account disablement impact, comms, privileged-access review. |
| **Identity / system owner** | Executes account disablement, credential/key rotation, MFA enforcement. |

---

## Phase 1 — Preparation

- Windows Security/System channels and Sysmon on `win-victim`; auditd on `linux-victim`; all flowing and verified.
- AlertMind account/lateral-movement/persistence rules deployed; behavioural built-ins (`92218/92307/92650/92652`) available for tool variants that evade name-based rules.
- A documented account-disable / credential-reset / session-revoke procedure with the identity owner.
- Inventory of privileged accounts and their expected logon sources (to spot anomalies fast).

## Phase 2 — Detection & Analysis *(Tier-1 → Tier-2)*

1. **Entry point:** a suspicious logon (`92652` NTLM remote logon / pass-the-hash), unexpected lateral movement (`100204` or the behavioural `92218/92307/92650`), a new account (`100101`), or key/credential access (`100116/100113/100100`).
2. **Identify the account and its footprint:**
   - `data.win.eventdata.targetUserName` / `user`, source host/IP, logon type.
   - `agent.name:"<host>" AND rule.id:92652` — enumerate every host the account authenticated to and when.
3. **Confirm compromise vs. legitimate:** compare source IP/host and time against the account's normal pattern (Phase-1 inventory). An `Administrator` NTLM logon from the Kali/attacker subnet is a strong positive.
4. **Trace lateral movement:** PsExec-style service creation from admin shares —
   - `agent.name:"<host>" AND rule.id:(100204 OR 92218 OR 92307 OR 92650)`
   - *Note:* impacket-psexec uses a **random** service/binary name (not `PSEXESVC.exe`), so `100204` may not fire while `92218/92307/92650` do — the behavioural built-ins are the reliable signal for the tool variant. Sysinternals PsExec fires `100204` directly.
5. **Hunt persistence established by the attacker:** new local account (`100101`), SSH `authorized_keys` addition (`100116`), sudoers change (`100102`), and any credential access that fed the compromise (`100100` shadow read, `100113` SSH-key read).
6. **Severity:** *Critical* if a privileged/`Administrator` account + lateral movement + persistence; *High* if lateral movement confirmed; *Medium* if a single anomalous logon with no movement yet.
7. **(Week 3) LLM assistant:** 5-line summary + ATT&CK tag + suggested pivots + draft user/owner notification — **human-reviewed; no autonomous action (it will *not* disable an account); no secrets sent.** Log tag accuracy.
8. **Escalate** to Tier-2 + identity owner for High/Critical with the full logon trail and lateral-movement chain.

## Phase 3 — Containment, Eradication & Recovery *(Tier-2 / IR lead + identity owner)*

**Short-term containment (act fast — the account is live):**
- **Disable the compromised account** and force sign-out / revoke active sessions and tokens.
- **Reset the password**; if key-based, remove the attacker's `authorized_keys` entry (`100116` target) and rotate the affected keypair.
- Isolate any host the account reached during lateral movement (`100204/92218/…`).
- If a rogue account was created (`100101`), disable it immediately.

**Evidence preservation:**
- Export the logon trail (`92652`), lateral-movement alerts, persistence artefacts; snapshot affected hosts; record the account's full activity timeline.

**Eradication:**
- Remove attacker-created accounts (`100101`) and persistence (`authorized_keys` entries, sudoers changes `100102`, services dropped via PsExec).
- On every host the account touched, hunt for and remove secondary implants (cross-link *malware.md*).
- Rotate credentials for **all** accounts that were exposed on compromised hosts, not just the primary.

**Recovery:**
- Re-enable the account only after reset + review; **enforce MFA** where available.
- Rebuild hosts where SYSTEM-level lateral execution occurred (PsExec ran as `nt authority\system`) — cleaning in place is not trusted.
- Monitor the account and affected hosts for renewed logons or persistence recreation for 72h.

## Phase 4 — Post-Incident Activity *(SOC manager)*

- **Lessons learned** + timeline (four MTTD/MTTR timestamps in `measurement/`).
- **Privileged-access review:** was the account over-privileged? Should it have been able to log on from that source? Tighten logon restrictions / tiering.
- **Detection tuning:** confirm the behavioural built-ins carried the impacket case; consider a rule on anomalous admin-share service creation; verify `100116`/`100101`/`100113` all fired for the persistence/credential steps.
- **Control recommendations:** MFA, LAPS/unique local-admin passwords, SMB signing, disable NTLM where feasible, SSH key hygiene.

---

## Appendix — key queries & evidence

```text
# Suspicious remote logons for an account
rule.id:92652 AND data.win.eventdata.targetUserName:"<account>"
# Lateral movement (named + behavioural)
agent.name:"<host>" AND rule.id:(100204 OR 92218 OR 92307 OR 92650)
# Persistence / rogue accounts / credential access
rule.id:(100101 OR 100116 OR 100102 OR 100113 OR 100100)
```
**Note on tool variants:** name-based `100204` catches Sysinternals PsExec (`PSEXESVC.exe`); impacket-psexec evades it with a random binary name but is caught behaviourally by `92218` (admin-share binary), `92307`/`92650` (service creation from systemroot) — document this indicator-vs-behavioural distinction.

**Evidence to collect:** full logon trail, source IPs/hosts, lateral-movement service names, attacker-created accounts, `authorized_keys` diffs, credential-reset and account-disable timestamps, snapshot IDs.
