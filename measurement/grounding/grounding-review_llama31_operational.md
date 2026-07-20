# Grounding review worksheet — llama3.1 · operational view

For each alert: read the **alert evidence**, then judge each assistant deliverable against it. Fill the six columns in the CSV. AUTO flags are hints to verify, not verdicts.

**Scoring key** — `summary_supported`: every line traceable to the alert (Y), some lines unsupported (partial), or key claims invented (N). `unsupported_statement_count`: number of assertions not backed by the alert. `queries_valid`: runnable/wellformed. `queries_relevant`: would actually advance this triage. `draft_appropriate`: accurate, no overclaim, safe to send after review. `confidence_calibrated`: stated confidence matches the evidence strength.

## A01
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1053_003_cron",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "3",
  "audit.command": "tee",
  "audit.exe": "/usr/bin/tee",
  "audit.cwd": "/home/notroot",
  "audit.file": "/etc/cron.d/amtest",
  "audit.auid": "1000",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "pts1",
  "audit.pid": "48762",
  "audit.ppid": "48761",
  "audit.epoch": "1783526367.815",
  "audit.serial": "74996"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1053.003`

_Summary:_
- Linux system alert: Cron configuration modified
- Scheduled-task persistence (T1053.003) detected
- Audit log shows suspicious syscall 257 by root user

_Investigation queries:_
- `Get cron job configuration for /etc/cron.d/amtest`
- `Check system logs for similar suspicious syscalls by root user`
- `Verify if any other scheduled tasks are modified or added`

_Draft message:_ We detected a potential security issue with your system's cron configuration. Please investigate and take necessary actions.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A02
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe",
  "targetObject": "HKU\\\\S-1-5-21-2783956757-1425684079-3775447278-1000\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\MicrosoftEdgeAutoLaunch_4BA50610520F860366FF3F962A4A3114"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1547.001`

_Summary:_
- Windows Sysmon alert
- Registry Run Keys / Startup Folder (T1547.001)
- Autorun persistence detected

_Investigation queries:_
- `Get-ItemProperty -Path 'HKU\S-1-5-21-2783956757-1425684079-3775447278-1000\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object -ExpandProperty MicrosoftEdgeAutoLaunch_4BA50610520F860366FF3F962A4A3114`
- `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | Where-Object {$_.TimeCreated -gt '2026-07-05T10:45:36.611Z'}`

_Draft message:_ Our security system detected a potential issue with your Windows registry. We are investigating further.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |

---

## A03
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\Windows\\\\System32\\\\mshta.exe",
  "commandLine": "mshta.exe  \\\"about:&lt;hta:application&gt;&lt;script language=\\\"VBScript\\\"&gt;Close(Execute(\\\"CreateObject(\\\"\\\"Wscript.Shell\\\"\\\").Run%%20\\\"\\\"powershell.exe%%20-nop%%20-Command%%20Write-Host%%20Hello,%%20MSHTA!;Start-Sleep%%20-Seconds%%205\\\"\\\"\\\"))&lt;/script&gt;'\\\"",
  "data.win.eventdata.utcTime": "2026-07-05 15:40:13.681",
  "data.win.system.systemTime": "2026-07-05T15:40:13.6831243Z"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1218`

_Summary:_
- Windows system binary proxy execution via mshta.exe
- Possible signed-binary proxy execution (T1218)
- Defense Evasion tactic
- System Binary Proxy Execution technique

_Investigation queries:_
- `Get all processes running under the context of mshta.exe on win-victim.`
- `Check for any suspicious PowerShell commands executed recently on win-victim.`

_Draft message:_ We detected a potential security issue with your system. Our team is investigating further to ensure your safety.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A04
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1037_init",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "3",
  "audit.command": "tee",
  "audit.exe": "/usr/bin/tee",
  "audit.cwd": "/home/notroot",
  "audit.file": "/etc/init.d/amtest_t1037_AM-LIN-T1037-20260708194238",
  "audit.auid": "1000",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "pts1",
  "audit.pid": "57504",
  "audit.ppid": "57503",
  "audit.epoch": "1783539765.038",
  "audit.serial": "79937"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1037`

_Summary:_
- Linux system alert: Boot/logon init script modified (rc.local / init.d)
- T1037 ATT&CK technique detected
- Persistence and Privilege Escalation tactics involved

_Investigation queries:_
- `Get the contents of /etc/init.d/amtest_t1037_AM-LIN-T1037-20260708194238 file.`
- `Check for suspicious modifications to rc.local or init.d scripts.`
- `Verify if user 'notroot' has any other suspicious activities.`

_Draft message:_ A security alert was triggered on your system. Our team is investigating the cause.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A05
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\WINDOWS\\\\system32\\\\reg.exe",
  "targetObject": "HKU\\\\S-1-5-21-2783956757-1425684079-3775447278-1000\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\AMTest",
  "data.win.eventdata.utcTime": "2026-07-05 16:05:21.898",
  "data.win.system.systemTime": "2026-07-05T16:05:21.9064865Z"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1547.001`

_Summary:_
- Registry Run Key modification detected on win-victim
- Possible autorun persistence via T1547.001
- Windows Sysmon CLI alert

_Investigation queries:_
- `SELECT * FROM registry WHERE path='HKU\S-1-5-21-2783956757-1425684079-3775447278-1000\Software\Microsoft\Windows\CurrentVersion\Run' AND value='AMTest'`
- `SELECT * FROM processes WHERE image='reg.exe'`

_Draft message:_ Our system detected a potential security issue with the registry. We are investigating further.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A06
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1552_004_ssh_keys",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "3",
  "audit.command": "bash",
  "audit.exe": "/usr/bin/bash",
  "audit.cwd": "/home/notroot",
  "audit.file": "/root/.ssh/authorized_keys",
  "audit.auid": "1000",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "pts1",
  "audit.pid": "43536",
  "audit.ppid": "43535",
  "audit.epoch": "1783506908.070",
  "audit.serial": "73567"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1098.004`

_Summary:_
- Linux system alert: /root/.ssh/authorized_keys accessed
- Possible SSH authorized-keys persistence (T1098.004)
- Auditd syscall 257 on /home/notroot by root user

_Investigation queries:_
- `Get the SSH client IP address and user credentials used for login.`
- `Check if any other suspicious files or directories exist in /root/.ssh/`
- `Verify if the authorized_keys file has been modified recently`

_Draft message:_ Alert: Possible unauthorized access to your system's SSH keys. Please investigate and secure your account.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A07
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1548_001_setuid",
  "audit.type": "SYSCALL",
  "audit.syscall": "90",
  "audit.success": "yes",
  "audit.exit": "0",
  "audit.command": "dconf-service",
  "audit.exe": "/usr/libexec/dconf-service",
  "audit.cwd": "/home/notroot",
  "audit.file": "/home/notroot/.config/dconf/user",
  "audit.auid": "1000",
  "audit.uid": "1000",
  "audit.euid": "1000",
  "audit.tty": "(none)",
  "audit.pid": "3627",
  "audit.ppid": "2936",
  "audit.epoch": "1783531194.273",
  "audit.serial": "76247"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1548.001`

_Summary:_
- Linux auditd alert: setuid/setgid bit change by user
- Possible privilege escalation (T1548.001)
- User notroot accessed /home/notroot/.config/dconf/user

_Investigation queries:_
- `Get the list of users with setuid/setgid bits changed in the last hour: select * from osquery where (syscall = 'setuid' or syscall = 'setgid') and timestamp > now() - interval '1h'`
- `Check for suspicious dconf-service activity: select * from osquery where process_name = 'dconf-service' and (cwd like '/home/%' or cwd like '/root/')`
- `Verify if the user notroot has any other suspicious activities in the last 24 hours: select * from osquery where auid = 1000 and timestamp > now() - interval '1d'`

_Draft message:_ We detected unusual activity on your system. Please investigate /home/notroot/.config/dconf/user for potential security issues.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |

---

## A08
**Alert evidence (key fields):**
```json
{
  "sourceImage_from_description": "C:\\\\ProgramData\\\\Microsoft\\\\Windows Defender\\\\Platform\\\\4.18.26050.15-0\\\\MsMpEng.exe",
  "grantedAccess_from_description": "0x3600"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1003.001`

_Summary:_
- LSASS access by MsMpEng.exe
- Possible credential dumping (T1003.001)
- Credential Access tactic
- Windows Defender process accessed LSASS memory
- High privilege escalation risk

_Investigation queries:_
- `Get the process tree of MsMpEng.exe around the time of the alert.`
- `Check for suspicious registry modifications or file creations by MsMpEng.exe.`
- `Verify if any credentials were dumped from LSASS memory.`

_Draft message:_ Our security system detected a potential issue with your Windows Defender process accessing sensitive memory. We're investigating further to ensure your system's integrity.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |

---

## A09
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1548_003_sudoers",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "3",
  "audit.command": "tee",
  "audit.exe": "/usr/bin/tee",
  "audit.cwd": "/home/notroot",
  "audit.file": "/etc/sudoers.d/amtest",
  "audit.auid": "1000",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "pts1",
  "audit.pid": "48553",
  "audit.ppid": "48552",
  "audit.epoch": "1783526031.814",
  "audit.serial": "74926"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1548.003`

_Summary:_
- Linux system alert: sudoers modified
- Privilege escalation persistence detected (T1548.003)
- Audit log shows suspicious syscall (257) with success and exit code 3

_Investigation queries:_
- `Get sudoers file contents around the time of modification (e.g., 'wazuh query auditd | grep /etc/sudoers.d/amtest')`
- `Check for suspicious processes running under uid/euid 0 (e.g., 'wazuh query process | grep uid=0')`

_Draft message:_ Your system's sudoers file has been modified. Please investigate and restore the original configuration.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | N |
| confidence_calibrated(Y/N) | Y |

---

## A10
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
  "commandLine": "cmd.exe  /c whoami",
  "data.win.eventdata.utcTime": "2026-07-04 18:31:22.294",
  "data.win.system.systemTime": "2026-07-04T18:31:22.3193565Z"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1059.001`

_Summary:_
- Office app winword.exe spawned cmd.exe
- Possible malicious macro (T1566/T1059)
- Initial Access and Execution tactics
- Phishing and Command and Scripting Interpreter techniques

_Investigation queries:_
- `Get all processes spawned by winword.exe in the last hour.`
- `Check if any other Office apps have spawned cmd.exe recently.`
- `Verify if user1 has executed any suspicious macros or scripts.`

_Draft message:_ We detected a possible malicious macro execution from your Office app. Please review your recent activities and ensure all software is up-to-date.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |

---

## A11
**Alert evidence (key fields):**
```json
{
  "sourceImage_from_description": "C:\\\\Program Files (x86)\\\\ossec-agent\\\\wazuh-agent.exe",
  "grantedAccess_from_description": "0x1fffff"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1003.001`

_Summary:_
- LSASS access by suspicious process
- Possible credential dumping (T1003.001)
- Windows system call detected

_Investigation queries:_
- `SELECT * FROM ossec WHERE image LIKE '%C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe%' AND access_mask = '0x1fffff'`
- `SELECT * FROM ossec WHERE event_id = 4656 AND image LIKE '%C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe%'`

_Draft message:_ A security alert was triggered on your system. We are investigating the cause.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |

---

## A12
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1543_002_systemd",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "19",
  "audit.command": "snapd",
  "audit.exe": "/usr/lib/snapd/snapd",
  "audit.cwd": "/",
  "audit.file": "/etc/systemd/system/snap-snapd-27406.mount.Ph97MJnHTvYL~",
  "audit.auid": "4294967295",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "(none)",
  "audit.pid": "767",
  "audit.ppid": "1",
  "audit.epoch": "1783510912.470",
  "audit.serial": "74009"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1543.002`

_Summary:_
- Systemd service persistence attempt via snapd
- Linux auditd alert on syscall 257 (mount)
- Possible privilege escalation and persistence

_Investigation queries:_
- `Get the list of systemd services modified recently: `osquery select * from system_service where last_modified > '2026-07-08T11:41:52Z';``
- `Check for suspicious snapd activity: `wazuh query 'audit.type=SYSCALL and audit.syscall=257 and audit.command=snapd';``

_Draft message:_ We detected a potential security issue with your systemd service. Please investigate.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |

---

## A13
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1136_accounts",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "5",
  "audit.command": "useradd",
  "audit.exe": "/usr/sbin/useradd",
  "audit.cwd": "/home/notroot",
  "audit.file": "/etc/passwd",
  "audit.auid": "1000",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "pts1",
  "audit.pid": "45112",
  "audit.ppid": "45111",
  "audit.epoch": "1783509573.142",
  "audit.serial": "73864"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1136/T1098`

_Summary:_
- Linux system alert: useradd syscall on /etc/passwd
- Possible account manipulation or persistence attempt
- User 'notroot' attempted to add a new user

_Investigation queries:_
- `Get the user's login history: SELECT * FROM osquery_login_history WHERE username='notroot';`
- `Check for suspicious processes running under the same UID: SELECT * FROM processes WHERE uid=1000;`
- `Verify if the added user exists in /etc/passwd and check its permissions`

_Draft message:_ A security alert was triggered on your system. We are investigating a potential issue with account manipulation.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A14
**Alert evidence (key fields):**
```json
{
  "sourceImage_from_description": "C:\\\\WINDOWS\\\\system32\\\\rundll32.exe",
  "grantedAccess_from_description": "0x1fffff",
  "data.win.eventdata.utcTime": "2026-07-05 19:33:38.621",
  "data.win.system.systemTime": "2026-07-05T19:33:38.6220985Z"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1003.001`

_Summary:_
- LSASS access by C:\\WINDOWS\\system32\\rundll32.exe
- Possible credential dumping (T1003.001)
- Credential Access tactic

_Investigation queries:_
- `Get the process list of rundll32.exe and its parent processes.`
- `Check for any suspicious registry modifications or file creations related to LSASS dumping.`

_Draft message:_ We detected a potential security issue with your system. Our team is investigating further.

> ⚑ AUTO: entities named but not found in the alert — **verify**: C:\\WINDOWS\\system32\\rundll32.exe
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A15
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\Program Files\\\\WindowsApps\\\\Microsoft.PowerShell_7.6.3.0_x64__8wekyb3d8bbwe\\\\pwsh.exe",
  "queryName": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-am-t1071dns-20260706214941.alertmind-lab.invalid",
  "data.win.eventdata.utcTime": "2026-07-06 16:20:19.424",
  "data.win.system.systemTime": "2026-07-06T16:20:21.7688783Z"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1071.004`

_Summary:_
- DNS query with long label detected on win-victim
- Possible DNS tunneling (heuristic)
- T1048/T1071.004 suspected

_Investigation queries:_
- `Get all DNS queries made by pwsh.exe in the last hour`
- `Check for any suspicious network connections from win-victim`
- `Verify if the queryName field matches any known malicious domains`

_Draft message:_ We detected a potential security issue with your system. Our team is investigating.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A16
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1070_logs",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "3",
  "audit.command": "bash",
  "audit.exe": "/usr/bin/bash",
  "audit.cwd": "/home/notroot",
  "audit.file": "/var/log/btmp",
  "audit.auid": "1000",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "pts1",
  "audit.pid": "53346",
  "audit.ppid": "53345",
  "audit.epoch": "1783533197.822",
  "audit.serial": "77955"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1070`

_Summary:_
- Linux system audit log modification detected
- Possible indicator removal (T1070)
- Defense Evasion tactic

_Investigation queries:_
- `Get the system's audit log for the past week: `wazuh-cluster get_audit_log -s <system> -t 604800``
- `Check for suspicious login attempts in /var/log/btmp and /var/log/wtmp: `cat /var/log/btmp | grep pts1` and `cat /var/log/wtmp | grep pts1``

_Draft message:_ We detected a potential security issue on your system. Please investigate the modification of your audit logs.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A17
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1547_006_kmod",
  "audit.type": "SYSCALL",
  "audit.syscall": "313",
  "audit.success": "yes",
  "audit.exit": "0",
  "audit.command": "modprobe",
  "audit.exe": "/usr/bin/kmod",
  "audit.auid": "1000",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "pts1",
  "audit.pid": "51813",
  "audit.ppid": "51812",
  "audit.epoch": "1783531749.723",
  "audit.serial": "76435"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1547.006`

_Summary:_
- Linux system alert: modprobe command executed by root (uid=0)
- Possible LKM rootkit activity
- Kernel module load/unload or modprobe config change detected

_Investigation queries:_
- `Get the modprobe command's arguments and context.`
- `Check for suspicious kernel module loads/unloads in audit logs around this time.`
- `Verify if any new kernel modules are loaded with unusual permissions or attributes.`

_Draft message:_ We detected a potential security issue on your system. Our team is investigating further to ensure the integrity of your environment.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A18
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
  "commandLine": "\\\"C:\\\\WINDOWS\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\" -NoProfile -EncodedCommand QQBsAGUAcgB0AE0AaQBuAGQAIABFAG4AYwBvAGQAZQBkACAAUABvAHcAZQByAFMAaABlAGwAbAAgAFQAZQBzAHQA",
  "data.win.eventdata.utcTime": "2026-07-05 10:21:38.629",
  "data.win.system.systemTime": "2026-07-05T10:21:38.8550404Z"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1059.001`

_Summary:_
- PowerShell encoded command executed on win-victim
- Possible obfuscated payload (T1059.001)
- Execution tactic, PowerShell technique

_Investigation queries:_
- `Get-EventLog -Newest 10 | Where-Object {$_.EventID -eq 4688} | Select-Object -ExpandProperty Message`
- `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Select-Object -ExpandProperty Message`
- `Get-ChildItem -Path 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0' | Where-Object {$_.Name -eq 'powershell.exe'}`

_Draft message:_ A PowerShell encoded command was executed on your system. We are investigating.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A19
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\Windows\\\\PSEXESVC.exe",
  "commandLine": "C:\\\\WINDOWS\\\\PSEXESVC.exe",
  "data.win.eventdata.utcTime": "2026-07-06 13:34:40.469",
  "data.win.system.systemTime": "2026-07-06T13:34:40.4711276Z"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1021.002/T1569.002`

_Summary:_
- PsExec service binary executed on win-victim
- Possible remote service execution / lateral movement (T1021.002/T1569.002)
- Windows Sysmon CLI detected suspicious process
- Execution of PSEXESVC.exe from C:\\Windows\\PSEXESVC.exe
- Command line: C:\\WINDOWS\\PSEXESVC.exe

_Investigation queries:_
- `SELECT * FROM osquery WHERE image LIKE '%PSEXESVC.exe%' AND command_line LIKE '%C:\\WINDOWS\\PSEXESVC.exe%';`
- `SELECT * FROM windows WHERE process_name='PSEXESVC.exe' AND parent_process_name='svchost.exe';`
- `SELECT * FROM registry WHERE key='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PSEXESVC'`

_Draft message:_ Our system detected a suspicious process running on your Windows machine. We are investigating further to ensure the security of our systems.

> ⚑ AUTO: entities named but not found in the alert — **verify**: C:\\WINDOWS\\PSEXESVC.exe; C:\\Windows\\PSEXESVC.exe
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |

---

## A20
**Alert evidence (key fields):**
```json
{
  "audit.key": "t1003_008_shadow_read",
  "audit.type": "SYSCALL",
  "audit.syscall": "257",
  "audit.success": "yes",
  "audit.exit": "7",
  "audit.command": "cron",
  "audit.exe": "/usr/sbin/cron",
  "audit.cwd": "/var/spool/cron",
  "audit.file": "/etc/shadow",
  "audit.auid": "4294967295",
  "audit.uid": "0",
  "audit.euid": "0",
  "audit.tty": "(none)",
  "audit.pid": "43800",
  "audit.ppid": "769",
  "audit.epoch": "1783507501.191",
  "audit.serial": "73613"
}
```
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1003.008`

_Summary:_
- Linux system alert: /etc/shadow read by cron process
- Possible credential access via T1003.008
- Auditd syscall 257 (read) on /etc/shadow

_Investigation queries:_
- `Get cron job schedule for /var/spool/cron`
- `Check system logs for suspicious activity around t1_attack_utc`
- `Verify user and group permissions on /etc/shadow`

_Draft message:_ Alert: Possible credential access detected. Review system logs and cron jobs.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |

---
