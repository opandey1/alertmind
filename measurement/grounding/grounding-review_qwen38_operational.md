# Grounding review worksheet — qwen3:8b · operational view

**Source run:** `assistant/outputs/runs/20260830_054251_ollama_oper_baseline/`

**Prompt version:** `23185744b88f77b7` · **Redaction version:** `cf0549f832d13b7f`

For each alert: read the **alert evidence**, then judge each assistant deliverable against it. Fill the six columns in the CSV. AUTO flags are hints to verify, not verdicts.

> **Note on AUTO flags in this worksheet.** The generator used for the llama3.1 and gpt-5.5 kits is not committed, so `auto_summary_lines`, `auto_queries_count`, `auto_draft_present` and `auto_tid_in_summary` were re-derived and reproduce those kits exactly, while `auto_queries_syntactic` and `auto_unknown_entities` use a re-derived heuristic that differs in sensitivity. Per the kit README these columns are hints to verify, never verdicts, so the difference does not affect the six human judgements — but do not compare raw flag counts across worksheets.

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
**Assistant** — disposition `likely_true_positive` · confidence `medium` · technique `T1053.003`

_Summary:_
- Auditd detected modification to /etc/cron.d/amtest with root privileges
- tee command used to write to cron configuration file
- Process executed with euid=0 (root) from auid=1000
- Alert triggered by rule detecting Cron persistence attempts
- Modification successful (audit.success=yes)

_Investigation queries:_
- `SELECT * FROM logs WHERE file="/etc/cron.d/amtest" AND user="1000" AND command LIKE "%tee%";`
- `SELECT * FROM processes WHERE pid=48762 AND ppid=48761 AND cmdline LIKE "%/etc/cron.d/amtest%";`
- `SELECT * FROM files WHERE path="/etc/cron.d/amtest" AND modification_time > NOW()-14400;`

_Draft message:_ We've detected a recent modification to the cron.d configuration file. Please verify if this change was authorized.


| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The generic SQL uses undefined tables/fields rather than concrete Wazuh/Discover syntax, so the set is not runnable in this environment; the intended file, process and modification checks are relevant. Draft and medium confidence are appropriate. |



## A02
**Alert evidence (key fields):**
```json
{
  "image": "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe",
  "targetObject": "HKU\\\\S-1-5-21-2783956757-1425684079-3775447278-1000\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\MicrosoftEdgeAutoLaunch_4BA50610520F860366FF3F962A4A3114"
}
```
**Assistant** — disposition `needs_investigation` · confidence `medium` · technique `T1547.001`

_Summary:_
- Registry Run key modified in HKU\S-1-5-21-2783956757-1425684079-3775447278-1000\Software\Microsoft\Windows\CurrentVersion\Run
- Process: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
- Registry value name: MicrosoftEdgeAutoLaunch_4BA50610520F860366FF3F962A4A3114
- MITRE ATT&CK T1547.001 (Registry Run Keys / Startup Folder)
- Persistence attempt detected

_Investigation queries:_
- `SELECT * FROM WinEventLog WHERE SourceName = 'Microsoft-Windows-Sysmon' AND EventID = 1 AND TimeCreated >= '2026-07-05T10:45:40'`
- `SELECT * FROM WinRegistry WHERE Hive = 'HKU' AND Key = 'S-1-5-21-2783956757-1425684079-3775447278-1000\Software\Microsoft\Windows\CurrentVersion\Run' AND ValueName LIKE 'MicrosoftEdgeAutoLaunch%'`
- `SELECT * FROM WinProcess WHERE ProcessName = 'msedge.exe' AND StartTime >= '2026-07-05T10:45:40'`

_Draft message:_ We've detected an unusual modification to a registry Run key associated with Microsoft Edge. Please review system activity for potential persistence mechanisms.

> ⚑ AUTO: entities named but not found in the alert — **verify**: HKU\S-1-5-21-2783956757-1425684079-3775447278-1000\Software\Microsoft\Windows\CurrentVersion\Run C:\Program (x86)\Microsoft\Edge\Application\msedge.exe
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported by the rule and Edge Run-key fields. The generic SQL is not runnable Wazuh/Discover syntax, but the registry and process checks are relevant. The cautious needs_investigation/medium pairing, draft and confidence are appropriate for a likely benign Edge auto-launch event. |

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
- mshta.exe executed with encoded PowerShell command line
- URL-encoded payload: 'CreateObject("Wscript.Shell").Run "powershell.exe -nop -Command Write-Host Hello, MSHTA!;Start-Sleep -Seconds 5'
- MITRE T1218: System Binary Proxy Execution
- Command line contains suspicious URL-encoded PowerShell execution
- Alert detected 29 seconds after initial event

_Investigation queries:_
- `SELECT * FROM logs WHERE command_line LIKE '%mshta.exe%' AND command_line LIKE '%powershell.exe%'`
- `SELECT * FROM logs WHERE process_name='mshta.exe' AND timestamp BETWEEN '2026-07-05 15:40:00' AND '2026-07-05 15:45:00'`
- `SELECT * FROM logs WHERE event_id='1' AND process_name='powershell.exe' AND timestamp BETWEEN '2026-07-05 15:40:00' AND '2026-07-05 15,45:00'`

_Draft message:_ We've detected unusual activity involving mshta.exe executing PowerShell commands. Our systems are currently investigating this to ensure there's no unauthorized access.

> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The SQL-like set is not runnable Wazuh/Discover syntax and one timestamp contains a comma in 15,45:00, but the mshta/PowerShell/time-window checks are relevant. Draft and high confidence are appropriate. |

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
**Assistant** — disposition `needs_investigation` · confidence `medium` · technique `T1037`

_Summary:_
- Auditd detected modification of init script /etc/init.d/amtest_t1037_AM-LIN-T1037-20260708194238
- Process executed as root (uid/euid 0) with tty pts1
- File modification coincides with T1037 MITRE technique
- Audit latency 1.711 seconds
- Script path matches common persistence targets

_Investigation queries:_
- `SELECT * FROM logs WHERE file_path = '/etc/init.d/amtest_t1037_AM-LIN-T1037-20260708194238' AND user_id = 0`
- `SELECT * FROM processes WHERE pid = 57504 OR ppid = 57503`
- `SELECT * FROM auditd WHERE audit_file = '/etc/init.d/amtest_t1037_AM-LIN-T1037-20260708194238' AND audit_uid = 0`

_Draft message:_ We've detected potential modification of system initialization scripts. Please review /etc/init.d/amtest_t1037_AM-LIN-T1037-20260708194238 for unexpected changes.

> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The generic logs/processes/auditd SQL is not runnable Wazuh/Discover syntax, but the file and process checks are relevant. Draft and medium confidence are appropriate. |

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
- Registry Run key modified under HKU\S-1-5-21-2783956757-1425684079-3775447278-1000
- Targeted Run key: AMTest in Software\Microsoft\Windows\CurrentVersion\Run
- Process: C:\WINDOWS\system32\reg.exe executed the change
- Alert detected 4.47 seconds after initial event
- MITRE T1547.001 (Registry Run Keys / Startup Folder) persistence technique

_Investigation queries:_
- `SELECT * FROM win_event WHERE event_id=100205 AND registry_key LIKE '%Run%'`
- `SELECT * FROM win_registry WHERE key_path LIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Run%'`
- `SELECT * FROM win_process WHERE image='reg.exe' AND command_line LIKE '%HKU\\S-1-5-21-2783956757-1425684079-3775447278-1000%'`

_Draft message:_ We've detected an unusual registry modification to the Run key under your user profile. This could indicate unauthorized persistence mechanisms. Please review the affected system for suspicious activity.

> ⚑ AUTO: entities named but not found in the alert — **verify**: HKU\S-1-5-21-2783956757-1425684079-3775447278-1000 C:\WINDOWS\system32\reg.exe
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The generic win_event/win_registry/win_process SQL is not runnable Wazuh/Discover syntax, but the Run-key and reg.exe checks are relevant. Draft and high confidence are appropriate. |

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
**Assistant** — disposition `needs_investigation` · confidence `medium` · technique `T1098.004`

_Summary:_
- Auditd detected modification of /root/.ssh/authorized_keys
- Process ran as UID 0 (root) with effective UID 0
- Activity logged under rule ID 100116 (SSH authorized keys persistence)
- Audit syscall 257 (open) succeeded with exit code 3
- Command executed as user 'notroot' in /home/notroot

_Investigation queries:_
- `SELECT * FROM auditd WHERE file='/root/.ssh/authorized_keys' AND uid=0 ORDER BY timestamp DESC;`
- `SELECT * FROM processes WHERE pid=43536 OR ppid=43535 ORDER BY timestamp DESC;`
- `SELECT * FROM files WHERE path='/root/.ssh/authorized_keys' AND modification_time > NOW() - INTERVAL '7days'`

_Draft message:_ We've detected unusual access to root's SSH authorized keys file. Please verify if recent changes were authorized.


| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | One unsupported attribution: auid=1000 and cwd=/home/notroot do not prove that the username was 'notroot'. The generic auditd/processes/files SQL is not runnable Wazuh/Discover syntax, but its checks are relevant. Draft and medium confidence are appropriate. |

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
**Assistant** — disposition `needs_investigation` · confidence `medium` · technique `T1548.001`

_Summary:_
- Linux auditd detected setuid/setgid bit change via dconf-service
- Audit syscall 90 (chown) succeeded on user config file
- Process ran as user 1000 with no elevation detected
- Alert matches MITRE T1548.001 technique
- No immediate privilege escalation observed

_Investigation queries:_
- `grep 'chown' /var/log/audit/audit.log | audit2why`
- `ps -ef | grep dconf-service`
- `find /home/notroot/.config/dconf/ -name 'user' -exec ls -l {} \;`

_Draft message:_ We detected unusual file permission changes related to your configuration settings. Our systems are monitoring for potential privilege escalation attempts, but no elevation was observed at this time.

> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | One factual error: on x86-64 syscall 90 is chmod, not chown. The command set is not a complete Wazuh/Discover query set (audit2why has no input), but the audit/process/file checks are relevant. Draft and needs_investigation/medium confidence are appropriate for benign dconf activity. |

## A08
**Alert evidence (key fields):**
```json
{
  "sourceImage_from_description": "C:\\\\ProgramData\\\\Microsoft\\\\Windows Defender\\\\Platform\\\\4.18.26050.15-0\\\\MsMpEng.exe",
  "grantedAccess_from_description": "0x3600"
}
```
**Assistant** — disposition `needs_investigation` · confidence `medium` · technique `T1003.001`

_Summary:_
- Windows Defender Platform process (MsMpEng.exe) accessed LSASS memory with elevated permissions
- Alert indicates potential credential dumping via LSASS memory access (T1003.001)
- Process is legitimate Windows Defender component but access pattern is suspicious
- No clear evidence of malicious payload execution yet
- Access permissions 0x3600 (READ_CONTROL, SYNCHRONIZE, and STANDARD_RIGHTS_READ)

_Investigation queries:_
- `SELECT * FROM win_event WHERE event_id=4672 AND process_path='C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26050.15-0\MsMpEng.exe'`
- `SELECT * FROM win_process WHERE process_name='MsMpEng.exe' AND parent_process_name!='Windows Defender Service'`
- `SELECT * FROM win_event WHERE event_id=4688 AND process_path LIKE '%MsMpEng.exe%'`

_Draft message:_ We've detected unusual LSASS memory access by Windows Defender process. This could indicate potential credential access activity - please review security logs for additional context.

> ⚑ AUTO: entities named but not found in the alert — **verify**: (MsMpEng.exe)
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | One unsupported access-mask decode: 0x3600 does not represent READ_CONTROL, SYNCHRONIZE and STANDARD_RIGHTS_READ. The generic Windows SQL is not runnable Wazuh/Discover syntax, but process-lineage and event checks are relevant. Draft and needs_investigation/medium confidence are appropriately cautious for Defender activity. |

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
- Auditd detected modification of /etc/sudoers.d/amtest with euid 0
- Process ran as root (uid/euid 0) from /home/notroot
- Alert triggered by sudoers file modification (T1548.003)
- Audit syscall 257 (tee) wrote to sudoers.d directory
- Parent process 48552 initiated the operation

_Investigation queries:_
- `SELECT * FROM logs WHERE file_path = '/etc/sudoers.d/amtest' AND user = 'notroot' ORDER BY timestamp DESC;`
- `CHECKSUM('/etc/sudoers.d/amtest')`
- `SELECT * FROM process_events WHERE pid = 48552 AND command_line LIKE '%tee%' ORDER BY timestamp DESC;`

_Draft message:_ The system detected an attempted modification of sudoers configuration files. Please verify if this was an authorized change.

> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | One factual error: x86-64 syscall 257 is openat, not the write performed by tee. The set is not runnable Wazuh/Discover syntax (CHECKSUM(...) is not a standalone query), but the sudoers, integrity and process checks are relevant. Draft and high confidence are appropriate. |

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
**Assistant** — disposition `likely_true_positive` · confidence `medium` · technique `T1566/T1059`

_Summary:_
- Office app (winword.exe) spawned cmd.exe
- Command line: cmd.exe /c whoami
- Alerted by rule 100200 (T1566/T1059)
- Timestamps show <1s detection latency
- Evidence file: win_100200-office_shell-T1566_T1059.png

_Investigation queries:_
- `SELECT * FROM win_event WHERE event_id=1 AND process_name='winword.exe' AND command_line LIKE '%cmd.exe%'`
- `SELECT * FROM win_process WHERE parent_process_name='winword.exe' AND child_process_name='cmd.exe'`
- `SELECT * FROM win_event WHERE event_id=1 AND command_line LIKE '%whoami%'`

_Draft message:_ We detected an unusual command execution from Office application. Please verify if any suspicious activity occurred.

> ⚑ AUTO: entities named but not found in the alert — **verify**: (winword.exe)
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | The complete operational prompt—not only the key_fields excerpt—states that winword.exe spawned cmd.exe and includes the rule ID, evidence file and immediate-latency note, so the summary is fully supported. The generic SQL is not runnable Wazuh/Discover syntax, but the parent/child and whoami checks are relevant. Draft and medium confidence are appropriate. |

## A11
**Alert evidence (key fields):**
```json
{
  "sourceImage_from_description": "C:\\\\Program Files (x86)\\\\ossec-agent\\\\wazuh-agent.exe",
  "grantedAccess_from_description": "0x1fffff"
}
```
**Assistant** — disposition `needs_investigation` · confidence `medium` · technique `T1003.001`

_Summary:_
- Wazuh agent.exe accessed LSASS with high privileges
- Potential credential dumping via LSASS memory extraction
- Alert triggered by Windows Sysmon rule 100203
- Access granted 0x1fffff (SeDebugPrivilege)
- No timing data available from event logs

_Investigation queries:_
- `SELECT * FROM win_event WHERE event_id=4688 AND process_path='C:\Program Files (x86)\ossec-agent\wazuh-agent.exe'`
- `SELECT * FROM win_process WHERE process_name='wazuh-agent.exe' AND parent_process_name NOT LIKE '%ossec-agent%'`
- `SELECT * FROM win_event WHERE event_id=1003 AND process_path='C:\Program Files (x86)\ossec-agent\wazuh-agent.exe'`

_Draft message:_ We've detected potential LSASS memory access by the Wazuh agent. Please verify if this activity is expected or if further investigation is needed.


| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | One unsupported equivalence: 0x1fffff is a process access mask, not SeDebugPrivilege itself. The generic SQL uses undefined tables and mismatched event identifiers rather than runnable Wazuh/Discover syntax, but validating Wazuh-agent process activity is relevant. Draft and needs_investigation/medium confidence are appropriate. |

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
- Systemd service file modified by snapd with root privileges
- Auditd detected modification of /etc/systemd/system/snap-snapd-27406.mount.Ph97MJnHTvYL~
- File created with UID 0 (root) and audit serial 74009
- Alert latency 1.842 seconds between system call and detection
- Potential persistence mechanism via systemd service unit

_Investigation queries:_
- `Find recent systemd unit file modifications: auditd.log | grep 'SYSCALL' | grep 'systemd' | grep 'audit.file' | sort -r | head -20`
- `Check for similar filenames in /etc/systemd/system/: find /etc/systemd/system/ -name 'snap-snapd-*.mount*'`
- `Verify snapd service status and configuration: systemctl status snapd && systemctl cat snapd`

_Draft message:_ We detected potential persistence activity via systemd service modification. Please review the snapd service configuration for unexpected changes.


| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |
| reviewer_notes | One unsupported statement: uid/euid=0 identify the snapd process context, not the created file's owner. The shell-like set is not a complete Wazuh/Discover query set and its first pipeline is not runnable as written, but unit-file and snapd checks are relevant. Draft is appropriately cautious; high-confidence likely_true_positive is not calibrated for benign snapd activity. |

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
**Assistant** — disposition `likely_true_positive` · confidence `medium` · technique `T1136/T1098`

_Summary:_
- Auditd detected modification to /etc/passwd via useradd command
- Audit UID 0 (root) executed useradd with AUID 1000
- System call 257 (open) succeeded with exit code 5
- Process initiated from pts1 terminal (PID 45112)
- Alert latency 1.4 seconds

_Investigation queries:_
- `Auditd events for /etc/passwd modifications in last 24h`
- `Check for recent sudo logs with user 1000`
- `File integrity checks on /etc/passwd and /etc/shadow`

_Draft message:_ We've detected potential account creation activity on your system. Please review the audit logs for useradd operations involving UID 0 and AUID 1000.


| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The investigation items are prose rather than runnable Wazuh/Discover queries, but passwd, sudo and integrity checks are relevant. Draft and medium confidence are appropriate. |

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
- Rundll32.exe (C:\WINDOWS\system32\rundll32.exe) accessed LSASS memory with 0x1fffff privileges
- Alert triggered by LSASS memory access detected via Sysmon rule 100203
- Timestamp: 2026-07-05 19:33:38.621 UTC
- MITRE ATT&CK T1003.001 (Credential Access - LSASS Memory)
- Detection latency: 2.129 seconds

_Investigation queries:_
- `SELECT * FROM syslog WHERE sourceImage='C:\WINDOWS\system32\rundll32.exe' AND event_id='100203'`
- `SELECT * FROM process_creation WHERE parent_process_name='rundll32.exe' AND timestamp > '2026-07-05 19:33:38'`
- `SELECT * FROM network_connection WHERE source_process='C:\WINDOWS\system32\rundll32.exe'`

_Draft message:_ We've detected potential credential access activity involving rundll32.exe. Our team is investigating and will follow up with additional details.

> ⚑ AUTO: entities named but not found in the alert — **verify**: Rundll32.exe (C:\WINDOWS\system32\rundll32.exe) rundll32.exe.
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The generic syslog/process_creation/network_connection SQL is not runnable Wazuh/Discover syntax, but rundll32 process and network checks are relevant. Draft and high confidence are appropriate. |

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
**Assistant** — disposition `likely_true_positive` · confidence `high` · technique `T1048/T1071.004`

_Summary:_
- DNS query with long label detected (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-am-t1071dns-20260706214941.alertmind-lab.invalid)
- Executed by PowerShell (C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.3.0_x64__8wekyb3d8bbwe\pwsh.exe)
- Heuristic alert for DNS tunneling (T1048/T1071.004)
- Timestamp: 2026-07-06 16:20:19.424 UTC
- Detection latency: 3.477 seconds

_Investigation queries:_
- `SELECT * FROM win_dns WHERE query_name LIKE '%am-t1071dns%' AND timestamp > NOW() - 1h`
- `SELECT * FROM win_process WHERE image = 'pwsh.exe' AND timestamp > NOW() - 1h`
- `SELECT * FROM win_event WHERE event_id = 1 AND timestamp > NOW() - 1h`

_Draft message:_ We've detected an unusual DNS query originating from PowerShell. Please verify if this activity is authorized.

> ⚑ AUTO: entities named but not found in the alert — **verify**: Files\WindowsApps\Microsoft.PowerShell_7.6.3.0_x64__8wekyb3d8bbwe\pwsh.exe)
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The generic win_dns/win_process/win_event SQL is not runnable Wazuh/Discover syntax, but DNS and PowerShell checks are relevant. Draft and high confidence are appropriate. |

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
- Linux auditd detected modification of /var/log/btmp (failed login log)
- Process ran as root (euid=0) with non-root auid=1000
- Audit syscall 257 (write) succeeded with exit code 3
- Alert triggered by T1070: Indicator Removal technique
- Auditd event timestamp matches Wazuh alert latency

_Investigation queries:_
- `Auditd events for file modifications to /var/log/btmp/* within 10 minutes`
- `Process tree for pid=53346 showing root privileges usage`
- `Check for other log file modifications in /var/log/ within last hour`

_Draft message:_ We've detected potential log file modification activity on your system. Our analysis suggests this may be an attempt to remove evidence of login attempts. No action is required at this time, but we recommend reviewing system logs for unusual activity.

> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | N |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | One factual error: x86-64 syscall 257 is openat, not write. The investigation items are prose rather than runnable Wazuh/Discover queries, but the btmp/process-tree/log checks are relevant. The draft is inappropriate because 'No action is required' conflicts with a high-confidence log-tampering alert; high confidence itself is supported. |

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
**Assistant** — disposition `likely_true_positive` · confidence `medium` · technique `T1547.006/T1014`

_Summary:_
- Linux auditd detected modprobe execution with root privileges
- syscall 313 (sys_modprobe) triggered T1547.006 rule
- audit.uid/euid 0 indicates potential privilege escalation
- modprobe command executed by user auid 1000
- kernel module load/unload activity flagged as possible LKM rootkit

_Investigation queries:_
- `SELECT * FROM logs WHERE source='linux_auditd_cli' AND audit.command='modprobe' AND audit.uid='0' ORDER BY timestamp DESC LIMIT 10`
- `SELECT DISTINCT audit.exe FROM logs WHERE audit.syscall='313' AND audit.uid='0' AND timestamp > NOW() - INTERVAL '1 day'`
- `SELECT * FROM files WHERE filename LIKE '/lib/modules/%' AND last_modified > NOW() - INTERVAL '1 hour'`

_Draft message:_ We've detected unusual kernel module activity that may require investigation. Your system's security team is aware and will verify this finding.

> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | partial |
| unsupported_statement_count(int) | 1 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | One factual error: x86-64 syscall 313 is finit_module, not sys_modprobe. The generic logs/files SQL is not runnable Wazuh/Discover syntax, but module-load and process checks are relevant. Draft and medium confidence are appropriate. |

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
- PowerShell.exe executed with encoded command line arguments
- EncodedCommand detected via Sysmon rule 100201
- T1059.001 technique flagged for obfuscated payload
- Execution tactic observed
- 4-second detection latency

_Investigation queries:_
- `SELECT * FROM win_event WHERE event_id=4104 AND process_name='powershell.exe' AND command_line LIKE '%EncodedCommand%'`
- `SELECT * FROM win_process WHERE image='powershell.exe' AND parent_image NOT LIKE '%explorer.exe%'`
- `SELECT * FROM win_network WHERE source_process='powershell.exe' AND destination_port BETWEEN 1 AND 1024`

_Draft message:_ We've detected a PowerShell process with encoded command line arguments. This could indicate an obfuscated payload - please review the attached screenshot for details.

> ⚑ AUTO: entities named but not found in the alert — **verify**: PowerShell.exe
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The generic win_event/win_process/win_network SQL is not runnable Wazuh/Discover syntax, but PowerShell script, parent and network checks are relevant. Draft and high confidence are appropriate. |

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
- PsExec service binary executed (C:\Windows\PSEXESVC.exe)
- Command line matches executable path (no arguments)
- Alert triggered by SMB/Windows Admin Shares (T1021.002)
- Service Execution technique detected (T1569.002)
- 2.28-second detection latency

_Investigation queries:_
- `SELECT * FROM win_event WHERE event_id=4697 AND source_name='Service Control Manager' AND description LIKE '%PSEXESVC%'`
- `SELECT * FROM win_service WHERE name='PSEXESVC' AND status='running'`
- `SELECT * FROM win_file WHERE path='C:\Windows\PSEXESVC.exe' AND hash NOT IN (SELECT hash FROM known_good_files)`

_Draft message:_ We've detected a PsExec service binary execution on your system. Our analysis suggests this may be an attempted remote service execution. Please review the security controls and consider isolating the affected host.

> ⚑ AUTO: entities named but not found in the alert — **verify**: (C:\Windows\PSEXESVC.exe)
> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | N |
| confidence_calibrated(Y/N) | Y |
| reviewer_notes | Summary fully supported. The generic win_event/win_service/win_file SQL is not runnable Wazuh/Discover syntax, but service, process and file-hash checks are relevant. The draft is inappropriate because it suggests host isolation before authorization or maliciousness is confirmed; high confidence is supported by the observed PSEXESVC execution. |

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
**Assistant** — disposition `likely_true_positive` · confidence `medium` · technique `T1003.008`

_Summary:_
- Auditd detected read access to /etc/shadow by cron process (uid 0)
- Linux audit syscall 257 (open) succeeded for sensitive shadow file
- Process /usr/sbin/cron accessed /etc/shadow with root privileges
- Alert triggered by T1003.008 credential access technique
- Audit serial 73613, latency 2.428 seconds

_Investigation queries:_
- `SELECT * FROM auditd WHERE audit.file='\/etc\/shadow' AND audit.uid='0' AND audit.command='cron'`
- `SELECT * FROM cron_jobs WHERE user='root' AND command LIKE '%shadow%'`
- `SELECT * FROM file_access WHERE file_path='\/etc\/shadow' AND process_name='cron'`

_Draft message:_ We've detected unusual access to the /etc/shadow file by the cron service. This may indicate a credential access attempt, but we're investigating further.

> ⚑ AUTO: summary states a T-code — check it is evidence-based, not asserted.

| dimension | verdict |
|---|---|
| summary_supported(Y/N/partial) | Y |
| unsupported_statement_count(int) | 0 |
| queries_valid(Y/N) | N |
| queries_relevant(Y/N) | Y |
| draft_appropriate(Y/N) | Y |
| confidence_calibrated(Y/N) | N |
| reviewer_notes | Summary fully supported. The generic auditd/cron_jobs/file_access SQL is not runnable Wazuh/Discover syntax, but shadow-access and cron checks are relevant. Draft is appropriately cautious; medium-confidence likely_true_positive is not calibrated for the benign cron context. |
