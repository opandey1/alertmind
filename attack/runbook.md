# AlertMind — Attack Simulation Runbook

Reproducer commands for each of the 24 custom detection rules. Referenced from report §7. The table below separates **rule-firing evidence** from **exact-command provenance**, so a reconstructed command is not presented as though it were preserved verbatim from shell history.

**Lab only.** Every command runs inside the isolated VirtualBox lab (`LabNet` NAT network) against `win-victim` / `linux-victim`. No command exploits a known software vulnerability: the triggers exercise legitimate operating-system features or dual-use administrative tooling. Identifiers are therefore **MITRE ATT&CK techniques, not CVEs** (report §7).

All 24 **rules** were confirmed firing during Week 1–2 validation (`WEEKLOG.md`). For corpus-linked and evidence-verified cases, the alert/evidence record establishes the detected behaviour. For seven rules with no alert selected into the frozen corpus, the reproducer command was reconstructed from validation notes; the rule-firing evidence remains retained, but the exact command should be re-run before an examiner demonstration. Where a trigger produced an alert that entered the frozen 20-alert benchmark corpus, the alert ID is given so the trigger traces to a scored result.

**Payload naming caveat.** Test artifacts are deliberately named `amtest*` / `AM-*` so they are easy to find and clean up. That self-labelling is the source of the A18 construct-validity limitation in report §11 — a real adversary would not label a payload as a test.

---

## Coverage at a glance

| Rule | Technique | Trigger (summary) | Validation scope | Command provenance | Corpus alert |
|---|---|---|---|---|---|
| 100100 | T1003.008 | read `/etc/shadow` | direct file-access behaviour | evidence-verified; corpus link is benign-only | A20 *(benign FP: cron)* |
| 100101 | T1136 | `useradd` | direct account creation | corpus-linked | A13 |
| 100102 | T1548.003 | write `/etc/sudoers.d/` | path-write detection only; comment grants no privilege | corpus-linked | A09 |
| 100103 | T1053.003 | write `/etc/cron.d/` | direct scheduled-task creation | corpus-linked | A01 |
| 100104 | T1543.002 | write systemd unit | path-write detection only; unit not enabled or started | evidence-verified; corpus link is benign-only | A12 *(benign FP: snapd)* |
| 100105 | T1037 | write `/etc/init.d/` script | executable script placed; not enabled at boot | corpus-linked | A04 |
| 100106 | T1546.004 | write `/etc/profile.d/` | path-write detection only; comment has no persistence effect | reconstructed from validation notes; rule firing evidenced | — |
| 100107 | T1574.006 | write `/etc/ld.so.preload` | path-write detection only; referenced library is non-functional | reconstructed from validation notes; rule firing evidenced | — |
| 100108 | T1547.006 / T1014 | `modprobe` kernel module | module-load behaviour; not a rootkit | corpus-linked | A17 |
| 100109 | T1548.001 / T1222.002 | setuid bit via `chmod 4755` | direct permission change | evidence-verified; corpus link is benign-only | A07 *(benign FP: dconf)* |
| 100110 | T1562.001 | write `/etc/audit/rules.d/` | path-write detection only; audit rules not reloaded | reconstructed from validation notes; rule firing evidenced | — |
| 100111 | T1070 | open or truncate `/var/log/btmp` | A16 validates the audit watch via append-open; truncation is the stronger semantic simulation | A16 from executed append-open form; truncation is an improved reproducer | A16 |
| 100112 | T1070.006 | timestomp via `touch -t` | direct timestamp modification | reconstructed from validation notes; rule firing evidenced | — |
| 100113 | T1552.004 | read `/root/.ssh/id_rsa` | direct private-key-path access when the file exists | reconstructed from validation notes; rule firing evidenced | — |
| 100114 | T1098 *(broad)* | append `/etc/ssh/sshd_config` | path-write detection only; comment does not change access | reconstructed from validation notes; rule firing evidenced | — |
| 100115 | T1195.001 *(tentative)* | append `/etc/apt/sources.list` | path-write detection only; comment does not alter a repository | reconstructed from validation notes; rule firing evidenced | — |
| 100116 | T1098.004 | append `authorized_keys` | authorized-keys write using a non-functional synthetic key | corpus-linked | A06 |
| 100200 | T1566 / T1059 | Office-parent-name simulation | parent-image-name matching only | corpus-linked | A10 |
| 100201 | T1059.001 | encoded PowerShell | direct encoded execution with a benign test payload | corpus-linked | A18 |
| 100202 | T1218 (.005) | `mshta.exe` | direct LOLBin execution; no malicious payload | corpus-linked | A03 |
| 100203 | T1003.001 | `comsvcs.dll MiniDump` of LSASS | direct credential-dump behaviour under lowered protection | corpus-linked | A14 *(+ benign FPs A08, A11)* |
| 100204 | T1021.002 / T1569.002 | PsExec against loopback | local service-execution pattern; not lateral movement | corpus-linked | A19 |
| 100205 | T1547.001 | Run-key write | direct persistence write | corpus-linked | A05 *(+ benign FP A02)* |
| 100206 | T1048 / T1071.004 | long-label DNS query | heuristic firing only; not tunnelling or exfiltration | corpus-linked | A15 |

Seven rules — 100106, 100107, 100110, 100112, 100113, 100114, 100115 — were validated end-to-end but produced no alert selected into the 20-alert benchmark corpus. They are detection-verified, not benchmark-scored; their listed command text is reconstructed from validation notes and should be re-run before an examiner demonstration.

**How the benign salt relates to the rules.** Rules 100203 and 100205 contribute both an attack alert and benign false-positive alert(s) to the benchmark. Rules 100100, 100104 and 100109 contribute a benign corpus alert, while their separate attack-like triggers were used for detection validation but were not selected into the benchmark. Together, the six false positives (A02, A07, A08, A11, A12, A20) are the benign salt that makes the assistant evaluation meaningful (report §9.1).

---

## Windows — `win-victim` (Sysmon)

### 100200 — Office / shell spawns child process · T1566 → T1059 *(W1)*
Produced corpus alert **A10**. Office-spawn **simulation**: a copied `cmd.exe` renamed to imitate an Office parent image, then spawning a shell child. This validates parent-image matching; it does not detonate a real macro (report §7).
```powershell
Copy-Item C:\Windows\System32\cmd.exe "$env:TEMP\winword.exe"
Start-Process "$env:TEMP\winword.exe" '/c cmd.exe /c whoami'
```
**Cleanup**
```powershell
Remove-Item "$env:TEMP\winword.exe"
```

### 100201 — Encoded PowerShell · T1059.001 *(W2)*
Produced corpus alert **A18**. The decoded payload is the self-identifying string `AlertMind Encoded PowerShell Test` — the A18 construct-validity case (report §11, Appendix A.3).

Method 1 — encode and execute in one line:
```powershell
$e=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('AlertMind Encoded PowerShell Test'))
powershell -NoProfile -EncodedCommand $e
```
Method 2 — build the encoded string, then run it:
```powershell
$Command = 'Write-Output "AlertMind Encoded PowerShell Test"; whoami; hostname'
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
$Encoded
powershell -NoProfile -EncodedCommand $Encoded
```
**Cleanup** — none required.

### 100202 — LOLBin: mshta · T1218 (.005) *(W3)*
Produced corpus alert **A03**.
```powershell
mshta.exe "about:blank"        # then close the window
```
Or via Atomic Red Team:
```powershell
Invoke-AtomicTest T1218.005
```
**Cleanup** — close the mshta window.

### 100203 — LSASS process access (credential dumping) · T1003.001 *(W5)*
Produced corpus alert **A14**. Requires `RunAsPPL=0` in the lab — a protection deliberately lowered, **not** a vulnerability exploited (report §7). The granted-access mask `0x1fffff` is what matches the tuned rule.
```powershell
$p=(Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump $p C:\Windows\Temp\l.dmp full
```
Variant used (alternate dump path):
```powershell
$p=(Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump $p C:\Users\user1\Desktop\project-alertmind\l.dmp full
```
**Cleanup**
```powershell
Remove-Item C:\Windows\Temp\l.dmp
```
> The benign counterparts caught by this same rule — **A08** (Windows Defender `MsMpEng.exe`, mask `0x3600`) and **A11** (`wazuh-agent.exe`, mask `0x1fffff`) — are naturally-occurring security-tool reads, not triggered commands. They are the two hardest false positives in the corpus. Tuning took three rounds: ~557 false positives untuned, then a positive-mask allowlist that missed `0x0xxx` dump masks, then the final negative exclusion (Appendix F).

### 100204 — PsExec-style service execution · T1021.002 / T1569.002 *(W6)*
Produced corpus alert **A19**. Run against loopback, so this simulates the service-execution *pattern*, not remote lateral movement (report §7).
```powershell
# Download PSTools (Sysinternals)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile "$env:TEMP\PSTools.zip"
Expand-Archive "$env:TEMP\PSTools.zip" -DestinationPath "$env:TEMP\PSTools" -Force

# Run PsExec against localhost — creates PSEXESVC.exe and fires 100204
& "$env:TEMP\PSTools\psexec.exe" -accepteula \\localhost -s cmd /c whoami
```
**Cleanup** — PsExec removes `PSEXESVC` on exit; then:
```powershell
Remove-Item "$env:TEMP\PSTools.zip","$env:TEMP\PSTools" -Recurse -Force
```
> Known limitation (Appendix F): `impacket-psexec` evades this name-based rule by uploading a randomly-named service binary. The behavioural built-ins 92218 / 92307 / 92650 catch that variant — an indicator-vs-behavioural detection lesson.

### 100205 — Run-key persistence · T1547.001 *(W4)*
Produced corpus alert **A05**.
```bat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v AMTest /d calc.exe /f
```
**Cleanup**
```bat
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v AMTest /f
```
> Benign counterpart **A02**: Microsoft Edge writing its own auto-launch Run key. The rule was re-narrowed during tuning to exclude a `RunNotification` prefix-match false positive (Appendix F).

### 100206 — Long-label DNS (tunnelling heuristic) · T1048 / T1071.004 *(W7)*
Produced corpus alert **A15**. Fires the long-label heuristic; it does not perform real tunnelling or exfiltration (report §7).

**Corpus provenance — commands that were executed.** A15's first DNS label was 82 characters: 55 repeated characters plus `-am-t1071dns-20260706214941`. That exceeds the DNS protocol's 63-character label limit, but Windows emitted the attempted query, Sysmon logged it, and rule 100206 fired. The commands are retained exactly as executed rather than rewritten after the fact.

Method 1 — `Resolve-DnsName` + `nslookup`, with run metadata appended:
```powershell
$RunId = "AM-T1071DNS-$(Get-Date -Format yyyyMMddHHmmss)"
$Start = (Get-Date).ToUniversalTime().ToString("o")
$LongLabel = ("a" * 55) + "-" + $RunId.ToLower()
$Domain = "$LongLabel.alertmind-lab.invalid"
Resolve-DnsName $Domain -ErrorAction SilentlyContinue
nslookup $Domain
$End = (Get-Date).ToUniversalTime().ToString("o")
"$RunId,T1071.004/T1048,100206,$Start,$End,,Long DNS label test using $Domain" | Out-File C:\Users\user1\Desktop\project-alertmind\timing-log.csv -Append -Encoding utf8
Write-Host "RUN_ID=$RunId"
Write-Host "DOMAIN=$Domain"
```

Method 2 — via `cmd.exe`, with an additional ICMP resolution:
```powershell
$RunId = "AM-T1071DNS-$(Get-Date -Format yyyyMMddHHmmss)"
$Domain = ("b" * 55) + "-$($RunId.ToLower()).alertmind-lab.invalid"
cmd.exe /c "nslookup $Domain"
cmd.exe /c "ping -n 1 $Domain"
Write-Host $RunId
Write-Host $Domain
```

**Cleanup** — none required; the `.invalid` TLD never resolves.

---

## Linux — `linux-victim` (auditd)

All Linux triggers run as an interactive user (`auid >= 1000`), which is what the tuned audit rules scope to.

### 100100 — `/etc/shadow` read · T1003.008 *(L1)*
```bash
sudo cat /etc/shadow
```
**Cleanup** — none required.
> Benign counterpart **A20**: a `cron` PAM job reading `/etc/shadow` with `auid` unset. This is the documented residual false positive; the planned tune scopes the audit rule to `auid>=1000 -F auid!=unset` (report §5, `WEEKLOG` Week 1).

### 100101 — Account creation · T1136 *(L3)*
Produced corpus alert **A13**.
```bash
sudo useradd amtest
```
**Cleanup**
```bash
sudo userdel -r amtest 2>/dev/null
```

### 100102 — Sudoers modification · T1548.003 *(L4)*
Produced corpus alert **A09**.
```bash
echo '# amtest' | sudo tee -a /etc/sudoers.d/amtest >/dev/null
```
**Cleanup**
```bash
sudo rm -f /etc/sudoers.d/amtest
```

### 100103 — Cron persistence · T1053.003 *(L5)*
Produced corpus alert **A01**.
```bash
echo '* * * * * root /usr/bin/id >/tmp/amtest-cron.out 2>&1' | sudo tee /etc/cron.d/amtest >/dev/null
```
**Cleanup**
```bash
sudo rm -f /etc/cron.d/amtest /tmp/amtest-cron.out
```

### 100104 — systemd unit write · T1543.002 *(L6)*
```bash
sudo touch /etc/systemd/system/amtest.service
```
**Cleanup**
```bash
sudo rm -f /etc/systemd/system/amtest.service
```
> Benign counterpart **A12**: `snapd` writing a legitimate `snap-snapd-*.mount` unit.

### 100105 — init.d / rc script persistence · T1037 *(L17)*
Produced corpus alert **A04**.
```bash
RUNID="AM-LIN-T1037-$(date -u +%Y%m%d%H%M%S)"
TARGET="/etc/init.d/amtest_t1037_$RUNID"
printf '#!/bin/sh\n# %s\nexit 0\n' "$RUNID" | sudo tee "$TARGET" >/dev/null
sudo chmod +x "$TARGET"
echo "RUNID=$RUNID"
echo "TARGET=$TARGET"
```
**Cleanup**
```bash
sudo rm -f /etc/init.d/amtest_t1037_AM-LIN-T1037-*
```

### 100106 — profile.d persistence · T1546.004 *(L7)*
```bash
echo '# amtest' | sudo tee -a /etc/profile.d/amtest.sh >/dev/null
```
**Cleanup**
```bash
sudo rm -f /etc/profile.d/amtest.sh
```

### 100107 — `ld.so.preload` hijack · T1574.006 *(L8)*
```bash
echo '/tmp/amtest.so' | sudo tee -a /etc/ld.so.preload >/dev/null
```
**Cleanup**
```bash
sudo sed -i '\|/tmp/amtest.so|d' /etc/ld.so.preload
```

### 100108 — Kernel module load · T1547.006 / T1014 *(L9)*
Produced corpus alert **A17**.
```bash
sudo modprobe dummy
```
**Cleanup** — none recorded; `sudo modprobe -r dummy` unloads the module if desired.

### 100109 — setuid bit set · T1548.001 / T1222.002 *(L10)*
```bash
cp /bin/true /tmp/amtest
sudo chown root:root /tmp/amtest
sudo chmod 4755 /tmp/amtest
```
**Cleanup**
```bash
sudo rm -f /tmp/amtest
```
> Benign counterpart **A07**: `dconf-service` writing under `~/.config/dconf/user`.

### 100110 — audit-rule tampering · T1562.001 *(L11)*
```bash
sudo touch /etc/audit/rules.d/zz-amtest.rules    # write only — do NOT reload
```
**Cleanup**
```bash
sudo rm -f /etc/audit/rules.d/zz-amtest.rules
```

### 100111 — Log tampering (`btmp`) · T1070 *(L12)*
Produced corpus alert **A16** using the original thin simulation:
```bash
sudo bash -c ': >> /var/log/btmp'
```
The shell opens `btmp` with write/append flags, which triggers the auditd `-p wa` watch and proves the sensor-to-rule path. The `:` builtin writes no data, however, so A16 is evidence of a successful **append-open detection**, not evidence that log content was actually removed or altered.

**Improved semantic reproducer — actual truncation with backup and restore:**
```bash
sudo cp --preserve=all /var/log/btmp /tmp/btmp.alertmind.bak
sudo truncate -s 0 /var/log/btmp
```
**Cleanup** — restore the lab file immediately after confirming the alert:
```bash
sudo cp --preserve=all /tmp/btmp.alertmind.bak /var/log/btmp
sudo rm -f /tmp/btmp.alertmind.bak
```
> This is destructive outside a disposable lab. Use only inside the isolated VM and restore the clean snapshot after validation.

### 100112 — Timestomping · T1070.006 *(L13)*
```bash
touch /tmp/amtest_ts
touch -t 202001010000 /tmp/amtest_ts
```
**Cleanup**
```bash
rm -f /tmp/amtest_ts
```

### 100113 — Private-key access · T1552.004 *(L14)*
```bash
sudo cat /root/.ssh/id_rsa 2>/dev/null
sudo ls -a /root/.ssh
```
**Cleanup** — none required.
> This rule watches `/root/.ssh/` broadly. Rule **100116** is implemented as a child of it (`if_sid 100113`) narrowing on `authorized_keys` writes — the fix for the overlapping-auditd-watch problem, where two `-w` watches on the same path collapse to one key (Appendix F).

### 100114 — sshd_config modification · T1098 *(broad)* *(L15)*
```bash
echo '# amtest' | sudo tee -a /etc/ssh/sshd_config >/dev/null
```
**Cleanup** — remove **before** restarting sshd:
```bash
sudo sed -i '/# amtest/d' /etc/ssh/sshd_config
```

### 100115 — APT repository config · T1195.001 *(tentative mapping)* *(L16)*
```bash
echo '# amtest' | sudo tee -a /etc/apt/sources.list >/dev/null
```
**Cleanup**
```bash
sudo sed -i '/# amtest/d' /etc/apt/sources.list
```
> The T1195.001 (supply-chain compromise) mapping is marked tentative in the detection crosswalk — repository-config tampering is adjacent to, but not a clean instance of, a compromised software dependency.

### 100116 — `authorized_keys` persistence · T1098.004 *(L2)*
Produced corpus alert **A06**.
```bash
sudo bash -c 'echo "ssh-ed25519 AAAAC3TESTalertmind-$(date +%s) attacker@evil" >> /root/.ssh/authorized_keys'
```
**Cleanup**
```bash
sudo sed -i '/AAAAC3TESTalertmind/d' /root/.ssh/authorized_keys
```

---

## Teardown checklist

Run every cleanup command above, then confirm nothing remains:

```bash
# Linux
ls /etc/cron.d/amtest /etc/sudoers.d/amtest /etc/profile.d/amtest.sh \
   /etc/systemd/system/amtest.service /etc/audit/rules.d/zz-amtest.rules \
   /tmp/amtest* /tmp/btmp.alertmind.bak 2>/dev/null
grep -n 'amtest' /etc/ssh/sshd_config /etc/apt/sources.list /etc/ld.so.preload 2>/dev/null
sudo ls /etc/init.d/ | grep amtest
getent passwd amtest
```

```powershell
# Windows
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v AMTest
Test-Path "$env:TEMP\winword.exe", "C:\Windows\Temp\l.dmp", "$env:TEMP\PSTools"
```

Then restore the VM snapshots to return `win-victim` / `linux-victim` to their clean post-setup state. If `RunAsPPL` was set to `0` for the LSASS validation, restore it to `1` and reboot.
