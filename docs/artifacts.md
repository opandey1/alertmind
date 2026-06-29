# Lab artifacts (OVAs) & how they're distributed

Large binaries are **not** committed to this repository — they exceed Git's practical limits and the Windows image carries a licensed OS that must not be redistributed. This file is the manifest: where the artifacts live, how to verify them, and how to import them.

## Distribution (no submission portal)

There is no course upload portal for large files, so artifacts are distributed out-of-band and only *referenced* here:

- **Linux/Kali artifacts** (`wazuh-siem`, `linux-victim`, `attacker`) — built from freely available Ubuntu/Kali distributions; shared only with the program team for evaluation convenience. Hosted in a **private Google Drive folder shared with the program team's accounts**; links + checksums recorded below. (Alternatively, rebuild them from the repo per `docs/rebuild-guide.md` — no download needed.)
- **Windows artifact** (`win-victim`) — **not redistributed and not in this manifest.** The Windows VM is *rebuilt, not downloaded*: evaluators use the official free **Microsoft Windows 11 Enterprise Evaluation** download (90-day) and then follow `docs/rebuild-guide.md` §5 for Sysmon and Wazuh-agent setup. This avoids shipping a licensed OS entirely.
- **Credentials** — never stored here or in Git. Reset to your own value with `docs/runbooks/wazuh-password-reset.md`, or use the password shared out-of-band in the submission notes.

> **Before submission:** open the Google Drive folder in an incognito/private browser window (or from a non-owner account) to confirm the program team can download the files **without requesting access**. A wrong share setting is the most common reproducibility blocker.

## Manifest

| Artifact | Role | Source | SHA256 | Notes |
|---|---|---|---|---|
| `wazuh-siem.ova` | SIEM host | _TODO: Drive link_ | _TODO_ | Wazuh 4.14.5 all-in-one, Ubuntu 24.04.4 |
| `linux-victim.ova` | Linux endpoint | _TODO: Drive link_ | _TODO_ | auditd + Wazuh agent, Ubuntu 24.04.4 |
| `attacker.ova` | Attacker | _TODO: Drive link_ | _TODO_ | Kali + tooling |
| `win-victim` | Windows endpoint | MS Win11 Eval VM + `rebuild-guide.md` §5 | n/a | Not shipped (licensing); built by evaluator |

_Generate each checksum with:_ `sha256sum <file>.ova` _(Linux/macOS) or_ `Get-FileHash <file>.ova -Algorithm SHA256` _(PowerShell), then paste the value above._

**Verify after download** (compare against the manifest before importing):
```bash
sha256sum wazuh-siem.ova
sha256sum linux-victim.ova
sha256sum attacker.ova
```

## Import (VirtualBox)

1. **File → Import Appliance** → select the `.ova`.
2. On the settings screen, set **MAC Address Policy → "Include all network adapter MAC addresses"** ("Keep all MAC addresses"). This preserves the documented DHCP IPs (`10.0.2.15` manager, `10.0.2.4` / `10.0.2.7` endpoints).
3. If MAC addresses are regenerated instead, the DHCP IPs may shift — re-check the manager IP (`ip a` on `wazuh-siem`) and update each agent's manager address (`/var/ossec/etc/ossec.conf` `<address>` / the Windows agent `ossec.conf`), then restart the agents.
4. Attach the VM to the `LabNet` NAT Network (and add the Host-Only adapter to `wazuh-siem`) per `rebuild-guide.md` §3.

## Git hygiene

These patterns are git-ignored so binaries never get committed:

```gitignore
*.ova
*.ovf
*.vdi
*.vbox-prev
*wazuh-passwords.txt
wazuh-install-files.tar
```
