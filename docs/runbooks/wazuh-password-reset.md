# Runbook — reset the Wazuh `admin` password

**Applies to:** `wazuh-siem` (Wazuh 4.14.5 all-in-one)
**Use when:** you imported the lab OVA (or lost the generated password) and need dashboard access without a shared secret. Resetting to your own value means **no credential ever has to be transmitted or stored** — the recommended path for evaluators.

> Verified against Wazuh 4.14 (the `wazuh-passwords-tool.sh` workflow). The tool auto-updates the dependent components in an all-in-one deployment.

## Password rules (the tool will reject otherwise)
- 8–64 characters, at least one uppercase, one lowercase, one number, and one symbol from `. * + ? -`.
- **Avoid `$`** (and other shell metacharacters) to skip escaping headaches.

## Procedure

1. **Log out of the Wazuh dashboard in the browser first.** Stale session cookies cause errors after a password change.

2. On `wazuh-siem`, locate the passwords tool — use the embedded copy if present, otherwise download the matching version:
   ```bash
   cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools/
   if [ ! -f wazuh-passwords-tool.sh ]; then
     sudo curl -sO https://packages.wazuh.com/4.14/wazuh-passwords-tool.sh
   fi
   ```

3. Change the `admin` (dashboard/indexer) password:
   ```bash
   sudo bash wazuh-passwords-tool.sh -u admin -p '<NEW_PASSWORD>'
   ```
   In an all-in-one deployment the tool updates the password where the dependent services need it. **Read the tool's output** — if it instructs you to restart additional components, do so.

4. Restart the dashboard (and Filebeat, to be safe):
   ```bash
   sudo systemctl restart wazuh-dashboard
   sudo systemctl restart filebeat
   ```

5. Log in at `https://<wazuh-siem Host-Only IP>` with `admin` / `<NEW_PASSWORD>`.

## Optional — reset Wazuh API users only if your assistant/API checks require them

The dashboard/indexer `admin` login and the Wazuh **API** users (`wazuh`, `wazuh-wui`) are *different credential domains*. For dashboard/indexer login you only need `admin` (above). Touch the API users only if a workflow specifically depends on them.

```bash
# advanced / only if needed:
sudo bash wazuh-passwords-tool.sh -A -u wazuh -p '<NEW_API_PASSWORD>'
```

To regenerate **all** indexer user passwords at once (prints each new value):

```bash
sudo bash wazuh-passwords-tool.sh -a
```

> When the read-only `assistant-svc` identity is built (Week 3), give it its **own** dedicated API credential and document it separately — do not reuse the built-in `wazuh`/`wazuh-wui` users for the assistant.

## Verify
```bash
# dashboard login works in the browser, and the indexer answers with the new creds:
curl -sk -u admin:'<NEW_PASSWORD>' "https://localhost:9200/_cluster/health?pretty" | grep status
```

## Notes
- Never commit the new password. If you must record it, keep it in the out-of-band submission notes only.
- If login still fails after a change, confirm you logged out of the old browser session, and that `wazuh-dashboard` restarted cleanly (`systemctl status wazuh-dashboard`).
- For deeper service-startup problems, see [`wazuh-recovery.md`](wazuh-recovery.md).
