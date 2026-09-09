# Broker TLS design evidence — 9 September 2026

Derived design, not a scan or remediation result. Source review `beb7884` was
approved by Claude and merged in PR #29 (`37629a1`). Its two evidence files
are unchanged. Repository drift for those inputs: none; current VM drift unknown.

## Bound local evidence

| ID and title | Repository path | SHA-256 of UTF-8 LF-normalized text |
|---|---|---|
| E1 — approved installed-byte TLS review | docs/reviews/dashboard-broker-control-flow-tls-2026-09-09.md | f31255cf22034824a965f04a0e38e23a81d76204752e14261cf8bebe4bc726e7 |
| E2 — nine matched files and package provenance | evidence/rbac/dashboard-broker-code-review-2026-09-09.json | 08b20bd54ef874236ab3f6275a4ad409f38bdc171a708181096cfaae68302262 |

Collection identity: concatenate the two rows, in the order above, as
`digest`, two ASCII spaces, repository path, LF; SHA-256 of the resulting
UTF-8 bytes is `f06674210409fcc8aee6b4b11de277e1d533ab5dab2df44d8d25c9dc6ce9385e`.
This normalized document identity is separate from E2's RAW vendor-file hashes.

I reopened the extracted, previously hash-matched 4.14.7 broker client.
Constructor lines 38–43 own the shared HTTPS agent; request builders 75–124
do not consult a host CA setting. Internal authentication 131–137 and requests
174–191 reach those same methods, including refresh on 401. The existing
review already identifies `/manager/info` and `/security/users/me` as internal
traffic; the design explicitly includes them, addressing Claude's trace nit
without rewriting the approved evidence.

## Public vendor research

Retrieved 9 September 2026; no vendor source installed or executed.

- [Current Wazuh release index](https://documentation.wazuh.com/current/release-notes/index.html)
  lists 4.14.7 at the top of its 4.x table. This is a documentation observation,
  not proof that no other build/backport exists.
- [Dashboard installation](https://documentation.wazuh.com/current/installation-guide/wazuh-dashboard/step-by-step.html)
  distinguishes Indexer `opensearch.ssl` settings from the Server host entries.
  Those Indexer settings are not a demonstrated override for the separate
  plugin axios client. Browser-facing `server.ssl` is a third connection.
- [Version compatibility](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/troubleshooting.html)
  requires matching Server/Dashboard major and minor versions. Do not install
  a development plugin into this 4.14 lab based on a search result.
- Upstream `main` resolved through GitHub's public commit API to
  `a73417bc36794ed1175ca3cc8c6974c1a5322afa`. At that revision,
  [server-api-client.ts](https://github.com/wazuh/wazuh-dashboard-plugins/blob/a73417bc36794ed1175ca3cc8c6974c1a5322afa/plugins/wazuh-core/server/services/server-api-client.ts)
  constructs host-specific agents for both authentication and requests. A
  configured CA file enables peer verification; the no-CA default is still false.
  The source comment mentions `verify_ca`, but executable CA-loading logic is
  the relevant evidence, not a proposed 4.14 configuration switch.
- The same revision's
  [core package metadata](https://github.com/wazuh/wazuh-dashboard-plugins/blob/a73417bc36794ed1175ca3cc8c6974c1a5322afa/plugins/wazuh-core/package.json)
  declares version 5.1.0 and platform 3.6.0. This is not evidence of support in
  the installed 4.14.7/2.19.5 package, nor a validated upgrade candidate.

SHA-256 of fetched UTF-8 source text at that immutable revision:

| Source | Digest |
|---|---|
| plugins/wazuh-core/server/services/server-api-client.ts | 1fafae0dda3e375c273f157b4881402a941528225bd90989b26aabd17a4b1c9b |
| plugins/wazuh-core/server/services/manage-hosts.ts | e22ca02f2921e4e1088c1c2eea4069bbf70ba615f1e1e93931df7a2d6bf01efe |
| plugins/wazuh-core/package.json | 9ed9b06d262269fccb9eb9ca110242cff99b7c74375ce1fb11958eaaea8dafd1 |

Conclusion: no supported configuration-only fix or compatible released upgrade
was established for the observed package in this research. That bounded result
does not assert the absence of vendor support. A future vendor-supported
4.14-compatible fix takes priority over maintaining our own patch.

## Checksum follow-up and limits

Local SHA-512 of the previously matched .deb:
`008f0aecf6730abf6308dc6b9375d9be103058b268acc85e7db93b7d5845c4f4436f2e59d009d3700d8b8fb2ab89d8d599728f602f1eec2e7e99df7edde239ea`.
Claude reported an independent match to the vendor sidecar. This author's
request to the [adjacent .deb.sha512 URL](https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_4.14.7-1_amd64.deb.sha512)
returned AccessDenied, so no new vendor-checksum verification is claimed here.
A checksum obtained from the same distribution origin is not an APT-signature
attestation. The approved E2 evidence remains unchanged.

No VM files, credentials, cookies, private keys, raw alerts or authenticated
responses were requested. Three package-only connective files remain distinct
from the nine owner-reported installed matches. No live state is re-attested.
