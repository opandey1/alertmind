# Dashboard broker TLS — offline candidate, not deployed

This is Choice 1 of the [approved design](../../../docs/hardening/broker-tls/hardening.md).
The existing shared client disables TLS peer verification for both internal
and scoped authentication/requests. This package builds a candidate and tests
that boundary; **it does not change the VM or authorize a Dashboard restart**.

## Build and provenance

Use a disposable workstation directory, not the VM or an installation directory.
Obtain the official `wazuh-dashboard_4.14.7-1_amd64.deb` separately. The builder
does not download anything, execute a package script, import vendor code, or
overwrite an output directory. It verifies the complete package SHA-256 before
parsing the archive, verifies the exact client hash, transforms one exact block,
and creates `original.cjs`, `candidate.cjs`, the packaged axios dependency graph
and a manifest. A temporary uncompressed archive is automatically removed.
On failure, never use a partial output: choose a new output directory.

From the repository root, with Python 3.10+:

```text
python -B siem/rbac/broker_tls/build_candidate.py --deb /path/to/wazuh-dashboard_4.14.7-1_amd64.deb --output /new/scratch/candidate
```

`contract.json` pins the input, candidate, LF-normalized policy, packaged primary
Node binary/header and the entire extracted-file manifest. Unknown versions,
modified sources, a second application and output drift fail closed. Contract
changes need independent review, not automatic hash refresh after failure.
Do not commit extracted vendor files, test keys, downloaded runtimes or packages.
The original vendor license notice remains in the generated client.

The official [SHA-512 checksum](https://packages.wazuh.com/4.x/checksums/wazuh/4.14.7/wazuh-dashboard_4.14.7-1_amd64.deb.sha512)
was independently retrieved on 9 September and matched the local package:
`008f0aecf6730abf6308dc6b9375d9be103058b268acc85e7db93b7d5845c4f4436f2e59d009d3700d8b8fb2ab89d8d599728f602f1eec2e7e99df7edde239ea`.
This closes the earlier wrong-location checksum lookup, without rewriting that
historical research record. At the reviewed upstream development revision,
`verify_ca` is passed/resolved but not read by `_createHttpsAgent`; a readable
`ca` path is its operative switch, not a usable settings-only fix here.

The nine matched files are **six JavaScript files and three JSON manifests**.
The broker client's final inline source-map line is 19,084 characters (line
194 of 194) and embeds unpatched TypeScript. The builder removes that whole
line, including `sourcesContent`, rather than shipping a misleading map.
The expected output hash includes this removal.

## Candidate boundary

- One shared HTTPS agent verifies the certificate and hostname using a bounded,
  pinned public Server certificate. No Indexer CA, private key, permissive
  identity callback, ambient trust fallback or per-request insecure fallback.
- The fixed Linux trust path is
  `/etc/wazuh-dashboard/certs/alertmind-server-api.pem`. All ancestors must be
  root-owned, non-symlink directories without group/other write permission;
  the final file has equivalent checks and a no-follow open/readback check.
  This does not contain root or an already compromised Node process.
- Every constructed axios request must retain `https://localhost:55000` and
  a valid raw URL. Localhost resolves narrowly to loopback IPv4 while keeping
  its DNS TLS identity. Flattened Host/proxy-auth overrides are rejected.
- Proxies and redirects are disabled at the shared request boundary, including
  authentication and retries. Request timeout is 30 seconds; live workload
  suitability remains unaccepted. Ordinary body/query/content-type and existing
  Authorization/cookie semantics remain intact.
- Errors discard axios config/request/cause objects. Allowlisted transport codes
  and HTTP status/data remain for vendor controllers and the 401 refresh path.
  Upstream HTTP error data is still application data, **not guaranteed redacted**;
  callers must not treat arbitrary error bodies as safe logs.
- Trust is loaded at construction. Updates require an intentional guarded
  restart; this candidate does not watch files. Startup/update guards and
  atomic deployment/rollback are a later package, not implemented here.

## Explicit synthetic tests

On a disposable workstation with free loopback TCP 55000, 55001 and 55002,
provide Python with `cryptography` and an explicit Node executable. Do not run
this on the Wazuh VM: its Server API uses the same port. The runner creates
short-lived synthetic certificates/keys in an automatically deleted temporary
directory. No live configuration, passwords, tokens or certificate files are
read. It starts only local IPv4 test servers and sends fabricated values.

```text
python -B siem/rbac/broker_tls/run_fixture.py --stage /scratch/candidate --node /path/to/node --run-synthetic
```

This loads the actual generated client and the **packaged axios 1.12.2**, with
native Node TLS. Host/context/cookie suppliers are stubs. Because the author
host is Windows, Linux root-ownership/no-follow metadata is an explicit adapter;
the fixed certificate pin is substituted **in memory only** with the synthetic
anchor pin. Neither production candidate bytes nor `contract.json` are changed.
The original control uses an IPv4-first DNS preference. The candidate supplies
its own narrow resolver. Output reports these proof limits.

Six mutation controls must lose their protection: verification set back to
false, origin validation removed, redirects enabled, proxy inheritance
restored, load-time anchor hostname check removed, and fixed resolver removed.
The last two use construction/callback assertions, not network leaks. For the
transport controls, server counters establish that rejected peers/origins receive
no application credentials and mutations cause observable arrivals. The harness
never prints those credentials or raw requests.

The September 12 follow-up adds a valid, correctly pinned wrong-SAN anchor and
direct resolver checks (plain options, `all`, callback-only, and non-localhost
rejection). Proxy cleanup and hostile tests cover standard and npm variable
families in lower/uppercase, including exclusion settings. The HTTP-only proxy
variables are checked against the actual dependency's HTTP resolver; they do
not route this HTTPS-only client. `npm_config_no_proxy` is honored by the
packaged dependency, whereas `npm_config_noproxy` is not. Windows environment
names are case-insensitive; native Linux casing validation remains for review.
The updated fixture has 16 groups; see [follow-up verification](verification-2026-09-12.json).
The original [verification record](verification.json) preserves the 14-group run.

Ten pure-Python builder guards run in ordinary CI with no download or network.
The opt-in TLS fixture is **not** included in the CI badge's test count.

## Acceptance still blocked

The package primary Node binary/header identify **18.19.0**; its manifest
records the Linux binary digest. Package axios resolves its own nested
`proxy-from-env` **1.1.0**, not the unrelated root 1.0.0 copy.
The author tested official, hash-verified Windows Node 18.19.0 and also Node
24.19.0; **neither is execution of the packaged Linux binary**. The package
contains a fallback runtime too; the VM's selected runtime remains unobserved.

Claude's September 10 approval of `e6c5419` reports the original 14-group fixture
passing on Linux Node 22.22.2/OpenSSL 3.5.5 after clearing npm proxy settings.
This is reviewer-reported Linux compatibility evidence, not execution of the
packaged Node 18.19.0 or native root/no-follow filesystem proof. It does not
approve live deployment or constitute a Linux run of this updated 16-group fixture.

Before a live apply package: independently review this change, validate the
packaged Linux runtime and native filesystem checks, establish suitability of
the actual pinned self-signed Server certificate, agree timeout/performance
tolerances, implement/rehearse startup drift guards and interrupted rollback,
and obtain explicit downtime approval. Stop the Dashboard before any future
client change; stopping Streamlit alone does not stop background authentication.
Restoring vulnerable original bytes is not authorization to restart them.

No new VM output, role/grant, credential, SSH change or model rerun is requested
by this offline deliverable. Real broker context, admin/saved-object continuity
and later analyst acceptance remain separate gates.
