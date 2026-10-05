# C3 transport diagnostics — focused review submission

Status: awaiting focused review; offline preparation only. This does not repair
or explain the reported VM freeze, accept a Dashboard context result, approve
the earlier C2 fix, or release another original-VM/browser run.

## Reported failure and scope

Owner repeatedly reports `observation; operation=READ_RULES; category=TIMEOUT`
after Server authentication, before the public browser challenge. A later guest
sample showed about3 GiB available memory, no interval swapping, CPU99-100%
idle,32 GiB disk free and four active services with NRestarts0. The VM has4
vCPUs; the original and clone were not running simultaneously. This sample
does not establish conditions during the freeze or API responsiveness.

The correction adds opt-in client-side request-stage/timing diagnostics, not
broker instrumentation or live debugging. C3 opts in; standalone Server and
human-baseline clients default to the previous diagnostic output. Their reader
pins/manifests/builders are refreshed transitively because the shared source
changes; accepted H3 and historical packets/results must NOT be replayed or
rewritten. Existing TLS, route, response, graph and predicate checks remain.

## Review targets

- `collect_server_inventory.py`: only literal transport labels, bounded request
  number and integer milliseconds may be exported, never exception text, URL,
  headers, token or response. Unknown/malformed snapshot values are suppressed.
- TCP connect, TLS handshake and peer-pin failure must precede any HTTP headers.
  A failed wrong-name probe still needs the specific hostname-verification code.
- Request sending, response headers, bounded body read and decode are distinct.
  Timings freeze on the first exception before cleanup and stay unchanged when
  formatted later. Values cap at86400000ms; this is NOT a wait/deadline increase.
- No automatic retry, redirect, DNS/proxy routing, new authentication or read.
  Socket timeout stays min(10s, remaining120s), request budget100, body1 MiB,
  page100 and items1000. No partial inventory or challenge after catalog failure.
- The extracted `_exchange` retains the same HTTP sequence. It additionally
  closes the connected peer if HTTPConnection setup/remaining-budget evaluation
  fails before the connection owns that peer; inspect this narrow cleanup edge.
- No stale timings may accompany a subsequent successful request/graph check.
  Default clients and fake inventory clients retain prior operation/code/category
  messages without transport fields. C3 clears token references on failure;
  reference release is not guaranteed memory erasure.
- New public stage is `/root/alertmind-dashboard-context-transportdiag`; C2 still
  uses the reviewed controlling-terminal correction and refuses overwrites.
  The old stage, packet, JS and four installed derivation-file pins are preserved.

## Verification and execution boundary

Nine additive methods across the existing Server/context test files cover the
above paths with synthetic clocks, peers/HTTP framing and mocks only. Existing
offline TLS MemoryBIO and actual JS/Node sandbox tests remain in the suite.
Run both focused files plus the reused human-baseline tests and full offline CI.
The additive verification JSON records the exact refreshed packet and results.
No VM, API, browser session or real credential is used by these author checks.

77e19ee remains awaiting review on this same branch, especially its real Linux
PTY test (skipped locally on Windows; Linux CI must exercise it). Existing
unresolved review debt remains retained. Focused approval must cover both fixes,
the refreshed exact packet and the owner-attested account/factory-context
equivalence boundary. Only then seek a separate ONE-run original-VM release.
Do not execute old C3 as a workaround, increase waits, restart services, reset
credentials, add broad permissions or proceed with C4 without a public challenge.

P1-04/05/06 and Phase1 closure remain open. Actual issued-token HTTP401 retry
remains NOT TESTED; accepted H3 and scoped P1-03 are unchanged.
