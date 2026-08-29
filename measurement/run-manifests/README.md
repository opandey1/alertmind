# Run manifests

Run manifests live outside `assistant/outputs/runs/` because run directories are
immutable evidence. A manifest may describe an existing run, but it must never
rewrite or repair the run's own audit log.

The two Qwen manifests currently recorded here are **pre-commit candidates**,
not the accepted final benchmark pair. Their audit logs embed `eb03b83`, which
predates the uncommitted code used for inference. Commit `9ac13c1` is a
post-run snapshot of the recovered run-producing source and tests; it was not
the checked-out commit at execution time. A provenance-clean rerun on committed
code is still required before publishing the final three-model comparison.

Audit-log integrity uses SHA-256 over newline-normalized UTF-8 content: decode
as UTF-8, replace CRLF and lone CR with LF, then encode as UTF-8 without a BOM.
This keeps verification stable across Windows and Linux checkouts.
