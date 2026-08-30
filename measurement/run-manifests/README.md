# Run manifests

Run manifests live outside `assistant/outputs/runs/` because run directories are
immutable evidence. A manifest may describe an existing run, but it must never
rewrite or repair the run's own audit log.

The accepted Qwen benchmark pair is:

- `20260830_054251_ollama_oper_baseline` — operational view.
- `20260830_070142_ollama_eval_baseline` — label-reduced evaluation view.

Both audit logs contain 20 rows from committed merge `7ca2543`; both manifests
are marked `final` and pin the effective request configuration, normalized
audit hash, model observation, aggregate metrics and raw performance figures.
The post-run model capture is
`qwen3-8b-ollama-show-final-20260830.txt`.

The August 27 manifests remain **pre-commit candidates** and are retained for
history, not reporting. Their audit logs embed `eb03b83`, which predates the
then-uncommitted Qwen execution code. Commit `9ac13c1` is only a post-run source
snapshot. The accepted August 30 pair supersedes those candidates without
rewriting or deleting them.

The accepted pair matches the candidates on all aggregate score dimensions,
but matches raw response hashes in 0/20 alerts in each view. That is one
observation of score stability across two stochastic samples, not evidence of
determinism; seed 42 does not guarantee byte-identical responses.

Audit-log integrity uses SHA-256 over newline-normalized UTF-8 content: decode
as UTF-8, replace CRLF and lone CR with LF, then encode as UTF-8 without a BOM.
This keeps verification stable across Windows and Linux checkouts.
