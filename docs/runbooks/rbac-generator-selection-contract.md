# Generator selection contract — upstream model, installed equivalence pending

Status: offline author implementation under the owner's independent-review
deferral. No execution packet, approved reference or maintenance admission.
The clone may remain off; do not repeat the completed Gate 2A/2B/2C diagnostic.

## Reference and evidence boundaries

The review reference is upstream systemd **v259.5**, commit
[`b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a`](https://github.com/systemd/systemd/commit/b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a).
The source inspected through the v259.5 tag is linked below at that commit.
No tag signature was verified here. This is not Ubuntu's patched source,
build configuration or proof of the code loaded by the installed PID 1.
The [retained image candidate](../../evidence/rbac/pid1-image-reference-candidate-v1.md)
matches historical reports, but neither authenticates loaded libraries nor
settles current manager environment, generator paths or host identity.

The separate [host runtime-artifact report](../../evidence/rbac/systemd-runtime-archive-host-smoke-2026-09-30.md)
now checks the same signed index's systemd and libsystemd-shared packages,
matches the manager candidate and records static ELF metadata for manager,
core and shared images. The ten NUL-terminated path/override suffix observations
in the shared image are not call-site or compiled path-construction proof.
No library is loaded, and installed loaded-library/current-path equivalence
and independent approval remain open.

## Path construction

[`generator_binary_paths_internal()`](https://github.com/systemd/systemd/blob/b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a/src/libsystemd/sd-path/path-lookup.c)
constructs separate unit and environment-generator paths. Its system defaults
start with `/run`, `/etc` and `/usr/local/lib` generator directories, followed
by build-time vendor-directory macros. It also consults the corresponding
environment override names. The candidate inventory's `/usr/lib` vendor paths
are assumptions, not verified installed macro values. Initial `/proc/1/environ`
absence is not proof of PID 1's current `getenv()` state; `Manager.Environment`
is a different property. The model accepts only the inventory's fixed ordered
paths and never uses an override, arbitrary root or auto-learned directory.

## Selection, masking and lower-priority entries

[`conf-files.c`](https://github.com/systemd/systemd/blob/b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a/src/basic/conf-files.c)
tracks accepted basenames and masked basenames separately. Empty-file masking
is evaluated before executable-bit eligibility. A previously accepted executable
or mask suppresses later same-named entries; a nonempty, non-executable regular
file is rejected without reserving the name. Accepted entries are sorted by
basename. Symlinks are resolved and checked by upstream code, so a digest of
literal `/dev/null` link text alone cannot establish the target or mask.

The pure model handles root:root, non-writable, non-set-ID **regular files only**:

| Earlier entry | Effect on a lower same-named executable |
| --- | --- |
| Nonempty executable regular file | Earlier executable remains the candidate |
| Empty regular file, executable or not | Lower executable is masked |
| Nonempty non-executable regular file | Lower executable remains eligible |
| Any symlink, including literal `/dev/null` | Whole model refuses; target review required |

It refuses even shadowed links. Basenames must match
`[A-Za-z0-9][A-Za-z0-9_-]{0,254}`. Hidden names, extensions, backup suffixes and
other names outside this deliberately narrow subset are **refused**, not
silently filtered or claimed to match all upstream directory filtering.
`earlier_same_name` is checked as raw inventory metadata; it is not a selector.

## Execution and effects are separate

[`execute_directories()`](https://github.com/systemd/systemd/blob/b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a/src/shared/exec-util.c)
requests executable regular entries with masked-file filtering. Its execution
machinery treats callback-based processing as serial even when parallel flags
are supplied. A sorted candidate list is not proof of invocation, completion,
execution order, output, permissions or dependency safety.

[`manager.c`](https://github.com/systemd/systemd/blob/b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a/src/core/manager.c)
runs environment generators before unit generators at startup and reload;
unit generators receive a derived manager environment. Namespace setup has
fallback paths, so this review asserts no universal generator sandbox.
Reload is manager-wide, not limited to the Dashboard service. Selected code,
interpreters, libraries, tools, generated environment and unit-graph effects
still need separate review in the installed context.

## Implemented contract and verification

[`model_default_generator_selection()`](../../siem/rbac/broker_tls/operator_maintenance_generator_selection.py)
validates a caller-supplied combined catalog: exact record/types/flags, fixed
paths, presence, sorted unique entries, recomputed raw precedence, consistent
regular-file metadata, empty-content hash, time bounds, shared entry/byte limits
and both inventory/catalog digests. It emits immutable per-entry decisions and
ASCII-sorted candidate lists for each class, with a canonical selection digest
bound to the source catalog, model version and upstream commit.

It performs no collection, filesystem access, generator execution, systemd
call or image-reference loading. Self-consistent fabricated inputs can pass;
hashes and supplied timing do not authenticate or freshen an observation.
Every proof/admission flag remains false, and review remains required. The
public maintenance controller still refuses before I/O. No held clone source,
guard capsule, reader, service or app behavior changes.

Twenty-six [synthetic tests](../../assistant/tests/test_broker_tls_generator_selection.py)
cover all 256 four-directory priority combinations in each class, independent
class precedence, empty masks, non-executable fall-through, link/name refusal,
strict types and claims, malformed metadata/digests, shared budgets, immutable
non-authorizing output and the no-I/O/controller-refusal boundary. They do not
prove native selection, freshness, authenticity or safe reload effects.

## Remaining work

Establish installed path-construction/build equivalence and current path-source
facts without treating this model or the image match as authority. Resolve
relevant links and bind a separately reviewed selected-code/dependency/effect
baseline. Then integrate freshly trusted observations before private mask/reload
under the outstanding host, writer, start-control and maintenance authorization
boundaries. Independent archive/native-result and later implementation review
remain queued; this slice neither replaces that review nor releases a VM step.
