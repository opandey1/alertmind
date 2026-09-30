"""Pure default-path regular-file selection model; NEVER reload admission.

Upstream v259.5 semantics are a review reference, not installed-manager proof.
No collector, filesystem, subprocess, generator or controller is invoked here.
Links (even literal /dev/null) and filenames outside the conservative subset
are refused, not treated as verified masks or silently filtered.
"""
from dataclasses import asdict, dataclass, field, fields
import hashlib
import json
import re

from . import operator_core as core
from . import operator_maintenance_generators as inventory

CONTRACT = 'upstream-v259.5-regular-subset-v1'
UPSTREAM_COMMIT = 'b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a'
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,254}', re.ASCII)
_SHA = re.compile(r'[0-9a-f]{64}', re.ASCII)
_EMPTY_SHA = hashlib.sha256(b'').hexdigest()


@dataclass(frozen=True)
class SelectionRow:
    directory: int
    name: str
    kind: str
    bytes: int
    sha256: str
    decision: str
    earlier_blocker: object  # Directory index, or None. Not raw precedence.


@dataclass(frozen=True)
class GeneratorSelectionCandidate:
    catalog_sha256: str
    unit_rows: tuple
    environment_rows: tuple
    unit_candidates: tuple  # SelectionRows sorted by ASCII basename, not launch order.
    environment_candidates: tuple
    selection_sha256: str
    contract: str = field(default=CONTRACT, init=False)
    upstream_commit: str = field(default=UPSTREAM_COMMIT, init=False)
    default_paths_assumed: bool = field(default=True, init=False)
    regular_subset_only: bool = field(default=True, init=False)
    effective_search_paths_proven: bool = field(default=False, init=False)
    effective_selection_proven: bool = field(default=False, init=False)
    observation_authenticity_proven: bool = field(default=False, init=False)
    observation_freshness_proven: bool = field(default=False, init=False)
    installed_contract_proven: bool = field(default=False, init=False)
    symlink_targets_verified: bool = field(default=False, init=False)
    generator_effects_proven: bool = field(default=False, init=False)
    generated_environment_proven: bool = field(default=False, init=False)
    dependency_closure_proven: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    continuous_control_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def _require(condition, suffix):
    core.require(condition, 'GENERATOR_SELECTION_' + suffix)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _record(value, expected_type):
    _require(type(value) is expected_type, 'SHAPE')
    declared = fields(expected_type)
    keys = set(vars(value))
    _require(keys <= {f.name for f in declared} and
             {f.name for f in declared if f.init} <= keys, 'SHAPE')
    for f in declared:
        if not f.init:
            actual = getattr(value, f.name)
            _require(type(actual) is type(f.default) and actual == f.default, 'CLAIMS')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True).encode('ascii')).hexdigest()


def _sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _validate_group(value, paths, elapsed):
    _record(value, inventory.GeneratorInventory)
    _require(_integer(value.collection_elapsed_ms, 0,
                      inventory.MAX_WINDOW_NS // 1_000_000 - 1) and
             value.collection_elapsed_ms == elapsed, 'WINDOW')
    _require(type(value.directories) is tuple and len(value.directories) == len(paths),
             'PATHS')
    for row, parts in zip(value.directories, paths):
        _require(type(row) is tuple and len(row) == 2 and type(row[0]) is str and
                 row[0] == '/' + '/'.join(parts) and type(row[1]) is bool, 'PATHS')
    _require(type(value.entries) is tuple and len(value.entries) <= inventory.MAX_ENTRIES,
             'COUNT')
    previous = None
    seen = {}
    total = 0
    for entry in value.entries:
        _record(entry, inventory.GeneratorEntry)
        _require(_integer(entry.directory, 0, len(paths) - 1), 'ENTRY')
        _require(type(entry.name) is str and _NAME.fullmatch(entry.name) is not None,
                 'NAME_UNREVIEWED')
        position = entry.directory, entry.name
        _require((previous is None or previous < position) and
                 value.directories[entry.directory][1], 'ORDER')
        previous = position
        _require(type(entry.earlier_same_name) is tuple and
                 all(type(i) is int for i in entry.earlier_same_name) and
                 entry.earlier_same_name == tuple(seen.get(entry.name, ())), 'PRECEDENCE')
        seen.setdefault(entry.name, []).append(entry.directory)
        _require(type(entry.kind) is str, 'ENTRY')
        _require(entry.kind not in ('null_link_literal', 'unresolved_symlink'),
                 'LINK_UNREVIEWED')
        _require(entry.kind in ('empty_regular', 'executable_regular',
                               'nonexecutable_regular'), 'ENTRY')
        _require(_integer(entry.bytes, 0, inventory.MAX_FILE_BYTES) and
                 _integer(entry.mode, 0, 0o7777) and not entry.mode & 0o6022 and
                 type(entry.uid) is int and entry.uid == 0 and
                 type(entry.gid) is int and entry.gid == 0, 'METADATA')
        expected_kind = ('empty_regular' if entry.bytes == 0 else
                         'executable_regular' if entry.mode & 0o111 else
                         'nonexecutable_regular')
        _require(entry.kind == expected_kind and _sha(entry.sha256) and
                 (entry.bytes != 0 or entry.sha256 == _EMPTY_SHA), 'ENTRY')
        total += entry.bytes
        _require(total <= inventory.MAX_TOTAL_BYTES, 'BYTES')
    expected = _digest(dict(version=1, directories=value.directories,
                            entries=[asdict(entry) for entry in value.entries]))
    _require(_sha(value.inventory_sha256) and value.inventory_sha256 == expected,
             'DIGEST')
    return len(value.entries), total


def _select(entries):
    rows = []
    blockers = {}
    for entry in entries:
        blocker = blockers.get(entry.name)
        if blocker is not None:
            decision = ('shadowed_by_empty_mask' if blocker[1] == 'empty_mask'
                        else 'shadowed_by_candidate')
        elif entry.kind == 'empty_regular':
            decision = 'empty_mask'
            blockers[entry.name] = entry.directory, decision
        elif entry.kind == 'executable_regular':
            decision = 'candidate'
            blockers[entry.name] = entry.directory, decision
        else:
            # A nonempty non-executable does NOT reserve this basename.
            decision = 'nonexecutable'
        rows.append(SelectionRow(entry.directory, entry.name, entry.kind,
                                 entry.bytes, entry.sha256, decision,
                                 None if blocker is None else blocker[0]))
    rows = tuple(rows)
    selected = tuple(sorted((r for r in rows if r.decision == 'candidate'),
                            key=lambda r: r.name))
    return rows, selected


def model_default_generator_selection(catalog):
    """Validate candidate data and model a conservative upstream subset only.

    Supplied hashes, metadata, timing and flags are NOT trusted observations.
    This function does not collect or authenticate them. No version or image
    record is loaded, and no comparison result grants authority to a controller.
    """
    _record(catalog, inventory.GeneratorCatalog)
    _require(_integer(catalog.collection_elapsed_ms, 0,
                      inventory.MAX_WINDOW_NS // 1_000_000 - 1), 'WINDOW')
    unit_count, unit_bytes = _validate_group(catalog.unit, inventory.DIRECTORIES,
                                           catalog.collection_elapsed_ms)
    env_count, env_bytes = _validate_group(catalog.environment, inventory.ENV_DIRECTORIES,
                                         catalog.collection_elapsed_ms)
    _require(unit_count + env_count <= inventory.MAX_ENTRIES, 'COUNT')
    _require(unit_bytes + env_bytes <= inventory.MAX_TOTAL_BYTES, 'BYTES')
    expected = _digest(dict(version=1, unit=catalog.unit.inventory_sha256,
                            environment=catalog.environment.inventory_sha256))
    _require(_sha(catalog.catalog_sha256) and catalog.catalog_sha256 == expected, 'DIGEST')
    unit_rows, unit_candidates = _select(catalog.unit.entries)
    env_rows, env_candidates = _select(catalog.environment.entries)
    digest = _digest(dict(version=1, contract=CONTRACT, upstream_commit=UPSTREAM_COMMIT,
                         catalog_sha256=expected, unit=[asdict(r) for r in unit_rows],
                         environment=[asdict(r) for r in env_rows]))
    return GeneratorSelectionCandidate(expected, unit_rows, env_rows, unit_candidates,
                                       env_candidates, digest)
