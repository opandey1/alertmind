"""Offline upgrade/recovery planning. No CLI, I/O, executor or startup permit.

Inputs are claims supplied by a future trusted adapter, not proof that those
claims were collected. A baseline hash identifies content, not approval or
package authenticity. No saved journal position is accepted as current state.
This module is deliberately outside the guard's held source capsule.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re

SCHEMA_VERSION = 1
MAX_BASELINE_BYTES = 16384
MAX_OBSERVATION_AGE_MS = 30000  # Candidate bound; native timing not accepted.
VERSION_KEYS = (
    'os_id', 'os_version', 'architecture', 'kernel_release', 'python_version',
    'wazuh_manager_version', 'wazuh_indexer_version', 'wazuh_dashboard_version',
    'node_version', 'wazuh_plugin_version', 'wazuh_core_plugin_version',
    'security_plugin_version',
)
DIGEST_KEYS = (
    'python_binary_sha256', 'python_sources_sha256', 'python_native_manifest_sha256',
    'loader_cache_sha256', 'dashboard_package_sha256', 'broker_client_sha256',
    'dependency_manifest_sha256', 'guard_entry_sha256', 'guard_bundle_sha256',
    'guard_launcher_sha256', 'unit_contract_sha256', 'trust_certificate_sha256',
)


class MaintenanceError(Exception):
    """Fixed codes only; never echo input bytes or exception messages."""


def _require(condition, code):
    if not condition:
        raise MaintenanceError(code)


def _digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'BASELINE_DUPLICATE')
        result[key] = value
    return result


@dataclass(frozen=True)
class Baseline:
    versions: tuple
    digests: tuple


def _baseline(value):
    _require(type(value) is Baseline and set(vars(value)) == {'versions', 'digests'}, 'BASELINE_SHAPE')
    for entries, keys, is_digest in ((value.versions, VERSION_KEYS, False),
                                    (value.digests, DIGEST_KEYS, True)):
        _require(type(entries) is tuple and len(entries) == len(keys), 'BASELINE_SHAPE')
        for item, key in zip(entries, keys):
            _require(type(item) is tuple and len(item) == 2 and type(item[0]) is str
                     and item[0] == key, 'BASELINE_SHAPE')
            valid = _digest(item[1]) if is_digest else (
                type(item[1]) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,95}', item[1]))
            _require(valid, 'BASELINE_VALUE')


def parse_baseline(raw):
    """Strict bounded public metadata; accepts candidate versions, not trust.

    Duplicate/extra/missing fields, non-finite numbers and unknown schema fail.
    Aggregate digests must eventually be produced from separately reviewed
    canonical manifests; this parser does not build or authenticate them.
    """
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_BASELINE_BYTES, 'BASELINE_SIZE')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda _: _require(False, 'BASELINE_JSON'))
    except (ValueError, UnicodeError, RecursionError):
        raise MaintenanceError('BASELINE_JSON') from None
    _require(type(data) is dict and set(data) == {'schema', 'versions', 'digests'}, 'BASELINE_SHAPE')
    _require(type(data['schema']) is int and data['schema'] == SCHEMA_VERSION, 'BASELINE_SCHEMA')
    for label, keys in (('versions', VERSION_KEYS), ('digests', DIGEST_KEYS)):
        _require(type(data[label]) is dict and set(data[label]) == set(keys), 'BASELINE_SHAPE')
    result = Baseline(tuple((k, data['versions'][k]) for k in VERSION_KEYS),
                      tuple((k, data['digests'][k]) for k in DIGEST_KEYS))
    _baseline(result)
    return result


def baseline_fingerprint(baseline):
    """Content address for retaining separate baselines, not an approval token."""
    _baseline(baseline)
    raw = json.dumps({'schema': SCHEMA_VERSION, 'versions': dict(baseline.versions),
                      'digests': dict(baseline.digests)}, sort_keys=True,
                     separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def changed_components(before, after):
    _baseline(before)
    _baseline(after)
    return tuple(k for (k, old), (_, new) in zip(before.versions + before.digests,
                                               after.versions + after.digests) if old != new)


@dataclass(frozen=True)
class ReviewEvidence:
    source_baseline_sha256: str | None
    target_baseline_sha256: str | None
    evidence_sha256: str | None
    independent_review_passed: bool | None
    native_validation_passed: bool | None
    owner_downtime_approved: bool | None


@dataclass(frozen=True)
class MaintenanceObservation:
    boot_id: str
    captured_monotonic_ms: int
    exclusive_control: bool | None
    persistent_inhibition: bool | None
    dashboard_stopped: bool | None
    backup_baseline_sha256: str | None
    backup_verified: bool | None
    installed: Baseline | None
    installed_metadata_verified: bool | None


@dataclass(frozen=True)
class MaintenanceDecision:
    next_step: str
    changed_components: tuple
    review_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def _record(value, cls, names):
    _require(type(value) is cls and set(vars(value)) == set(names), 'MAINTENANCE_SHAPE')


def _optional_bool(value):
    _require(value is None or type(value) is bool, 'MAINTENANCE_VALUE')


def _optional_digest(value):
    _require(value is None or _digest(value), 'MAINTENANCE_VALUE')


def _boot_id(value):
    _require(type(value) is str and re.fullmatch(
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value), 'MAINTENANCE_VALUE')


def next_maintenance_step(source, target, observation, review, *, current_boot_id,
                          now_monotonic_ms, goal='upgrade'):
    """One advisory step from current claims; re-observe after EVERY operation.

    Never returns a command, auto-resume sequence, uninstall, unmask or start.
    A fresh timestamp/boot claim is only a replay check, not an authenticated
    observation. The future adapter must establish every claim independently.
    Recovery to old bytes always keeps inhibition, even if they match exactly.
    """
    _baseline(source)
    _baseline(target)
    _require(type(goal) is str and goal in ('upgrade', 'recover'), 'MAINTENANCE_GOAL')
    _record(observation, MaintenanceObservation, (
        'boot_id', 'captured_monotonic_ms', 'exclusive_control', 'persistent_inhibition',
        'dashboard_stopped', 'backup_baseline_sha256', 'backup_verified', 'installed',
        'installed_metadata_verified'))
    _record(review, ReviewEvidence, ('source_baseline_sha256', 'target_baseline_sha256', 'evidence_sha256',
        'independent_review_passed', 'native_validation_passed', 'owner_downtime_approved'))
    _boot_id(current_boot_id)
    _boot_id(observation.boot_id)
    for value in (now_monotonic_ms, observation.captured_monotonic_ms):
        _require(type(value) is int and 0 <= value < 2 ** 63, 'MAINTENANCE_VALUE')
    for value in (observation.exclusive_control, observation.persistent_inhibition,
                  observation.dashboard_stopped, observation.backup_verified,
                  observation.installed_metadata_verified, review.independent_review_passed,
                  review.native_validation_passed, review.owner_downtime_approved):
        _optional_bool(value)
    for value in (observation.backup_baseline_sha256, review.source_baseline_sha256,
                  review.target_baseline_sha256, review.evidence_sha256):
        _optional_digest(value)
    if observation.installed is not None:
        _baseline(observation.installed)
    changed = changed_components(source, target)
    def decision(code):
        return MaintenanceDecision(code, changed)
    age = now_monotonic_ms - observation.captured_monotonic_ms
    if observation.boot_id != current_boot_id or not 0 <= age <= MAX_OBSERVATION_AGE_MS:
        return decision('HOLD_STALE_OBSERVATION')
    if review.owner_downtime_approved is not True:
        return decision('HOLD_OWNER_DOWNTIME_APPROVAL')
    if observation.exclusive_control is not True:
        return decision('HOLD_EXCLUSIVE_CONTROL')
    if observation.persistent_inhibition is not True:
        return decision('REQUIRE_PERSISTENT_INHIBITION_AND_REOBSERVE')
    if observation.dashboard_stopped is not True:
        return decision('REQUIRE_STOPPED_DASHBOARD_AND_REOBSERVE')
    if observation.installed is None or observation.installed_metadata_verified is not True:
        return decision('HOLD_FRESH_INSTALLED_INVENTORY')
    installed = observation.installed
    # Known mixed source/target components still cannot be replayed as an install.
    unknown = any(actual not in (old, new) for (_, actual), (_, old), (_, new) in zip(
        installed.versions + installed.digests, source.versions + source.digests,
        target.versions + target.digests))
    if unknown:
        return decision('HOLD_UNREVIEWED_DRIFT')
    if installed != source and installed != target:
        return decision('HOLD_PARTIAL_UPGRADE_FOR_RECOVERY')
    if observation.backup_verified is not True or observation.backup_baseline_sha256 != baseline_fingerprint(source):
        return decision('HOLD_VERIFIED_SOURCE_BACKUP')
    if goal == 'recover':
        return decision('SOURCE_RESTORED_KEEP_INHIBITED' if installed == source else
                        'PLAN_SOURCE_RESTORE_WHILE_INHIBITED')
    if (review.source_baseline_sha256 != baseline_fingerprint(source)
            or review.target_baseline_sha256 != baseline_fingerprint(target)
            or review.evidence_sha256 is None or review.independent_review_passed is not True
            or review.native_validation_passed is not True):
        return decision('HOLD_TARGET_REVALIDATION')
    if installed == target:
        return decision('TARGET_MATCHES_KEEP_INHIBITED')
    return decision('PLAN_UPGRADE_WHILE_INHIBITED')
