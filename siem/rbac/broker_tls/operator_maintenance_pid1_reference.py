"""Pure candidate comparison for a separately supplied PID 1 image reference.

The reference is untrusted input until an external reviewer pins its provenance.
Matching it to an observation cannot authenticate a package, the host, or the
collector, and cannot authorize a manager operation. No live I/O occurs here.
"""
from dataclasses import dataclass, field, fields
import hashlib
import json
import re

from . import operator_core as core
from . import operator_maintenance_pid1_image as image

SCHEMA = 1
MAX_REFERENCE_BYTES = 512
_DIGEST = re.compile(r'[0-9a-f]{64}')
_VERSION = re.compile(r'[A-Za-z0-9.+:~_-]{1,128}')
_BOOT = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_KEYS = frozenset({'schema', 'candidate_path', 'package_name', 'architecture',
                   'executable_sha256', 'dpkg_claimed_version'})
_FALSE_CLAIMS = ('independently_pinned_image_verified', 'package_authenticity_proven',
                 'intended_host_proven', 'loaded_code_proven',
                 'current_generator_paths_proven', 'atomic_snapshot_proven',
                 'continuous_control_proven', 'mutation_authorized', 'startup_authorized')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        core.require(key not in result, 'PID1_REF_JSON')
        result[key] = value
    return result


def _invalid_constant(_):
    raise core.OperatorError('PID1_REF_JSON')


@dataclass(frozen=True)
class Pid1ImageReference:
    candidate_path: str
    package_name: str
    architecture: str
    executable_sha256: str
    dpkg_claimed_version: str


def _reference(value):
    core.require(type(value) is Pid1ImageReference
                 and set(vars(value)) == {field.name for field in fields(Pid1ImageReference)},
                 'PID1_REF_SHAPE')
    core.require(type(value.candidate_path) is str
                 and value.candidate_path == image.IMAGE_PATH
                 and type(value.package_name) is str and value.package_name == 'systemd'
                 and type(value.architecture) is str and value.architecture == 'amd64'
                 and type(value.executable_sha256) is str
                 and _DIGEST.fullmatch(value.executable_sha256) is not None
                 and type(value.dpkg_claimed_version) is str
                 and _VERSION.fullmatch(value.dpkg_claimed_version) is not None,
                 'PID1_REF_VALUE')


def parse_pid1_image_reference(raw):
    """Parse exact public metadata, never attest its source or auto-learn it."""
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_REFERENCE_BYTES,
                 'PID1_REF_SIZE')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                          parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise core.OperatorError('PID1_REF_JSON') from None
    core.require(type(data) is dict and set(data) == _KEYS, 'PID1_REF_SHAPE')
    core.require(type(data['schema']) is int and data['schema'] == SCHEMA,
                 'PID1_REF_SHAPE')
    reference = Pid1ImageReference(*(data[key] for key in (
        'candidate_path', 'package_name', 'architecture',
        'executable_sha256', 'dpkg_claimed_version')))
    _reference(reference)
    return reference


def reference_fingerprint(reference):
    """Canonical content address; it does not authenticate approval/provenance."""
    _reference(reference)
    payload = {'schema': SCHEMA, **vars(reference)}
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True).encode('ascii')
    return hashlib.sha256(canonical).hexdigest()


def _observation(value):
    core.require(type(value) is image.Pid1ImageInventory
                 and set(vars(value)) == {item.name for item in fields(image.Pid1ImageInventory)
                                          if item.init},
                 'PID1_REF_OBSERVATION')
    core.require(type(value.boot_id) is str and _BOOT.fullmatch(value.boot_id) is not None
                 and type(value.pid1_start_ticks) is int and value.pid1_start_ticks >= 0
                 and type(value.collection_elapsed_ms) is int
                 and 0 <= value.collection_elapsed_ms < image.MAX_WINDOW_NS // 1_000_000
                 and type(value.executable_sha256) is str
                 and _DIGEST.fullmatch(value.executable_sha256) is not None
                 and type(value.dpkg_claimed_version) is str
                 and _VERSION.fullmatch(value.dpkg_claimed_version) is not None
                 and type(value.candidate_path) is str
                 and value.candidate_path == image.IMAGE_PATH
                 and type(value.passes) is int and value.passes == 2
                 and value.running_and_disk_bytes_matched is True
                 and value.local_dpkg_status_and_list_claim_matched is True
                 and value.review_required is True
                 and all(getattr(value, name) is False for name in _FALSE_CLAIMS),
                 'PID1_REF_OBSERVATION')


@dataclass(frozen=True)
class Pid1ImageCandidateMatch:
    reference_sha256: str
    observed_boot_id: str
    observed_pid1_start_ticks: int
    candidate_fields_match: bool = field(default=True, init=False)
    reference_provenance_verified: bool = field(default=False, init=False)
    observation_authenticity_proven: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    observation_freshness_proven: bool = field(default=False, init=False)
    effective_generator_paths_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def compare_pid1_image_reference(observation, reference):
    """Fail on candidate drift; a match still carries no trust or permit.

    A caller can forge either typed value. External, trusted collection and an
    independently retained reference/evidence pin are prerequisites to any
    later gate. This pure comparison neither checks them nor checks freshness.
    """
    _reference(reference)
    _observation(observation)
    core.require(observation.executable_sha256 == reference.executable_sha256
                 and observation.dpkg_claimed_version == reference.dpkg_claimed_version,
                 'PID1_REF_MISMATCH')
    return Pid1ImageCandidateMatch(reference_fingerprint(reference),
                                   observation.boot_id, observation.pid1_start_ticks)
