"""Offline operator safety core. No CLI, service calls, writes, or live reads.

The future privileged adapter must supply fresh observations and bounded,
descriptor-relative no-follow reads. Passing this core is NOT startup approval.
Recovery returns ONE next action; re-observe after that action, never replay a
saved action list or infer current state from a journal's last completed step.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re


BASE = '/usr/share/wazuh-dashboard/'
CLIENT = BASE + 'plugins/wazuhCore/server/services/server-api-client.js'
NODE = BASE + 'node/bin/node'
HEADER = BASE + 'node/include/node/node_version.h'
PACKAGE_VERSION = '4.14.7-1'
CONTRACT = {
    'package_sha256': '83f472d9e5f59b28b1abb6260c466e77b99ae427ce8c5f76203d847f2f598b6f',
    'original_sha256': 'd691047acfa9b9a779a94251c6b813e0296eaf53b3b202e89cb56b44eee48afb',
    'candidate_sha256': 'd76b98b673b8c3fd7d6f015e7d8783e45e5c1d996b69d0ed2c96dfc53615f868',
    'policy_lf_sha256': '8847b5bec11cc279b207390504cef24eaff679b52d1f08d3ebf1363012a9e7b2',
    'packaged_node_version': '18.19.0',
    'packaged_linux_node_sha256': '157f76a2eff8bbe4017cfecdac5629b9e60c7a6106fed26ab6e2cda802b89cd0',
    'packaged_node_header_sha256': '7fec24722b96de1a2adf54e60094080c537dd7189af664f507a17b59249acc36',
    'files_digest': '16fc85e86aefb8f82b64df8aeee2b963f54d5295457801378c4534eb32bba5e9',
}
MAX_MANIFEST = 512 * 1024


class OperatorError(Exception):
    """Fixed diagnostic codes only; never serialize supplier exceptions."""


def require(condition, code):
    if not condition:
        raise OperatorError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'MANIFEST_DUPLICATE_KEY')
        result[key] = value
    return result


def reject_constant(_):
    raise OperatorError('MANIFEST_JSON')


@dataclass(frozen=True)
class FileCheck:
    path: str
    digest: str
    limit: int
    size: int | None = None


def installed_checks(raw):
    """Derive fixed installed targets from the independently pinned manifest.

    Do not let a newly generated manifest redefine expected production bytes.
    original.cjs is backup provenance, never the allowed installed client.
    No paths/contents from rejected manifests are read or included in errors.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST, 'MANIFEST_SIZE')
    try:
        manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                              parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise OperatorError('MANIFEST_JSON') from None
    require(type(manifest) is dict, 'MANIFEST_SHAPE')
    require(all(manifest.get(k) == v for k, v in CONTRACT.items()), 'MANIFEST_CONTRACT')
    files = manifest.get('files')
    require(type(files) is dict and 2 <= len(files) <= 4096, 'MANIFEST_FILES')
    require(sha(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())
            == CONTRACT['files_digest'], 'MANIFEST_FILES_DIGEST')
    checks = []
    total = 0
    for name, info in sorted(files.items()):
        require(type(name) is str and type(info) is dict
                and set(info) == {'bytes', 'sha256'}, 'MANIFEST_ENTRY')
        size, digest = info['bytes'], info['sha256']
        require(type(size) is int and 0 <= size <= 2 * 1024 * 1024
                and type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest),
                'MANIFEST_ENTRY')
        total += size
        if name in ('original.cjs', 'candidate.cjs'):
            require(digest == CONTRACT[name.removesuffix('.cjs') + '_sha256'],
                    'MANIFEST_CLIENT')
            if name == 'candidate.cjs':
                checks.append(FileCheck(CLIENT, digest, 2 * 1024 * 1024, size))
            continue
        p = PurePosixPath(name)
        require(name.startswith('node_modules/') and not p.is_absolute()
                and str(p) == name and '..' not in p.parts
                and not re.search(r'[\\:\x00-\x20\x7f]', name), 'MANIFEST_PATH')
        checks.append(FileCheck(BASE + name, digest, 2 * 1024 * 1024, size))
    require({'original.cjs', 'candidate.cjs'} <= files.keys()
            and total <= 32 * 1024 * 1024, 'MANIFEST_FILES')
    checks.extend((FileCheck(NODE, CONTRACT['packaged_linux_node_sha256'], 100 * 1024 * 1024),
                   FileCheck(HEADER, CONTRACT['packaged_node_header_sha256'], 65536)))
    return tuple(checks)


def verify_installed_bytes(manifest, read_bounded, *, package_version, selected_node):
    """Byte portion of a future pre-start guard, not a live inventory collector.

    read_bounded(path, limit) must enforce its bound BEFORE allocating/reading,
    and return bytes from fresh trusted descriptors. This function independently
    enforces the returned bound/digest and performs two passes for visible drift.
    Two equal passes are not an atomic snapshot, metadata proof or live-code
    attestation. package_version/selected_node must come from a future reviewed
    adapter, not operator-entered or persisted assertions.
    """
    require(package_version == PACKAGE_VERSION, 'PACKAGE_VERSION')
    require(selected_node == NODE, 'RUNTIME_PATH')
    checks = installed_checks(manifest)
    for _ in range(2):
        for check in checks:
            try:
                raw = read_bounded(check.path, check.limit)
            except Exception:
                raise OperatorError('ARTIFACT_READ') from None
            require(type(raw) is bytes and len(raw) <= check.limit
                    and (check.size is None or len(raw) == check.size), 'ARTIFACT_SIZE')
            require(sha(raw) == check.digest, 'ARTIFACT_DIGEST')
    return {'byte_integrity_passed': True, 'checked_files': len(checks),
            'passes': 2, 'startup_authorized': False, 'live_acceptance': False}


@dataclass(frozen=True)
class RecoveryObservation:
    # None means not observed, not false. Even a stopped Dashboard needs a
    # durable startup inhibitor before any rollback byte/metadata operation.
    dashboard_stopped: bool | None
    startup_inhibited: bool | None
    client_digest: str | None
    backup_digest: str | None
    backup_metadata_verified: bool | None
    original_metadata_restored: bool | None


def recovery_step(observation):
    """Conservative rollback decision, never an installer or restart authority.

    An adapter must verify a private exact backup, ownership, link and metadata
    preservation, startup inhibition and fresh service state independently. An
    original digest alone does not prove original ownership/mode restoration.
    Unknown/replaced installed bytes require investigation, never blind overwrite.
    No function here applies an action, deletes a resource or starts a service.
    """
    require(type(observation) is RecoveryObservation, 'RECOVERY_OBSERVATION')
    for value in (observation.dashboard_stopped, observation.startup_inhibited,
                  observation.backup_metadata_verified, observation.original_metadata_restored):
        require(value is None or type(value) is bool, 'RECOVERY_OBSERVATION')
    for digest in (observation.client_digest, observation.backup_digest):
        require(digest is None or type(digest) is str
                and re.fullmatch('[0-9a-f]{64}', digest), 'RECOVERY_OBSERVATION')
    if observation.startup_inhibited is not True:
        return 'INHIBIT_STARTUP_AND_REOBSERVE'
    if observation.dashboard_stopped is not True:
        return 'STOP_DASHBOARD_AND_REOBSERVE'
    original = CONTRACT['original_sha256']
    candidate = CONTRACT['candidate_sha256']
    if observation.client_digest not in (original, candidate):
        return 'HOLD_UNKNOWN_CLIENT'
    if observation.backup_digest != original or observation.backup_metadata_verified is not True:
        return 'HOLD_UNVERIFIED_BACKUP'
    if observation.client_digest == candidate:
        return 'RESTORE_ORIGINAL_ATOMICALLY_WHILE_INHIBITED'
    if observation.original_metadata_restored is not True:
        return 'RESTORE_ORIGINAL_METADATA_WHILE_INHIBITED'
    return 'ROLLED_BACK_KEEP_STOPPED_AND_INHIBITED'
