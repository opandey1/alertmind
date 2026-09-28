"""Dormant PID 1 image and local dpkg-claim inventory; never an admission gate.

The fixed Ubuntu candidate path is not an independently reviewed VM baseline.
This reads the running executable and matching disk bytes without executing
either. Local dpkg records are claims, not package authenticity or host proof.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import os
import re
import threading
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_cgroup as cg
from . import operator_maintenance_processes as census

IMAGE_PARTS = ('usr', 'lib', 'systemd', 'systemd')
STATUS_PARTS = ('var', 'lib', 'dpkg', 'status')
LIST_PARTS = ('var', 'lib', 'dpkg', 'info', 'systemd.list')
IMAGE_PATH = '/usr/lib/systemd/systemd'
LIMITS = {IMAGE_PARTS: 32 * 1024 * 1024, STATUS_PARTS: 16 * 1024 * 1024,
          LIST_PARTS: 2 * 1024 * 1024}
MAX_WINDOW_NS = 30_000_000_000
MAX_STATUS_PARAGRAPHS = 65536
MAX_LIST_LINES = 32768
CHUNK = 65536
_FIELD = re.compile(rb'[A-Za-z][A-Za-z0-9-]{0,79}')
_VERSION = re.compile(rb'[A-Za-z0-9.+:~_-]{1,128}')


def _status_version(raw):
    """Parse only one installed amd64 systemd claim from bounded deb822 data."""
    core.require(type(raw) is bytes and 0 < len(raw) <= LIMITS[STATUS_PARTS]
                 and raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw,
                 'PID1_DPKG_STATUS')
    paragraphs = raw.rstrip(b'\n').split(b'\n\n')
    core.require(len(paragraphs) <= MAX_STATUS_PARAGRAPHS and all(paragraphs),
                 'PID1_DPKG_STATUS')
    found = []
    selected = {b'package', b'status', b'version', b'architecture'}
    for paragraph in paragraphs:
        fields = {}
        previous = None
        for line in paragraph.split(b'\n'):
            if line.startswith((b' ', b'\t')):
                core.require(previous is not None and previous not in selected,
                             'PID1_DPKG_STATUS')
                continue
            name, separator, value = line.partition(b':')
            core.require(separator and _FIELD.fullmatch(name) is not None
                         and (not value or value.startswith(b' ')), 'PID1_DPKG_STATUS')
            key = name.lower()
            core.require(key not in fields, 'PID1_DPKG_STATUS')
            fields[key] = value.strip()
            previous = key
        if fields.get(b'package') == b'systemd':
            found.append(fields)
    core.require(len(found) == 1 and selected <= found[0].keys(), 'PID1_DPKG_STATUS')
    claim = found[0]
    core.require(claim[b'status'] == b'install ok installed'
                 and claim[b'architecture'] == b'amd64'
                 and _VERSION.fullmatch(claim[b'version']) is not None,
                 'PID1_DPKG_STATUS')
    return claim[b'version'].decode('ascii')


def _listed_image(raw):
    core.require(type(raw) is bytes and 0 < len(raw) <= LIMITS[LIST_PARTS]
                 and raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw,
                 'PID1_DPKG_LIST')
    lines = raw[:-1].split(b'\n')
    core.require(len(lines) <= MAX_LIST_LINES and all(lines)
                 and all(len(line) <= 4096 and line.startswith(b'/') for line in lines)
                 and lines.count(IMAGE_PATH.encode('ascii')) == 1, 'PID1_DPKG_LIST')


def _disk_at(tree, parts, check):
    """Fixed root-owned file read, held-directory/no-follow, with leaf recheck."""
    core.require(type(parts) is tuple and parts in LIMITS, 'PID1_IMAGE_TARGET')
    limit = LIMITS[parts]
    check()
    parent = tree.directory(parts[:-1])
    name = parts[-1]
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fs._trusted(before, False, ((0, 0),))
    core.require(before.st_nlink == 1 and 0 < before.st_size <= limit,
                 'PID1_IMAGE_METADATA')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        stamp = fs._stamp(before)
        core.require(stamp == fs._stamp(os.fstat(fd)), 'PID1_IMAGE_CHANGED')
        raw = bytearray()
        while len(raw) <= limit:
            check()
            part = os.read(fd, min(CHUNK, limit + 1 - len(raw)))
            check()
            if not part:
                break
            raw.extend(part)
        core.require(len(raw) <= limit and len(raw) == before.st_size,
                     'PID1_IMAGE_SIZE')
        core.require(stamp == fs._stamp(os.fstat(fd)) == fs._stamp(
            os.stat(name, dir_fd=parent, follow_symlinks=False)), 'PID1_IMAGE_CHANGED')
        return bytes(raw), stamp
    finally:
        os.close(fd)


def _running_image(proc1, device, check):
    """Only exception to no-follow: kernel /proc/1/exe magic link, exact text."""
    check()
    core.require(census._exe(proc1, device) == IMAGE_PATH, 'PID1_IMAGE_PATH')
    before = os.stat('exe', dir_fd=proc1)  # Follow procfs magic link, not a disk path.
    fs._trusted(before, False, ((0, 0),))
    core.require(before.st_nlink == 1 and 0 < before.st_size <= LIMITS[IMAGE_PARTS],
                 'PID1_IMAGE_METADATA')
    fd = os.open('exe', os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=proc1)
    try:
        stamp = fs._stamp(before)
        core.require(stamp == fs._stamp(os.fstat(fd)), 'PID1_IMAGE_CHANGED')
        raw = bytearray()
        limit = LIMITS[IMAGE_PARTS]
        while len(raw) <= limit:
            check()
            part = os.read(fd, min(CHUNK, limit + 1 - len(raw)))
            check()
            if not part:
                break
            raw.extend(part)
        core.require(len(raw) <= limit and len(raw) == before.st_size,
                     'PID1_IMAGE_SIZE')
        core.require(stamp == fs._stamp(os.fstat(fd)) == fs._stamp(
            os.stat('exe', dir_fd=proc1)), 'PID1_IMAGE_CHANGED')
        core.require(census._exe(proc1, device) == IMAGE_PATH, 'PID1_IMAGE_CHANGED')
        return bytes(raw), stamp
    finally:
        os.close(fd)


def _snapshot(tree, pid, started, check):
    check()
    boot = tree.read(cg.BOOT_PARTS, 37)
    boot_id = cg._boot(boot[0])
    mount = tree.read(('proc', str(pid), 'mountinfo'), cg.MAX_MOUNTINFO)
    proc_device = census._proc_device(mount[0])
    device = os.fstat(tree.directory(('proc',))).st_dev
    core.require((os.major(device), os.minor(device)) == proc_device,
                 'PID1_IMAGE_PROC_DEVICE')
    proc1 = tree.directory(('proc', '1'))
    core.require(os.fstat(proc1).st_dev == device, 'PID1_IMAGE_PROC_DEVICE')
    deadline = started + MAX_WINDOW_NS
    stat_raw = census._small(proc1, 'stat', device, deadline)
    status_raw = census._small(proc1, 'status', device, deadline)
    start_ticks, kernel, zombie = census._stat_record(stat_raw, 1)
    uids, gids, _ = census._status(status_raw, 1)
    core.require(not kernel and not zombie and uids == (0,) * 4
                 and gids == (0,) * 4, 'PID1_IMAGE_IDENTITY')
    running, running_stamp = _running_image(proc1, device, check)
    disk, disk_stamp = _disk_at(tree, IMAGE_PARTS, check)
    core.require(running_stamp == disk_stamp and running == disk,
                 'PID1_IMAGE_MISMATCH')
    package_status, status_stamp = _disk_at(tree, STATUS_PARTS, check)
    package_list, list_stamp = _disk_at(tree, LIST_PARTS, check)
    version = _status_version(package_status)
    _listed_image(package_list)
    core.require(stat_raw == census._small(proc1, 'stat', device, deadline)
                 and status_raw == census._small(proc1, 'status', device, deadline),
                 'PID1_IMAGE_CHANGED')
    core.require(boot == tree.read(cg.BOOT_PARTS, 37)
                 and mount == tree.read(('proc', str(pid), 'mountinfo'), cg.MAX_MOUNTINFO),
                 'PID1_IMAGE_CHANGED')
    metadata = tree.verify()
    check()
    digest = hashlib.sha256(running).hexdigest()
    token = (hashlib.sha256(boot[0]).digest(), hashlib.sha256(mount[0]).digest(),
             hashlib.sha256(stat_raw).digest(), hashlib.sha256(status_raw).digest(),
             running_stamp, disk_stamp, status_stamp, list_stamp,
             hashlib.sha256(package_status).digest(), hashlib.sha256(package_list).digest(),
             boot[1], mount[1], metadata)
    return boot_id, start_ticks, digest, version, token


@dataclass(frozen=True)
class Pid1ImageInventory:
    boot_id: str
    pid1_start_ticks: int
    executable_sha256: str
    dpkg_claimed_version: str
    collection_elapsed_ms: int
    candidate_path: str = field(default=IMAGE_PATH, init=False)
    passes: int = field(default=2, init=False)
    running_and_disk_bytes_matched: bool = field(default=True, init=False)
    local_dpkg_status_and_list_claim_matched: bool = field(default=True, init=False)
    independently_pinned_image_verified: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    intended_host_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    current_generator_paths_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    continuous_control_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def observe_pid1_image_inventory():
    """Evidence-only fixed-path collector; no package command or systemd call."""
    try:
        fs._platform()
        core.require(hasattr(time, 'CLOCK_BOOTTIME') and hasattr(time, 'clock_gettime_ns')
                     and os.readlink in os.supports_dir_fd, 'PID1_IMAGE_PLATFORM')
        owner = os.getpid(), threading.get_native_id()
        started = previous = time.clock_gettime_ns(time.CLOCK_BOOTTIME)

        def check():
            nonlocal previous
            core.require((os.getpid(), threading.get_native_id()) == owner,
                         'PID1_IMAGE_CALLER')
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            core.require(previous <= now and 0 <= now - started < MAX_WINDOW_NS,
                         'PID1_IMAGE_TIMEOUT')
            previous = now

        check()
        with ExitStack() as stack:
            root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, root)
            tree = cg._Tree(root, stack)
            first = _snapshot(tree, owner[0], started, check)
            check()
            second = _snapshot(tree, owner[0], started, check)
            core.require(first == second, 'PID1_IMAGE_CHANGED')
            tree.verify()
        check()
        return Pid1ImageInventory(first[0], first[1], first[2], first[3],
                                  (previous - started) // 1_000_000)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
