"""Dormant read-only check of PID 1's *initial* generator-path overrides.

This reads potentially sensitive procfs environment bytes only inside a trusted
root/Linux process. It never returns values, launches systemd, or authorizes a
reload. /proc/1/environ is not the manager's current getenv() state, and PID 1
alignment is not intended-host or installed-systemd attestation.
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

OVERRIDES = (b'SYSTEMD_GENERATOR_PATH', b'SYSTEMD_ENVIRONMENT_GENERATOR_PATH')
MAX_ENV_BYTES = 256 * 1024
MAX_ENV_ENTRIES = 4096
MAX_WINDOW_NS = 30_000_000_000
CHUNK = 4096


def _parse_initial(raw):
    """Reject an override without retaining or returning any environment value."""
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_ENV_BYTES,
                 'GENERATOR_INITIAL_ENV_FORMAT')
    # proc_pid_environ(5) permits, but does not require, a final NUL.
    rows = (raw[:-1] if raw.endswith(b'\0') else raw).split(b'\0')
    core.require(len(rows) <= MAX_ENV_ENTRIES, 'GENERATOR_INITIAL_ENV_COUNT')
    names = set()
    for row in rows:
        name, separator, _ = row.partition(b'=')
        core.require(separator and re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_]*', name)
                     is not None, 'GENERATOR_INITIAL_ENV_FORMAT')
        if name in OVERRIDES:
            core.require(name not in names, 'GENERATOR_INITIAL_ENV_DUPLICATE')
            names.add(name)
    core.require(not names, 'GENERATOR_PATH_OVERRIDE_PRESENT')


def _environ_at(proc1, device, check):
    """Read only the fixed procfs leaf; caller holds and verifies its ancestors."""
    check()
    before = os.stat('environ', dir_fd=proc1, follow_symlinks=False)
    census._metadata(before, False, device)
    core.require(before.st_uid == 0 and before.st_gid == 0
                 and 0 <= before.st_size <= MAX_ENV_BYTES, 'GENERATOR_INITIAL_ENV_METADATA')
    fd = os.open('environ', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=proc1)
    try:
        key = cg._key(before)
        core.require(key == cg._key(os.fstat(fd)), 'GENERATOR_INITIAL_ENV_CHANGED')
        raw = bytearray()
        while len(raw) <= MAX_ENV_BYTES:
            check()
            part = os.read(fd, min(CHUNK, MAX_ENV_BYTES + 1 - len(raw)))
            check()
            if not part:
                break
            raw.extend(part)
        core.require(len(raw) <= MAX_ENV_BYTES, 'GENERATOR_INITIAL_ENV_SIZE')
        core.require(key == cg._key(os.fstat(fd)) == cg._key(
            os.stat('environ', dir_fd=proc1, follow_symlinks=False)),
            'GENERATOR_INITIAL_ENV_CHANGED')
        return bytes(raw)
    finally:
        os.close(fd)


def _snapshot(tree, pid, started, check):
    """Private fixed-path snapshot. No raw procfs bytes leave the public entry."""
    check()
    boot = tree.read(cg.BOOT_PARTS, 37)
    boot_id = cg._boot(boot[0])
    mount = tree.read(('proc', str(pid), 'mountinfo'), cg.MAX_MOUNTINFO)
    proc_device = census._proc_device(mount[0])
    device = os.fstat(tree.directory(('proc',))).st_dev
    core.require((os.major(device), os.minor(device)) == proc_device,
                 'GENERATOR_PROC_DEVICE')
    proc1 = tree.directory(('proc', '1'))
    core.require(os.fstat(proc1).st_dev == device, 'GENERATOR_PROC_DEVICE')
    deadline = started + MAX_WINDOW_NS
    stat_raw = census._small(proc1, 'stat', device, deadline)
    status_raw = census._small(proc1, 'status', device, deadline)
    start_ticks, kernel, zombie = census._stat_record(stat_raw, 1)
    uids, gids, _ = census._status(status_raw, 1)
    core.require(not kernel and not zombie and uids == (0,) * 4
                 and gids == (0,) * 4, 'GENERATOR_PID1_IDENTITY')
    executable = census._exe(proc1, device)
    core.require(executable is not None, 'GENERATOR_PID1_EXE')
    raw = _environ_at(proc1, device, check)
    _parse_initial(raw)
    metadata = tree.verify()
    check()
    # Private hashes compare complete bytes without returning names or values.
    token = tuple(hashlib.sha256(value).digest() for value in
                  (boot[0], mount[0], stat_raw, status_raw,
                   os.fsencode(executable), raw))
    return boot_id, start_ticks, (token, boot[1], mount[1], metadata)


@dataclass(frozen=True)
class InitialGeneratorOverrideObservation:
    boot_id: str
    pid1_start_ticks: int
    collection_elapsed_ms: int
    passes: int = field(default=2, init=False)
    procfs_initial_environment_no_path_override_observed: bool = field(default=True, init=False)
    pid1_is_installed_systemd_proven: bool = field(default=False, init=False)
    current_process_environment_proven: bool = field(default=False, init=False)
    effective_search_paths_proven: bool = field(default=False, init=False)
    compiled_vendor_paths_proven: bool = field(default=False, init=False)
    generator_selection_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    continuous_control_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def observe_initial_generator_path_overrides():
    """No-argument evidence-only candidate; never a generator-search permit."""
    try:
        fs._platform()
        core.require(hasattr(time, 'CLOCK_BOOTTIME') and hasattr(time, 'clock_gettime_ns')
                     and os.readlink in os.supports_dir_fd, 'GENERATOR_INITIAL_ENV_PLATFORM')
        owner = os.getpid(), threading.get_native_id()
        started = previous = time.clock_gettime_ns(time.CLOCK_BOOTTIME)

        def check():
            nonlocal previous
            core.require((os.getpid(), threading.get_native_id()) == owner,
                         'GENERATOR_INITIAL_ENV_CALLER')
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            core.require(previous <= now and 0 <= now - started < MAX_WINDOW_NS,
                         'GENERATOR_INITIAL_ENV_TIMEOUT')
            previous = now

        check()
        with ExitStack() as stack:
            root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, root)
            tree = cg._Tree(root, stack)
            first = _snapshot(tree, owner[0], started, check)
            check()
            second = _snapshot(tree, owner[0], started, check)
            core.require(first == second, 'GENERATOR_INITIAL_ENV_CHANGED')
            tree.verify()
        check()  # A failed cleanup, changed caller or expired window cannot pass.
        return InitialGeneratorOverrideObservation(first[0], first[1],
                                                   (previous - started) // 1_000_000)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
