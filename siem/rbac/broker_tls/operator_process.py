"""Point-in-time process executable observation, not a guard or memory attestation.

PID comes only from fixed systemd queries. Procfs/host kernel and Python launch
are trusted. Only /proc/<pid>/exe is deliberately followed as a kernel magic link;
all directories and small proc files are opened relative to held no-follow FDs.
No signals to the observed process, ptrace, writes, Node execution or broker call.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import os
import re

from . import operator_core as core
from . import operator_fs as fs
from . import operator_service as service

LIMITS = {'stat': 8192, 'status': 65536, 'cmdline': 128 * 1024, 'environ': 1024 * 1024}
EXE_LIMIT = 100 * 1024 * 1024


def _pid(value):
    core.require(type(value) is int and 1 < value < 2**32, 'PROCESS_PID')


def _start_time(raw, pid):
    core.require(type(raw) is bytes and 0 < len(raw) <= LIMITS['stat']
                 and raw.startswith(str(pid).encode() + b' ('), 'PROCESS_STAT')
    end = raw.rfind(b') ')
    fields = raw[end + 2:].split() if end >= 0 else []
    # Fields after comm begin at field 3 (state); starttime is field 22.
    core.require(len(fields) >= 20 and fields[0] in (b'R', b'S', b'D', b'I')
                 and re.fullmatch(rb'[0-9]{1,20}', fields[19]), 'PROCESS_STAT')
    value = int(fields[19])
    core.require(0 < value < 2**64, 'PROCESS_STAT')
    return value


def _credentials(raw, identity):
    core.require(type(raw) is bytes and len(raw) <= LIMITS['status'], 'PROCESS_IDENTITY')
    for name, expected in zip((b'Uid:', b'Gid:'), identity):
        rows = [line[len(name):].split() for line in raw.split(b'\n') if line.startswith(name)]
        core.require(len(rows) == 1 and rows[0] == [str(expected).encode()] * 4, 'PROCESS_IDENTITY')


def _nul_fields(raw, *, environment=False):
    code = 'PROCESS_ENVIRONMENT' if environment else 'PROCESS_CMDLINE'
    bound = LIMITS['environ' if environment else 'cmdline']
    core.require(type(raw) is bytes and len(raw) <= bound, code)
    if environment and not raw:
        return []
    core.require(bool(raw) and raw.endswith(b'\0'), code)
    fields = raw[:-1].split(b'\0')
    if not environment:
        core.require(bool(fields[0]), code)
    else:
        names = set()
        for entry in fields:
            name, sep, _ = entry.partition(b'=')
            core.require(sep and re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_]*', name)
                         and name not in names, code)
            names.add(name)
    return fields


def _key(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid


def _open_directory(stack, parent, name, owners):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fs._trusted(before, True, owners)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    stack.callback(os.close, fd)
    core.require(_key(before) == _key(os.fstat(fd)), 'PROCESS_CHANGED')
    return fd


def _read_small(directory, name, owners):
    core.require(name in LIMITS, 'PROCESS_TARGET')
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    fs._trusted(before, False, owners)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        core.require(_key(before) == _key(os.fstat(fd)), 'PROCESS_CHANGED')
        data = bytearray()
        while len(data) <= LIMITS[name]:
            chunk = os.read(fd, min(65536, LIMITS[name] + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        core.require(len(data) <= LIMITS[name], 'PROCESS_SIZE')
        core.require(_key(before) == _key(os.fstat(fd)) == _key(
            os.stat(name, dir_fd=directory, follow_symlinks=False)), 'PROCESS_CHANGED')
        return bytes(data)
    finally:
        os.close(fd)


def _executable(directory, owners):
    core.require(os.readlink('exe', dir_fd=directory) == core.NODE, 'PROCESS_EXECUTABLE')
    # Intentional procfs magic-link follow; never use the link text as an open path.
    fd = os.open('exe', os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        fs._trusted(before, False, owners)
        core.require(0 < before.st_size <= EXE_LIMIT, 'PROCESS_SIZE')
        digest, count = hashlib.sha256(), 0
        while count <= EXE_LIMIT:
            chunk = os.read(fd, min(65536, EXE_LIMIT + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            digest.update(chunk)
        core.require(count == before.st_size and count <= EXE_LIMIT, 'PROCESS_SIZE')
        core.require(fs._stamp(before) == fs._stamp(os.fstat(fd)) == fs._stamp(
            os.stat('exe', dir_fd=directory, follow_symlinks=True)), 'PROCESS_CHANGED')
        core.require(os.readlink('exe', dir_fd=directory) == core.NODE, 'PROCESS_CHANGED')
        core.require(digest.hexdigest() == core.CONTRACT['packaged_linux_node_sha256'], 'PROCESS_DIGEST')
        return before.st_dev, before.st_ino
    finally:
        os.close(fd)


@dataclass(frozen=True)
class _Snapshot:
    start_time: int
    executable_inode: tuple
    cmdline: bytes = field(repr=False)
    environment: bytes = field(repr=False)


def _native_snapshot(pid, identity):
    _pid(pid)
    owners = ((0, 0), identity)
    with ExitStack() as stack:
        root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root)
        fs._trusted(os.fstat(root), True, ((0, 0),))
        proc = _open_directory(stack, root, 'proc', ((0, 0),))
        directory = _open_directory(stack, proc, str(pid), owners)
        initial = _key(os.fstat(directory))
        start = _start_time(_read_small(directory, 'stat', owners), pid)
        _credentials(_read_small(directory, 'status', owners), identity)
        cmd = _read_small(directory, 'cmdline', owners)
        env = _read_small(directory, 'environ', owners)
        _nul_fields(cmd)
        _nul_fields(env, environment=True)
        executable = _executable(directory, owners)
        _credentials(_read_small(directory, 'status', owners), identity)
        core.require(_start_time(_read_small(directory, 'stat', owners), pid) == start, 'PROCESS_CHANGED')
        core.require(initial == _key(os.fstat(directory)) == _key(
            os.stat(str(pid), dir_fd=proc, follow_symlinks=False)), 'PROCESS_CHANGED')
        return _Snapshot(start, executable, cmd, env)


def _anchor():
    data = service._read_configuration()
    core.require(data['ActiveState'] == 'active', 'PROCESS_NOT_RUNNING')
    _pid(data['MainPID'])
    core.require(data['ExecMainStartTimestampMonotonic'] > 0, 'PROCESS_NOT_RUNNING')
    core.require(data['User'] == 'wazuh-dashboard' and data['Group'] == 'wazuh-dashboard', 'PROCESS_IDENTITY')
    # Private full configuration participates in equality, not just PID.
    return data


@dataclass(frozen=True)
class ProcessObservation:
    argument_count: int
    argv0_matches_packaged_path: bool
    environment_entries: int
    runtime_override_named: bool
    process_executable_matches_pin: bool = field(default=True, init=False)
    passes: int = field(default=2, init=False)
    service_reads: int = field(default=3, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_running_process():
    """Inspect only the manager's current MainPID; no operator-supplied PID.

    Requires a running process. Must not start an unsafe/unpatched Dashboard just
    to satisfy this observation; later pre-start guard cannot depend on MainPID.
    """
    service._check_tool()
    try:
        identity = fs._identity()
        anchor = _anchor()
        snapshots = []
        for _ in range(2):
            snapshots.append(_native_snapshot(anchor['MainPID'], identity))
            core.require(_anchor() == anchor, 'PROCESS_CHANGED')
        core.require(snapshots[0] == snapshots[1], 'PROCESS_CHANGED')
        args = _nul_fields(snapshots[1].cmdline)
        env = _nul_fields(snapshots[1].environment, environment=True)
        names = {e.partition(b'=')[0] for e in env}
        risk = {n.encode('ascii') for n in service.RISK_NAMES}
        return ProcessObservation(len(args), args[0] == core.NODE.encode(), len(env), bool(names & risk))
    except OSError:
        raise core.OperatorError('PROCESS_IO') from None
