# PID 1 clone-native compatibility — unprivileged diagnostic

Status: **Gate 2A owner result received 2026-09-30; independent review pending**.
The owner reconfirmed clone identity, disconnected adapters, unchanged state
and no AlertMind app use, then returned all four expected PASS lines and the
final STOP POINT. The [retained result](../../evidence/rbac/pid1-clone-native-probe-2026-09-30.md)
records this completed checkpoint. Preserve the packet below; do not rerun
Gate 2A for this accepted observation.
The owner-reported [Gate 1](../../evidence/rbac/pid1-current-clone-preflight-2026-09-28.md)
and the [host-side Ubuntu archive comparison](../../evidence/rbac/pid1-ubuntu-archive-host-smoke-2026-09-28.md)
agree on the executable bytes. Neither establishes trusted Python execution on
the clone. This gate checks selected Linux/procfs/Python and local dpkg input
shapes **without importing or executing AlertMind project code**. It does not
run `operator_maintenance_pid1_image.py`.

For any separately requested future repetition, first identify
`Ubuntu SOC 201 - Current Isolated Clone`
in VirtualBox by its **VM entry and settings**, not its copied guest hostname.
Confirm every clone network adapter is disconnected, no AlertMind app is
using it, no clone updates or configuration changes occurred after Gate 1,
and the original VM remains untouched. If any condition is uncertain, stop.
Run the block once as the clone's **unprivileged console user**. Do not add
`sudo`, change the Python path/flags, reconnect networking, or run it on the
original VM. It reads fixed, public OS/procfs/dpkg files; it prints only
PASS/STOP labels. It does not display process records,
environment variables, package contents, credentials or raw alerts.

```bash
(
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'STOP: run as the unprivileged clone console user'
    exit 1
fi
if [ ! -x /usr/bin/python3.14 ]; then
    printf '%s\n' 'STOP: fixed Python 3.14 candidate is absent'
    exit 1
fi
timeout --signal=TERM --kill-after=2s 20s /usr/bin/python3.14 -I -S -B - <<'ALERTMIND_PID1_CLONE_NATIVE_PROBE'
import os
import stat
import sys
import time

def need(condition, code):
    if not condition:
        raise SystemExit('STOP: ' + code)

def bounded(path, limit, proc=False, expected_uid=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        unsafe = 0o6222 if proc else 0o6022
        need(stat.S_ISREG(before.st_mode) and before.st_uid == expected_uid
             and not before.st_mode & unsafe, 'UNSAFE_INPUT_METADATA')
        if not proc:
            need(before.st_nlink == 1 and 0 < before.st_size <= limit,
                 'DISK_INPUT_SIZE')
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        need(len(data) <= limit and data.endswith(b'\n'), 'INPUT_SHAPE')
        if not proc:
            need(len(data) == before.st_size, 'DISK_INPUT_CHANGED')
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_mode, before.st_size)
             == (after.st_dev, after.st_ino, after.st_mode, after.st_size),
             'INPUT_CHANGED')
        return bytes(data)
    finally:
        os.close(fd)

try:
    need(sys.platform == 'linux' and sys.version_info[:2] == (3, 14)
         and os.geteuid() != 0 and os.uname().machine == 'x86_64',
         'PLATFORM')
    need(os.readlink('/proc/self/exe') == '/usr/bin/python3.14'
         and sys.flags.isolated == 1 and sys.flags.no_site == 1
         and sys.flags.dont_write_bytecode == 1, 'PYTHON_LAUNCH')
    need(all(hasattr(os, name) for name in
             ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK', 'O_CLOEXEC'))
         and os.open in os.supports_dir_fd
         and os.stat in os.supports_dir_fd
         and os.stat in os.supports_follow_symlinks
         and os.readlink in os.supports_dir_fd
         and hasattr(time, 'CLOCK_BOOTTIME'), 'PYTHON_FEATURES')
    need(time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= 0, 'BOOTTIME')

    mount = bounded('/proc/self/mountinfo', 256 * 1024,
                    proc=True, expected_uid=os.geteuid())
    matches = []
    for row in mount[:-1].split(b'\n'):
        halves = row.split(b' - ')
        need(len(halves) == 2, 'PROC_MOUNT_SHAPE')
        left, right = halves[0].split(), halves[1].split()
        need(len(left) >= 6 and len(right) == 3, 'PROC_MOUNT_SHAPE')
        if left[4] == b'/proc':
            options = left[5].split(b',') + right[2].split(b',')
            need(left[3] == b'/' and right[0] == b'proc'
                 and all((not item.startswith(b'hidepid') or item == b'hidepid=0')
                         and not item.startswith(b'subset') for item in options),
                 'PROC_MOUNT_POLICY')
            matches.append(left[2])
    need(len(matches) == 1, 'PROC_MOUNT_COUNT')

    pid_stat = bounded('/proc/1/stat', 8192, proc=True)
    pid_status = bounded('/proc/1/status', 65536, proc=True)
    need(pid_stat.startswith(b'1 (') and pid_stat.rfind(b') ') > 0,
         'PID1_STAT_SHAPE')
    fields = {}
    for row in pid_status.split(b'\n'):
        name, sep, value = row.partition(b':')
        if name in (b'Uid', b'Gid', b'Pid', b'Tgid', b'Threads'):
            need(sep and name not in fields, 'PID1_STATUS_SHAPE')
            fields[name] = value.split()
    need(set(fields) == {b'Uid', b'Gid', b'Pid', b'Tgid', b'Threads'}
         and fields[b'Uid'] == [b'0'] * 4
         and fields[b'Gid'] == [b'0'] * 4
         and fields[b'Pid'] == [b'1'] and fields[b'Tgid'] == [b'1']
         and len(fields[b'Threads']) == 1, 'PID1_STATUS_SHAPE')

    status = bounded('/var/lib/dpkg/status', 16 * 1024 * 1024)
    listing = bounded('/var/lib/dpkg/info/systemd.list', 2 * 1024 * 1024)
    need(b'\r' not in status and b'\0' not in status
         and len(status.rstrip(b'\n').split(b'\n\n')) <= 65536,
         'DPKG_STATUS_SHAPE')
    lines = listing[:-1].split(b'\n')
    need(b'\r' not in listing and b'\0' not in listing
         and 0 < len(lines) <= 32768
         and all(line.startswith(b'/') and len(line) <= 4096 for line in lines)
         and lines.count(b'/usr/lib/systemd/systemd') == 1,
         'DPKG_LIST_SHAPE')

    print('PASS isolated unprivileged Python 3.14 feature probe')
    print('PASS visible procfs mount and PID 1 stat/status candidate shapes')
    print('PASS bounded local dpkg status and systemd file-list candidate shapes')
    print('PASS no AlertMind module imported; no privileged observer executed')
    print('STOP POINT: return only these PASS/STOP lines; do not run the PID 1 observer')
except OSError:
    raise SystemExit('STOP: NATIVE_PROBE_IO') from None
ALERTMIND_PID1_CLONE_NATIVE_PROBE
)
```

If the command times out, returns nonzero, or prints any STOP other than the
final STOP POINT, **stop and preserve the output**; do not retry with a
different path, interpreter or privileges. Report only the Gate 0 operator
attestation and the sanitized PASS/STOP lines. This is a compatibility
*candidate*, not an exact reproduction of the dormant collector's two-pass,
descriptor-relative checks: a PASS does not prove its native execution would
succeed. In particular, this unprivileged probe does not follow `/proc/1/exe`
or authenticate the running Python, source imports, installed package or host
namespace. No versioned PID 1 reference may be promoted from this result.
The separately reviewed trusted source/runtime launch and actual native
observer result remain the next gate; no original-VM or live maintenance
command is released here.
