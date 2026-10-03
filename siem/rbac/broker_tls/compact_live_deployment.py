"""Fixed original-VM maintenance facade. Offline candidate; not execution release.

Reuses pinned compact operator and endpoint functions, never the clone driver/CLI.
Normal root/OS/vendor runtime are trusted; no concurrent privileged maintenance.
No API call, credential prompt, discovery, fault injection or automatic retry.
"""
import hashlib
import os
from pathlib import Path
import stat
import sys
import types

STAGE = '/root/alertmind-broker-tls-compact/stage'
ENDPOINT_STATE = '/root/alertmind-broker-tls-compact/live-endpoint-state'
LIMIT = 128 * 1024
PINS = {
    'compact_operator.py': '2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942',
    'compact_clone_endpoint.py': 'e790465fbe599c697cf0ede9d19c5fbd6a84c7f5b67576647275043b80f603eb',
}
ACTIONS = frozenset(('preflight', 'correct-endpoint', 'preflight-inhibited',
                     'recover-endpoint', 'restore-endpoint', 'prepare',
                     'install', 'resume', 'check', 'pause', 'rollback'))
ENDPOINT_ACTIONS = ACTIONS - {'install', 'resume', 'check', 'pause', 'rollback'}


class LiveError(Exception):
    """Only static codes reach console output."""


def require(ok, code):
    if not ok:
        raise LiveError(code)


def source(name):
    """Read one fixed, pinned root-private module; not a general import loader."""
    require(name in PINS, 'SOURCE_NAME')
    path = Path(STAGE) / name
    for parent in path.parents:
        value = parent.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and
                not value.st_mode & 0o022, 'STAGE_METADATA')
        if str(parent).startswith('/root/alertmind-broker-tls-compact'):
            require(value.st_gid == 0 and stat.S_IMODE(value.st_mode) == 0o700,
                    'STAGE_METADATA')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (0, 0, 0o400)
            and 0 < before.st_size <= LIMIT, 'STAGE_METADATA')
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    identity = lambda value: tuple(getattr(value, key) for key in fields)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(identity(os.fstat(fd)) == identity(before), 'SOURCE_CHANGED')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(LIMIT + 1)
        require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()),
                'SOURCE_CHANGED')
    finally:
        os.close(fd)
    require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == PINS[name],
            'SOURCE_PIN')
    return raw


def load(name):
    raw = source(name)
    result = types.ModuleType('alertmind_live_' + name[:-3])
    result.__file__ = STAGE + '/' + name
    # Module name is not __main__: neither reused module's CLI is called.
    exec(compile(raw, result.__file__, 'exec'), result.__dict__)
    if name == 'compact_clone_endpoint.py':
        require(result.OPERATOR_SHA == PINS['compact_operator.py'], 'OPERATOR_PIN')
        # Rebind only this private module instance, never the historical source.
        result.STATE = ENDPOINT_STATE
        result.BACKUP = ENDPOINT_STATE + '/original-wazuh-yml.bin'
        result.RECEIPT = ENDPOINT_STATE + '/receipt.json'
    return result


def health(host):
    for unit in ('wazuh-indexer.service', 'wazuh-manager.service', 'filebeat.service'):
        require(host.run(['/usr/bin/systemctl', 'is-active', unit]).strip() == b'active',
                'SERVICE_HEALTH')


def active(host):
    pid = host.info('MainPID')
    require(host.info('ActiveState') == 'active' and pid.isdigit() and int(pid) > 0,
            'NOT_ACTIVE')


def context(m):
    # Only the three interfaces required by the reused endpoint functions.
    return types.SimpleNamespace(stage=lambda _, host: m.stage(host),
                                 health=health, active=active)


def preflight(m, e, host):
    d = context(m)
    if host.exists(e.STATE):
        e.preflight(m, d, host)
        return 'ready-inhibited'
    e.baseline(m, d, host)
    e.boundary(m, d, host)
    raw = host.read(m.CONFIG, root=False)
    try:
        m.configuration(raw)
    except m.CompactError as error:
        if str(error) != 'CONFIG_ENDPOINT':
            raise
        e.corrected(m, raw)  # Prospective exact one-scalar correction; no write.
        return 'needs-endpoint-correction'
    return 'endpoint-compatible'


def dispatch(action, m, e, host):
    require(action in ACTIONS, 'ARGUMENTS')
    d = context(m)
    if action == 'preflight':
        return preflight(m, e, host)
    if action in ('correct-endpoint', 'recover-endpoint', 'restore-endpoint',
                  'preflight-inhibited'):
        functions = {'correct-endpoint': e.apply, 'recover-endpoint': e.recover_apply,
                     'restore-endpoint': e.restore, 'preflight-inhibited': e.preflight}
        functions[action](m, d, host)
    elif action == 'prepare':
        require(preflight(m, e, host) != 'needs-endpoint-correction', 'ENDPOINT_REQUIRED')
        m.prepare(host)
    elif action == 'resume':
        health(host)  # No start release with a failed peer service.
        m.resume(host)
    else:
        # In particular, emergency pause/rollback are not blocked by peer health
        # or endpoint-source loading. Operator retains stopped-safe recovery.
        m.ACTIONS[action](host)
    return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    m, e = None, None
    try:
        require(len(argv) == 1 and argv[0] in ACTIONS, 'ARGUMENTS')
        require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX')
        m = load('compact_operator.py')
        if argv[0] in ENDPOINT_ACTIONS:
            e = load('compact_clone_endpoint.py')
            host = e.endpoint_host(m)
        else:
            host = m.LinuxHost()
        result = dispatch(argv[0], m, e, host)
    except Exception as error:
        safe = (LiveError,) + ((m.CompactError,) if m is not None else ()) + (
            (e.EndpointError,) if e is not None else ())
        code = str(error) if isinstance(error, safe) else 'IO_OR_TOOL'
        print('STOP original broker TLS: ' + code + '; preserve state; no automatic retry',
              file=sys.stderr)
        return 1
    print('PASS original broker TLS: ' + argv[0] + (('; ' + result) if result else ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
