"""Fixed-target local-first operator candidate; no VM execution released here.

Trusts the lab OS, root administrator, systemd and packaged Python/PyYAML.
No runtime attestation, discovered target, secret output or remote request.
CLI mutations require root on Linux; offline tests use an in-memory host.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

UNIT = 'wazuh-dashboard.service'
VERSION = '4.14.7-1'
PYTHON = '/var/ossec/framework/python/bin/python3'
BASE = '/root/alertmind-broker-tls-compact'
STAGE = BASE + '/stage'
STATE = BASE + '/state'
RECEIPT = STATE + '/receipt.json'
BACKUP = STATE + '/original-client.bin'
CLIENT = '/usr/share/wazuh-dashboard/plugins/wazuhCore/server/services/server-api-client.js'
CONFIG = '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml'
SOURCE_CERT = '/var/ossec/api/configuration/ssl/server.crt'
CERT = '/etc/alertmind/certs/alertmind-server-api.pem'
HELPER = '/usr/local/libexec/alertmind-broker-tls-compact.py'
DROPIN_DIR = '/etc/systemd/system/' + UNIT + '.d'
GUARD = DROPIN_DIR + '/90-alertmind-broker-tls.conf'
INHIBIT = DROPIN_DIR + '/00-alertmind-broker-maintenance.conf'
DENY = b'[Service]\nExecStartPre=/bin/false\n'
STARTUP = ('[Service]\nExecStartPre=+' + PYTHON + ' -I -B ' + HELPER + ' check\n').encode()
ORIGINAL_SHA = 'd691047acfa9b9a779a94251c6b813e0296eaf53b3b202e89cb56b44eee48afb'
CANDIDATE_SHA = 'fe721feb8599293853e10d33823e68ff72df001be00382e3701d5da645aba28f'
CERT_SHA = '5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87'
FRAGMENTS = ('/etc/systemd/system/' + UNIT, '/usr/lib/systemd/system/' + UNIT)
LIMIT = 128 * 1024


class CompactError(Exception):
    """Only static codes reach the console or systemd journal."""


def require(ok, code):
    if not ok:
        raise CompactError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(value):
    # Reads can legitimately update atime; content/ownership identity must not.
    return tuple(getattr(value, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'JSON_DUPLICATE')
        result[key] = value
    return result


def parse_json(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise CompactError('JSON') from None


def certificate(raw):
    match = re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n'
                         rb'([A-Za-z0-9+/=\r\n]+)\r?\n'
                         rb'-----END CERTIFICATE-----\r?\n?', raw)
    require(match is not None, 'CERT_PEM')
    try:
        encoded = match[1].replace(b'\r', b'').replace(b'\n', b'')
        der = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise CompactError('CERT_PEM') from None
    require(base64.b64encode(der) == encoded and sha(der) == CERT_SHA, 'CERT_PIN')


def wazuh_identity():
    # Resolve the named vendor principal; numeric IDs differ between installs.
    try:
        import pwd
        import grp
        user, group = pwd.getpwnam('wazuh'), grp.getgrnam('wazuh')
        require(user.pw_uid > 0 and group.gr_gid > 0 and
                user.pw_gid == group.gr_gid, 'SOURCE_CERT_IDENTITY')
        return user.pw_uid, group.gr_gid
    except CompactError:
        raise
    except Exception:
        raise CompactError('SOURCE_CERT_IDENTITY') from None


def configuration(raw):
    # The existing package provides PyYAML. No config snippets/errors are logged.
    import yaml

    class Loader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            event = self.peek_event()
            require(not isinstance(event, yaml.AliasEvent) and
                    getattr(event, 'anchor', None) is None, 'CONFIG_ALIAS')
            return super().compose_node(parent, index)

        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                require(type(key) in (str, int) and key != '<<' and
                        key not in result, 'CONFIG_DUPLICATE')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        data = yaml.load(raw.decode('utf-8'), Loader=Loader)
        require(type(data) is dict and type(data.get('hosts')) is list and
                len(data['hosts']) == 1, 'CONFIG_HOSTS')
        entry = data['hosts'][0]
        require(type(entry) is dict and len(entry) == 1, 'CONFIG_HOSTS')
        host = next(iter(entry.values()))
        require(type(host) is dict and host.get('url') == 'https://localhost' and
                type(host.get('port')) is int and host['port'] == 55000 and
                host.get('run_as') is True and host.get('username') == 'wazuh-wui' and
                type(host.get('password')) is str and bool(host['password']),
                'CONFIG_ENDPOINT')
    except CompactError:
        raise
    except Exception:
        raise CompactError('CONFIG') from None


def decode_receipt(raw):
    data = parse_json(raw)
    keys = {'schema', 'phase', 'helper_sha256', 'config_sha256', 'fragment',
            'fragment_sha256', 'client_metadata'}
    require(type(data) is dict and set(data) == keys and
            type(data['schema']) is int and data['schema'] == 1,
            'RECEIPT')
    require(data['phase'] in ('prepared', 'installed', 'running', 'rolled-back') and
            data['fragment'] in FRAGMENTS, 'RECEIPT')
    for key in ('helper_sha256', 'config_sha256', 'fragment_sha256'):
        require(type(data[key]) is str and re.fullmatch('[0-9a-f]{64}', data[key]),
                'RECEIPT')
    values = data['client_metadata']
    require(type(values) is list and len(values) == 3 and
            all(type(x) is int and x >= 0 for x in values) and
            values[0] <= 0o777 and not values[0] & 0o022, 'RECEIPT')
    return data


class LinuxHost:
    """Conventional trusted-admin adapter; no alternate-root CLI or shell calls."""
    def __init__(self):
        require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX')
        import resource
        # Configuration contains the existing broker credential in memory.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)

    def run(self, argv):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, cwd='/',
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
        require(result.returncode == 0 and len(result.stdout) <= LIMIT and
                len(result.stderr) <= LIMIT, 'TOOL')
        return result.stdout

    def info(self, name):
        value = self.run(['/usr/bin/systemctl', 'show', UNIT, '--property=' + name,
                          '--value']).decode('utf-8').strip()
        return value

    def packages(self):
        for name in ('wazuh-dashboard', 'wazuh-manager'):
            value = self.run(['/usr/bin/dpkg-query', '-W',
                              '-f=${Status}|${Version}', name])
            require(value == ('install ok installed|' + VERSION).encode(), 'PACKAGE')

    def parents(self, path, *, root=True):
        for parent in reversed(Path(path).parents):
            item = parent.lstat()
            require(stat.S_ISDIR(item.st_mode) and not item.st_mode & 0o022 and
                    (not root or item.st_uid == 0), 'PARENT_METADATA')
            if str(parent) == BASE or str(parent).startswith(BASE + '/'):
                require(item.st_uid == 0 and item.st_gid == 0 and
                        stat.S_IMODE(item.st_mode) == 0o700, 'PRIVATE_DIRECTORY')

    def read(self, path, *, root=True):
        self.parents(path, root=root)
        before = os.lstat(path)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                not before.st_mode & 0o022 and (not root or before.st_uid == 0) and
                0 < before.st_size <= LIMIT, 'FILE_METADATA')
        if path.startswith(BASE + '/'):
            require(before.st_uid == 0 and before.st_gid == 0 and
                    stat.S_IMODE(before.st_mode) == 0o400, 'PRIVATE_FILE')
        return self._read_checked(path, before)

    def read_source_certificate(self):
        """Only the pinned public API certificate; no general permission waiver."""
        uid, gid = wazuh_identity()
        layout = {'/': (0, 0, 0o755), '/var': (0, 0, 0o755),
                  '/var/ossec': (0, gid, 0o750),
                  '/var/ossec/api': (0, gid, 0o750),
                  '/var/ossec/api/configuration': (0, gid, 0o770),
                  '/var/ossec/api/configuration/ssl': (0, gid, 0o770)}
        parents = {}
        for parent in reversed(Path(SOURCE_CERT).parents):
            value = parent.lstat()
            require(str(parent) in layout and stat.S_ISDIR(value.st_mode) and
                    (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) ==
                    layout[str(parent)], 'SOURCE_CERT_PARENT')
            parents[str(parent)] = identity(value)
        require(set(parents) == set(layout), 'SOURCE_CERT_PARENT')
        before = os.lstat(SOURCE_CERT)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) ==
                (uid, gid, 0o400) and 0 < before.st_size <= LIMIT, 'SOURCE_CERT_FILE')
        raw = self._read_checked(SOURCE_CERT, before)
        for parent, expected in parents.items():
            require(identity(os.lstat(parent)) == expected, 'SOURCE_CERT_CHANGED')
        certificate(raw)  # Exact DER pin before any caller may copy these bytes.
        return raw

    def _read_checked(self, path, before):
        # Shared stable, bounded leaf I/O; callers must admit metadata first.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            held = os.fstat(fd)
            require(identity(held) == identity(before), 'FILE_CHANGED')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(LIMIT + 1)
            require(len(raw) == before.st_size and
                    identity(os.fstat(fd)) == identity(before) and
                    identity(os.lstat(path)) == identity(before), 'FILE_CHANGED')
            return raw
        finally:
            os.close(fd)

    def exists(self, path):
        return os.path.lexists(path)

    def metadata(self, path):
        value = os.lstat(path)
        return [stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid]

    def mkdir(self, path):
        parent = str(Path(path).parent)
        if not self.exists(parent):
            self.mkdir(parent)
        self.parents(path)
        if not self.exists(path):
            mode = 0o700 if path == BASE or path.startswith(BASE + '/') else 0o755
            os.mkdir(path, mode)
            os.chmod(path, mode)  # Public trust ancestors must survive umask 077.
            self.sync(parent)
        item = os.lstat(path)
        require(stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and
                not item.st_mode & 0o022, 'DIRECTORY')
        if path == BASE or path.startswith(BASE + '/'):
            require(item.st_gid == 0 and stat.S_IMODE(item.st_mode) == 0o700,
                    'PRIVATE_DIRECTORY')

    def sync(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def put(self, path, raw, *, expected, metadata=(0o644, 0, 0), root=True):
        require(0 < len(raw) <= LIMIT, 'WRITE_SIZE')
        parent = str(Path(path).parent)
        self.mkdir(parent) if root else self.parents(path, root=False)
        current = self.read(path, root=root) if self.exists(path) else None
        require(current == expected, 'TARGET_CHANGED')
        fd, temporary = tempfile.mkstemp(prefix='.alertmind-', dir=parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), metadata[0])
                os.fchown(stream.fileno(), metadata[1], metadata[2])
                os.fsync(stream.fileno())
            current = self.read(path, root=root) if self.exists(path) else None
            require(current == expected, 'TARGET_CHANGED')
            os.replace(temporary, path)
            self.sync(parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        require(self.read(path, root=root) == raw and self.metadata(path) == list(metadata),
                'WRITE_READBACK')

    def remove(self, path, expected):
        require(self.read(path) == expected, 'TARGET_CHANGED')
        os.unlink(path)
        self.sync(str(Path(path).parent))

    def control(self, action):
        require(action in ('daemon-reload', 'stop', 'start'), 'ACTION')
        argv = ['/usr/bin/systemctl', action]
        self.run(argv if action == 'daemon-reload' else argv + [UNIT])

    def valid_time(self):
        # Exact DER pin already identifies the accepted localhost certificate.
        # The candidate itself checks notBefore, expiry and SAN at construction.
        self.run(['/usr/bin/openssl', 'x509', '-in', CERT, '-noout', '-checkend', '0'])


def present(host, path, *, root=True):
    return host.read(path, root=root) if host.exists(path) else None


def put_known(host, path, raw, allowed, *, metadata=(0o644, 0, 0), root=True):
    current = present(host, path, root=root)
    require(current in allowed, 'TARGET_CHANGED')
    if current != raw or host.metadata(path) != list(metadata):
        host.put(path, raw, expected=current, metadata=metadata, root=root)


def stopped(host):
    require(host.info('ActiveState') in ('inactive', 'failed') and
            host.info('MainPID') == '0', 'NOT_STOPPED')


def wiring(host, inhibited):
    require(host.info('NeedDaemonReload') == 'no', 'RELOAD_REQUIRED')
    expected = sorted(([INHIBIT] if inhibited else []) +
                      ([GUARD] if host.exists(GUARD) else []))
    require(sorted(host.info('DropInPaths').split()) == expected, 'DROPINS')
    if inhibited:
        require(host.read(INHIBIT) == DENY, 'INHIBITION')
    if host.exists(GUARD):
        require(host.read(GUARD) == STARTUP, 'STARTUP_WIRING')


def inhibit(host):
    put_known(host, INHIBIT, DENY, (None, DENY))
    host.control('daemon-reload')
    host.control('stop')
    stopped(host)
    wiring(host, True)


def stage(host):
    candidate = host.read(STAGE + '/candidate.cjs')
    helper = host.read(STAGE + '/compact_operator.py')
    manifest = parse_json(host.read(STAGE + '/bundle.json'))
    require(type(manifest) is dict and type(manifest.get('schema')) is int and
            manifest == {'schema': 1, 'candidate_sha256': CANDIDATE_SHA,
                         'operator_sha256': sha(helper)}, 'STAGE')
    require(sha(candidate) == CANDIDATE_SHA, 'CANDIDATE')
    return candidate, helper


def save(host, receipt, phase):
    receipt = dict(receipt, phase=phase)
    raw = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode()
    host.put(RECEIPT, raw, expected=present(host, RECEIPT), metadata=(0o400, 0, 0))


def baseline(host, receipt):
    host.packages()
    config = host.read(CONFIG, root=False)
    configuration(config)
    require(sha(config) == receipt['config_sha256'], 'CONFIG_CHANGED')
    require(host.info('FragmentPath') == receipt['fragment'] and
            sha(host.read(receipt['fragment'])) == receipt['fragment_sha256'],
            'UNIT_CHANGED')


def installed(host, receipt):
    baseline(host, receipt)
    require(sha(host.read(CLIENT, root=False)) == CANDIDATE_SHA, 'INSTALLED_CLIENT')
    require(host.metadata(CLIENT) == receipt['client_metadata'], 'CLIENT_METADATA')
    require(sha(host.read(HELPER)) == receipt['helper_sha256'] and
            host.metadata(HELPER) == [0o400, 0, 0] and
            host.read(GUARD) == STARTUP, 'INSTALLED_GUARD')
    certificate(host.read(CERT))
    host.valid_time()


def prepare(host):
    require(not host.exists(RECEIPT), 'STATE_EXISTS')
    require(all(not host.exists(p) for p in (CERT, HELPER, GUARD)),
            'EXISTING_DEPLOYMENT')
    require(present(host, INHIBIT) in (None, DENY), 'INHIBITION')
    host.packages()
    require(host.info('DropInPaths') in ('', INHIBIT) and
            host.info('KillMode') == 'control-group',
            'UNIT_BASELINE')
    fragment = host.info('FragmentPath')
    require(fragment in FRAGMENTS, 'UNIT_BASELINE')
    fragment_raw = host.read(fragment)
    original = host.read(CLIENT, root=False)
    require(sha(original) == ORIGINAL_SHA, 'ORIGINAL_CLIENT')
    _, helper = stage(host)
    host.read_source_certificate()
    config = host.read(CONFIG, root=False)
    configuration(config)
    receipt = {'schema': 1, 'phase': 'prepared', 'helper_sha256': sha(helper),
               'config_sha256': sha(config), 'fragment': fragment,
               'fragment_sha256': sha(fragment_raw),
               'client_metadata': host.metadata(CLIENT)}
    # All compatibility reads precede inhibition; no broker file is edited here.
    inhibit(host)
    baseline(host, receipt)
    require(host.read(CLIENT, root=False) == original and
            host.metadata(CLIENT) == receipt['client_metadata'], 'ORIGINAL_CHANGED')
    host.mkdir(STATE)
    # A crash before the receipt may leave our inhibition/directory/backup.
    # Only identical backup bytes can be reused; never bless a partial receipt.
    put_known(host, BACKUP, original, (None, original), metadata=(0o400, 0, 0))
    save(host, receipt, 'prepared')


def install(host):
    inhibit(host)
    receipt = decode_receipt(host.read(RECEIPT))
    # Also the recovery entry after a crash in resume: re-inhibit and stop
    # before replacing anything, even if the verified candidate has started.
    baseline(host, receipt)
    candidate, helper = stage(host)
    require(sha(helper) == receipt['helper_sha256'], 'HELPER_CHANGED')
    original = host.read(BACKUP)
    require(sha(original) == ORIGINAL_SHA, 'BACKUP')
    pem = host.read_source_certificate()
    put_known(host, CERT, pem, (None, pem))
    put_known(host, HELPER, helper, (None, helper), metadata=(0o400, 0, 0))
    put_known(host, GUARD, STARTUP, (None, STARTUP))
    put_known(host, CLIENT, candidate, (original, candidate),
              metadata=receipt['client_metadata'], root=False)
    host.control('daemon-reload')
    wiring(host, True)
    installed(host, receipt)
    save(host, receipt, 'installed')


def check(host):
    require(not host.exists(INHIBIT), 'MAINTENANCE')
    receipt = decode_receipt(host.read(RECEIPT))
    require(receipt['phase'] in ('installed', 'running'), 'NOT_INSTALLED')
    wiring(host, False)
    installed(host, receipt)


def resume(host):
    inhibit(host)
    receipt = decode_receipt(host.read(RECEIPT))
    require(receipt['phase'] == 'installed', 'NOT_INSTALLED')
    # Retry after an interruption between un-inhibition/start/receipt update.
    # Re-establish a stopped, inhibited checkpoint before another start.
    installed(host, receipt)
    # From this point a failure re-establishes inhibition and stop. A power loss
    # after removal still leaves a fully verified secure installation, not raw
    # original bytes. Never rewrite the patch while inhibition is absent.
    try:
        host.remove(INHIBIT, DENY)
        host.control('daemon-reload')
        check(host)
        host.control('start')
        require(host.info('ActiveState') == 'active' and
                host.info('MainPID').isdigit() and int(host.info('MainPID')) > 0,
                'START_FAILED')
        save(host, receipt, 'running')
    except Exception:
        inhibit(host)
        raise


def rollback(host):
    # Stop/inhibit BEFORE parsing state: damaged or incomplete state cannot
    # accidentally leave Dashboard running while the operator diagnoses it.
    inhibit(host)
    receipt = decode_receipt(host.read(RECEIPT))
    original = host.read(BACKUP)
    require(sha(original) == ORIGINAL_SHA, 'BACKUP')
    current = host.read(CLIENT, root=False)
    require(sha(current) in (ORIGINAL_SHA, CANDIDATE_SHA), 'TARGET_CHANGED')
    host.put(CLIENT, original, expected=current,
             metadata=receipt['client_metadata'], root=False)
    for path, expected_sha in ((GUARD, sha(STARTUP)), (HELPER, receipt['helper_sha256'])):
        raw = present(host, path)
        if raw is not None:
            require(sha(raw) == expected_sha, 'TARGET_CHANGED')
            host.remove(path, raw)
    pem = present(host, CERT)
    if pem is not None:
        certificate(pem)
        host.remove(CERT, pem)
    host.control('daemon-reload')
    wiring(host, True)
    stopped(host)
    save(host, receipt, 'rolled-back')
    # Deliberately keep INHIBIT and private backup. Original TLS is insecure.


ACTIONS = {'pause': inhibit, 'prepare': prepare, 'install': install, 'check': check,
           'resume': resume, 'rollback': rollback}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        require(len(argv) == 1 and argv[0] in ACTIONS, 'ARGUMENTS')
        ACTIONS[argv[0]](LinuxHost())
    except CompactError as error:
        print('STOP compact broker TLS: ' + str(error), file=sys.stderr)
        return 1
    except Exception:
        print('STOP compact broker TLS: IO_OR_TOOL', file=sys.stderr)
        return 1
    print('PASS compact broker TLS: ' + argv[0])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
