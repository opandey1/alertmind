"""Compact active-path contract; fake unit/files, never the VM or live secrets."""
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / 'siem/rbac/broker_tls' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


m = module('compact_operator')
b = module('build_compact_bundle')
ORIGINAL = b'original miniature client'
CANDIDATE = b'secure miniature client'
HELPER = b'# miniature staged helper, never executed\n'
DER = b'synthetic DER fixture; not a certificate or live proof'
PEM = b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(DER) + b'\n-----END CERTIFICATE-----\n'
CONFIG = (b'hosts:\n  - default:\n      url: https://localhost\n      port: 55000\n'
          b'      run_as: true\n      username: wazuh-wui\n'
          b'      password: synthetic-only-never-logged\n')


class PowerLoss(BaseException):
    """Bypass ordinary exception recovery to model a killed process."""


class FakeHost:
    def __init__(self):
        self.files = {m.CLIENT: ORIGINAL, m.CONFIG: CONFIG, m.SOURCE_CERT: PEM,
                      m.FRAGMENTS[0]: b'[Service]\nExecStart=/vendor/dashboard\n',
                      m.STAGE + '/candidate.cjs': CANDIDATE,
                      m.STAGE + '/compact_operator.py': HELPER,
                      m.STAGE + '/bundle.json': json.dumps({
                          'schema': 1, 'candidate_sha256': m.CANDIDATE_SHA,
                          'operator_sha256': m.sha(HELPER)}).encode()}
        self.meta = {p: [0o400 if p.startswith(m.BASE) else 0o644, 0, 0]
                     for p in self.files}
        self.meta[m.CLIENT] = [0o640, 126, 128]
        self.dirs = {m.BASE, m.STAGE}
        self.active = 'active'
        self.pid = '71'
        self.loaded = []
        self.need_reload = 'no'
        self.extra_dropins = []
        self.fragment = m.FRAGMENTS[0]
        self.killmode = 'control-group'
        self.version_ok = True
        self.expired = False
        self.start_failure = False
        self.events = []
        self.crash_at = None

    def event(self, kind, target):
        self.events.append((kind, target))
        if len(self.events) == self.crash_at:
            raise PowerLoss()

    def exists(self, path):
        return path in self.files or path in self.dirs

    def read(self, path, *, root=True):
        if path.startswith(m.BASE + '/'):
            m.require(self.meta[path] == [0o400, 0, 0], 'PRIVATE_FILE')
        return self.files[path]

    def metadata(self, path):
        return self.meta[path]

    def mkdir(self, path):
        self.dirs.add(path)
        self.event('mkdir', path)

    def packages(self):
        m.require(self.version_ok, 'PACKAGE')

    def info(self, key):
        return {'ActiveState': self.active, 'MainPID': self.pid,
                'DropInPaths': ' '.join(self.loaded), 'FragmentPath': self.fragment,
                'NeedDaemonReload': self.need_reload, 'KillMode': self.killmode}[key]

    def put(self, path, raw, *, expected, metadata=(0o644, 0, 0), root=True):
        m.require(self.files.get(path) == expected, 'TARGET_CHANGED')
        if path in (m.CLIENT, m.CERT, m.HELPER, m.GUARD, m.BACKUP, m.RECEIPT):
            # This assertion is independent of the flow's order checks.
            assert self.active in ('inactive', 'failed') or path == m.RECEIPT
            assert path == m.RECEIPT or m.INHIBIT in self.loaded
        self.files[path] = raw
        self.meta[path] = list(metadata)
        if path in (m.INHIBIT, m.GUARD):
            self.need_reload = 'yes'
        self.event('put', path)

    def remove(self, path, expected):
        m.require(self.files[path] == expected, 'TARGET_CHANGED')
        del self.files[path]
        del self.meta[path]
        if path in (m.INHIBIT, m.GUARD):
            self.need_reload = 'yes'
        self.event('remove', path)

    def control(self, action):
        if action == 'daemon-reload':
            self.loaded = sorted([p for p in (m.INHIBIT, m.GUARD) if p in self.files]
                                 + self.extra_dropins)
            self.need_reload = 'no'
        elif action == 'stop':
            self.active, self.pid = 'inactive', '0'
        elif action == 'start':
            m.require(not self.start_failure, 'TOOL')
            m.check(self)  # Model the mandatory systemd pre-start callback.
            assert self.files[m.CLIENT] == CANDIDATE
            self.active, self.pid = 'active', '72'
        else:
            raise AssertionError(action)
        self.event('control', action)

    def valid_time(self):
        m.require(not self.expired, 'TOOL')


class CompactFlowTests(unittest.TestCase):
    def setUp(self):
        for key, raw in (('ORIGINAL_SHA', ORIGINAL), ('CANDIDATE_SHA', CANDIDATE),
                         ('CERT_SHA', DER)):
            p = patch.object(m, key, m.sha(raw))
            p.start()
            self.addCleanup(p.stop)
        self.h = FakeHost()

    def ready(self):
        m.prepare(self.h)
        m.install(self.h)

    def test_prepare_install_resume_preserves_metadata_and_logs_no_secret(self):
        self.ready()
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.h.files[m.BACKUP], ORIGINAL)
        self.assertEqual(self.h.meta[m.BACKUP], [0o400, 0, 0])
        self.assertNotIn(b'synthetic-only-never-logged', self.h.files[m.RECEIPT])
        m.resume(self.h)
        m.check(self.h)
        self.assertEqual(self.h.active, 'active')
        self.assertEqual(self.h.meta[m.CLIENT], [0o640, 126, 128])
        self.assertEqual(m.decode_receipt(self.h.files[m.RECEIPT])['phase'], 'running')

    def test_prepare_refuses_unknown_baselines_before_mutation(self):
        changes = [lambda h: setattr(h, 'version_ok', False),
                   lambda h: h.files.update({m.CLIENT: b'unknown client'}),
                   lambda h: h.files.update({m.CONFIG: CONFIG.replace(b'localhost', b'127.0.0.1')}),
                   lambda h: h.files.update({m.SOURCE_CERT: PEM + b'private data'}),
                   lambda h: h.files.update({m.GUARD: b'unknown guard'}),
                   lambda h: setattr(h, 'loaded', ['/unknown/dropin']),
                   lambda h: setattr(h, 'killmode', 'process')]
        for change in changes:
            with self.subTest(change=change):
                h = FakeHost()
                change(h)
                with self.assertRaises(m.CompactError):
                    m.prepare(h)
                self.assertEqual(h.events, [])

    def test_startup_refuses_package_config_client_trust_helper_and_wiring_drift(self):
        changes = [lambda h: setattr(h, 'version_ok', False),
                   lambda h: h.files.update({m.CONFIG: CONFIG + b'# changed\n'}),
                   lambda h: h.files.update({m.CLIENT: ORIGINAL}),
                   lambda h: h.files.update({m.CERT: b'unknown trust'}),
                   lambda h: h.files.pop(m.CERT),
                   lambda h: h.files.update({m.HELPER: HELPER + b'# changed'}),
                   lambda h: h.meta.update({m.CLIENT: [0o644, 126, 128]}),
                   lambda h: h.meta.update({m.RECEIPT: [0o644, 0, 0]}),
                   lambda h: h.files.update({m.FRAGMENTS[0]: b'unknown unit'}),
                   lambda h: setattr(h, 'need_reload', 'yes'),
                   lambda h: setattr(h, 'loaded', h.loaded + ['/unknown/dropin']),
                   lambda h: setattr(h, 'expired', True)]
        for change in changes:
            with self.subTest(change=change):
                self.h = FakeHost()
                self.ready()
                m.resume(self.h)
                change(self.h)
                before = list(self.h.events)
                with self.assertRaises((m.CompactError, KeyError)):
                    m.check(self.h)
                self.assertEqual(self.h.events, before)

    def test_inhibited_startup_refuses_without_mutation(self):
        self.ready()
        before = list(self.h.events)
        with self.assertRaisesRegex(m.CompactError, 'MAINTENANCE'):
            m.check(self.h)
        self.assertEqual(self.h.events, before)

    def test_install_refuses_unknown_targets_and_stays_stopped(self):
        for path in (m.CERT, m.HELPER, m.CLIENT):
            with self.subTest(path=path):
                h = FakeHost()
                m.prepare(h)
                h.files[path] = b'unknown'
                h.meta[path] = [0o644, 0, 0]
                with self.assertRaises(m.CompactError):
                    m.install(h)
                self.assertEqual(h.files[path], b'unknown')
                self.assertEqual(h.active, 'inactive')
                self.assertEqual(h.files[m.INHIBIT], m.DENY)

    def test_prepare_recovers_each_completed_mutation_without_overwriting_unknown_backup(self):
        m.prepare(self.h)
        points = len(self.h.events)
        for point in range(1, points + 1):
            with self.subTest(point=point):
                h = FakeHost()
                h.crash_at = point
                with self.assertRaises(PowerLoss):
                    m.prepare(h)
                self.assertEqual(h.files[m.CLIENT], ORIGINAL)
                h.crash_at = None
                if not h.exists(m.RECEIPT):
                    m.prepare(h)
                m.install(h)
                self.assertEqual(h.active, 'inactive')
                self.assertEqual(h.files[m.CLIENT], CANDIDATE)
        h = FakeHost()
        h.files[m.BACKUP], h.meta[m.BACKUP] = b'unknown', [0o400, 0, 0]
        with self.assertRaisesRegex(m.CompactError, 'TARGET_CHANGED'):
            m.prepare(h)
        self.assertEqual(h.files[m.BACKUP], b'unknown')

    def test_install_recovers_each_completed_mutation_under_inhibition(self):
        m.prepare(self.h)
        self.h.events = []
        m.install(self.h)
        for point in range(1, len(self.h.events) + 1):
            with self.subTest(point=point):
                h = FakeHost()
                m.prepare(h)
                h.events, h.crash_at = [], point
                with self.assertRaises(PowerLoss):
                    m.install(h)
                self.assertEqual(h.active, 'inactive')
                self.assertEqual(h.files[m.INHIBIT], m.DENY)
                h.crash_at = None
                m.install(h)
                m.resume(h)
                self.assertEqual(h.active, 'active')

    def test_resume_recovers_each_completed_mutation_with_only_secure_start(self):
        self.ready()
        self.h.events = []
        m.resume(self.h)
        for point in range(1, len(self.h.events) + 1):
            with self.subTest(point=point):
                h = FakeHost()
                m.prepare(h)
                m.install(h)
                h.events, h.crash_at = [], point
                with self.assertRaises(PowerLoss):
                    m.resume(h)
                self.assertEqual(h.files[m.CLIENT], CANDIDATE)
                self.assertEqual(h.files[m.GUARD], m.STARTUP)
                h.crash_at = None
                # Receipt may be running if killed just after its atomic save.
                m.install(h)
                m.resume(h)
                self.assertEqual(h.active, 'active')

    def test_restart_failure_reestablishes_durable_inhibition(self):
        self.ready()
        self.h.start_failure = True
        with self.assertRaisesRegex(m.CompactError, 'TOOL'):
            m.resume(self.h)
        self.assertEqual(self.h.active, 'inactive')
        self.assertIn(m.INHIBIT, self.h.loaded)

    def test_rollback_original_never_restarts_and_secure_reinstall_is_possible(self):
        self.ready()
        m.resume(self.h)
        before = len(self.h.events)
        m.rollback(self.h)
        m.rollback(self.h)
        self.assertEqual(self.h.files[m.CLIENT], ORIGINAL)
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.h.loaded, [m.INHIBIT])
        self.assertNotIn(('control', 'start'), self.h.events[before:])
        self.assertEqual(self.h.meta[m.CLIENT], [0o640, 126, 128])
        m.install(self.h)
        m.resume(self.h)
        self.assertEqual(self.h.files[m.CLIENT], CANDIDATE)

    def test_rollback_recovers_each_completed_mutation_and_refuses_damaged_backup(self):
        self.ready()
        self.h.events = []
        m.rollback(self.h)
        for point in range(1, len(self.h.events) + 1):
            with self.subTest(point=point):
                h = FakeHost()
                m.prepare(h)
                m.install(h)
                h.events, h.crash_at = [], point
                with self.assertRaises(PowerLoss):
                    m.rollback(h)
                h.crash_at = None
                m.rollback(h)
                self.assertEqual(h.files[m.CLIENT], ORIGINAL)
                self.assertEqual(h.active, 'inactive')
        self.h.files[m.BACKUP] = b'bad backup'
        with self.assertRaisesRegex(m.CompactError, 'BACKUP'):
            m.rollback(self.h)
        self.assertEqual(self.h.active, 'inactive')

    def test_pause_stops_a_secure_running_install_without_changing_client(self):
        self.ready()
        m.resume(self.h)
        m.inhibit(self.h)
        self.assertEqual(self.h.files[m.CLIENT], CANDIDATE)
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.h.files[m.INHIBIT], m.DENY)


class CompactParserAndAdapterTests(unittest.TestCase):
    def test_production_pins_still_equal_existing_reviewed_contract(self):
        contract = json.loads((ROOT / 'siem/rbac/broker_tls/contract.json').read_bytes())
        self.assertEqual(m.ORIGINAL_SHA, contract['original_sha256'])
        self.assertEqual(m.CANDIDATE_SHA, contract['candidate_sha256'])
        self.assertEqual(m.CERT_SHA, '5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87')
        self.assertIn(b'ExecStartPre=+', m.STARTUP)
        self.assertIn(b' -I -B ', m.STARTUP)
        self.assertNotIn(b'ExecStart=', m.STARTUP)
        self.assertEqual(m.DENY, b'[Service]\nExecStartPre=/bin/false\n')

    def test_yaml_requires_exact_endpoint_and_rejects_ambiguous_inputs(self):
        m.configuration(CONFIG)
        for raw in (CONFIG.replace(b'55000', b'true'),
                    CONFIG.replace(b'localhost', b'other.invalid'),
                    CONFIG.replace(b'run_as: true', b'run_as: false'),
                    CONFIG.replace(b'run_as: true', b'run_as: true\n      run_as: false'),
                    CONFIG.replace(b'username: wazuh-wui', b'username: other'),
                    CONFIG.replace(b'hosts:', b'hosts: &anchored'),
                    CONFIG + b'hosts: []\n', b'hosts: [*missing]\n'):
            with self.subTest(raw=raw), self.assertRaises(m.CompactError):
                m.configuration(raw)

    def test_certificate_rejects_unknown_pin_multiple_certificates_and_private_key(self):
        for raw in (PEM, PEM + PEM, PEM + b'-----BEGIN PRIVATE KEY-----\n', b'garbage'):
            with self.subTest(raw=raw), self.assertRaises(m.CompactError):
                m.certificate(raw)

    def test_json_duplicate_and_receipt_type_errors(self):
        with self.assertRaisesRegex(m.CompactError, 'JSON_DUPLICATE'):
            m.parse_json(b'{"schema":1,"schema":1}')
        receipt = {'schema': 1, 'phase': 'prepared', 'fragment': m.FRAGMENTS[0],
                   'helper_sha256': 'a' * 64, 'config_sha256': 'b' * 64,
                   'fragment_sha256': 'c' * 64, 'client_metadata': [0o640, 126, 128]}
        m.decode_receipt(json.dumps(receipt).encode())
        for key, value in (('schema', True), ('phase', 'unknown'), ('fragment', '/arbitrary'),
                           ('helper_sha256', 'bad'), ('client_metadata', [0o666, 0, 0])):
            with self.subTest(key=key), self.assertRaises(m.CompactError):
                m.decode_receipt(json.dumps(dict(receipt, **{key: value})).encode())

    def test_stable_identity_ignores_atime_but_not_content_metadata(self):
        fields = dict(st_dev=1, st_ino=2, st_mode=0o100644, st_uid=0, st_gid=0,
                      st_nlink=1, st_size=7, st_mtime_ns=100, st_ctime_ns=101,
                      st_atime_ns=102)
        expected = m.identity(SimpleNamespace(**fields))
        self.assertEqual(expected, m.identity(SimpleNamespace(**dict(fields, st_atime_ns=999))))
        for key in ('st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid'):
            self.assertNotEqual(expected, m.identity(SimpleNamespace(**dict(fields, **{key: 999}))))

    def test_cli_static_errors_never_include_raw_exception_or_config(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(m.main(['arbitrary-command']), 1)
        self.assertEqual(stderr.getvalue(), 'STOP compact broker TLS: ARGUMENTS\n')
        stderr = io.StringIO()
        with patch.object(m, 'LinuxHost', side_effect=ValueError('synthetic-secret')):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(m.main(['check']), 1)
        self.assertEqual(stderr.getvalue(), 'STOP compact broker TLS: IO_OR_TOOL\n')

    def test_non_root_or_non_linux_cannot_launch_adapter(self):
        with patch.object(m.sys, 'platform', 'win32'):
            with self.assertRaisesRegex(m.CompactError, 'ROOT_LINUX'):
                m.LinuxHost()
        with patch.object(m.sys, 'platform', 'linux'), patch.object(m.os, 'geteuid', return_value=1001, create=True):
            with self.assertRaisesRegex(m.CompactError, 'ROOT_LINUX'):
                m.LinuxHost()
        calls = []
        resource = SimpleNamespace(RLIMIT_CORE=4,
                                   setrlimit=lambda *args: calls.append(args))
        with patch.object(m.sys, 'platform', 'linux'), \
                patch.object(m.os, 'geteuid', return_value=0, create=True), \
                patch.dict(sys.modules, {'resource': resource}), patch.object(m.os, 'umask') as umask:
            m.LinuxHost()
            self.assertEqual(calls, [(4, (0, 0))])
            umask.assert_called_once_with(0o077)

    def test_fixed_tool_adapter_uses_no_shell_and_discards_tool_diagnostics(self):
        host = object.__new__(m.LinuxHost)
        with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=b'value', stderr=b'')) as run:
            self.assertEqual(host.run(['/usr/bin/systemctl', 'show', m.UNIT]), b'value')
            self.assertEqual(run.call_args.kwargs['cwd'], '/')
            self.assertNotIn('shell', run.call_args.kwargs)
            self.assertNotIn('PYTHONPATH', run.call_args.kwargs['env'])
        with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(
                returncode=1, stdout=b'secret', stderr=b'secret')):
            with self.assertRaisesRegex(m.CompactError, '^TOOL$'):
                host.run(['/usr/bin/systemctl', 'show', m.UNIT])

    def test_public_directory_creation_explicitly_overcomes_private_umask(self):
        host = object.__new__(m.LinuxHost)
        with patch.object(host, 'exists', side_effect=[True, False]), \
                patch.object(host, 'parents'), patch.object(host, 'sync'), \
                patch.object(m.os, 'mkdir') as mkdir, patch.object(m.os, 'chmod') as chmod, \
                patch.object(m.os, 'lstat', return_value=SimpleNamespace(st_mode=0o40755, st_uid=0)):
            host.mkdir('/etc/alertmind/certs')
            mkdir.assert_called_once_with('/etc/alertmind/certs', 0o755)
            chmod.assert_called_once_with('/etc/alertmind/certs', 0o755)

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'Linux no-follow filesystem adapter')
    def test_disposable_leaf_read_and_replace_preserves_metadata_without_fd_leak(self):
        # Isolate leaf I/O from root-only ancestor admission, not production policy.
        host = object.__new__(m.LinuxHost)
        with tempfile.TemporaryDirectory() as tmp, patch.object(host, 'parents'):
            path = str(Path(tmp) / 'leaf')
            Path(path).write_bytes(b'before')
            os.chmod(path, 0o600)
            before = len(os.listdir('/proc/self/fd'))
            for _ in range(8):
                self.assertEqual(host.read(path, root=False), b'before')
            metadata = [0o600, os.geteuid(), os.getegid()]
            host.put(path, b'after', expected=b'before', metadata=metadata, root=False)
            self.assertEqual(host.read(path, root=False), b'after')
            self.assertEqual(host.metadata(path), metadata)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            with self.assertRaisesRegex(m.CompactError, 'TARGET_CHANGED'):
                host.put(path, b'unknown', expected=b'before', metadata=metadata, root=False)
            self.assertEqual(host.read(path, root=False), b'after')

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'Linux no-follow filesystem adapter')
    def test_disposable_leaf_refuses_symlink_hardlink_and_nonowner_writes(self):
        host = object.__new__(m.LinuxHost)
        with tempfile.TemporaryDirectory() as tmp, patch.object(host, 'parents'):
            path = str(Path(tmp) / 'leaf')
            other = str(Path(tmp) / 'other')
            Path(path).write_bytes(b'public fixture')
            os.chmod(path, 0o666)
            with self.assertRaisesRegex(m.CompactError, 'FILE_METADATA'):
                host.read(path, root=False)
            os.chmod(path, 0o600)
            os.symlink(path, other)
            with self.assertRaisesRegex(m.CompactError, 'FILE_METADATA'):
                host.read(other, root=False)
            os.unlink(other)
            os.link(path, other)
            with self.assertRaisesRegex(m.CompactError, 'FILE_METADATA'):
                host.read(path, root=False)


class CompactBundleTests(unittest.TestCase):
    def test_builder_new_public_bundle_and_tamper_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / 'source'
            src.mkdir()
            contract = {'candidate_sha256': m.sha(CANDIDATE), 'original_sha256': m.sha(ORIGINAL)}
            (root / 'contract.json').write_text(json.dumps(contract), encoding='utf-8')
            (root / 'compact_operator.py').write_bytes(b'raise RuntimeError("must not execute")\r\n')
            (src / 'manifest.json').write_text(json.dumps(contract), encoding='utf-8')
            (src / 'candidate.cjs').write_bytes(CANDIDATE)
            out = root / 'new'
            with patch.object(b, 'HERE', root):
                result = b.build(src, out)
                self.assertEqual((out / 'candidate.cjs').read_bytes(), CANDIDATE)
                self.assertNotIn(b'\r', (out / 'compact_operator.py').read_bytes())
                self.assertEqual(result['operator_sha256'], m.sha((out / 'compact_operator.py').read_bytes()))
                sums = (out / 'SHA256SUMS').read_text().splitlines()
                self.assertEqual(len(sums), 3)
                for line in sums:
                    digest, name = line.split('  ')
                    self.assertEqual(m.sha((out / name).read_bytes()), digest)
                with self.assertRaisesRegex(ValueError, 'OUTPUT_EXISTS'):
                    b.build(src, out)
                (src / 'candidate.cjs').write_bytes(b'tampered')
                with self.assertRaisesRegex(ValueError, 'CANDIDATE'):
                    b.build(src, root / 'bad')
                self.assertFalse((root / 'bad').exists())

    def test_builder_duplicate_manifest_and_size_refusals(self):
        with self.assertRaisesRegex(ValueError, 'JSON_DUPLICATE'):
            b.unique([('x', 1), ('x', 2)])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'oversized'
            path.write_bytes(b'x' * (b.LIMIT + 1))
            with self.assertRaisesRegex(ValueError, 'SIZE'):
                b.read(path)


if __name__ == '__main__':
    unittest.main()
