"""Original-VM wiring, synthetic files/services only; no root or VM execution."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import test_broker_tls_compact as t

l = t.module('compact_live_deployment')
b = t.module('build_compact_live_packet')
e = t.module('compact_clone_endpoint')
m = t.m
OLD = t.CONFIG.replace(b'https://localhost', b'https://127.0.0.1')


class Host(t.FakeHost):
    def __init__(self, raw=OLD):
        super().__init__()
        self.files[m.CONFIG] = raw
        self.meta[m.CONFIG] = [0o600, 126, 128]
        self.peer_active = True
        self.extra_attributes = False

    def config_no_extended_metadata(self):
        e.require(not self.extra_attributes, 'CONFIG_EXTENDED_METADATA')

    def run(self, argv):
        if argv[:2] == ['/usr/bin/systemctl', 'is-active']:
            return b'active\n' if self.peer_active else b'failed\n'
        assert argv[:2] == ['/usr/bin/openssl', 'x509']
        return b''

    def put(self, path, raw, **kwargs):
        if path in (m.CONFIG, e.BACKUP, e.RECEIPT):
            assert self.active in ('inactive', 'failed') and self.pid == '0'
            assert self.loaded == [m.INHIBIT] and self.files[m.INHIBIT] == m.DENY
            if path == m.CONFIG:
                self.config_no_extended_metadata()
        return super().put(path, raw, **kwargs)


class LiveFlowTests(unittest.TestCase):
    def setUp(self):
        for obj, key, value in (
            (m, 'ORIGINAL_SHA', m.sha(t.ORIGINAL)),
            (m, 'CANDIDATE_SHA', m.sha(t.CANDIDATE)),
            (m, 'CERT_SHA', m.sha(t.DER)),
            (e, 'dashboard_identity', lambda: (126, 128)),
            (e, 'STATE', l.ENDPOINT_STATE),
            (e, 'BACKUP', l.ENDPOINT_STATE + '/original-wazuh-yml.bin'),
            (e, 'RECEIPT', l.ENDPOINT_STATE + '/receipt.json')):
            p = patch.object(obj, key, value)
            p.start()
            self.addCleanup(p.stop)
        self.h = Host()

    def run_action(self, action):
        return l.dispatch(action, m, e, self.h)

    def test_ip_preflight_is_read_only_and_prepare_does_not_correct_implicitly(self):
        self.assertEqual(self.run_action('preflight'), 'needs-endpoint-correction')
        self.assertEqual(self.h.events, [])
        with self.assertRaisesRegex(l.LiveError, '^ENDPOINT_REQUIRED$'):
            self.run_action('prepare')
        self.assertEqual(self.h.events, [])
        self.assertEqual(self.h.files[m.CONFIG], OLD)

    def test_explicit_correction_connects_inhibited_phase_and_unchanged_operator(self):
        self.run_action('correct-endpoint')
        self.assertEqual(self.h.files[e.BACKUP], OLD)
        self.assertEqual(self.h.files[m.CONFIG], t.CONFIG)
        self.assertEqual(self.h.metadata(m.CONFIG), [0o600, 126, 128])
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.run_action('preflight'), 'ready-inhibited')
        self.run_action('preflight-inhibited')
        self.run_action('prepare')
        self.run_action('install')
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.h.files[m.HELPER], t.HELPER)  # Not the live facade/clone driver.
        self.run_action('resume')
        self.run_action('check')
        self.assertEqual(self.h.active, 'active')
        self.assertNotIn(m.BASE + '/endpoint-state', self.h.dirs)

    def test_already_localhost_skips_yaml_mutation_and_endpoint_backup(self):
        self.h = Host(t.CONFIG)
        self.assertEqual(self.run_action('preflight'), 'endpoint-compatible')
        self.run_action('prepare')
        self.run_action('install')
        self.run_action('resume')
        self.assertNotIn(e.STATE, self.h.dirs)
        self.assertNotIn(('put', m.CONFIG), self.h.events)

    def test_baseline_refusals_make_no_mutation_or_scope_expansion(self):
        for variant in ('package', 'health', 'extensions', 'config', 'extra-dropin'):
            with self.subTest(variant=variant):
                self.h = Host()
                if variant == 'package': self.h.version_ok = False
                if variant == 'health': self.h.peer_active = False
                if variant == 'extensions': self.h.extra_attributes = True
                if variant == 'config': self.h.files[m.CONFIG] = OLD.replace(b'run_as: true', b'run_as: false')
                if variant == 'extra-dropin': self.h.loaded = ['/unknown/dropin']
                with self.assertRaises((l.LiveError, e.EndpointError, m.CompactError)):
                    self.run_action('preflight')
                self.assertEqual(self.h.events, [])

    def test_interrupted_yaml_write_has_explicit_stopped_recovery_then_restore(self):
        original_put = self.h.put
        def interrupted(path, raw, **kwargs):
            original_put(path, raw, **kwargs)
            if path == m.CONFIG:
                raise t.PowerLoss()
        with patch.object(self.h, 'put', interrupted), self.assertRaises(t.PowerLoss):
            self.run_action('correct-endpoint')
        self.assertEqual(self.h.active, 'inactive')
        self.run_action('recover-endpoint')
        self.run_action('preflight-inhibited')
        self.run_action('restore-endpoint')
        self.assertEqual(self.h.files[m.CONFIG], OLD)
        self.assertEqual(self.h.loaded, [m.INHIBIT])

    def test_endpoint_restore_after_tls_prepare_is_refused_and_keeps_inhibition(self):
        self.run_action('correct-endpoint')
        self.run_action('prepare')
        with self.assertRaisesRegex(e.EndpointError, '^TLS_ALREADY_PREPARED$'):
            self.run_action('restore-endpoint')
        self.assertEqual(self.h.files[m.CONFIG], t.CONFIG)
        self.assertEqual(self.h.active, 'inactive')

    def test_failed_peer_blocks_resume_but_not_emergency_pause_or_rollback(self):
        self.h = Host(t.CONFIG)
        self.run_action('prepare')
        self.run_action('install')
        self.h.peer_active = False
        with self.assertRaisesRegex(l.LiveError, '^SERVICE_HEALTH$'):
            self.run_action('resume')
        self.assertEqual(self.h.active, 'inactive')
        self.run_action('pause')
        self.run_action('rollback')
        self.assertEqual(self.h.files[m.CLIENT], t.ORIGINAL)
        self.assertEqual(self.h.loaded, [m.INHIBIT])

    def test_clone_fault_actions_arbitrary_paths_and_extra_args_refused_before_load(self):
        for args in (['interrupt-install'], ['refuse-missing-trust'], ['/tmp/helper'],
                     ['resume', '--force']):
            with patch.object(l, 'load') as load, contextlib.redirect_stderr(io.StringIO()) as out:
                self.assertEqual(l.main(args), 1)
                load.assert_not_called()
                self.assertIn('ARGUMENTS', out.getvalue())

    def test_loader_rebinds_private_endpoint_instance_without_running_clone_cli(self):
        source = (t.ROOT / 'siem/rbac/broker_tls/compact_clone_endpoint.py').read_bytes()
        with patch.object(l, 'source', return_value=source):
            loaded = l.load('compact_clone_endpoint.py')
        self.assertEqual(loaded.STATE, l.ENDPOINT_STATE)
        self.assertEqual(loaded.BACKUP, l.ENDPOINT_STATE + '/original-wazuh-yml.bin')
        self.assertEqual(loaded.__name__, 'alertmind_live_compact_clone_endpoint')
        self.assertEqual(loaded.OPERATOR_SHA, l.PINS['compact_operator.py'])
        # Original module/source remains clone-scoped; main()/driver() never called.
        fresh = t.module('compact_clone_endpoint')
        self.assertEqual(fresh.STATE, m.BASE + '/endpoint-state')

    def test_main_pause_loads_only_operator_and_suppresses_untrusted_errors(self):
        host = Mock()
        fake = Mock(LinuxHost=Mock(return_value=host), CompactError=m.CompactError)
        fake.ACTIONS = {'pause': Mock(side_effect=ValueError('synthetic-private-do-not-print'))}
        with patch.object(l.sys, 'platform', 'linux'), patch.object(l.os, 'geteuid', return_value=0, create=True), \
             patch.object(l, 'load', return_value=fake) as load, \
             contextlib.redirect_stderr(io.StringIO()) as out:
            self.assertEqual(l.main(['pause']), 1)
        load.assert_called_once_with('compact_operator.py')
        self.assertNotIn('synthetic-private', out.getvalue())
        self.assertIn('IO_OR_TOOL', out.getvalue())


class LivePacketTests(unittest.TestCase):
    def test_public_packet_binds_unchanged_dependencies_excludes_driver_and_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / 'bundle'
            bundle.mkdir()
            operator = (b.HERE / 'compact_operator.py').read_bytes().replace(b'\r\n', b'\n')
            payloads = {'candidate.cjs': b'synthetic-public-candidate\n', 'compact_operator.py': operator,
                        'bundle.json': b'{"synthetic":true}\n'}
            for name, raw in payloads.items():
                (bundle / name).write_bytes(raw)
            (bundle / 'SHA256SUMS').write_bytes(''.join(
                b.sha(raw) + '  ' + name + '\n' for name, raw in payloads.items()).encode())
            pins = {name: b.sha(raw) for name, raw in payloads.items()}
            with patch.object(b, 'BASE_PINS', pins):
                output = root / 'packet.json'
                with patch.object(l, 'main', side_effect=AssertionError('must not execute')):
                    digest = b.build(bundle, output)
                self.assertEqual(digest, b.sha(output.read_bytes()))
                packet = json.loads(output.read_bytes())
                self.assertEqual(packet['review_status'], 'awaiting-focused-review')
                names = {entry['name'] for entry in packet['files']}
                self.assertEqual(names, set(payloads) | {
                    'compact_clone_endpoint.py', 'compact_live_deployment.py', 'SHA256SUMS'})
                self.assertNotIn('compact_clone_rehearsal.py', names)
                for entry in packet['files']:
                    self.assertEqual(b.sha(base64.b64decode(entry['base64'])), entry['sha256'])
                with self.assertRaises(FileExistsError):
                    b.build(bundle, output)
                (bundle / 'compact_operator.py').write_bytes(operator + b'# drift\n')
                with self.assertRaisesRegex(ValueError, '^BUNDLE_PIN$'):
                    b.build(bundle, root / 'refused.json')
                self.assertFalse((root / 'refused.json').exists())

    def test_reused_lf_sources_match_both_builder_and_loader_pins(self):
        for name, digest in l.PINS.items():
            raw = (b.HERE / name).read_bytes().replace(b'\r\n', b'\n')
            self.assertEqual(b.sha(raw), digest)
        self.assertEqual(b.ENDPOINT_PIN, l.PINS['compact_clone_endpoint.py'])
        self.assertEqual(b.BASE_PINS['compact_operator.py'], l.PINS['compact_operator.py'])


class LiveSourceTests(unittest.TestCase):
    def test_bounded_no_follow_read_closes_fd_on_identity_drift_and_pin_failure(self):
        raw = b'# public source\n'
        value = SimpleNamespace(st_mode=0o100400, st_uid=0, st_gid=0, st_nlink=1,
                                st_size=len(raw), st_dev=1, st_ino=2,
                                st_mtime_ns=3, st_ctime_ns=4)
        path = Mock(parents=[], lstat=Mock(return_value=value))
        for variant in ('valid', 'changed', 'pin'):
            with self.subTest(variant=variant):
                fstat = value if variant != 'changed' else SimpleNamespace(
                    **dict(vars(value), st_ino=9))
                pins = {'compact_operator.py': b.sha(raw) if variant != 'pin' else '0' * 64}
                with patch.object(l, 'PINS', pins), patch.object(l, 'Path') as paths, \
                     patch.object(l.os, 'O_NOFOLLOW', 0x20000, create=True), \
                     patch.object(l.os, 'open', return_value=91) as opened, \
                     patch.object(l.os, 'fstat', return_value=fstat), \
                     patch.object(l.os, 'fdopen', return_value=io.BytesIO(raw)), \
                     patch.object(l.os, 'close') as closed:
                    paths.return_value.__truediv__.return_value = path
                    if variant == 'valid':
                        self.assertEqual(l.source('compact_operator.py'), raw)
                    else:
                        with self.assertRaisesRegex(l.LiveError, 'SOURCE_CHANGED|SOURCE_PIN'):
                            l.source('compact_operator.py')
                    closed.assert_called_once_with(91)
                    self.assertTrue(opened.call_args[0][1] & l.os.O_NOFOLLOW)

    def test_symlink_or_wrong_private_metadata_refused_before_open(self):
        for mode, uid, links in ((0o120400, 0, 1), (0o100644, 0, 1),
                                 (0o100400, 1001, 1), (0o100400, 0, 2)):
            path = Mock(parents=[], lstat=Mock(return_value=SimpleNamespace(
                st_mode=mode, st_uid=uid, st_gid=0, st_nlink=links, st_size=1)))
            with patch.object(l, 'Path') as paths, patch.object(l.os, 'open') as opened:
                paths.return_value.__truediv__.return_value = path
                with self.assertRaisesRegex(l.LiveError, '^STAGE_METADATA$'):
                    l.source('compact_operator.py')
                opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
