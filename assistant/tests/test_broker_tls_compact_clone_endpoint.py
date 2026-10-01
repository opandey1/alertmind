"""Only synthetic config/files/systemd: no credentials, root, VM or service action."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_broker_tls_compact as t

e = t.module('compact_clone_endpoint')
d = t.module('compact_clone_rehearsal')
b = t.module('build_compact_clone_endpoint_packet')
m = t.m
OLD = t.CONFIG.replace(b'https://localhost', b'https://127.0.0.1')


class Host(t.FakeHost):
    def __init__(self):
        super().__init__()
        self.files[m.CONFIG] = OLD
        self.meta[m.CONFIG] = [0o600, 126, 128]
        self.extra_attributes = False

    def config_no_extended_metadata(self):
        e.require(not self.extra_attributes, 'CONFIG_EXTENDED_METADATA')

    def put(self, path, raw, **kwargs):
        if path in (m.CONFIG, e.BACKUP, e.RECEIPT):
            # Independent safety assertion, not a mocked successful inhibit call.
            assert self.active in ('inactive', 'failed') and self.pid == '0'
            assert self.loaded == [m.INHIBIT] and self.files[m.INHIBIT] == m.DENY
            if path == m.CONFIG:
                self.config_no_extended_metadata()
        return super().put(path, raw, **kwargs)


class EndpointTests(unittest.TestCase):
    def setUp(self):
        for obj, key, value in (
                (m, 'ORIGINAL_SHA', m.sha(t.ORIGINAL)),
                (m, 'CANDIDATE_SHA', m.sha(t.CANDIDATE)),
                (m, 'CERT_SHA', m.sha(t.DER)),
                (e, 'dashboard_identity', lambda: (126, 128)),
                (d, 'stage', lambda *_: None),
                (d, 'health', lambda *_: None)):
            p = patch.object(obj, key, value)
            p.start()
            self.addCleanup(p.stop)
        self.h = Host()
        self.h.run = lambda *_: b''  # No openssl or systemctl child in these tests.

    def test_scalar_only_preserves_quotes_comments_unicode_crlf_and_secret_url_text(self):
        for quote in ('', "'", '"'):
            raw = OLD.replace(b'url: https://127.0.0.1',
                              ('url: ' + quote + e.OLD_URL + quote + ' # keep comment').encode())
            raw = raw.replace(b'synthetic-only-never-logged',
                              'synthetic-https://127.0.0.1-秘密'.encode()).replace(b'\n', b'\r\n')
            with self.subTest(quote=quote):
                replacement = e.corrected(m, raw)
                expected = raw.replace(('url: ' + quote + e.OLD_URL + quote).encode(),
                                       ('url: ' + quote + e.NEW_URL + quote).encode(), 1)
                self.assertEqual(replacement, expected)
                self.assertIn('synthetic-https://127.0.0.1-秘密'.encode(), replacement)

    def test_refuses_unknown_url_yaml_alias_duplicate_tag_and_other_contract_drift(self):
        for raw in (OLD.replace(b'https://127.0.0.1', b'https://remote.invalid'),
                    OLD.replace(b'https://127.0.0.1', b'https://localhost'),
                    OLD.replace(b'url: ', b'url: !!str '),
                    OLD.replace(b'url: ', b'url: &endpoint '),
                    OLD.replace(b'port: 55000', b'port: 55000\n      port: 55001'),
                    OLD.replace(b'port: 55000', b'port: "55000"'),
                    OLD.replace(b'run_as: true', b'run_as: false'),
                    OLD.replace(b'username: wazuh-wui', b'username: another-user')):
            with self.subTest(raw=raw[:5]):
                with self.assertRaises((e.EndpointError, m.CompactError)):
                    e.corrected(m, raw)

    def test_apply_private_backup_then_config_write_with_exact_metadata_and_no_start(self):
        e.apply(m, d, self.h)
        self.assertEqual(self.h.files[e.BACKUP], OLD)
        self.assertEqual(self.h.metadata(e.BACKUP), [0o400, 0, 0])
        self.assertEqual(self.h.metadata(e.RECEIPT), [0o400, 0, 0])
        self.assertEqual(self.h.files[m.CONFIG], t.CONFIG)
        self.assertEqual(self.h.metadata(m.CONFIG), [0o600, 126, 128])
        self.assertLess(self.h.events.index(('put', e.BACKUP)),
                        self.h.events.index(('put', m.CONFIG)))
        self.assertEqual(self.h.active, 'inactive')
        self.assertNotIn(('start', m.UNIT), self.h.events)
        self.assertNotIn(m.RECEIPT, self.h.files)
        e.preflight(m, d, self.h)
        with self.assertRaisesRegex(d.RehearsalError, '^NOT_ACTIVE$'):
            d.preflight(m, self.h)  # Original active-service requirement untouched.

    def test_metadata_extensions_existing_state_and_incompatible_inputs_refuse_before_write(self):
        variants = ('metadata', 'extensions', 'state', 'client', 'package', 'dropins', 'url')
        for change in variants:
            self.h = Host()
            self.h.run = lambda *_: b''
            if change == 'metadata': self.h.meta[m.CONFIG] = [0o644, 126, 128]
            if change == 'extensions': self.h.extra_attributes = True
            if change == 'state': self.h.dirs.add(e.STATE)
            if change == 'client': self.h.files[m.CLIENT] = b'changed'
            if change == 'package': self.h.version_ok = False
            if change == 'dropins': self.h.extra_dropins = ['/unexpected']; self.h.loaded = ['/unexpected']
            if change == 'url': self.h.files[m.CONFIG] = t.CONFIG
            with self.subTest(change=change):
                with self.assertRaises((e.EndpointError, m.CompactError)):
                    e.apply(m, d, self.h)
                self.assertEqual(self.h.events, [])

    def test_interruption_before_or_after_config_write_requires_explicit_recovery(self):
        for checkpoint in (e.RECEIPT, m.CONFIG):
            self.h = Host()
            self.h.run = lambda *_: b''
            real_put = self.h.put
            def interrupted(path, raw, **kwargs):
                real_put(path, raw, **kwargs)
                if path == checkpoint:
                    raise t.PowerLoss()
            with patch.object(self.h, 'put', side_effect=interrupted):
                with self.assertRaises(t.PowerLoss):
                    e.apply(m, d, self.h)
            self.assertEqual(self.h.active, 'inactive')
            self.assertEqual(self.h.files[m.INHIBIT], m.DENY)
            with self.assertRaisesRegex(e.EndpointError, 'ENDPOINT_STATE_EXISTS'):
                e.apply(m, d, self.h)
            e.recover_apply(m, d, self.h)
            self.assertEqual(self.h.files[m.CONFIG], t.CONFIG)
            e.preflight(m, d, self.h)

    def test_restore_exact_original_config_without_restart_and_reject_post_tls_rollback(self):
        e.apply(m, d, self.h)
        e.restore(m, d, self.h)
        self.assertEqual(self.h.files[m.CONFIG], OLD)
        self.assertEqual(self.h.metadata(m.CONFIG), [0o600, 126, 128])
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.h.files[m.INHIBIT], m.DENY)
        with self.assertRaisesRegex(e.EndpointError, 'ENDPOINT_NOT_APPLIED'):
            e.preflight(m, d, self.h)
        self.h.files[m.RECEIPT] = b'existing TLS receipt'
        before = list(self.h.events)
        with self.assertRaisesRegex(e.EndpointError, 'TLS_ALREADY_PREPARED'):
            e.restore(m, d, self.h)
        self.assertEqual(self.h.events, before)

    def test_inhibited_preflight_rejects_running_missing_inhibitor_drift_and_private_tamper(self):
        for change in ('running', 'missing', 'config', 'backup', 'receipt', 'unit'):
            self.h = Host()
            self.h.run = lambda *_: b''
            e.apply(m, d, self.h)
            if change == 'running': self.h.active, self.h.pid = 'active', '71'
            if change == 'missing': del self.h.files[m.INHIBIT]; self.h.loaded = []
            if change == 'config': self.h.files[m.CONFIG] += b'# other change\n'
            if change == 'backup': self.h.files[e.BACKUP] += b'# other change\n'
            if change == 'receipt': self.h.files[e.RECEIPT] = b'{"schema":1}'
            if change == 'unit': self.h.files[m.FRAGMENTS[0]] += b'# drift\n'
            with self.subTest(change=change):
                with self.assertRaises((e.EndpointError, m.CompactError)):
                    e.preflight(m, d, self.h)

    def test_main_emits_only_static_status_not_yaml_or_private_hashes(self):
        with patch.object(e, 'driver', return_value=d), \
                patch.object(d, 'operator', return_value=m), \
                patch.object(e, 'endpoint_host', return_value=self.h), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(e.main(['apply']), 0)
            self.assertNotIn('synthetic-only-never-logged', out.getvalue())
            self.assertNotIn(m.sha(OLD), out.getvalue())
            self.assertEqual(e.main(['apply']), 1)
            self.assertIn('ENDPOINT_STATE_EXISTS', err.getvalue())
            self.assertNotIn(m.sha(OLD), err.getvalue())
        with patch.object(e, 'driver', side_effect=ValueError('synthetic-secret')), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(e.main(['apply']), 1)
            self.assertNotIn('synthetic-secret', err.getvalue())

    def test_native_adapter_refuses_unknown_extended_metadata_before_config_write(self):
        with patch.object(m, 'LinuxHost', Host), \
                patch.object(e.os, 'listxattr', create=True, return_value=['system.posix_acl_access']):
            host = e.endpoint_host(m)
            with self.assertRaisesRegex(e.EndpointError, 'CONFIG_EXTENDED_METADATA'):
                host.put(m.CONFIG, t.CONFIG, expected=OLD, metadata=[0o600, 126, 128], root=False)
            self.assertEqual(host.files[m.CONFIG], OLD)
            self.assertEqual(host.events, [])

    def test_stopped_endpoint_correction_flows_into_unchanged_tls_prepare_and_secure_start(self):
        e.apply(m, d, self.h)
        e.preflight(m, d, self.h)
        m.prepare(self.h)
        with self.assertRaisesRegex(e.EndpointError, 'TLS_ALREADY_PREPARED'):
            e.restore(m, d, self.h)
        m.install(self.h)
        m.resume(self.h)
        self.assertEqual(self.h.files[m.CLIENT], t.CANDIDATE)
        self.assertEqual(self.h.files[m.CONFIG], t.CONFIG)
        self.assertEqual(self.h.files[e.BACKUP], OLD)
        self.assertEqual(self.h.active, 'active')


class EndpointPacketTests(unittest.TestCase):
    def test_public_packet_round_trip_and_syntax_only_existing_output_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            operator, driver = b'# synthetic operator\n', b'# synthetic driver\n'
            (root / 'compact_operator.py').write_bytes(operator)
            (root / 'compact_clone_rehearsal.py').write_bytes(driver)
            (root / 'compact_clone_endpoint.py').write_bytes(b'raise AssertionError("never execute")\r\n')
            output = root / 'packet.json'
            with patch.object(b, 'HERE', root), patch.object(b, 'OPERATOR_SHA', b.sha(operator)), \
                    patch.object(b, 'DRIVER_SHA', b.sha(driver)):
                self.assertEqual(b.build(output), b.sha(output.read_bytes()))
                packet = json.loads(output.read_bytes())
                self.assertEqual(packet['review_status'], 'awaiting-focused-review')
                self.assertEqual(packet['revision'], 'clone-only-url-v1')
                self.assertEqual(len(packet['files']), 2)
                for item in packet['files']:
                    raw = base64.b64decode(item['base64'], validate=True)
                    self.assertEqual(b.sha(raw), item['sha256'])
                    self.assertNotIn(b'\r', raw)
                before = output.read_bytes()
                with self.assertRaises(FileExistsError): b.build(output)
                self.assertEqual(output.read_bytes(), before)

    def test_builder_refuses_changed_reviewed_base_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(b, 'HERE', Path(temp)):
            (Path(temp) / 'compact_clone_rehearsal.py').write_bytes(b'changed')
            out = Path(temp) / 'packet.json'
            with self.assertRaisesRegex(ValueError, 'BASE_CHANGED'): b.build(out)
            self.assertFalse(out.exists())
