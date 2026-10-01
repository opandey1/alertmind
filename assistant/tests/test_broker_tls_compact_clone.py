"""Batch B preparation only: fake systemd/files, synthetic packet, no VM or root run."""
import base64
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import test_broker_tls_compact as t

d = t.module('compact_clone_rehearsal')
b = t.module('build_compact_clone_packet')
m = t.m


class CloneFlowTests(unittest.TestCase):
    def setUp(self):
        for name, raw in (('ORIGINAL_SHA', t.ORIGINAL), ('CANDIDATE_SHA', t.CANDIDATE),
                          ('CERT_SHA', t.DER)):
            p = patch.object(m, name, m.sha(raw))
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(d, 'OPERATOR_SHA', m.sha(t.HELPER))
        p.start()
        self.addCleanup(p.stop)
        self.h = t.FakeHost()
        p = patch.object(d, 'health', lambda h: None)
        p.start()
        self.addCleanup(p.stop)

    def ready(self):
        m.prepare(self.h)
        m.install(self.h)
        m.resume(self.h)

    def test_interrupt_after_durable_trust_bypasses_cleanup_then_recovers(self):
        m.prepare(self.h)
        host = self.h

        class BoundHost(t.FakeHost):
            def __init__(self):
                self.__dict__ = host.__dict__

        with patch.object(m, 'LinuxHost', BoundHost), \
                patch.object(d.os, '_exit', side_effect=t.PowerLoss()) as abrupt:
            with self.assertRaises(t.PowerLoss):
                d.interrupt_install(m, self.h)
        abrupt.assert_called_once_with(73)
        self.assertEqual(self.h.files[m.CERT], t.PEM)
        self.assertNotIn(m.HELPER, self.h.files)
        self.assertNotIn(m.GUARD, self.h.files)
        self.assertEqual(self.h.files[m.CLIENT], t.ORIGINAL)
        self.assertEqual(m.decode_receipt(self.h.files[m.RECEIPT])['phase'], 'prepared')
        with patch.object(d, 'denied_start') as denial:
            d.prove_interruption(m, self.h)
        denial.assert_called_once_with(m, self.h, guard=False)
        m.install(self.h)
        m.resume(self.h)
        d.final(m, self.h)

    def test_interrupt_requires_prepared_stopped_unmodified_checkpoint(self):
        self.ready()
        before = list(self.h.events)
        with self.assertRaisesRegex(d.RehearsalError, 'CHECKPOINT'):
            d.interrupt_install(m, self.h)
        self.assertEqual(self.h.events, before)

    def test_missing_trust_fault_uses_guard_not_inhibitor_then_restores_inhibition(self):
        self.ready()
        before = {p: self.h.files[p] for p in (m.CONFIG, m.SOURCE_CERT, m.BACKUP, m.CLIENT)}

        def deny(module, host, *, guard):
            self.assertTrue(guard)
            self.assertNotIn(m.CERT, host.files)
            self.assertNotIn(m.INHIBIT, host.loaded)
            self.assertEqual(host.files[m.GUARD], m.STARTUP)
            self.assertEqual(host.active, 'inactive')

        with patch.object(d, 'denied_start', side_effect=deny):
            d.refuse_missing_trust(m, self.h)
        self.assertEqual(self.h.files[m.INHIBIT], m.DENY)
        self.assertEqual({p: self.h.files[p] for p in before}, before)
        m.install(self.h)
        m.resume(self.h)
        d.final(m, self.h)

    def test_negative_proof_failure_still_reinhibits_and_stops(self):
        self.ready()
        with patch.object(d, 'denied_start', side_effect=d.RehearsalError('PRESTART_PROOF')):
            with self.assertRaisesRegex(d.RehearsalError, 'PRESTART_PROOF'):
                d.refuse_missing_trust(m, self.h)
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.h.files[m.INHIBIT], m.DENY)
        self.assertIn(m.INHIBIT, self.h.loaded)

    def test_rollback_proof_requires_original_bytes_and_leaves_start_denied(self):
        self.ready()
        m.rollback(self.h)
        with patch.object(d, 'denied_start') as denial:
            d.prove_rollback(m, self.h)
        denial.assert_called_once_with(m, self.h, guard=False)
        self.assertEqual(self.h.files[m.CLIENT], t.ORIGINAL)
        self.assertEqual(self.h.active, 'inactive')
        self.assertEqual(self.h.files[m.INHIBIT], m.DENY)
        m.install(self.h)
        m.resume(self.h)
        d.final(m, self.h)

    def test_native_denial_requires_matching_nonignored_failed_prestart(self):
        value = ('{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no ; '
                 'start_time=x ; stop_time=y ; pid=99 ; code=exited ; status=1 }')
        self.assertTrue(d.failed_prestart(value, '/bin/false', '/bin/false'))
        self.assertFalse(d.failed_prestart(value, '/bin/false', '/bin/false', value))
        self.assertTrue(d.failed_prestart(value.replace('status=1', 'status=1/FAILURE'),
                                         '/bin/false', '/bin/false'))
        for bad in (value.replace('ignore_errors=no', 'ignore_errors=yes'),
                    value.replace('status=1', 'status=0'),
                    value.replace('code=exited', 'code=killed'),
                    value.replace('path=/bin/false', 'path=/other'),
                    value.replace('argv[]=/bin/false', 'argv[]=/other'), ''):
            self.assertFalse(d.failed_prestart(bad, '/bin/false', '/bin/false'))
        m.prepare(self.h)
        old_info = self.h.info
        started = [False]
        self.h.info = lambda name: ((value if started[0] else value.replace('status=1', 'status=0'))
                                   if name == 'ExecStartPre' else old_info(name))
        result = SimpleNamespace(returncode=1, stdout=b'', stderr=b'not printed')

        def attempt(*args, **kwargs):
            started[0] = True
            return result

        with patch.object(d.subprocess, 'run', side_effect=attempt) as run:
            d.denied_start(m, self.h, guard=False)
        self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl', 'start', m.UNIT])
        self.assertEqual(run.call_args.kwargs['timeout'], 30)
        self.assertEqual(self.h.events[-1], ('control', 'stop'))
        with patch.object(d.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(d.RehearsalError, 'PRESTART_PROOF'):
                d.denied_start(m, self.h, guard=False)  # Cached old failure is not evidence.
        result.returncode = 0
        with patch.object(d.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(d.RehearsalError, 'START_NOT_DENIED'):
                d.denied_start(m, self.h, guard=False)

    def test_final_rejects_stopped_state_and_cli_rejects_other_actions(self):
        before = list(self.h.events)
        self.h.run = lambda argv: b''  # No native tool execution in this test.
        with patch.object(d, 'stage'):
            d.preflight(m, self.h)
        self.assertEqual(self.h.events, before)
        self.h.files[m.CONFIG] = t.CONFIG.replace(b'localhost', b'127.0.0.1')
        with patch.object(d, 'stage'):
            with self.assertRaisesRegex(m.CompactError, 'CONFIG_ENDPOINT'):
                d.preflight(m, self.h)
        self.assertEqual(self.h.events, before)
        self.h.files[m.CONFIG] = t.CONFIG
        self.ready()
        self.h.active, self.h.pid = 'inactive', '0'
        with self.assertRaisesRegex(d.RehearsalError, 'NOT_ACTIVE'):
            d.final(m, self.h)
        with patch.object(d, 'operator') as loader:
            self.assertEqual(d.main(['original-vm']), 1)
            self.assertEqual(d.main(['preflight', '/alternate-root']), 1)
        loader.assert_not_called()
        with patch.object(d, 'operator', return_value=m), \
                patch.object(m, 'LinuxHost', return_value=self.h), \
                patch.dict(d.ACTIONS, {'preflight': lambda *_: (_ for _ in ()).throw(
                    ValueError('synthetic-secret-never-print'))}), \
                t.contextlib.redirect_stderr(t.io.StringIO()) as errors:
            self.assertEqual(d.main(['preflight']), 1)
        self.assertNotIn('synthetic-secret', errors.getvalue())
        self.assertIn('CHECK_OR_TOOL', errors.getvalue())
        with patch.object(d, 'operator', return_value=m), \
                patch.object(m, 'LinuxHost', return_value=self.h), \
                patch.dict(d.ACTIONS, {'preflight': lambda *_: (_ for _ in ()).throw(
                    m.CompactError('CONFIG_ENDPOINT'))}), \
                t.contextlib.redirect_stderr(t.io.StringIO()) as errors:
            self.assertEqual(d.main(['preflight']), 1)
        self.assertIn('CONFIG_ENDPOINT', errors.getvalue())


class ClonePacketTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        self.output = self.root / 'packet.json'
        self.payloads = {'candidate.cjs': b'// synthetic, never executed\n',
                         'compact_operator.py': b'# synthetic operator, never executed\n',
                         'bundle.json': b'{"synthetic":true}\n'}
        self.pins = {n: b.sha(raw) for n, raw in self.payloads.items()}
        for name, raw in self.payloads.items():
            (self.bundle / name).write_bytes(raw)
        sums = ''.join(self.pins[n] + '  ' + n + '\n' for n in self.payloads).encode()
        (self.bundle / 'SHA256SUMS').write_bytes(sums)
        (self.root / 'compact_operator.py').write_bytes(self.payloads['compact_operator.py'])
        (self.root / 'compact_clone_rehearsal.py').write_bytes(
            b'raise AssertionError("must never execute")\r\n')
        for name, value in (('PINS', self.pins), ('HERE', self.root)):
            p = patch.object(b, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_packet_round_trip_pins_all_public_bytes_without_execution(self):
        digest = b.build(self.bundle, self.output)
        raw = self.output.read_bytes()
        self.assertEqual(b.sha(raw), digest)
        packet = json.loads(raw)
        self.assertEqual(packet['operator_commit'], b.APPROVED_COMMIT)
        self.assertIn('not execution release', packet['scope'])
        self.assertEqual({f['name'] for f in packet['files']}, d.FILES)
        for item in packet['files']:
            content = base64.b64decode(item['base64'], validate=True)
            self.assertEqual(b.sha(content), item['sha256'])
            self.assertNotIn(b'\r', content)

    def test_builder_refuses_extra_changed_payload_and_wrong_sums(self):
        extra = self.bundle / 'unexpected.secret'
        extra.write_bytes(b'synthetic only')
        with self.assertRaisesRegex(ValueError, 'BUNDLE_FILES'):
            b.build(self.bundle, self.output)
        extra.unlink()
        file = self.bundle / 'candidate.cjs'
        file.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'BUNDLE_PIN'):
            b.build(self.bundle, self.output)
        file.write_bytes(self.payloads[file.name])
        (self.bundle / 'SHA256SUMS').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'BUNDLE_SUMS'):
            b.build(self.bundle, self.output)
        self.assertFalse(self.output.exists())

    def test_builder_refuses_changed_approved_helper_and_existing_output(self):
        (self.root / 'compact_operator.py').write_bytes(b'# changed\n')
        with self.assertRaisesRegex(ValueError, 'OPERATOR_CHANGED'):
            b.build(self.bundle, self.output)
        (self.root / 'compact_operator.py').write_bytes(self.payloads['compact_operator.py'])
        self.output.write_bytes(b'preserve existing output')
        with self.assertRaises(FileExistsError):
            b.build(self.bundle, self.output)
        self.assertEqual(self.output.read_bytes(), b'preserve existing output')
