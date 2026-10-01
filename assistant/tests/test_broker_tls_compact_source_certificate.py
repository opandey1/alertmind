"""Reported source layout regression; mocked metadata, no root/VM or live secrets."""
import base64
from pathlib import PurePosixPath
from types import SimpleNamespace
import stat
import sys
import unittest
from unittest.mock import patch

import test_broker_tls_compact as t

m = t.m


class MetadataPath(PurePosixPath):
    """Linux path spelling on every CI OS; metadata is supplied by the fixture."""
    def lstat(self):
        return m.os.lstat(str(self))


class SourceCertificateTests(unittest.TestCase):
    def setUp(self):
        self.host = object.__new__(m.LinuxHost)
        self.uid, self.gid = 153, 127  # Deliberately not an asserted host UID.
        layout = {'/': (0, 0, 0o755), '/var': (0, 0, 0o755),
                  '/var/ossec': (0, self.gid, 0o750),
                  '/var/ossec/api': (0, self.gid, 0o750),
                  '/var/ossec/api/configuration': (0, self.gid, 0o770),
                  '/var/ossec/api/configuration/ssl': (0, self.gid, 0o770),
                  m.SOURCE_CERT: (self.uid, self.gid, 0o400)}
        self.metadata = {}
        for index, (path, (uid, gid, mode)) in enumerate(layout.items()):
            self.metadata[path] = SimpleNamespace(
                st_dev=1, st_ino=index + 1, st_mode=mode | (
                    stat.S_IFREG if path == m.SOURCE_CERT else stat.S_IFDIR),
                st_uid=uid, st_gid=gid, st_nlink=1, st_size=len(t.PEM),
                st_mtime_ns=10, st_ctime_ns=10)
        for target, attribute, value in (
                (m, 'CERT_SHA', m.sha(t.DER)),
                (m, 'Path', MetadataPath),
                (m, 'wazuh_identity', lambda: (self.uid, self.gid)),
                (m.os, 'lstat', lambda path: self.metadata[str(path)])):
            p = patch.object(target, attribute, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(self.host, '_read_checked', return_value=t.PEM)
        self.leaf = p.start()
        self.addCleanup(p.stop)

    def test_exact_reported_layout_returns_only_pinned_public_certificate(self):
        self.assertEqual(self.host.read_source_certificate(), t.PEM)
        self.leaf.assert_called_once_with(m.SOURCE_CERT, self.metadata[m.SOURCE_CERT])

    def test_named_identity_resolution_refuses_missing_root_or_wrong_primary_group(self):
        user = SimpleNamespace(pw_uid=941, pw_gid=942)
        group = SimpleNamespace(gr_gid=942)
        pwd = SimpleNamespace(getpwnam=lambda name: user if name == 'wazuh' else None)
        grp = SimpleNamespace(getgrnam=lambda name: group if name == 'wazuh' else None)
        # Call the real resolver; setUp patches it only for reader tests.
        real = t.module('compact_operator').wazuh_identity
        with patch.dict(sys.modules, {'pwd': pwd, 'grp': grp}):
            self.assertEqual(real(), (941, 942))
            for uid, primary, gid in ((0, 942, 942), (941, 0, 0), (941, 941, 942)):
                user.pw_uid, user.pw_gid, group.gr_gid = uid, primary, gid
                with self.assertRaisesRegex(Exception, '^SOURCE_CERT_IDENTITY$'):
                    real()
        with patch.dict(sys.modules, {'pwd': SimpleNamespace(
                getpwnam=lambda _: (_ for _ in ()).throw(KeyError('do-not-log')))}):
            with self.assertRaisesRegex(Exception, '^SOURCE_CERT_IDENTITY$'):
                real()

    def test_every_source_parent_refuses_unknown_owner_group_mode_and_symlink(self):
        for path in PurePosixPath(m.SOURCE_CERT).parents:
            original = self.metadata[str(path)]
            for change in ({'st_uid': 999}, {'st_gid': 999},
                           {'st_mode': stat.S_IFDIR | 0o777},
                           {'st_mode': stat.S_IFLNK | 0o777}):
                with self.subTest(path=str(path), change=change):
                    self.metadata[str(path)] = SimpleNamespace(**dict(vars(original), **change))
                    with self.assertRaisesRegex(m.CompactError, '^SOURCE_CERT_PARENT$'):
                        self.host.read_source_certificate()
                    self.leaf.assert_not_called()
            self.metadata[str(path)] = original

    def test_source_leaf_refuses_root_wrong_group_modes_links_and_bad_sizes(self):
        original = self.metadata[m.SOURCE_CERT]
        for change in ({'st_uid': 0}, {'st_gid': 999}, {'st_nlink': 2},
                       {'st_mode': stat.S_IFLNK | 0o400},
                       {'st_mode': stat.S_IFREG | 0o444},
                       {'st_mode': stat.S_IFREG | 0o666},
                       {'st_size': 0}, {'st_size': m.LIMIT + 1}):
            with self.subTest(change=change):
                self.metadata[m.SOURCE_CERT] = SimpleNamespace(**dict(vars(original), **change))
                with self.assertRaisesRegex(m.CompactError, '^SOURCE_CERT_FILE$'):
                    self.host.read_source_certificate()
                self.leaf.assert_not_called()

    def test_source_parent_change_after_leaf_read_is_refused(self):
        def changed(*_):
            self.metadata['/var/ossec/api/configuration'].st_ctime_ns += 1
            return t.PEM
        self.leaf.side_effect = changed
        with self.assertRaisesRegex(m.CompactError, '^SOURCE_CERT_CHANGED$'):
            self.host.read_source_certificate()

    def test_source_bytes_still_require_exact_der_pin_and_one_public_pem(self):
        for raw, code in ((b'-----BEGIN CERTIFICATE-----\n' +
                           base64.b64encode(b'wrong synthetic DER') +
                           b'\n-----END CERTIFICATE-----\n', 'CERT_PIN'),
                          (t.PEM + b'private-data', 'CERT_PEM')):
            with self.subTest(code=code):
                self.leaf.return_value = raw
                with self.assertRaisesRegex(m.CompactError, '^' + code + '$'):
                    self.host.read_source_certificate()

    def test_generic_and_installed_trust_reads_have_no_source_exception(self):
        with self.assertRaisesRegex(m.CompactError, '^PARENT_METADATA$'):
            self.host.read(m.SOURCE_CERT)
        for path in (m.CERT, m.HELPER):
            for parent in PurePosixPath(path).parents:
                self.metadata[str(parent)] = SimpleNamespace(**dict(
                    vars(self.metadata['/']), st_mode=stat.S_IFDIR | 0o755))
            self.metadata[path] = SimpleNamespace(**dict(
                vars(self.metadata[m.SOURCE_CERT]), st_mode=stat.S_IFREG | 0o400))
            with self.subTest(path=path):
                with self.assertRaisesRegex(m.CompactError, '^FILE_METADATA$'):
                    self.host.read(path)
        self.leaf.assert_not_called()

    def test_prepare_and_install_use_pinned_source_accessor_not_generic_read(self):
        with patch.object(m, 'ORIGINAL_SHA', m.sha(t.ORIGINAL)), \
                patch.object(m, 'CANDIDATE_SHA', m.sha(t.CANDIDATE)):
            host = t.FakeHost()
            original_read = host.read
            def no_generic_source(path, **kwargs):
                self.assertNotEqual(path, m.SOURCE_CERT)
                return original_read(path, **kwargs)
            with patch.object(host, 'read', side_effect=no_generic_source), \
                    patch.object(host, 'read_source_certificate', wraps=host.read_source_certificate) as source:
                m.prepare(host)
                m.install(host)
            self.assertEqual(source.call_count, 2)
            self.assertEqual(host.files[m.CERT], t.PEM)
            self.assertEqual(host.metadata(m.CERT), [0o644, 0, 0])
