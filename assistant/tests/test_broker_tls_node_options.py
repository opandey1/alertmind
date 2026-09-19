"""Conffile content/observation tests; synthetic IO, no host bus or Node."""
from dataclasses import asdict
import errno
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_node_options as n
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_runtime as runtime
if __package__:
    from .test_broker_tls_service import values
    from .test_broker_tls_operator_fs import FakeFS, metadata
else:
    from test_broker_tls_service import values
    from test_broker_tls_operator_fs import FakeFS, metadata

WARN = b'--unhandled-rejections=warn\n'
HEAP = b'--max-old-space-size=4096\n'


class NodeOptionsTests(unittest.TestCase):
    def observe(self, *, configs=None, packages=None, chunks=None):
        package = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')
        with patch.object(n.service, '_check_tool') as tool, patch.object(
                n.fs, '_identity', return_value=(126, 128)) as identity, patch.object(
                n.runtime, 'read_package_identity', side_effect=packages or [package] * 3) as registry, patch.object(
                n.service, '_read_configuration', side_effect=configs or [values()] * 3) as manager, patch.object(
                n, '_read_options', side_effect=chunks or [WARN] * 2) as reader:
            result = n.observe_node_options()
            self.assertEqual(registry.call_count, 3)
            self.assertEqual(manager.call_count, 3)
            self.assertEqual([c.args for c in reader.call_args_list], [((126, 128),)] * 2)
            tool.assert_called_once_with(); identity.assert_called_once_with()
            return result

    def test_exact_supported_tokens_and_fixed_path(self):
        self.assertEqual(n.ALLOWED, frozenset(('--unhandled-rejections=warn', '--max-old-space-size=4096')))
        self.assertEqual(n.REQUIRED, '--unhandled-rejections=warn')
        self.assertEqual(n.OPTIONS_PARTS, ('etc', 'wazuh-dashboard', 'node.options'))
        self.assertEqual(n.MAX_OPTIONS, 16384)
        self.assertEqual(n.parse_node_options(WARN), 1)
        self.assertEqual(n.parse_node_options(WARN + HEAP), 2)
        self.assertEqual(n.parse_node_options(HEAP + WARN.rstrip(b'\n')), 2)

    def test_stock_comments_and_column_zero_comment_semantics(self):
        # Comments are removed by vendor grep before xargs interpretation.
        raw = b'## Node command line options\n\n#--max-old-space-size=4096\n' + WARN
        self.assertEqual(n.parse_node_options(raw), 1)
        self.assertEqual(n.parse_node_options(b'# "quotes" \\ --require=SECRET\n \t\n' + WARN), 1)
        for prefix in (b' #comment\n', b'\t#comment\n'):
            with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_OPTION$'):
                n.parse_node_options(prefix + WARN)

    def test_size_type_and_exact_boundary(self):
        for raw in (b'', '', None, bytearray(WARN), memoryview(WARN), b'#' * (n.MAX_OPTIONS + 1)):
            with self.subTest(raw=type(raw)), self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_SIZE$'):
                n.parse_node_options(raw)
        self.assertEqual(n.parse_node_options(b'#' * (n.MAX_OPTIONS - len(WARN) - 1) + b'\n' + WARN), 1)

    def test_non_ascii_crlf_and_controls_rejected_even_in_comments(self):
        for char in (b'\x00', b'\x0b', b'\x0c', b'\r', b'\x1b', b'\x7f', b'\xff', '\u2028'.encode()):
            with self.subTest(char=char), self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_FORMAT$'):
                n.parse_node_options(b'#' + char + b'\n' + WARN)
        with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_FORMAT$'):
            n.parse_node_options(WARN.replace(b'\n', b'\r\n'))

    def test_no_quotes_whitespace_expansion_or_multiple_active_tokens(self):
        bad = (b' --unhandled-rejections=warn', b'--unhandled-rejections=warn ',
               b'"--unhandled-rejections=warn"', b"'--unhandled-rejections=warn'",
               b'--unhandled-rejections=warn --max-old-space-size=4096',
               b'--unhandled-rejections=warn\t', b'--unhandled-rejections=warn # note',
               b'--unhandled-rejections=warn\\', b'$(SECRET)', b'`SECRET`', b'${NODE_OPTIONS}', b'*')
        for token in bad:
            with self.subTest(token=token), self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_OPTION$'):
                n.parse_node_options(token + b'\n')

    def test_unknown_loader_debug_and_value_variants_are_rejected(self):
        for token in (b'--require=SECRET', b'-r SECRET', b'--import=SECRET', b'--experimental-loader=SECRET',
                      b'--inspect', b'--openssl-config=SECRET', b'--use-openssl-ca', b'--eval=SECRET',
                      b'--max-old-space-size=8192', b'--max_old_space_size=4096', b'--max-old-space-size=04096',
                      b'--unhandled-rejections=none', b'--', b'NODE_OPTIONS=SECRET'):
            with self.subTest(token=token):
                with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_OPTION$') as caught:
                    n.parse_node_options(WARN + token + b'\n')
                self.assertNotIn('SECRET', str(caught.exception))

    def test_duplicates_and_missing_stock_option_fail(self):
        for raw in (WARN + WARN, HEAP + HEAP + WARN):
            with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_DUPLICATE$'):
                n.parse_node_options(raw)
        for raw in (b'\n', b'# only comments\n', HEAP):
            with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_REQUIRED$'):
                n.parse_node_options(raw)

    def test_owner_exception_is_only_exact_config_tree(self):
        for parts in ((), ('etc',), ('etc', 'alertmind'), ('etc', 'wazuh-dashboard-other'), n.fs.VENDOR):
            self.assertEqual(n._config_owners(parts, (126, 128)), ((0, 0),))
        for parts in (n.CONFIG_PARTS, n.OPTIONS_PARTS):
            self.assertEqual(n._config_owners(parts, (126, 128)), ((0, 0), (126, 128)))
        with self.assertRaisesRegex(core.OperatorError, '^FS_COMPONENTS$'):
            n._config_owners(('etc', '..'), (126, 128))
        # The shared vendor policy and root-only bootstrap are NOT broadened.
        self.assertEqual(n.fs._owners(n.OPTIONS_PARTS, (126, 128)), ((0, 0),))

    def test_read_dispatch_fixed_parts_limit_and_policy(self):
        with patch.object(n.fs, '_read_root', return_value=b'public') as reader:
            self.assertEqual(n._read_options((126, 128)), b'public')
            args = reader.call_args.args
            self.assertEqual(args[:2], (('etc', 'wazuh-dashboard', 'node.options'), 16384))
            self.assertEqual(args[2](('etc',)), ((0, 0),))
            self.assertEqual(args[2](n.OPTIONS_PARTS), ((0, 0), (126, 128)))

    def test_descriptor_policy_accepts_service_tree_not_ancestors_or_writers(self):
        for owner in ((0, 0), (126, 128)):
            for bad in (None, 'root_owner', 'etc_owner', 'leaf_writer', 'config_writer', 'mixed_owner', 'symlink'):
                fs = FakeFS()
                fs.nodes = {10: metadata(True), 11: metadata(True, st_ino=2),
                    12: metadata(True, st_ino=3, st_uid=owner[0], st_gid=owner[1]),
                    13: metadata(st_ino=4, st_uid=owner[0], st_gid=owner[1])}
                fs.names = {(10, 'etc'): 11, (11, 'wazuh-dashboard'): 12, (12, 'node.options'): 13}
                if bad in ('root_owner', 'etc_owner'):
                    fd = 10 if bad == 'root_owner' else 11
                    fs.nodes[fd].st_uid, fs.nodes[fd].st_gid = 126, 128
                elif bad in ('leaf_writer', 'config_writer'):
                    fs.nodes[13 if bad == 'leaf_writer' else 12].st_mode |= 0o020
                elif bad == 'mixed_owner':
                    fs.nodes[13].st_uid, fs.nodes[13].st_gid = 0, 128
                elif bad == 'symlink':
                    fs.nodes[13].st_mode = stat.S_IFLNK | 0o777
                policy = lambda p: n._config_owners(p, (126, 128))
                with self.subTest(owner=owner, bad=bad), patch.object(n.fs, 'os', fs):
                    if bad is None:
                        self.assertEqual(n.fs._read_at(10, n.OPTIONS_PARTS, 16384, policy), b'abc')
                    else:
                        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                            n.fs._read_at(10, n.OPTIONS_PARTS, 16384, policy)
                        fs.read.assert_not_called()

    def test_two_pass_counts_minimized_frozen_non_authorizing_result(self):
        result = self.observe(chunks=[WARN + HEAP] * 2)
        self.assertEqual(asdict(result), dict(option_count=2, checked_files=1, passes=2,
            service_reads=3, package_reads=3, content_policy_passed=True,
            selected_source_proven=False, effective_environment_proven=False, startup_authorized=False))
        self.assertNotIn('SECRET', repr(result))
        for name in ('selected_source_proven', 'effective_environment_proven', 'startup_authorized'):
            with self.assertRaises(AttributeError):
                setattr(result, name, True)

    def test_inactive_service_and_unobserved_alternate_source_never_authorize(self):
        config = values()
        config.update(ActiveState='inactive', MainPID=0, ExecMainStartTimestampMonotonic=0,
                      Environment=['OSD_PATH_CONF=/PRIVATE'], EnvironmentFiles=[['/PRIVATE', True]],
                      PassEnvironment=['NODE_OPTIONS'])
        result = self.observe(configs=[config] * 3)
        self.assertFalse(result.selected_source_proven or result.effective_environment_proven or result.startup_authorized)
        self.assertNotIn('PRIVATE', repr(result))

    def test_every_pass_validates_content_and_exact_byte_equality(self):
        for chunks in ([b'--require=SECRET', WARN], [WARN, b'--require=SECRET']):
            with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_OPTION$'):
                self.observe(chunks=chunks)
        for second in (WARN + b'\n', b'#changed\n' + WARN, WARN + HEAP):
            with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_CHANGED$'):
                self.observe(chunks=[WARN, second])

    def test_package_and_manager_changes_on_each_pass(self):
        package = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')
        changed = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'hold')
        for index in (1, 2):
            packages = [package] * 3; packages[index] = changed
            with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_CHANGED$'):
                self.observe(packages=packages)
            configs = [values() for _ in range(3)]
            configs[index]['Environment'] = ['PRIVATE=CHANGED']
            with self.assertRaisesRegex(core.OperatorError, '^NODE_OPTIONS_CHANGED$'):
                self.observe(configs=configs)

    def test_namespace_and_tool_gate_before_file_access(self):
        with patch.object(n.service, '_check_tool', side_effect=core.OperatorError('FS_PLATFORM')), patch.object(
                n.fs, '_identity') as identity, patch.object(n, '_read_options') as reader, self.assertRaisesRegex(
                core.OperatorError, '^FS_PLATFORM$'):
            n.observe_node_options()
        identity.assert_not_called(); reader.assert_not_called()
        for key in ('RootDirectory', 'RootImage'):
            config = values(); config[key] = '/PRIVATE'
            with patch.object(n.service, '_check_tool'), patch.object(n.fs, '_identity', return_value=(126, 128)), patch.object(
                    n.runtime, 'read_package_identity'), patch.object(n.service, '_read_configuration', return_value=config), patch.object(
                    n, '_read_options') as reader, self.assertRaisesRegex(core.OperatorError, '^LAUNCH_NAMESPACE$'):
                n.observe_node_options()
            reader.assert_not_called()

    def test_missing_and_io_errors_are_static_not_optional_success(self):
        for error, code in ((errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'),
                            (errno.ELOOP, 'FS_SYMLINK'), (errno.ENOTDIR, 'FS_NOT_DIRECTORY'), (errno.EIO, 'FS_IO')):
            with self.subTest(error=error), self.assertRaisesRegex(core.OperatorError, '^' + code + '$') as caught:
                self.observe(chunks=[OSError(error, 'SECRET')])
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertIsNone(caught.exception.__cause__)


if __name__ == '__main__':
    unittest.main()
