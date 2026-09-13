"""Offline fixed launch-file pins and observation composition; no host IO."""
from dataclasses import asdict
import errno
from pathlib import Path, PurePosixPath
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_launch as l
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_runtime as runtime
if __package__:
    from .test_broker_tls_service import values
else:
    from test_broker_tls_service import values


PINNED = (
    ('bin/opensearch-dashboards', 939, '30993e61fae26ab0c7d73836fd510f1c9a54e9110a7e9c63edc9cbaff505f9d5'),
    ('bin/use_node', 3531, 'e1ec334650c93f2a4869cd679f2ff5a434a580f2c9b0e15cc4ef4f826803c464'),
    ('src/cli/dist.js', 1187, '3425aafe16f4e139902826a4b929c61e74f930f2e7ef08cf7fe123cb81b7eefe'),
)


class LaunchTests(unittest.TestCase):
    def observe(self, *, configs=None, packages=None, chunks=None):
        # Keep actual allowlisted paths, with synthetic byte pins only in tests.
        checks = tuple(core.FileCheck(core.BASE + name, core.sha(b'abc'), 3, 3)
                       for name, _, _ in PINNED)
        package = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')
        with patch.object(l.service, '_check_tool'), patch.object(l.fs, '_identity', return_value=(126, 128)), patch.object(
                l.runtime, 'read_package_identity', side_effect=packages or [package] * 3) as registry, patch.object(
                l.service, '_read_configuration', side_effect=configs or [values()] * 3) as manager, patch.object(
                l.fs, '_read_native', side_effect=chunks or [b'abc'] * 6) as reader, patch.object(l, 'CHECKS', checks):
            result = l.observe_launch_files()
            self.assertEqual(registry.call_count, 3)
            self.assertEqual(manager.call_count, 3)
            self.assertEqual([c.args for c in reader.call_args_list],
                [(PurePosixPath(c.path).parts[1:], 3, (126, 128)) for c in checks] * 2)
            return result

    def test_independent_pins_and_read_limits(self):
        self.assertEqual([(c.path, c.size, c.digest, c.limit) for c in l.CHECKS],
                         [(core.BASE + n, size, sha, size) for n, size, sha in PINNED])
        self.assertEqual(l.WRAPPER, core.BASE + 'bin/opensearch-dashboards')

    def test_two_pass_composition_and_minimized_result(self):
        result = self.observe()
        self.assertTrue(result.launch_bytes_match_pins and result.configured_wrapper_path)
        self.assertFalse(result.configured_wrapper_argv_only)
        self.assertEqual((result.checked_files, result.passes, result.service_reads, result.package_reads), (3, 2, 3, 3))
        self.assertNotIn('SECRET', repr(result) + str(asdict(result)))
        self.assertEqual(set(asdict(result)), {'configured_wrapper_path', 'configured_wrapper_argv_only',
            'explicit_execution_flags', 'wrapper_environment_override_named', 'checked_files', 'passes',
            'service_reads', 'package_reads', 'launch_bytes_match_pins', 'selected_runtime_proven',
            'effective_environment_proven', 'dependency_resolution_proven', 'startup_authorized'})

    def test_observation_flags_are_frozen_and_not_authority(self):
        result = self.observe()
        for name in ('selected_runtime_proven', 'effective_environment_proven',
                     'dependency_resolution_proven', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
            with self.assertRaises(AttributeError):
                setattr(result, name, True)

    def test_inactive_service_does_not_require_a_pid(self):
        config = values()
        config.update(ActiveState='inactive', MainPID=0, ExecMainStartTimestampMonotonic=0)
        config['ExecStartEx'][0][1] = [l.WRAPPER]
        self.assertTrue(self.observe(configs=[config] * 3).configured_wrapper_argv_only)

    def test_namespace_rejected_before_file_reads(self):
        for name in ('RootDirectory', 'RootImage'):
            config = values(); config[name] = '/PRIVATE'
            with self.subTest(name=name), patch.object(l.service, '_read_configuration', return_value=config), self.assertRaisesRegex(
                    core.OperatorError, '^LAUNCH_NAMESPACE$'):
                l._configuration()

    def test_configuration_drift_including_private_environment(self):
        for name, val in (('MainPID', 124), ('Environment', ['SOME_SECRET=CHANGED']),
                          ('DropInPaths', ['/PRIVATE'])):
            config = values(); config[name] = val
            with self.subTest(name=name), self.assertRaisesRegex(core.OperatorError, '^LAUNCH_CHANGED$'):
                self.observe(configs=[values(), config, config])

    def test_package_drift_rejected(self):
        first = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')
        second = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'hold')
        with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_CHANGED$'):
            self.observe(packages=[first, second, second])

    def test_each_file_and_each_pass_checks_digest(self):
        for index in range(6):
            chunks = [b'abc'] * 6; chunks[index] = b'abd'
            with self.subTest(index=index), self.assertRaisesRegex(core.OperatorError, '^LAUNCH_DIGEST$'):
                self.observe(chunks=chunks)

    def test_wrong_byte_type_short_and_oversized_read(self):
        for raw in ('abc', bytearray(b'abc'), b'', b'ab', b'abcd'):
            with self.subTest(raw=raw), self.assertRaisesRegex(core.OperatorError, '^LAUNCH_SIZE$'):
                self.observe(chunks=[raw] * 6)

    def test_native_errors_are_fixed_and_suppressed(self):
        for error, code in ((OSError(errno.EACCES, 'PRIVATE'), 'FS_ACCESS'),
                            (OSError(errno.ENOENT, 'PRIVATE'), 'FS_MISSING'),
                            (OSError(errno.ELOOP, 'PRIVATE'), 'FS_SYMLINK')):
            with self.subTest(code=code), self.assertRaises(core.OperatorError) as caught:
                self.observe(chunks=[error] * 6)
            self.assertEqual(str(caught.exception), code)
            self.assertTrue(caught.exception.__suppress_context__)

    def test_tool_platform_gate_precedes_manager_and_files(self):
        with patch.object(l.service, '_check_tool', side_effect=core.OperatorError('FS_PLATFORM')), patch.object(
                l.service, '_read_configuration') as manager, patch.object(l.fs, '_read_native') as reader, self.assertRaisesRegex(
                core.OperatorError, '^FS_PLATFORM$'):
            l.observe_launch_files()
        manager.assert_not_called(); reader.assert_not_called()

    def test_unknown_command_is_not_opened_and_names_are_visibility_only(self):
        config = values()
        config['ExecStartEx'][0][:3] = ['/PRIVATE', ['/PRIVATE', 'SECRET'], ['ignore-failure']]
        config['Environment'] = ['OSD_NODE_HOME=/PRIVATE']
        result = self.observe(configs=[config] * 3)
        self.assertFalse(result.configured_wrapper_path or result.configured_wrapper_argv_only)
        self.assertTrue(result.explicit_execution_flags and result.wrapper_environment_override_named)
        config['ExecStartEx'] = []
        config['Environment'] = ['UNLISTED=SECRET']
        result = self.observe(configs=[config] * 3)
        self.assertFalse(result.configured_wrapper_path or result.wrapper_environment_override_named)
        self.assertFalse(result.effective_environment_proven)


if __name__ == '__main__':
    unittest.main()
