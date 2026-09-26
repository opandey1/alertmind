"""Portable tests of owner-report pins and proposed launch data, not VM proof."""
import ast
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_guard_entry as entry
from siem.rbac.broker_tls import operator_python_policy as policy

REPORT = ROOT / 'evidence/rbac/python-runtime-c3-owner-report-2026-09-26.txt'


class PythonRuntimePolicyTests(unittest.TestCase):
    def setUp(self):
        self.raw = REPORT.read_bytes().replace(b'\r\n', b'\n')

    def reject(self, raw, code=None):
        with self.assertRaises(policy.PythonPolicyError) as caught:
            policy.check_c3_report(raw)
        if code is not None:
            self.assertEqual(str(caught.exception), code)
        self.assertRegex(str(caught.exception), r'^PY_[A-Z_]+$')

    def test_owner_transcript_matches_all_pins_and_explicit_limits(self):
        result = policy.check_c3_report(self.raw)
        self.assertEqual((result.file_count, result.package_count,
                          result.declared_dependency_edges), (9, 7, 15))
        self.assertIs(result.report_matches_pins, True)
        for name in ('live_host_checked', 'package_authenticity_proven',
                     'native_resolution_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        with self.assertRaises(TypeError):
            policy.ReportedMetadataMatch(startup_authorized=True)

    def test_lf_and_crlf_match_but_no_other_text_normalization(self):
        self.assertEqual(policy.check_c3_report(self.raw),
                         policy.check_c3_report(self.raw.replace(b'\n', b'\r\n')))
        for raw in (self.raw.rstrip(b'\n'), self.raw.replace(b'FILE 00', b'FILE  00'),
                    self.raw.replace(b'\n', b'\r'), self.raw + b'\n'):
            self.reject(raw)

    def test_type_bounds_encoding_controls_and_long_lines_fail(self):
        for raw in (None, '', bytearray(self.raw), b'', b'a' * (policy.MAX_REPORT_BYTES + 1)):
            self.reject(raw, 'PY_REPORT_SIZE')
        for raw in (b'\xef\xbb\xbf' + self.raw, b'\xff' + self.raw,
                    self.raw.replace(b'FILE', b'FI\x00LE', 1),
                    self.raw.replace(b'FILE', b'FI\tLE', 1),
                    self.raw + b'A' * 513 + b'\n', self.raw + b'X\n' * 64):
            self.reject(raw, 'PY_REPORT_FORMAT')

    def test_all_truncated_line_prefixes_fail_without_index_errors(self):
        lines = self.raw.splitlines(keepends=True)
        for count in range(len(lines)):
            with self.subTest(count=count):
                self.reject(b''.join(lines[:count]))

    def test_missing_duplicate_reordered_and_extra_files_fail(self):
        lines = self.raw.splitlines(keepends=True)
        file_lines = [i for i, line in enumerate(lines) if line.startswith(b'FILE ')]
        for index in file_lines:
            with self.subTest(index=index):
                self.reject(b''.join(lines[:index] + lines[index + 1:]))
                self.reject(b''.join(lines[:index] + [lines[index]] + lines[index:]))
        reordered = list(lines)
        reordered[file_lines[0]], reordered[file_lines[1]] = (
            reordered[file_lines[1]], reordered[file_lines[0]])
        self.reject(b''.join(reordered))
        self.reject(self.raw + lines[file_lines[0]])

    def test_every_file_pin_field_drift_is_rejected(self):
        for index, original in enumerate(policy.MAPPED_FILES):
            replacements = dict(path=original.path + '.other', sha256='a' * 64,
                                size=original.size + 1, package=original.package + '-other',
                                version=original.version + '.1', needed=('unknown.so',),
                                soname='unknown.so')
            for name, value in replacements.items():
                with self.subTest(index=index, field=name):
                    files = list(policy.MAPPED_FILES)
                    files[index] = replace(original, **{name: value})
                    with self.assertRaisesRegex(policy.PythonPolicyError, '^PY_METADATA_DRIFT$'):
                        policy.compare_metadata(tuple(files), policy.LOADER_CACHE)

    def test_parser_rejects_hash_size_package_and_path_drift(self):
        for old, new in ((b'52e0a13e', b'62e0a13e'), (b'bytes=7477160', b'bytes=7477161'),
                         (b'package=python3.14-minimal ', b'package=other '),
                         (b'version=3.14.4-1ubuntu0.2 ', b'version=3.14.5-1ubuntu0.2 '),
                         (b'path=/usr/bin/python3.14', b'path=/usr/bin/python3.15')):
            with self.subTest(old=old):
                self.reject(self.raw.replace(old, new, 1), 'PY_METADATA_DRIFT')

    def test_elf_unknown_duplicate_missing_and_wrong_id_entries_fail(self):
        line = b'ELF 04 NEEDED libzstd.so.1\n'
        for replacement in (b'', line + line, b'ELF 05 NEEDED libzstd.so.1\n',
                            b'ELF 04 RPATH /tmp\n', b'ELF 04 RUNPATH /tmp\n',
                            b'ELF 04 NEEDED unknown.so\n'):
            self.reject(self.raw.replace(line, replacement))
        soname = b'ELF 04 SONAME libcrypto.so.3\n'
        self.reject(self.raw.replace(soname, soname + soname))
        self.reject(self.raw.replace(soname, b'ELF 04 SONAME other.so\n'))

    def test_summary_header_stop_and_unexpected_output_fail(self):
        for old, new in ((b'count=9', b'count=8'),
                         (policy.PATH_LIST_SHA256.encode(), b'a' * 64),
                         (b'mapped_files=9', b'mapped_files=8'), (b'packages=7', b'packages=8'),
                         (b'no_rpath_runpath=yes', b'no_rpath_runpath=no'),
                         (policy.REPORT_STOP.encode(), b'PASS startup authorized')):
            self.reject(self.raw.replace(old, new))
        self.reject(b'PRIVATE_OUTPUT\n' + self.raw)
        self.reject(self.raw + b'PRIVATE_OUTPUT\n')

    def test_generated_loader_cache_is_pinned_but_not_package_authenticated(self):
        for changes in (dict(size=70232), dict(sha256='a' * 64), dict(path='/tmp/cache')):
            with self.assertRaisesRegex(policy.PythonPolicyError, '^PY_LOADER_CACHE_DRIFT$'):
                policy.compare_metadata(policy.MAPPED_FILES, replace(policy.LOADER_CACHE, **changes))
        self.reject(self.raw.replace(b'bytes=70231', b'bytes=70232'), 'PY_LOADER_CACHE_DRIFT')
        result = policy.compare_metadata(policy.MAPPED_FILES, policy.LOADER_CACHE)
        self.assertIs(result.package_authenticity_proven, False)

    def test_direct_metadata_api_rejects_ambiguous_types_and_collections(self):
        for files in (list(policy.MAPPED_FILES), policy.MAPPED_FILES[:-1],
                      policy.MAPPED_FILES + policy.MAPPED_FILES[:1], iter(policy.MAPPED_FILES)):
            with self.assertRaisesRegex(policy.PythonPolicyError, '^PY_METADATA_FILES$'):
                policy.compare_metadata(files, policy.LOADER_CACHE)
        for bad in (None, replace(policy.MAPPED_FILES[0], size=True),
                    replace(policy.MAPPED_FILES[0], needed=['libm.so.6']),
                    replace(policy.MAPPED_FILES[0], path=object())):
            with self.assertRaisesRegex(policy.PythonPolicyError, '^PY_METADATA_FORMAT$'):
                policy.compare_metadata((bad,) + policy.MAPPED_FILES[1:], policy.LOADER_CACHE)
        with self.assertRaisesRegex(policy.PythonPolicyError, '^PY_METADATA_FORMAT$'):
            policy.compare_metadata(policy.MAPPED_FILES, replace(policy.LOADER_CACHE, size=True))

    def test_fixed_paths_and_declared_names_match_c2_c3_contract(self):
        paths = [item.path for item in policy.MAPPED_FILES]
        self.assertEqual(len(set(paths)), 9)
        self.assertEqual(hashlib.sha256(('\n'.join(paths) + '\n').encode()).hexdigest(),
                         policy.PATH_LIST_SHA256)
        self.assertEqual(len({item.package for item in policy.MAPPED_FILES}), 7)
        needed = [name for item in policy.MAPPED_FILES for name in item.needed]
        self.assertEqual(len(needed), 15)
        self.assertLessEqual(set(needed), {item.soname for item in policy.MAPPED_FILES})
        self.assertIn('libzstd.so.1', policy.MAPPED_FILES[4].needed)
        runbook = (ROOT / 'docs/runbooks/rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        for index in (0, 1):
            self.assertIn(policy.MAPPED_FILES[index].sha256, runbook)

    def test_exact_candidate_launch_is_data_only_and_non_authorizing(self):
        environment = dict(policy.CANDIDATE_ENVIRONMENT)
        argv = list(policy.CANDIDATE_ARGV)
        result = policy.check_candidate_launch(argv, environment)
        self.assertEqual(tuple(argv), policy.CANDIDATE_ARGV)
        self.assertEqual(environment, dict(policy.CANDIDATE_ENVIRONMENT))
        self.assertIs(result.candidate_matches, True)
        for name in ('effective_environment_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertEqual(policy.CANDIDATE_ARGV[-1], entry.ENTRY_PATH)

    def test_launch_rejects_missing_extra_reordered_and_alternate_arguments(self):
        argv = policy.CANDIDATE_ARGV
        bad_values = [None, ' '.join(argv), argv + ('--help',), tuple(reversed(argv))]
        bad_values += [argv[:i] + argv[i + 1:] for i in range(len(argv))]
        bad_values += [argv[:i] + ('OTHER',) + argv[i + 1:] for i in range(len(argv))]
        bad_values += [('/usr/bin/python3',) + argv[1:],
                       argv[:5] + ('pycache_prefix=/tmp/cache',) + argv[6:]]
        for bad in bad_values:
            with self.subTest(argv=bad), self.assertRaisesRegex(
                    policy.PythonPolicyError, '^PY_LAUNCH_ARGV$'):
                policy.check_candidate_launch(bad, dict(policy.CANDIDATE_ENVIRONMENT))

    def test_environment_rejects_all_inheritance_including_empty_injection_keys(self):
        expected = dict(policy.CANDIDATE_ENVIRONMENT)
        bad_values = [None, {}, list(expected.items())]
        for key in expected:
            bad_values.extend(({k: v for k, v in expected.items() if k != key},
                               dict(expected, **{key: 'OTHER'})))
        for key in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'PYTHONPATH',
                    'PYTHONHOME', 'PYTHONPYCACHEPREFIX', 'BASH_ENV', 'EXTRA'):
            bad_values.append(dict(expected, **{key: ''}))
        for bad in bad_values:
            with self.subTest(environment=bad), self.assertRaisesRegex(
                    policy.PythonPolicyError, '^PY_LAUNCH_ENVIRONMENT$'):
                policy.check_candidate_launch(policy.CANDIDATE_ARGV, bad)

    def test_no_io_execution_or_guard_capsule_wiring(self):
        source = Path(policy.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        imports = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
        imports |= {alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imports, {'dataclasses', 'hashlib', 're'})
        self.assertNotIn('operator_python_policy.py', {pin[0] for pin in entry.PINNED_MODULES})
        self.assertNotIn('operator_python_policy', Path(entry.__file__).read_text(encoding='utf-8'))
        with patch('builtins.open', side_effect=AssertionError('IO_CALLED')):
            policy.check_c3_report(self.raw)
            policy.check_candidate_launch(policy.CANDIDATE_ARGV, dict(policy.CANDIDATE_ENVIRONMENT))
        with self.assertRaises(policy.PythonPolicyError) as caught:
            policy.check_candidate_launch(policy.CANDIDATE_ARGV, {'SECRET_PASSWORD': 'PRIVATE_VALUE'})
        self.assertEqual(str(caught.exception), 'PY_LAUNCH_ENVIRONMENT')
        self.assertNotIn('PRIVATE', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
