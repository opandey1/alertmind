"""Historical C1 source-pin provenance and pure byte comparison, not imports."""
import ast
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_python_policy as policy

REPORT = ROOT / 'evidence/rbac/python-runtime-c1-owner-report-2026-09-26.txt'


def report():
    return REPORT.read_bytes().replace(b'\r\n', b'\n')


def origins():
    return re.findall(r'^ORIGIN ([0-9a-f]{64})  (\S+)  (\S+)$', report().decode(), re.M)


class PythonSourcePinTests(unittest.TestCase):
    def test_retained_owner_transcript_hash_summary_and_non_authorizing_stop(self):
        raw = report()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'b67be416f452f7ca3159195a2632bada396c8c509439d22171d08a917ba3d187')
        self.assertEqual(len(raw.splitlines()), 107)
        self.assertNotIn(b'[sudo:', raw)
        self.assertIn(b'PASS C1 metadata: origins=50 cache_present=49 cache_absent=0\n', raw)
        self.assertTrue(raw.endswith(b'STOP: Gate C1 metadata only; no guard or root-run Python authorization.\n'))

    def test_origin_records_reproduce_accepted_manifest_and_b2_c2_path_sets(self):
        rows = origins()
        self.assertEqual(len(rows), 50)
        records = ''.join(f'{digest}  {path}  {package}\n' for digest, package, path in rows)
        self.assertEqual(hashlib.sha256(records.encode()).hexdigest(), policy.C1_ORIGIN_MANIFEST_SHA256)
        self.assertEqual(policy.C1_ORIGIN_MANIFEST_SHA256,
                         '6625b3d3dd24b51ceb4f4396d3eb21eada5fa2a7f87e8951cc3b7ceaded61c1d')
        self.assertIn(('ORIGIN_MANIFEST_SHA256 ' + policy.C1_ORIGIN_MANIFEST_SHA256).encode(), report())
        paths = [path for _, _, path in rows]
        self.assertEqual(len(set(paths)), 50)
        runbook = (ROOT / 'docs/runbooks/rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        recorded = runbook.split("mapfile -t origins <<'ALERTMIND_B2_FILE_ORIGINS'\n", 1)[1].split(
            '\nALERTMIND_B2_FILE_ORIGINS', 1)[0].splitlines()
        self.assertEqual(paths, recorded)
        self.assertEqual(hashlib.sha256(('\n'.join(sorted(paths)) + '\n').encode()).hexdigest(),
                         '41fe4f2680be2f097dcfd240ab15f6334957a629d822533212821364c5aacfeb')

    def test_all_source_pins_and_extension_overlap_match_historical_records(self):
        rows = origins()
        selected = [(path, digest, package) for digest, package, path in rows if path.endswith('.py')]
        self.assertEqual(len(selected), 49)
        self.assertEqual([(p.path, p.sha256, p.package) for p in policy.SOURCE_FILES], selected)
        self.assertTrue(all(p.version == '3.14.4-1ubuntu0.2' for p in policy.SOURCE_FILES))
        self.assertEqual({p.package for p in policy.SOURCE_FILES}, {'libpython3.14-minimal:amd64'})
        self.assertTrue(all(not hasattr(p, 'size') for p in policy.SOURCE_FILES))
        self.assertEqual(policy.SOURCE_LIMIT, 1024 * 1024)  # ceiling, not measured size
        extension = policy.MAPPED_FILES[1]
        self.assertEqual(rows[0], (extension.sha256, extension.package, extension.path))
        caches = re.findall(r'^CACHE_PRESENT [0-9a-f]{64}  (\S+)$', report().decode(), re.M)
        expected = [str(Path(p.path).parent).replace('\\', '/') + '/__pycache__/' +
                    Path(p.path).stem + '.cpython-314.pyc' for p in policy.SOURCE_FILES]
        self.assertEqual(caches, expected)  # evidence only; never accepted as selected bytecode

    def test_each_source_digest_rejects_changed_bytes_without_normalization(self):
        for index, pin in enumerate(policy.SOURCE_FILES):
            raw = ('public source fixture ' + str(index) + '\n').encode()
            pins = list(policy.SOURCE_FILES)
            pins[index] = replace(pin, sha256=hashlib.sha256(raw).hexdigest())
            with patch.object(policy, 'SOURCE_FILES', tuple(pins)):
                self.assertIsNone(policy.check_source_bytes(index, raw))
                for altered in (raw + b' ', raw.replace(b'\n', b'\r\n'), b'x' * len(raw)):
                    with self.subTest(index=index), self.assertRaisesRegex(
                            policy.PythonPolicyError, '^PY_SOURCE_DIGEST$'):
                        policy.check_source_bytes(index, altered)

    def test_index_type_and_range_rejected_without_digest_work(self):
        for index in (-1, 49, True, False, 1.0, '0', None, [], 10 ** 100):
            with patch.object(policy.hashlib, 'sha256') as digest, self.assertRaisesRegex(
                    policy.PythonPolicyError, '^PY_SOURCE_INDEX$'):
                policy.check_source_bytes(index, b'bytes')
            digest.assert_not_called()

    def test_source_type_and_ceiling_enforced_without_content_execution(self):
        raw = b'x' * policy.SOURCE_LIMIT
        pin = replace(policy.SOURCE_FILES[0], sha256=hashlib.sha256(raw).hexdigest())
        with patch.object(policy, 'SOURCE_FILES', (pin,) + policy.SOURCE_FILES[1:]):
            self.assertIsNone(policy.check_source_bytes(0, raw))
        for bad in (b'', raw + b'x', 'PRIVATE_VALUE', None, bytearray(b'x')):
            with patch.object(policy.hashlib, 'sha256') as digest, self.assertRaisesRegex(
                    policy.PythonPolicyError, '^PY_SOURCE_SIZE$'):
                policy.check_source_bytes(0, bad)
            digest.assert_not_called()

    def test_pins_are_immutable_and_guard_remains_excluded(self):
        with self.assertRaises(FrozenInstanceError):
            policy.SOURCE_FILES[0].path = '/tmp/other'
        self.assertNotIn('operator_python_policy.py', {p[0] for p in guard.PINNED_MODULES})
        self.assertNotIn('operator_python_runtime', Path(guard.__file__).read_text(encoding='utf-8'))
        tree = ast.parse(Path(policy.__file__).read_text(encoding='utf-8'))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {'open', 'exec', 'eval', 'compile', '__import__'})
        self.assertEqual(imports, {'dataclasses', 'hashlib', 're'})


if __name__ == '__main__':
    unittest.main()
