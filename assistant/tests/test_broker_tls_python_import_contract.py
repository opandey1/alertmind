"""Static, offline direct-import contract for the dormant guard capsule.

This does not authenticate an interpreter, stdlib, transitive import, or the
module objects already present in a running Python process.
"""
import ast
import hashlib
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_guard_entry as entry


# A pin update that changes even an already-known direct import must be
# reviewed here. This is an inventory, not a runtime allowlist or trust proof.
DIRECT_ROOTS = {
    'operator_core.py': {'dataclasses', 'hashlib', 'json', 'pathlib', 're'},
    'operator_fs.py': {'contextlib', 'errno', 'grp', 'os', 'pathlib', 'pwd',
                       're', 'stat', 'sys'},
    'operator_bootstrap.py': {'base64', 'binascii', 'dataclasses', 'pathlib', 're', 'types'},
    'operator_runtime.py': {'dataclasses', 're'},
    'operator_service.py': {'dataclasses', 'json', 'os', 'pathlib', 're',
                            'selectors', 'subprocess', 'time'},
    'operator_launch.py': {'dataclasses', 'pathlib'},
    'operator_unit_sources.py': {'dataclasses'},
    'operator_manager_environment.py': {'dataclasses', 'json', 're'},
    'operator_node_options.py': {'dataclasses', 'pathlib'},
    'operator_dependency.py': {'dataclasses', 'pathlib'},
    'operator_dependency_graph.py': {'dataclasses', 'json', 'pathlib', 're'},
    'operator_import_sites.py': {'dataclasses', 'pathlib'},
    'operator_file_set.py': {'contextlib', 'dataclasses', 'os', 'pathlib', 'stat'},
}
ALL_DIRECT_ROOTS = frozenset((
    'base64', 'binascii', 'contextlib', 'dataclasses', 'errno', 'hashlib',
    'grp', 'json', 'os', 'pathlib', 'pwd', 're', 'selectors', 'stat',
    'subprocess', 'sys', 'time', 'types',
))
IMPORT_TIME_ROOTS = ALL_DIRECT_ROOTS - {'grp', 'pwd'}


def _trees():
    base = Path(entry.__file__).parent
    return [(name, ast.parse((base / name).read_bytes(), filename=name))
            for name, _, _ in entry.PINNED_MODULES]


class GuardPythonImportContractTests(unittest.TestCase):
    def test_documented_diagnostic_imports_all_direct_roots(self):
        runbook = (ROOT / 'docs' / 'runbooks' /
                   'rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        marker = "<<'ALERTMIND_IMPORT_ORIGINS'\n"
        self.assertEqual(runbook.count(marker), 1)
        source = runbook.split(marker, 1)[1].split('\nALERTMIND_IMPORT_ORIGINS', 1)[0]
        tree = ast.parse(source)
        imports = {alias.name.split('.', 1)[0]
                   for node in tree.body if isinstance(node, ast.Import)
                   for alias in node.names}
        self.assertEqual(imports, ALL_DIRECT_ROOTS)

    def test_c1_origin_manifest_matches_reviewed_b2_path_set(self):
        runbook = (ROOT / 'docs' / 'runbooks' /
                   'rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        marker = "mapfile -t origins <<'ALERTMIND_B2_FILE_ORIGINS'\n"
        self.assertEqual(runbook.count(marker), 1)
        text = runbook.split(marker, 1)[1].split('\nALERTMIND_B2_FILE_ORIGINS', 1)[0]
        paths = text.splitlines()
        self.assertEqual(len(paths), 50)
        self.assertEqual(len(set(paths)), 50)
        self.assertEqual(paths[0],
                         '/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so')
        self.assertTrue(all(path.startswith('/usr/lib/python3.14/') for path in paths))
        self.assertEqual(len([path for path in paths if path.endswith('.py')]), 49)
        self.assertEqual(len([path for path in paths if path.endswith('.so')]), 1)
        digest = hashlib.sha256((text + '\n').encode('utf-8')).hexdigest()
        self.assertEqual(digest,
                         '0648932e6294710318bba50f9c829327a7f1fff3be030606174fd44822c06497')
        self.assertIn(digest, runbook)

    def test_c1_remains_a_metadata_only_stop_gate(self):
        runbook = (ROOT / 'docs' / 'runbooks' /
                   'rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        marker = "sudo bash <<'ALERTMIND_PYTHON_ORIGIN_C1'\n"
        self.assertEqual(runbook.count(marker), 1)
        block = runbook.split(marker, 1)[1].split('\nALERTMIND_PYTHON_ORIGIN_C1', 1)[0]
        self.assertIn('set -euo pipefail', block)
        self.assertIn('readlink -e -- /usr/bin/python3', block)
        self.assertIn('check_chain "$path"', block)
        self.assertIn('dpkg-query --search -- "$path"', block)
        self.assertIn('cache_present=', block)
        self.assertIn('cache_absent=', block)
        self.assertIn('no guard or root-run Python authorization', block)
        for executable in ('python3.14', 'systemctl', 'curl', 'wget', 'ldd',
                           'apt-get', 'dpkg --configure'):
            self.assertIsNone(re.search(r'(?m)^\s*(?:/usr/bin/)?' +
                                        re.escape(executable) + r'(?:\s|$)', block))

    def test_c2_embedded_diagnostic_matches_b2_roots_and_sorted_origins(self):
        runbook = (ROOT / 'docs' / 'runbooks' /
                   'rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        c1_marker = "mapfile -t origins <<'ALERTMIND_B2_FILE_ORIGINS'\n"
        c1_paths = runbook.split(c1_marker, 1)[1].split(
            '\nALERTMIND_B2_FILE_ORIGINS', 1)[0].splitlines()
        sorted_digest = hashlib.sha256(
            ('\n'.join(sorted(c1_paths)) + '\n').encode('utf-8')).hexdigest()
        self.assertEqual(sorted_digest,
                         '41fe4f2680be2f097dcfd240ab15f6334957a629d822533212821364c5aacfeb')
        marker = "<<'ALERTMIND_CACHE_LOADER_C2'\n"
        self.assertEqual(runbook.count(marker), 1)
        source = runbook.split(marker, 1)[1].split(
            '\nALERTMIND_CACHE_LOADER_C2', 1)[0]
        tree = ast.parse(source)
        imports = {alias.name.split('.', 1)[0]
                   for node in tree.body if isinstance(node, ast.Import)
                   for alias in node.names}
        self.assertEqual(imports, ALL_DIRECT_ROOTS)
        self.assertIn(sorted_digest, source)
        self.assertIn("open('/proc/self/maps'", source)
        self.assertIn("sys.pycache_prefix != prefix", source)
        self.assertIn("stat.S_ISCHR(device.st_mode)", source)
        self.assertIn("path.startswith(prefix + '/')", source)

    def test_c2_shell_is_unprivileged_read_only_and_stops_after_diagnostic(self):
        runbook = (ROOT / 'docs' / 'runbooks' /
                   'rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        marker = "<<'ALERTMIND_CACHE_LOADER_C2'\n"
        block = runbook.split('## Gate C2 — ', 1)[1].split('\n```bash\n', 1)[1]
        block = block.split('\n```', 1)[0]
        self.assertEqual(block.count(marker), 1)
        self.assertIn('if [ "$(id -u)" -eq 0 ]; then', block)
        self.assertIn('if [ -e /usr/lib/python314.zip ] || [ -L /usr/lib/python314.zip ]; then',
                      block)
        self.assertIn('/usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin', block)
        self.assertIn('/usr/bin/timeout 30s /usr/bin/python3.14 -I -S -B', block)
        self.assertIn('-X pycache_prefix=/dev/null/alertmind-c2 -', block)
        self.assertIn('no guard or root-run Python authorization', block)
        for executable in ('sudo', 'systemctl', 'curl', 'wget', 'ldd',
                           'apt-get', 'dpkg --configure', 'strace'):
            self.assertIsNone(re.search(r'(?m)^\s*(?:/usr/bin/)?' +
                                        re.escape(executable) + r'(?:\s|$)', block))

    def test_c3_fixed_mapped_paths_match_owner_c2_output(self):
        runbook = (ROOT / 'docs' / 'runbooks' /
                   'rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        marker = "mapfile -t mapped <<'ALERTMIND_C2_MAPPED_FILES'\n"
        self.assertEqual(runbook.count(marker), 1)
        text = runbook.split(marker, 1)[1].split(
            '\nALERTMIND_C2_MAPPED_FILES', 1)[0]
        paths = text.splitlines()
        self.assertEqual(paths, [
            '/usr/bin/python3.14',
            '/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so',
            '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
            '/usr/lib/x86_64-linux-gnu/libc.so.6',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
            '/usr/lib/x86_64-linux-gnu/libexpat.so.1.11.2',
            '/usr/lib/x86_64-linux-gnu/libm.so.6',
            '/usr/lib/x86_64-linux-gnu/libz.so.1.3.1',
            '/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7',
        ])
        digest = hashlib.sha256((text + '\n').encode('utf-8')).hexdigest()
        self.assertEqual(digest,
                         '0b112d9d770034238714593a83cc70c81cf232c2c7601d917e736b28e452e9ba')
        self.assertIn(digest, runbook)

    def test_c3_is_unprivileged_metadata_only_and_fail_closed(self):
        runbook = (ROOT / 'docs' / 'runbooks' /
                   'rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        marker = "/bin/bash <<'ALERTMIND_MAPPED_FILE_C3'\n"
        self.assertEqual(runbook.count(marker), 1)
        block = runbook.split(marker, 1)[1].split(
            '\nALERTMIND_MAPPED_FILE_C3', 1)[0]
        self.assertIn('/usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin',
                      runbook.split(marker, 1)[0].split('\n')[-2])
        for required in ('[ "$(id -u)" -ne 0 ]',
                         'check_chain "$path" file',
                         'dpkg-query --search -- "$path"',
                         'dpkg --verify "$owner"',
                         'readelf -hW -- "$path"',
                         'readelf -dW -- "$path"',
                         '/etc/ld.so.preload',
                         'no native-closure, package-authenticity or root-run guard authorization'):
            self.assertIn(required, block)
        fixed_list = "mapfile -t mapped <<'ALERTMIND_C2_MAPPED_FILES'\n"
        command_text = block.split(fixed_list, 1)[0] + block.split(
            '\nALERTMIND_C2_MAPPED_FILES', 1)[1]
        for executable in ('sudo', 'python3.14', 'ldd', 'systemctl', 'curl',
                           'wget', 'apt-get', 'dpkg --configure'):
            self.assertIsNone(re.search(r'(?m)^\s*(?:/usr/bin/)?' +
                                        re.escape(executable) + r'(?:\s|$)',
                                        command_text))

    def test_exact_direct_absolute_imports_per_pinned_module(self):
        self.assertEqual(set(DIRECT_ROOTS),
                         {name for name, _, _ in entry.PINNED_MODULES})
        observed_all = set()
        for name, tree in _trees():
            observed = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    observed.update(alias.name.split('.', 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    observed.add(node.module.split('.', 1)[0])
            with self.subTest(name=name):
                self.assertEqual(observed, DIRECT_ROOTS[name])
            observed_all.update(observed)
        self.assertEqual(observed_all, ALL_DIRECT_ROOTS)

    def test_relative_imports_use_only_earlier_held_modules(self):
        order = {name[:-3]: index for index, (name, _, _)
                 in enumerate(entry.PINNED_MODULES)}
        for name, tree in _trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level == 0:
                    continue
                with self.subTest(name=name, line=node.lineno):
                    self.assertEqual(node.level, 1)
                    dependencies = ([node.module] if node.module else
                                    [alias.name for alias in node.names])
                    for dependency in dependencies:
                        self.assertIn(dependency, order)
                        self.assertLess(order[dependency], order[name[:-3]])

    def test_identity_modules_are_deferred_but_still_in_runtime_scope(self):
        import_time = set()
        for _, tree in _trees():
            for node in tree.body:
                if isinstance(node, ast.Import):
                    import_time.update(alias.name.split('.', 1)[0]
                                       for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    import_time.add(node.module.split('.', 1)[0])
        self.assertEqual(import_time, IMPORT_TIME_ROOTS)
        fs_tree = dict(_trees())['operator_fs.py']
        identity = next(node for node in fs_tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == '_identity')
        deferred = {alias.name for node in ast.walk(identity)
                    if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(deferred, {'grp', 'pwd'})

    def test_no_recognized_dynamic_import_or_execution_calls(self):
        forbidden_names = {'__import__', 'eval', 'exec', 'import_module',
                           'load_module', 'run_module', 'run_path'}
        forbidden_attrs = {'import_module', 'load_module', 'run_module', 'run_path'}
        for name, tree in _trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                with self.subTest(name=name, line=node.lineno):
                    self.assertFalse(isinstance(func, ast.Name) and
                                     func.id in forbidden_names)
                    self.assertFalse(isinstance(func, ast.Attribute) and
                                     func.attr in forbidden_attrs)


if __name__ == '__main__':
    unittest.main()
