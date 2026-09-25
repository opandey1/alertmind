"""Static, offline direct-import contract for the dormant guard capsule.

This does not authenticate an interpreter, stdlib, transitive import, or the
module objects already present in a running Python process.
"""
import ast
from pathlib import Path
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
