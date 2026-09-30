"""Host-only renderer for a clone diagnostic; never imports the subject code.

The emitted script holds exact LF sources in memory instead of importing a
writable checkout. Its external checksum still needs independent review.
This builder is not a runtime trust anchor, installer or observer launcher.
"""
import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
ORDER = (
    'operator_core', 'operator_fs', 'operator_python_paths', 'operator_service',
    'operator_maintenance_state', 'operator_maintenance_cgroup',
    'operator_maintenance_processes', 'operator_maintenance_pid1_image',
)
MAX_SOURCE = 65536
MAX_PACKET = 256 * 1024
ARTIFACT = 'pid1_clone_entry.py'


def need(condition):
    if not condition:
        raise ValueError('CLONE_PACKET_BUILD')


def eager_nodes(node):
    # Include imports in module-level conditionals and class bodies, but not
    # deferred function bodies. This is an import-closure check, not an AST sandbox.
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from eager_nodes(child)


def source_records():
    """Read the fixed eager dependency closure; no subject function is called.

    The census has a deferred namespace-observer import in an unused function.
    It is not bundled: the emitted empty-path package cannot resolve that import.
    """
    result = []
    loaded = set()
    for name in ORDER:
        raw = (BASE / 'broker_tls' / (name + '.py')).read_bytes()
        need(0 < len(raw) <= MAX_SOURCE and raw.endswith(b'\n') and b'\r' not in raw)
        tree = ast.parse(raw, filename=name + '.py')
        for node in eager_nodes(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                need(node.level == 1)
                targets = {node.module} if node.module else {a.name for a in node.names}
                need(targets <= loaded)
            if isinstance(node, ast.Import):
                need(all(not a.name.startswith(('siem', '_alertmind_pid1_clone'))
                         for a in node.names))
        compile(tree, name + '.py', 'exec')  # Syntax only; no imported subject.
        result.append((name, len(raw), hashlib.sha256(raw).hexdigest(),
                       base64.b64encode(raw).decode('ascii')))
        loaded.add(name)
    return tuple(result)


def render_packet():
    template = (BASE / 'pid1_clone_entry.py.in').read_bytes()
    need(template.endswith(b'\n') and b'\r' not in template)
    text = template.decode('ascii')
    need(text.count('@SOURCES@') == 1)
    rows = '\n'.join('    ' + repr(row) + ',' for row in source_records())
    raw = text.replace('@SOURCES@', rows).encode('ascii')
    need(0 < len(raw) <= MAX_PACKET)
    compile(raw, ARTIFACT, 'exec')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = render_packet()
    # Exclusive creation; never overwrite a prior packet or evidence file.
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'artifact': ARTIFACT, 'bytes': len(raw),
                      'sha256': hashlib.sha256(raw).hexdigest(),
                      'source_count': len(ORDER), 'observer_executed': False,
                      'review_required': True}, sort_keys=True))


if __name__ == '__main__':
    main()
