"""Offline guards for the unprivileged, clone-only PID 1 compatibility packet."""
import ast
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest


PACKET = (Path(__file__).resolve().parents[2] / 'docs' / 'runbooks' /
          'rbac-pid1-clone-native-compatibility.md')
MARKER = 'ALERTMIND_PID1_CLONE_NATIVE_PROBE'


def blocks():
    text = PACKET.read_text(encoding='utf-8')
    shell = text.split('```bash\n', 1)[1].split('\n```', 1)[0]
    python = shell.split("<<'" + MARKER + "'\n", 1)[1].rsplit('\n' + MARKER, 1)[0]
    return text, shell, python


class CloneNativePacketTests(unittest.TestCase):
    def test_shell_syntax_and_single_heredoc(self):
        _, shell, _ = blocks()
        self.assertEqual(shell.count("<<'" + MARKER + "'"), 1)
        self.assertEqual(shell.count('\n' + MARKER), 1)
        bash = (r'C:\Program Files\Git\bin\bash.exe' if sys.platform == 'win32'
                and Path(r'C:\Program Files\Git\bin\bash.exe').is_file()
                else shutil.which('bash') if sys.platform != 'win32' else None)
        if bash is None:
            self.skipTest('bash is unavailable on this host')
        result = subprocess.run([bash, '-n'], input=shell, text=True,
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_embedded_python_compiles_without_project_imports(self):
        _, _, python = blocks()
        tree = ast.parse(python)
        compile(tree, str(PACKET), 'exec')
        imported = {name.name for node in ast.walk(tree)
                    if isinstance(node, ast.Import) for name in node.names}
        self.assertEqual(imported, {'os', 'stat', 'sys', 'time'})
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))

    def test_unprivileged_fixed_runtime_and_bounded_reads(self):
        text, shell, python = blocks()
        self.assertIn('Ubuntu SOC 201 - Current Isolated Clone', text)
        self.assertIn('if [ "$(id -u)" -eq 0 ]; then', shell)
        self.assertIn('timeout --signal=TERM --kill-after=2s 20s '
                      '/usr/bin/python3.14 -I -S -B -', shell)
        self.assertNotIn('sudo ', shell)
        for path in ('/proc/self/mountinfo', '/proc/1/stat', '/proc/1/status',
                     '/var/lib/dpkg/status', '/var/lib/dpkg/info/systemd.list'):
            self.assertIn(path, python)
        self.assertIn('O_NOFOLLOW', python)
        self.assertIn('limit + 1 - len(data)', python)
        self.assertIn('unsafe = 0o6222 if proc else 0o6022', python)
        self.assertEqual(0o644 & 0o6022, 0)  # Root-owned dpkg files may be owner-writable.
        self.assertNotEqual(0o664 & 0o6022, 0)

    def test_no_mutating_or_privileged_call_in_embedded_probe(self):
        _, shell, python = blocks()
        tree = ast.parse(python)
        forbidden = {'write', 'unlink', 'remove', 'rename', 'replace', 'mkdir',
                     'chmod', 'chown', 'system', 'popen', 'kill', 'execv', 'execve'}
        called = {node.func.attr for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(called & forbidden)
        self.assertIsNone(re.search(
            r'(?m)^\s*(?:sudo\s+)?(?:systemctl|dpkg|apt|curl|ssh|reboot)\b', shell))


if __name__ == '__main__':
    unittest.main()
