"""Offline shell contract and synthetic launch tests; no real root observer."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac import build_pid1_clone_packet as build

RUNBOOK = ROOT / 'docs/runbooks/rbac-pid1-clone-observation.md'
SOURCE_SHA = '5b15151c91c3f6a2eb0e473489df1d70485cbe7c03cb1d8ffa22b7dc21c98106'
PYTHON_SHA = '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'
STAGE = '/root/alertmind-pid1-clone-2b/pid1_clone_entry.py'
PYTHON = '/usr/bin/python3.14'
STAMP = '%d:%i:%f:%u:%g:%h:%s:%y:%z'
FINAL = 'PASS post-launch staged source and interpreter: metadata, digests and identity unchanged'


def packet():
    text = RUNBOOK.read_text(encoding='utf-8')
    blocks = re.findall(r'```bash\n(.*?)\n```', text, re.S)
    if len(blocks) != 1:
        raise AssertionError('Exactly one candidate shell block required')
    shell = blocks[0] + '\n'
    match = re.search(r"<<'ALERTMIND_CLONE_ROOT'\n(.*?)\nALERTMIND_CLONE_ROOT\n", shell, re.S)
    if match is None:
        raise AssertionError('Quoted root instructions missing')
    return text, shell, match.group(1) + '\n'


def bash_path():
    if sys.platform == 'win32':
        candidate = Path(r'C:\Program Files\Git\bin\bash.exe')
        return str(candidate) if candidate.is_file() else None
    return shutil.which('bash')


# Replace every external root-side tool with a test function before execution.
# Native Python remains an argv literal only: fake_timeout never executes it.
FIXTURE = r'''
observed=no
fake_id() { case "$1" in -u) printf '%s\n' "${MOCK_UID:-0}" ;; -g) printf '%s\n' "${MOCK_GID:-0}" ;; *) return 90 ;; esac; }
fake_stat() {
    local format="$2" path="${@: -1}"
    if [ "$format" = '%d:%i:%f:%u:%g:%h:%s:%y:%z' ]; then
        if [ "$observed" = yes ] && [ "${BAD_STAMP_AFTER:-}" = "$path" ]; then printf 'changed:%s\n' "$path"; else printf 'original:%s\n' "$path"; fi
    elif [ "$path" = /root/alertmind-pid1-clone-2b/pid1_clone_entry.py ]; then
        printf '%s\n' "${SOURCE_META:-regular file:0:0:400:1:121691}"
    elif [ "$path" = /usr/bin/python3.14 ]; then
        printf '%s\n' "${PYTHON_META:-regular file:0:0:755:1:7477160}"
    elif [ "$path" = "${BAD_PARENT:-not-a-path}" ]; then
        printf '%s\n' 'symbolic link:0:0:777'
    elif [ "$path" = /root ] || [ "$path" = /root/alertmind-pid1-clone-2b ]; then
        printf '%s\n' 'directory:0:0:700'
    else
        case "$path" in /|/usr|/usr/bin) printf '%s\n' 'directory:0:0:755' ;; *) return 91 ;; esac
    fi
}
fake_sha256sum() {
    local path="${@: -1}" digest
    case "$path" in
        /root/alertmind-pid1-clone-2b/pid1_clone_entry.py) digest='5b15151c91c3f6a2eb0e473489df1d70485cbe7c03cb1d8ffa22b7dc21c98106' ;;
        /usr/bin/python3.14) digest='52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41' ;;
        *) return 92 ;;
    esac
    if [ "${BAD_HASH:-}" = "$path" ] || { [ "$observed" = yes ] && [ "${BAD_HASH_AFTER:-}" = "$path" ]; }; then digest=wrong; fi
    printf '%s  %s\n' "$digest" "$path"
}
fake_env() {
    [ "$1" = -i ] && [ "$2" = HOME=/nonexistent ] && [ "$3" = LC_ALL=C ] && [ "$4" = PATH=/usr/bin:/bin ] || return 93
    shift 4
    [ "$1" = fake_timeout ] || return 94
    "$@"
}
fake_timeout() {
    [ "$1" = --foreground ] || return 95
    shift
    [ "$1" = --signal=TERM ] && [ "$2" = --kill-after=2s ] || return 95
    local duration="$3"
    shift 3
    if [ "$duration" = 5s ] && [ "$1" = fake_sha256sum ]; then
        [ "${HASH_TIMEOUT:-no}" = no ] || return 124
        "$@"
    elif [ "$duration" = 40s ] && [ "$1" = /usr/bin/python3.14 ]; then
        [ "$#" = 8 ] && [ "$2" = -I ] && [ "$3" = -S ] && [ "$4" = -B ] && [ "$5" = -X ] && [ "$6" = pycache_prefix=/dev/null/alertmind-pid1-clone ] && [ "$7" = /root/alertmind-pid1-clone-2b/pid1_clone_entry.py ] && [ "$8" = --observe ] || return 96
        observed=yes
        printf '%s\n' 'TEST_OBSERVER_CALLED'
        return "${OBSERVER_EXIT:-0}"
    else
        return 97
    fi
}
'''


class CloneBoundedLaunchTests(unittest.TestCase):
    def run_root_fixture(self, **overrides):
        bash = bash_path()
        if bash is None:
            self.skipTest('Bash unavailable; static contract still runs')
        _, _, inner = packet()
        for command, fake in (('/usr/bin/id', 'fake_id'),
                              ('/usr/bin/stat', 'fake_stat'),
                              ('/usr/bin/sha256sum', 'fake_sha256sum'),
                              ('/usr/bin/env', 'fake_env'),
                              ('/usr/bin/timeout', 'fake_timeout')):
            inner = inner.replace(command, fake)
            self.assertNotIn(command, inner)
        self.assertNotIn('sudo ', inner)
        self.assertNotIn('exec ', inner)
        env = {k: v for k, v in os.environ.items() if k not in {
            'MOCK_UID', 'MOCK_GID', 'BAD_STAMP_AFTER', 'SOURCE_META', 'PYTHON_META',
            'BAD_PARENT', 'BAD_HASH', 'BAD_HASH_AFTER', 'HASH_TIMEOUT', 'OBSERVER_EXIT',
            'BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS'}}
        env.update(overrides)
        return subprocess.run([bash, '--noprofile', '--norc', '-s'],
                              input=FIXTURE + inner, env=env, text=True,
                              capture_output=True, check=False, timeout=10)

    def denied(self, result, code, observer=False):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('STOP: ' + code, result.stdout)
        self.assertNotIn(FINAL, result.stdout)
        self.assertEqual('TEST_OBSERVER_CALLED' in result.stdout, observer)

    def test_candidate_status_is_not_execution_or_reference_approval(self):
        text, _, _ = packet()
        for value in ('not executed or released', 'Do not run this candidate yet',
                      'Ubuntu SOC 201 - Current Isolated Clone',
                      'temporary review deferral', 'not authentication'):
            self.assertIn(value, text)

    def test_source_pin_stays_equal_to_the_existing_staged_packet(self):
        _, _, inner = packet()
        self.assertEqual(hashlib.sha256(build.render_packet()).hexdigest(), SOURCE_SHA)
        self.assertEqual(len(build.render_packet()), 121691)
        self.assertIn("source_sha='" + SOURCE_SHA + "'", inner)
        self.assertIn("python_sha='" + PYTHON_SHA + "'", inner)

    def test_no_install_service_network_credential_or_file_write_operation(self):
        _, shell, _ = packet()
        self.assertIsNone(re.search(r'\b(?:apt|apt-get|dpkg|systemctl|curl|ssh|chmod|chown|install|mkdir|rm|tee|eval|reboot)\b', shell))
        self.assertNotIn('> ', shell)
        self.assertNotIn('2>', shell)
        self.assertEqual(shell.count('sudo '), 1)
        self.assertNotIn('--verify-only', shell)

    def test_all_owner_confirmations_precede_any_root_command(self):
        _, shell, _ = packet()
        root = shell.index('if sudo ')
        for value in ('[ "$clone" = CLONE-ONLY ]',
                      '[ "$trust" = TRUSTED-DIAGNOSTIC ]',
                      '[ "$release" = LAUNCH-RELEASED ]'):
            self.assertLess(shell.index(value), root)

    def test_outer_and_inner_shell_syntax(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Bash unavailable')
        _, shell, inner = packet()
        for value in (shell, inner):
            result = subprocess.run([bash, '-n'], input=value, text=True,
                                    capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cleared_environment_fixed_argv_and_nested_timeout_contract(self):
        _, shell, inner = packet()
        self.assertEqual(shell.count('/usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin'), 2)
        self.assertIn('60s \\\n    /bin/bash --noprofile --norc -s', shell)
        self.assertIn('40s \\\n    /usr/bin/python3.14 -I -S -B -X pycache_prefix=/dev/null/alertmind-pid1-clone', inner)
        self.assertEqual(inner.count('5s /usr/bin/sha256sum'), 2)
        self.assertEqual(inner.count('/usr/bin/timeout --foreground '), 3)
        self.assertIn('/usr/bin/timeout --signal=TERM --kill-after=2s 60s', shell)
        self.assertEqual(inner.count('"$entry" --observe'), 1)
        self.assertIn('124|137) fail CLONE_OBSERVATION_TIMEOUT', inner)
        self.assertIn('124|137) printf', shell)

    def test_core_cwd_metadata_and_stamps_precede_observation(self):
        _, _, inner = packet()
        launch = inner.index('if /usr/bin/env')
        for value in ('ulimit -S -c 0', 'ulimit -H -c 0', 'cd /',
                      'check_files\nsource_stamp=', 'check_hashes\n', 'CLONE_SOURCE_CHANGED',
                      'CLONE_PYTHON_CHANGED'):
            self.assertLess(inner.index(value), launch)
        self.assertEqual(inner.count(STAMP), 6)
        self.assertNotIn('%x', inner)  # Access-time updates do not indicate source drift.

    def test_synthetic_success_calls_only_the_fake_observer_then_rechecks(self):
        result = self.run_root_fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count('TEST_OBSERVER_CALLED'), 1)
        self.assertIn(FINAL, result.stdout)
        self.assertLess(result.stdout.index('TEST_OBSERVER_CALLED'), result.stdout.index(FINAL))

    def test_nonroot_uid_or_gid_stops_before_observation(self):
        for value in ({'MOCK_UID': '1000'}, {'MOCK_GID': '1000'}):
            with self.subTest(value=value):
                self.denied(self.run_root_fixture(**value), 'root identity mismatch')

    def test_untrusted_parent_or_stage_stops_before_observation(self):
        for path, code in (('/', 'CLONE_PARENT_METADATA'), ('/root', 'CLONE_PARENT_METADATA'),
                           ('/usr', 'CLONE_PARENT_METADATA'), ('/usr/bin', 'CLONE_PARENT_METADATA'),
                           ('/root/alertmind-pid1-clone-2b', 'CLONE_STAGE_METADATA')):
            with self.subTest(path=path):
                self.denied(self.run_root_fixture(BAD_PARENT=path), code)

    def test_source_type_owner_mode_link_or_size_drift_is_denied(self):
        for value in ('symbolic link:0:0:777:1:121691', 'regular file:1000:0:400:1:121691',
                      'regular file:0:1000:400:1:121691', 'regular file:0:0:600:1:121691',
                      'regular file:0:0:400:2:121691', 'regular file:0:0:400:1:121690'):
            with self.subTest(value=value):
                self.denied(self.run_root_fixture(SOURCE_META=value), 'CLONE_SOURCE_METADATA')

    def test_python_metadata_drift_is_denied_before_any_python_execution(self):
        self.denied(self.run_root_fixture(PYTHON_META='regular file:0:0:777:1:7477160'),
                    'CLONE_PYTHON_METADATA')

    def test_each_wrong_digest_is_denied_before_observation(self):
        for path, code in ((STAGE, 'CLONE_SOURCE_DIGEST'), (PYTHON, 'CLONE_PYTHON_DIGEST')):
            with self.subTest(path=path):
                self.denied(self.run_root_fixture(BAD_HASH=path), code)

    def test_hash_timeout_cannot_be_treated_as_a_passing_digest(self):
        self.denied(self.run_root_fixture(HASH_TIMEOUT='yes'), 'CLONE_SOURCE_DIGEST')

    def test_nonzero_observer_or_timeout_has_no_success_footer(self):
        for status, code in (('1', 'CLONE_OBSERVATION_FAILED'),
                             ('124', 'CLONE_OBSERVATION_TIMEOUT'),
                             ('137', 'CLONE_OBSERVATION_TIMEOUT')):
            with self.subTest(status=status):
                self.denied(self.run_root_fixture(OBSERVER_EXIT=status), code, observer=True)

    def test_post_observation_digest_drift_rejects_the_result(self):
        for path, code in ((STAGE, 'CLONE_SOURCE_DIGEST'), (PYTHON, 'CLONE_PYTHON_DIGEST')):
            with self.subTest(path=path):
                self.denied(self.run_root_fixture(BAD_HASH_AFTER=path), code, observer=True)

    def test_post_observation_identity_stamp_drift_rejects_the_result(self):
        for path, code in ((STAGE, 'CLONE_SOURCE_CHANGED'), (PYTHON, 'CLONE_PYTHON_CHANGED')):
            with self.subTest(path=path):
                self.denied(self.run_root_fixture(BAD_STAMP_AFTER=path), code, observer=True)

    def test_missing_or_wrong_owner_confirmations_stop_before_sudo(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Bash unavailable')
        _, shell, _ = packet()
        for value in ('WRONG\n', 'CLONE-ONLY\nWRONG\n',
                      'CLONE-ONLY\nTRUSTED-DIAGNOSTIC\nWRONG\n'):
            with self.subTest(value=value):
                result = subprocess.run([bash, '--noprofile', '--norc', '-c', shell],
                                        input=value, text=True, capture_output=True,
                                        check=False, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('STOP:', result.stdout)
                self.assertNotIn('TEST_OBSERVER_CALLED', result.stdout)
                self.assertNotIn('sudo', result.stderr)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux-only unprivileged process-group check')
    def test_native_unprivileged_nested_timeout_group_and_cancellation(self):
        if os.geteuid() == 0:
            self.skipTest('Do not run the disposable process test as root')
        timeout = Path('/usr/bin/timeout')
        if not timeout.is_file() or not Path('/bin/bash').is_file():
            self.skipTest('GNU timeout or Bash unavailable')
        help_result = subprocess.run([str(timeout), '--help'], capture_output=True,
                                     text=True, check=False, timeout=5)
        if '--foreground' not in help_result.stdout or 'GNU coreutils' not in help_result.stdout:
            self.skipTest('GNU foreground-timeout contract unavailable')

        def run_owned_group(body, duration):
            # Only this newly created session/group can be killed on test failure.
            process = subprocess.Popen(
                [str(timeout), '--signal=TERM', '--kill-after=0.2s', duration,
                 '/bin/bash', '--noprofile', '--norc', '-c', body],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=6)
                return process.pid, process.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=3)
                raise

        probe = shlex.join([sys.executable, '-I', '-S', '-B', '-c',
                            'import os; print(os.getpgrp())'])
        pid, status, stdout, stderr = run_owned_group(
            '/usr/bin/timeout --foreground --signal=TERM --kill-after=0.2s 3s ' + probe, '5s')
        self.assertEqual(status, 0, stderr)
        self.assertEqual(stdout.strip(), str(pid))
        leaf = shlex.join([sys.executable, '-I', '-S', '-B', '-c',
                           'import time; time.sleep(10)'])
        _, status, stdout, _ = run_owned_group(
            'set -e; /usr/bin/timeout --foreground --signal=TERM --kill-after=0.2s 10s '
            + leaf + '; printf SHOULD_NOT_PASS', '0.5s')
        self.assertIn(status, (124, 137))
        self.assertNotIn('SHOULD_NOT_PASS', stdout)


if __name__ == '__main__':
    unittest.main()
