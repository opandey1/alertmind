"""Finite synthetic context/predicate checks; never a VM or browser login."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'siem/rbac' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


m = load('observe_dashboard_context')
b = load('build_dashboard_context_packet')
s = load('collect_server_inventory')
CHALLENGE = 'a' * 64


def summary():
    return {'two_pass_observation_equal': True, 'readonly_role_id': 33,
            'roles': [{'id': 11, 'label': 'administrator', 'rules': [41, 42], 'users': [2]},
                      {'id': 33, 'label': 'readonly', 'rules': [], 'users': []}],
            'users': [{'id': 2, 'label': 'broker', 'allow_run_as': True}],
            'rules': [{'id': 41 + i, 'roles': [11], 'predicate_class': label,
                       'predicate_sha256': s.digest(rule)} for i, (label, rule) in enumerate(m.PREDICATES.items())]}


def browser():
    return {'schema': 1, 'challenge': CHALLENGE, 'endpoint': '/api/v1/configuration/account',
            'source': 'dashboard-scoped-account', 'user_name_is_socanalyst': True,
            'exact_indexer_role': True, 'backend_roles_empty': True, 'account_shape_version': 1,
            'two_reads_equal': True, 'top_level_username_present': False,
            'matches': {k: False for k in m.PREDICATES}, 'broker_run_as_body_observed': False,
            'server_effective_policy_observed': False, 'mutation_authorized': False}


def account():
    return {'user_name': 'socanalyst', 'is_internal_user': True, 'is_reserved': False,
            'is_hidden': False, 'backend_roles': [], 'custom_attribute_names': [],
            'roles': ['alertmind_socanalyst_ro'], 'tenants': {'global_tenant': False, 'socanalyst': True},
            'user_requested_tenant': None}


class ObservationTests(unittest.TestCase):
    def test_catalog_uses_live_role_ids_and_covers_both_exact_rules(self):
        result = m.catalog_contract(s, summary())
        self.assertEqual([r['id'] for r in result], [41, 42])
        self.assertEqual([r['roles'] for r in result], [[11], [11]])

    def test_extra_missing_duplicate_or_unknown_predicate_refused(self):
        for change in ('extra', 'missing', 'duplicate', 'unknown', 'digest', 'link'):
            value = summary()
            if change == 'extra': value['rules'].append(copy.deepcopy(value['rules'][0]))
            if change == 'missing': value['rules'].pop()
            if change == 'duplicate': value['rules'][1] = copy.deepcopy(value['rules'][0])
            if change == 'unknown': value['rules'][0]['predicate_class'] = 'unreviewed_predicate'
            if change == 'digest': value['rules'][0]['predicate_sha256'] = '0' * 64
            if change == 'link': value['rules'][0]['roles'] = [33]
            with self.subTest(change=change), self.assertRaises(m.ObservationError):
                m.catalog_contract(s, value)

    def test_broker_reserved_rule_id_and_readonly_baseline_are_explicit(self):
        for edit in (lambda v: v['users'][0].update(id=9),
                     lambda v: v['users'][0].update(allow_run_as=False),
                     lambda v: v['roles'][1].update(rules=[99]),
                     lambda v: v['roles'][1].update(users=[99]),
                     lambda v: v.update(two_pass_observation_equal=False)):
            value = summary(); edit(value)
            with self.assertRaises(m.ObservationError): m.catalog_contract(s, value)

    def test_direct_indexer_claim_replay_and_wrong_identity_flags_refused(self):
        for edit in (lambda v: v.update(source='direct-indexer-account'),
                     lambda v: v.update(challenge='b' * 64),
                     lambda v: v.update(user_name_is_socanalyst=False),
                     lambda v: v.update(exact_indexer_role=False),
                     lambda v: v.update(two_reads_equal=False),
                     lambda v: v.update(broker_run_as_body_observed=True),
                     lambda v: v.update(schema=True)):
            value = browser(); edit(value)
            with self.assertRaises(m.ObservationError): m.browser_summary(s, json.dumps(value), CHALLENGE)

    def test_secret_or_unknown_fields_and_duplicate_json_refused(self):
        value = browser(); value['token'] = 'SYNTHETIC-PRIVATE'
        for raw in (json.dumps(value), json.dumps(browser())[:-1] + ',"schema":1}', 'x' * 4097):
            with self.assertRaises((m.ObservationError, s.InventoryError)):
                m.browser_summary(s, raw, CHALLENGE)

    def test_every_matching_predicate_and_nonboolean_refused(self):
        for label in m.PREDICATES:
            for flag in (True, 0, 'false'):
                value = browser(); value['matches'][label] = flag
                with self.assertRaises(m.ObservationError): m.browser_summary(s, json.dumps(value), CHALLENGE)

    def test_before_after_contract_accepts_only_owner_carried_scoped_evidence(self):
        fake = types.SimpleNamespace(collect=mock.Mock(side_effect=[summary(), summary()]), digest=s.digest)
        fake.decode = s.decode
        client = types.SimpleNamespace(deadline=0)
        read = mock.Mock(return_value=json.dumps(browser()))
        code = mock.Mock(return_value={'public': 'pin'})
        result = m.observe(fake, client, 'synthetic', CHALLENGE, read, code)
        self.assertEqual(fake.collect.call_count, 2)
        read.assert_called_once_with(CHALLENGE)
        self.assertEqual(code.call_count, 2)
        self.assertEqual(result['matching_role_ids'], [])
        self.assertEqual(result['readonly_role_id_observed'], 33)
        self.assertTrue(result['observation_source_attested_by_owner_not_cryptographically_proven'])
        for key in ('broker_run_as_body_observed', 'server_effective_policy_observed',
                    'mutation_authorized', 'loaded_code_proven'):
            self.assertIs(result[key], False)
        self.assertIsNone(result['server_mapping_payload'])
        self.assertNotIn(CHALLENGE, json.dumps(result))

    def test_catalog_or_code_drift_stops_without_partial_result(self):
        for edit_code in (False, True):
            changed = summary(); changed['unrelated_current_policy'] = 'changed'
            fake = types.SimpleNamespace(collect=mock.Mock(side_effect=[summary(), summary() if edit_code else changed]),
                                         digest=s.digest, decode=s.decode)
            with self.assertRaises(m.ObservationError):
                m.observe(fake, types.SimpleNamespace(deadline=0), 'synthetic', CHALLENGE,
                          lambda _: json.dumps(browser()), mock.Mock(side_effect=[{'p': 1}, {'p': 2 if edit_code else 1}]))

    def test_browser_failure_prevents_second_server_read(self):
        fake = types.SimpleNamespace(collect=mock.Mock(return_value=summary()), digest=s.digest, decode=s.decode)
        with self.assertRaises(m.ObservationError):
            m.observe(fake, types.SimpleNamespace(deadline=0), 'synthetic', CHALLENGE,
                      lambda _: json.dumps({'secret': 'SYNTHETIC'}), lambda: {})
        fake.collect.assert_called_once()

    def test_file_stamp_excludes_atime_only(self):
        value = types.SimpleNamespace(st_dev=1, st_ino=2, st_mode=3, st_uid=4, st_gid=5,
                                      st_nlink=1, st_size=6, st_mtime_ns=7, st_ctime_ns=8, st_atime_ns=9)
        first = m.stamp(value); value.st_atime_ns += 1
        self.assertEqual(first, m.stamp(value))
        for field in ('st_ino', 'st_mode', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            changed = copy.copy(value); setattr(changed, field, getattr(changed, field) + 1)
            self.assertNotEqual(first, m.stamp(changed))

    def test_public_packet_is_deterministic_exact_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            a, other = Path(temp) / 'a', Path(temp) / 'b'
            digest = b.build(a); self.assertEqual(digest, b.build(other))
            self.assertEqual(a.read_bytes(), other.read_bytes())
            value = json.loads(a.read_bytes()); self.assertEqual(len(value['files']), 4)
            self.assertEqual(value['review_status'], 'awaiting-focused-review')
            files = {x['name']: base64.b64decode(x['base64'], validate=True) for x in value['files']}
            self.assertEqual(b.sha(files['collect_server_inventory.py']), b.SERVER_SHA)
            self.assertEqual(files['SHA256SUMS'], ''.join(b.sha(files[n]) + '  ' + n + '\n' for n in b.FILES).encode())
            with self.assertRaises(FileExistsError): b.build(a)

    def test_public_packet_refuses_reader_or_text_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in b.FILES: (root / name).write_bytes((b.HERE / name).read_bytes())
            with mock.patch.object(b, 'HERE', root):
                (root / 'collect_server_inventory.py').write_text('raise RuntimeError("SYNTHETIC")\n')
                with self.assertRaisesRegex(ValueError, 'SERVER_READER'): b.build(root / 'out')
                (root / 'collect_server_inventory.py').write_bytes((m.HERE / 'collect_server_inventory.py').read_bytes())
                (root / 'dashboard_context_observation.js').write_bytes(b'bad\rbytes\n')
                with self.assertRaisesRegex(ValueError, 'TEXT'): b.build(root / 'out')

    def test_stage_exact_file_set_manifest_and_reader_pin(self):
        real_stat = Path.lstat
        def controlled(path):
            info = real_stat(path)
            return types.SimpleNamespace(st_mode=(stat.S_IFDIR | 0o700) if path.is_dir() else (stat.S_IFREG | 0o400),
                                         st_uid=0, st_gid=0, st_size=info.st_size)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); packet = root / 'packet'; b.build(packet)
            files = json.loads(packet.read_bytes())['files']; packet.unlink()
            for item in files: (root / item['name']).write_bytes(base64.b64decode(item['base64']))
            with mock.patch.object(Path, 'lstat', controlled):
                self.assertEqual(set(m.verify_stage(root)), set(b.FILES) | {'SHA256SUMS'})
                (root / 'extra').write_text('unexpected')
                with self.assertRaisesRegex(m.ObservationError, 'STAGE_FILES'): m.verify_stage(root)
                (root / 'extra').unlink()
                (root / 'collect_server_inventory.py').write_bytes(b'# changed\n')
                with self.assertRaisesRegex(m.ObservationError, 'STAGE_BYTES'): m.verify_stage(root)
                (root / 'SHA256SUMS').write_bytes(''.join(b.sha((root / n).read_bytes()) + '  ' + n + '\n'
                                                        for n in b.FILES).encode())
                with self.assertRaisesRegex(m.ObservationError, 'SERVER_READER'): m.verify_stage(root)

    def test_code_snapshot_metadata_digest_and_atime_handling(self):
        real_stat = Path.lstat
        mode = {'leaf': 0o640, 'parent_owner': 0}
        def controlled(info, directory=False):
            return types.SimpleNamespace(st_mode=(stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | mode['leaf']),
                st_uid=mode['parent_owner'] if directory else 126, st_gid=0 if directory else 128,
                st_dev=info.st_dev, st_ino=info.st_ino, st_nlink=info.st_nlink, st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns)
        def path_stat(path):
            info = real_stat(path)
            return controlled(info, stat.S_ISDIR(info.st_mode))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); leaf = root / 'public.js'; leaf.write_bytes(b'public bytes')
            pwd = types.SimpleNamespace(getpwnam=lambda _: types.SimpleNamespace(pw_uid=126, pw_gid=128))
            with mock.patch.dict('sys.modules', {'pwd': pwd}), mock.patch.object(m, 'PLUGIN_ROOT', root), \
                    mock.patch.object(m, 'CODE_PINS', {'public.js': b.sha(b'public bytes')}), \
                    mock.patch.object(Path, 'lstat', path_stat), \
                    mock.patch.object(os, 'fstat', lambda fd: controlled(real_stat(leaf))):
                self.assertEqual(m.code_snapshot(), {'public.js': b.sha(b'public bytes')})
                mode['leaf'] = 0o660
                with self.assertRaisesRegex(m.ObservationError, 'CODE_METADATA'): m.code_snapshot()
                mode['leaf'] = 0o640; mode['parent_owner'] = 999
                with self.assertRaisesRegex(m.ObservationError, 'CODE_METADATA'): m.code_snapshot()
                mode['parent_owner'] = 0; leaf.write_bytes(b'changed bytes')
                with self.assertRaisesRegex(m.ObservationError, 'CODE_BYTES'): m.code_snapshot()


class StagingInputTests(unittest.TestCase):
    """Execute only C2's public-input prefix, never decoding/staging/helpers."""

    @classmethod
    def setUpClass(cls):
        runbook = (ROOT / 'docs/runbooks/rbac-dashboard-context-observation.md').read_text()
        block = re.findall(r'```bash\n(.*?)\n```', runbook, re.S)[0]
        source = block.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        cls.prefix = source.split('raw = base64.b64decode(', 1)[0]
        cls.finish = "\nassert expected == 'a' * 64\nassert parts == ['e30=']\nassert tty.closed\nprint('PASS_C2_PUBLIC_INPUT', flush=True)\n"
        cls.public = 'REVIEWED-RELEASED-CONTEXT\n' + 'a' * 64 + '\ne30=\nALERTMIND_PUBLIC_SOURCE_END\n'

    def pipe_source(self, data, interactive=True, available=True):
        # Actual Python '-' consumes source stdin to EOF, as in the heredoc.
        # Only /dev/tty is simulated on Windows; do not replace sys.stdin.
        bootstrap = """import builtins, io
class PublicConsole(io.StringIO):
    def isatty(self):
        return INTERACTIVE
    def readline(self, size=-1):
        assert 0 < size <= 4098
        return super().readline(size)
console = PublicConsole(DATA)
def terminal_open(path, mode, encoding):
    assert (path, mode, encoding) == ('/dev/tty', 'r', 'ascii')
    if not AVAILABLE:
        raise OSError('SYNTHETIC unavailable console')
    return console
builtins.open = terminal_open
""".replace('INTERACTIVE', repr(interactive)).replace('AVAILABLE', repr(available)).replace('DATA', repr(data))
        return subprocess.run([sys.executable, '-I', '-B', '-'],
                              input=(bootstrap + self.prefix + self.finish).encode(),
                              capture_output=True, timeout=10)

    def test_heredoc_source_eof_does_not_consume_public_console_input(self):
        result = self.pipe_source(self.public)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'PASS_C2_PUBLIC_INPUT', result.stdout)
        self.assertNotIn(b'EOFError', result.stderr)

    def test_missing_terminal_eof_and_bounded_public_lines_refuse_before_decode(self):
        head = 'REVIEWED-RELEASED-CONTEXT\n' + 'a' * 64 + '\n'
        cases = [(self.public, False, True), (self.public, True, False),
                 ('', True, True), ('WRONG-RELEASE\n', True, True),
                 ('REVIEWED-RELEASED-CONTEXT\nnot-a-digest\n', True, True),
                 (head + 'e30=\n', True, True),
                 (head + 'e30=', True, True),
                 (head + 'x' * 4097 + '\n', True, True),
                 (head + ('x' * 4096 + '\n') * 86, True, True)]
        for number, (data, interactive, available) in enumerate(cases):
            with self.subTest(case=number):
                result = self.pipe_source(data, interactive, available)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'STOP: public context staging refused', result.stderr)
                self.assertNotIn(b'PASS_C2_PUBLIC_INPUT', result.stdout)
                self.assertNotIn(b'EOFError', result.stderr)

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'),
                         'Linux controlling-terminal regression')
    def test_real_controlling_terminal_reads_while_bash_heredoc_supplies_source(self):
        import errno
        import pty
        import select
        import signal
        import time
        # Only the exact public-input prefix runs. No sudo, decoding, root writes,
        # approved collector, network or credentials; this is a disposable PTY.
        command = shlex.quote(sys.executable) + " -I -B - <<'ALERTMIND_C2_TEST'\n" + \
                  self.prefix + self.finish + '\nALERTMIND_C2_TEST\n'
        pid, master = pty.fork()
        if pid == 0:
            try:
                env = dict(os.environ)
                for key in ('BASH_ENV', 'ENV'):
                    env.pop(key, None)
                shell = shutil.which('bash')
                os.execve(shell, [shell, '--noprofile', '--norc', '-c', command], env)
            except BaseException:
                os._exit(127)  # Failed exec must never resume the child test runner.
        reaped, output = False, bytearray()
        deadline = time.monotonic() + 10

        def until(needle):
            while needle not in output:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, 'PTY public prompt timed out')
                ready, _, _ = select.select([master], [], [], remaining)
                self.assertTrue(ready, 'PTY public prompt timed out')
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        self.fail('PTY ended before completion; synthetic output: ' + repr(output[-1024:]))
                    raise
                self.assertTrue(chunk, 'PTY closed before public-input completion')
                output.extend(chunk)
                self.assertLessEqual(len(output), 65536)

        try:
            until(b'original-VM/browser run release:')
            os.write(master, b'REVIEWED-RELEASED-CONTEXT\n')
            until(b'independently reviewed PUBLIC packet SHA-256:')
            os.write(master, b'a' * 64 + b'\n')
            until(b'ending with ALERTMIND_PUBLIC_SOURCE_END:')
            os.write(master, b'e30=\nALERTMIND_PUBLIC_SOURCE_END\n')
            until(b'PASS_C2_PUBLIC_INPUT')
            while True:
                ended, status = os.waitpid(pid, os.WNOHANG)
                if ended:
                    reaped = True
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    break
                self.assertLess(time.monotonic(), deadline, 'PTY child did not exit')
                time.sleep(0.01)
        finally:
            if not reaped:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            os.close(master)


# Execute the real reviewed browser script with in-memory synthetic Fetch
# responses. No real browser, cookie jar, network or filesystem in the sandbox.
HARNESS = r'''
const vm = require('node:vm');
let raw = ''; process.stdin.on('data', x => raw += x);
process.stdin.on('end', async () => {
  const x = JSON.parse(raw), logs = [], calls = []; let cursor = 0;
  const ctx = {location: {origin: x.origin || 'https://127.0.0.1'}, prompt: () => x.challenge,
    console: {log: x => logs.push(x)}, AbortController, setTimeout, clearTimeout, TextDecoder,
    fetch: async (path, options) => {
      calls.push({path, method: options.method, credentials: options.credentials, redirect: options.redirect});
      if (x.error) throw new Error('SYNTHETIC-PRIVATE-EXCEPTION');
      const row = x.accounts[Math.min(cursor++, x.accounts.length - 1)];
      const body = x.raw ?? JSON.stringify({total: Object.keys(row).length, data: row});
      return {status: x.status || 200, url: 'https://127.0.0.1' + path, type: 'basic',
        headers: {get: () => 'application/json'},
        body: new ReadableStream({start(c) {c.enqueue(new TextEncoder().encode(body)); c.close();}})};
    }};
  try { await vm.runInNewContext(x.source, ctx, {timeout: 2000}); }
  catch (_) { process.exitCode = 1; }
  process.stdout.write(JSON.stringify({logs, calls}));
});
'''


@unittest.skipUnless(shutil.which('node'), 'Node required for synthetic browser script')
class BrowserScriptTests(unittest.TestCase):
    def run_script(self, **change):
        data = {'source': (m.HERE / 'dashboard_context_observation.js').read_text(),
                'challenge': CHALLENGE, 'accounts': [account(), account()]}
        data.update(change)
        process = subprocess.run([shutil.which('node'), '-e', HARNESS], input=json.dumps(data),
                                 text=True, capture_output=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_actual_script_two_fixed_gets_sanitized_output_and_no_other_routes(self):
        result = self.run_script()
        self.assertEqual(json.loads(result['logs'][0]), browser())
        self.assertEqual(result['calls'], [{'path': '/api/v1/configuration/account', 'method': 'GET',
                                          'credentials': 'same-origin', 'redirect': 'error'}] * 2)
        self.assertNotIn('tenants', result['logs'][0])

    def test_admin_session_wrong_grants_or_custom_attributes_stop(self):
        for field, value in (('user_name', 'admin'), ('roles', ['all_access']),
                             ('backend_roles', ['admin']), ('custom_attribute_names', ['SYNTHETIC-PRIVATE']),
                             ('is_internal_user', False)):
            row = account(); row[field] = value
            with self.subTest(field=field):
                result = self.run_script(accounts=[row])
                self.assertTrue(result['logs'][0].startswith('STOP Dashboard context:'))
                self.assertEqual(len(result['calls']), 1)
                self.assertNotIn('SYNTHETIC-PRIVATE', result['logs'][0])

    def test_unknown_fields_raw_secrets_and_tenant_drift_are_not_exported(self):
        row = account(); row['unexpected_secret'] = 'SYNTHETIC-PRIVATE'
        result = self.run_script(accounts=[row]); self.assertIn('SHAPE', result['logs'][0])
        changed = account(); changed['tenants']['global_tenant'] = True
        result = self.run_script(accounts=[account(), changed])
        self.assertIn('DRIFT', result['logs'][0]); self.assertNotIn('SYNTHETIC-PRIVATE', str(result['logs']))

    def test_http_failures_invalid_json_oversize_and_exceptions_never_become_pass(self):
        for kwargs in ({'status': 403}, {'status': 401}, {'status': 500}, {'raw': '{bad'},
                       {'raw': 'x' * 16385}, {'error': True}):
            with self.subTest(kwargs=list(kwargs)):
                result = self.run_script(**kwargs)
                self.assertTrue(result['logs'][0].startswith('STOP Dashboard context:'))
                self.assertNotIn('SYNTHETIC-PRIVATE', result['logs'][0])
                self.assertEqual(len(result['calls']), 1)

    def test_wrong_origin_or_missing_challenge_prevents_all_reads(self):
        for kwargs in ({'origin': 'http://127.0.0.1'}, {'origin': 'https://localhost'},
                       {'origin': 'https://127.0.0.1:19200'}, {'challenge': None}, {'challenge': 'password'}):
            result = self.run_script(**kwargs)
            self.assertEqual(result['calls'], [])
            self.assertTrue(result['logs'][0].startswith('STOP Dashboard context:'))

    def test_dashboard_wrapper_required_direct_indexer_response_refused(self):
        for value in (account(), {'total': 1, 'data': account()}, {'total': 9, 'data': None},
                      {'total': 9, 'data': account(), 'unexpected': 'SYNTHETIC-PRIVATE'}):
            result = self.run_script(raw=json.dumps(value))
            self.assertIn('SHAPE', result['logs'][0])
            self.assertNotIn('SYNTHETIC-PRIVATE', result['logs'][0])
            self.assertEqual(len(result['calls']), 1)

    def test_recursive_find_subset_checks_dicts_and_literal_list_members(self):
        # Test the actual function separately with synthetic structures, not
        # by relaxing the live nine-field account contract.
        source = (m.HERE / 'dashboard_context_observation.js').read_text()
        start, end = source.index('  function findLiteral('), source.index('  function validate(')
        function = source[start:end]
        js = "const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);\n" + function
        cases = [({'user_name': 'admin'}, True), ({'nested': {'user_name': 'admin'}}, True),
                 ({'nested': [{'user_name': ['other', 'admin']}]}, True),
                 ({'user_name': 'socanalyst'}, False), ({'user_name': 'administrator'}, False),
                 ({'nested': {'user_name': ['socanalyst']}}, False)]
        js += '\nconsole.log(JSON.stringify(' + json.dumps([a for a, _ in cases]) + \
              '.map(x=>findLiteral(x,"user_name","admin"))));'
        proc = subprocess.run([shutil.which('node'), '-e', js], text=True, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), [b for _, b in cases])


if __name__ == '__main__':
    unittest.main()
