"""Offline fake API/unit/files + real JSON/YAML/HTTP/JS parsing; no live requests."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_server_inventory import fixture, page, WirePeer, wire, m as server
from test_broker_tls_compact import FakeHost, PowerLoss, m as compact, ORIGINAL, CANDIDATE, DER

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'siem/rbac' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


m = module('human_readonly_operator')
b = module('build_human_readonly_packet')
staging = module('stage_human_readonly')
UI = (b'# Keep comments and unrelated settings\nserver.host: 0.0.0.0\n'
      b'opensearch_security.multitenancy.enabled: false\n'
      b'opensearch_security.readonly_mode.roles: ["kibana_read_only", "preserved_label"] # retain\n'
      b'# EOF stays identical\n')


def baseline():
    catalog, me, processed, config = fixture()
    catalog['users'][1]['id'] = 2
    catalog['users'].reverse()
    catalog['roles'][0]['users'] = [2, 3]
    catalog['roles'][0]['rules'] = [1, 2]
    catalog['rules'] = [
        {'id': 1, 'name': 'existing_elastic_admin', 'roles': [7],
         'rule': {'FIND': {'username': 'elastic'}}},
        {'id': 2, 'name': 'existing_opensearch_admin', 'roles': [7],
         'rule': {'FIND': {'user_name': 'admin'}}}]
    return {'catalog': catalog, 'me': me, 'processed': processed, 'config': config}


def digest(snapshot):
    value = server.summarize(snapshot['catalog'], snapshot['me'], snapshot['processed'],
                             snapshot['config'], 'SERVER-OPERATOR-SECRET')
    value['two_pass_observation_equal'] = True
    return server.digest(value)


class Host(FakeHost):
    def __init__(self):
        super().__init__()
        self.files[m.UI] = UI
        self.meta[m.UI] = [0o640, 126, 128]
        self.extension_ok = True
        self.service_ok = True

    def ui_metadata(self):
        m.need(self.extension_ok, 'UI_METADATA')

    def run(self, argv):
        assert argv[:2] == ['/usr/bin/systemctl', 'is-active']
        m.need(self.service_ok, 'SERVICE_HEALTH')
        return b'active\n'

    def put(self, path, *args, **kwargs):
        if path == m.UI:
            assert self.active == 'inactive' and compact.INHIBIT in self.loaded
        super().put(path, *args, **kwargs)


class FakeAPI:
    def __init__(self, host):
        self.host, self.value = host, baseline()
        self.username = 'SERVER-OPERATOR-SECRET'
        self.calls = []
        self.lost_response = None
        self.failure_before = None

    def snapshot(self):
        return copy.deepcopy(self.value)

    def mutate(self, action, role_id, rule_id):
        assert self.host.active == 'inactive' and compact.INHIBIT in self.host.loaded
        if self.failure_before == action:
            raise m.HumanError('WRITE_HTTP')
        self.calls.append(m.API.route(action, role_id, rule_id))
        catalog = self.value['catalog']
        role = next(r for r in catalog['roles'] if r['id'] == role_id)
        if action == 'create':
            catalog['rules'].append(dict(copy.deepcopy(m.PAYLOAD), id=105, roles=[]))
        elif action == 'link':
            role['rules'].append(rule_id)
            catalog['rules'][-1]['roles'] = [role_id]
        elif action == 'unlink':
            role['rules'].remove(rule_id)
            catalog['rules'][-1]['roles'] = []
        elif action == 'delete':
            catalog['rules'] = [r for r in catalog['rules'] if r['id'] != rule_id]
        else:
            raise AssertionError(action)
        if self.lost_response == action:
            raise PowerLoss()


class HumanTransactionTests(unittest.TestCase):
    def setUp(self):
        for key, raw in (('ORIGINAL_SHA', ORIGINAL), ('CANDIDATE_SHA', CANDIDATE), ('CERT_SHA', DER)):
            p = patch.object(compact, key, compact.sha(raw))
            p.start()
            self.addCleanup(p.stop)

    def ready(self):
        host = Host()
        compact.prepare(host)
        compact.install(host)
        compact.resume(host)
        host.events.clear()
        api = FakeAPI(host)
        engine = m.Engine(host, compact, server, api, expected=digest(api.value))
        return host, api, engine

    def test_success_scoped_graph_ui_metadata_and_secure_rollback_resume(self):
        h, api, e = self.ready()
        before = copy.deepcopy(api.value)
        e.preflight()
        self.assertEqual(api.calls, [])
        self.assertNotIn(m.JOURNAL, h.files)
        e.prepare()
        self.assertEqual(h.active, 'active')
        e.install()
        self.assertEqual(h.active, 'inactive')
        self.assertEqual(h.meta[m.UI], [0o640, 126, 128])
        self.assertEqual(h.meta[m.JOURNAL], [0o400, 0, 0])
        self.assertEqual(h.files[m.UI], m.ui_candidate(UI))
        self.assertEqual(m.projection(api.value, before, 8, 105, True)['roles'], [8])
        e.resume()
        e.check()
        e.rollback()
        self.assertEqual(api.value, before)
        self.assertEqual(h.files[m.UI], UI)
        self.assertEqual(h.files[compact.CLIENT], CANDIDATE)
        self.assertIn(compact.GUARD, h.files)
        self.assertEqual(h.active, 'inactive')
        e.resume(baseline=True)
        self.assertEqual(h.active, 'active')
        self.assertEqual([v[0] for v in api.calls], ['POST', 'POST', 'DELETE', 'DELETE'])

    def test_lost_create_and_link_responses_reconcile_without_repeating_mutation(self):
        for action in ('create', 'link'):
            with self.subTest(action=action):
                h, api, e = self.ready()
                e.prepare()
                api.lost_response = action
                with self.assertRaises(PowerLoss):
                    e.install()
                self.assertEqual(h.active, 'inactive')
                api.lost_response = None
                e.install()
                self.assertEqual(len(api.calls), 2)
                e.rollback()
                self.assertEqual(api.value, baseline())

    def test_explicit_secure_restoration_after_rollback_uses_same_scope(self):
        h, api, e = self.ready()
        e.prepare(); e.install(); e.resume(); e.rollback(); e.resume(baseline=True)
        e.restore()
        self.assertEqual(h.active, 'inactive')
        self.assertEqual(h.files[m.UI], m.ui_candidate(UI))
        self.assertEqual(h.files[compact.CLIENT], CANDIDATE)
        e.resume(); e.check()
        self.assertEqual(len([c for c in api.calls if c[0] == 'POST']), 4)

    def test_rollback_after_lost_unlink_or_delete_response_is_scoped_and_idempotent(self):
        for action in ('unlink', 'delete'):
            with self.subTest(action=action):
                h, api, e = self.ready()
                e.prepare(); e.install()
                api.lost_response = action
                with self.assertRaises(PowerLoss):
                    e.rollback()
                api.lost_response = None
                e.rollback()
                self.assertEqual(api.value, baseline())
                self.assertEqual(h.files[m.UI], UI)
                self.assertEqual(len([c for c in api.calls if c[0] == 'DELETE']), 2)

    def test_every_install_local_write_control_interruption_can_roll_back(self):
        h, api, e = self.ready()
        e.prepare()
        h.events.clear()
        e.install()
        count = len(h.events)
        for event in range(1, count + 1):
            with self.subTest(event=event):
                h, api, e = self.ready()
                e.prepare()
                h.events.clear(); h.crash_at = event
                with self.assertRaises(PowerLoss):
                    e.install()
                h.crash_at = None
                e.rollback()
                self.assertEqual(api.value, baseline())
                self.assertEqual(h.files[m.UI], UI)
                self.assertEqual(h.active, 'inactive')
                self.assertEqual(h.files[compact.CLIENT], CANDIDATE)

    def test_every_rollback_local_interruption_can_finish_without_unrelated_edits(self):
        h, api, e = self.ready()
        e.prepare(); e.install(); h.events.clear(); e.rollback()
        for event in range(1, len(h.events) + 1):
            with self.subTest(event=event):
                h, api, e = self.ready()
                e.prepare(); e.install(); h.events.clear(); h.crash_at = event
                with self.assertRaises(PowerLoss):
                    e.rollback()
                h.crash_at = None
                e.rollback()
                self.assertEqual(api.value, baseline())
                self.assertEqual(h.files[m.UI], UI)

    def test_prepared_backups_are_reused_exactly_after_pre_journal_crash(self):
        h, api, e = self.ready()
        h.crash_at = 2
        with self.assertRaises(PowerLoss):
            e.prepare()
        h.crash_at = None
        e.prepare()
        self.assertEqual(api.calls, [])
        self.assertEqual(h.active, 'active')

    def test_refuses_unrelated_graph_ui_drift_collision_and_missing_backup(self):
        for kind in ('admin', 'ui', 'metadata', 'collision', 'backup'):
            with self.subTest(kind=kind):
                h, api, e = self.ready(); e.prepare()
                if kind == 'admin':
                    api.value['catalog']['rules'][0]['rule'] = m.PREDICATE
                elif kind == 'ui':
                    h.files[m.UI] += b'new.setting: true\n'
                elif kind == 'metadata':
                    h.meta[m.UI][0] = 0o600
                elif kind == 'backup':
                    h.files[m.BEFORE_UI] += b'changed\n'
                else:
                    api.value['catalog']['rules'].append(dict(m.PAYLOAD, id=105, roles=[]))
                with self.assertRaises((m.HumanError, compact.CompactError)):
                    e.install()
                self.assertEqual(api.calls, [])
                self.assertEqual(h.active, 'inactive')

    def test_link_ui_missing_owned_rule_and_wrong_role_refuse_rollback(self):
        for kind in ('wrong-role', 'predicate', 'missing-rule'):
            with self.subTest(kind=kind):
                h, api, e = self.ready(); e.prepare(); e.install()
                if kind == 'wrong-role':
                    api.value['catalog']['rules'][-1]['roles'] = [7]
                elif kind == 'predicate':
                    api.value['catalog']['rules'][-1]['rule'] = {'FIND': {'user_name': 'socanalyst'}}
                else:
                    api.value['catalog']['rules'].pop()  # Stale role edge remains.
                calls = list(api.calls)
                with self.assertRaises(m.HumanError):
                    e.rollback()
                self.assertEqual(api.calls, calls)

    def test_failed_start_reinhibits_and_preserves_tls(self):
        h, api, e = self.ready(); e.prepare(); e.install()
        h.start_failure = True
        with self.assertRaises(compact.CompactError):
            e.resume()
        self.assertEqual(h.active, 'inactive')
        self.assertIn(compact.INHIBIT, h.loaded)
        self.assertEqual(h.files[compact.CLIENT], CANDIDATE)

    def test_role_is_resolved_by_name_and_production_digest_drift_refuses(self):
        h, api, e = self.ready()
        self.assertEqual(e.preflight()[1], 8)  # Not historical numeric ID 2.
        e.expected = m.OBSERVED
        with self.assertRaisesRegex(m.HumanError, 'BASELINE_CHANGED'):
            e.prepare()
        self.assertNotIn(m.JOURNAL, h.files)
        self.assertEqual(api.calls, [])

    def test_alias_acl_and_foreign_unit_refuse_before_permissions_change(self):
        for kind in ('ACL', 'unit', 'package', 'service'):
            with self.subTest(kind=kind):
                h, api, e = self.ready()
                if kind == 'ACL': h.extension_ok = False
                if kind == 'unit': h.extra_dropins = ['/etc/unknown.conf']; h.loaded += h.extra_dropins
                if kind == 'package': h.version_ok = False
                if kind == 'service': h.service_ok = False
                with self.assertRaises((m.HumanError, compact.CompactError)):
                    e.prepare()
                self.assertEqual(api.calls, [])
                self.assertNotIn(m.JOURNAL, h.files)


class HumanReaderWriterTests(unittest.TestCase):
    def test_yaml_flow_block_dotted_nested_preserves_unrelated_bytes(self):
        self.assertEqual(m.ui_candidate(UI), UI.replace(
            b'["kibana_read_only", "preserved_label"]',
            b'["kibana_read_only", "preserved_label", "alertmind_socanalyst_ro"]'))
        samples = (
            b'opensearch_security:\n  multitenancy:\n    enabled: false\n  readonly_mode:\n    roles:\n      - kibana_read_only\n# retained\n',
            b'opensearch_security.readonly_mode:\n  roles: [kibana_read_only]\nopensearch_security.multitenancy.enabled: false\n',
            UI + b'unchanged.list: [kibana_read_only, preserved_label, alertmind_socanalyst_ro]\n',
        )
        for raw in samples:
            after = m.ui_candidate(raw)
            self.assertIn(m.LABEL.encode(), after)
            self.assertTrue(after.endswith(b'\n'))

    def test_yaml_duplicate_ambiguous_alias_unknown_and_already_added_refuse(self):
        bad = [UI + b'opensearch_security.readonly_mode.roles: [kibana_read_only]\n',
               UI + b'opensearch_security:\n  readonly_mode:\n    roles: [kibana_read_only]\n',
               UI.replace(b'false', b'true'), UI.replace(b'["kibana_read_only", "preserved_label"]', b'&alias [kibana_read_only]'),
               UI.replace(b'kibana_read_only', b'unknown'), m.ui_candidate(UI), UI.replace(b'\n', b'\r\n')]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(m.HumanError):
                m.ui_candidate(raw)

    def test_writer_routes_no_wildcards_users_roles_policies_or_reserved_rule(self):
        self.assertEqual(m.API.route('create', 8, None), ('POST', '/security/rules', m.PAYLOAD))
        self.assertEqual(m.API.route('link', 8, 105)[1], '/security/roles/8/rules?rule_ids=105')
        for action, role, rule in [('update', 8, 105), ('delete', 8, 1), ('delete', 8, 'all'),
                                   ('delete', 8, True), ('link', True, 105), ('create', 8, 105)]:
            with self.subTest(action=action, rule=rule), self.assertRaises(m.HumanError):
                m.API.route(action, role, rule)

    def test_mutation_uses_real_http_json_framing_and_disposes_response(self):
        data = {'error': 0, 'data': page([dict(m.PAYLOAD, id=105, roles=[])])}
        peer = WirePeer(wire(json.dumps(data).encode()), fragment=3)
        c = server.Client(object()); c.token = 'synthetic.only.token'
        with patch.object(c, 'connect', return_value=peer):
            m.API(server, c, 'operator').mutate('create', 8, None)
        self.assertTrue(peer.closed)
        self.assertTrue(peer.file.closed)
        self.assertEqual(peer.timeouts_after_release, 0)

    def test_writer_refuses_partial_http_redirect_and_bad_content_type(self):
        for data, status, content in [(page([], 1), b'200', b'application/json'),
                                     (page([{}]), b'201', b'application/json'),
                                     (page([{}]), b'302', b'application/json'),
                                     (page([{}]), b'200', b'text/plain')]:
            data = {'error': 0, 'data': data}
            raw = wire(json.dumps(data).encode()).replace(b'200 OK', status + b' OK').replace(b'application/json', content)
            c = server.Client(object()); c.token = 'synthetic.only.token'
            peer = WirePeer(raw)
            with patch.object(c, 'connect', return_value=peer), self.assertRaises((m.HumanError, server.InventoryError)):
                m.API(server, c, 'operator').mutate('create', 8, None)
            self.assertTrue(peer.closed)

    def test_packet_deterministic_lf_pinned_reuse_exact_stage_and_python310_syntax(self):
        runbook = (ROOT / 'docs/runbooks/rbac-human-readonly-deployment.md').read_text()
        public_build = runbook.split('```powershell\n', 1)[1].split('```', 1)[0]
        self.assertTrue(public_build.startswith('$HumanReadonlyPacket = '))
        self.assertIn('--output $HumanReadonlyPacket', public_build)
        self.assertIn('[IO.File]::ReadAllBytes($HumanReadonlyPacket)', runbook)
        if os.name == 'nt' and shutil.which('powershell'):
            # No builder execution: exercise the retained variable's real PS scope.
            script = ('function python { $global:LASTEXITCODE = 0 }\n' + public_build +
                      '\nif (-not $HumanReadonlyPacket.EndsWith(".json")) { throw "PACKET_SCOPE" }')
            result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        with tempfile.TemporaryDirectory() as folder:
            one, two = Path(folder) / 'one.json', Path(folder) / 'two.json'
            pin = b.build(one)
            self.assertEqual(b.build(two), pin)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            files = staging.decode(one.read_bytes(), pin)
            self.assertEqual(set(files), set(staging.NAMES))
            self.assertEqual(m.PINS, b.PINS)
            for name in staging.NAMES:
                self.assertNotIn(b'\r', files[name])
                if name.endswith('.py'): ast.parse(files[name], feature_version=(3, 10))
            with self.assertRaises(ValueError):
                staging.decode(one.read_bytes(), '0' * 64)
            with self.assertRaises(FileExistsError):
                b.build(one)

    def test_staging_input_reads_controlling_tty_not_heredoc_stdin(self):
        tty = io.StringIO('review\n')
        with patch('sys.stdin', io.StringIO('source-only\n')):
            self.assertEqual(staging.line(tty, 20), 'review')
        for raw in ('', 'no-newline', 'x' * 30 + '\n'):
            with self.assertRaises(ValueError):
                staging.line(io.StringIO(raw), 20)
        with self.assertRaises(OSError), patch('builtins.open', side_effect=OSError('no tty')):
            # main converts this to static failure, with no stage writes.
            open('/dev/tty')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux controlling-terminal staging regression')
    def test_real_staging_public_input_uses_tty_while_source_stdin_is_at_eof(self):
        import errno
        import pty
        import select
        import signal
        import time
        # Only the input function executes, unprivileged. No decoding/root files.
        prefix = 'import sys\n' + '\n'.join((ROOT / 'siem/rbac/stage_human_readonly.py').read_text()
                                           .split('def main():', 1)[0].splitlines())
        code = prefix + "\nwith open('/dev/tty', encoding='ascii') as tty:\n print('PUBLIC_READY', flush=True)\n assert line(tty, 20) == 'public-only'\nprint('TTY_INPUT_OK', flush=True)\n"
        source_read, source_write = os.pipe()
        os.write(source_write, code.encode()); os.close(source_write)
        pid, master = pty.fork()
        if pid == 0:
            try:
                os.dup2(source_read, 0); os.close(source_read)
                os.execv(sys.executable, [sys.executable, '-I', '-B', '-'])
            except BaseException:
                os._exit(127)
        os.close(source_read)
        reaped, output, sent = False, bytearray(), False
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], .1)
                if ready:
                    try: chunk = os.read(master, 4096)
                    except OSError as error:
                        if error.errno != errno.EIO: raise
                        break
                    if not chunk: break
                    output.extend(chunk)
                    if b'PUBLIC_READY' in output and not sent:
                        os.write(master, b'public-only\n'); sent = True
                ended, status = os.waitpid(pid, os.WNOHANG)
                if ended:
                    reaped = True
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    break
            self.assertIn(b'TTY_INPUT_OK', output)
        finally:
            if not reaped:
                ended, status = os.waitpid(pid, os.WNOHANG)
                if not ended:
                    os.kill(pid, signal.SIGKILL)
                    ended, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            os.close(master)

    def test_console_failure_has_no_exception_or_secret_text(self):
        with patch.object(m.sys, 'platform', 'win32'), patch.object(m, 'modules', side_effect=Exception('SECRET')):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                self.assertEqual(m.main(['install']), 1)
            self.assertNotIn('SECRET', stream.getvalue())
            self.assertIn('ROOT_STAGE_CONSOLE', stream.getvalue())


NODE = shutil.which('node')
if NODE is None:
    candidate = Path.home() / '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'
    NODE = str(candidate) if candidate.exists() else None


@unittest.skipUnless(NODE, 'Node required for synthetic browser execution')
class HumanBrowserAcceptanceTests(unittest.TestCase):
    def run_js(self, variant='success'):
        policy = {'rbac_mode': 'white'}
        for actions, resources in server.READONLY.values():
            for action in actions:
                policy.setdefault(action, {}).update({r: 'allow' for r in resources})
        account = {'user_name': 'socanalyst', 'is_reserved': False, 'is_hidden': False,
                   'is_internal_user': True, 'user_requested_tenant': None, 'backend_roles': [],
                   'custom_attribute_names': [], 'tenants': {}, 'roles': [m.LABEL]}
        harness = r'''
const fs = require('fs'), vm = require('vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const account = input.account, policy = input.policy, calls = [], logs = [];
if (input.variant === 'elevated') policy['security:create'] = {'*:*:*': 'allow'};
if (input.variant === 'wrong-account') account.roles.push('all_access');
let number = 0;
const sandbox = {location: {origin: 'https://127.0.0.1'}, AbortController, TextDecoder,
  Uint8Array, setTimeout, clearTimeout, prompt: () => ++number === 1 ?
    'RELEASED-SAFE-ACCEPTANCE' : 'default', console: {log: x => logs.push(x)},
  fetch: async (url, options) => {
    const request = options.body ? JSON.parse(options.body) : null;
    calls.push([url, request]);
    let status = 200, body;
    if (!request) body = {total: 9, data: account};
    else if (request.path === '/security/users/me/policies') body = {error: 0, data: policy};
    else if (request.path.startsWith('/agents')) body = {error: 0, data: {
      total_failed_items: 0, failed_items: [], total_affected_items: 3, affected_items: [{id: '001'}]}};
    else {
      status = 403; body = {error: 4000, detail: 'SECRET-RAW-ERROR'};
      if (input.variant === 'validation') {status = 400; body.error = 4003;}
      if (input.variant === 'duplicate') {status = 200; body = {error: 0, data: {
        total_failed_items: 1, failed_items: [{error: {code: 4005}}], total_affected_items: 0, affected_items: []}};}
      if (input.variant === 'generic403') body.error = 3013;
      if (input.variant === 'auth401') status = 401;
      if (input.variant === 'proxy500') status = 500;
    }
    const data = new TextEncoder().encode(JSON.stringify(body)); let used = false;
    return {status, url: 'https://127.0.0.1' + url, type: 'basic',
      headers: {get: () => 'application/json'}, body: {getReader: () => ({
        read: async () => used ? {done: true} : (used = true, {done: false, value: data}),
        cancel: async () => {}, releaseLock: () => {}})}};
  }};
vm.runInNewContext(input.source, sandbox).then(() => console.log(JSON.stringify({calls, logs})));
'''
        result = subprocess.run([NODE, '-e', harness], input=json.dumps({
            'account': account, 'policy': policy, 'variant': variant,
            'source': (ROOT / 'siem/rbac/human_readonly_acceptance.js').read_text()}).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def test_actual_session_paths_exact_policy_positive_control_and_fail_safe_duplicate(self):
        result = self.run_js()
        value = json.loads(result['logs'][0])
        self.assertTrue(value['effective_readonly_policy_exact'])
        self.assertEqual(value['duplicate_rule_create_http'], 403)
        calls = [c[1] for c in result['calls'] if c[1]]
        self.assertEqual([c['method'] for c in calls], ['GET', 'GET', 'GET', 'POST', 'GET'])
        self.assertEqual(calls[3]['body']['body'], m.PAYLOAD)
        self.assertTrue(all(c['body']['devTools'] for c in calls))
        self.assertNotIn('SECRET-RAW-ERROR', '|'.join(result['logs']))

    def test_auth_validation_duplicate_partial_or_proxy_failures_are_never_denial_pass(self):
        for variant in ('validation', 'duplicate', 'generic403', 'auth401', 'proxy500', 'elevated', 'wrong-account'):
            with self.subTest(variant=variant):
                result = self.run_js(variant)
                self.assertTrue(result['logs'][0].startswith('STOP human acceptance:'))
                self.assertNotIn('SECRET', result['logs'][0])
                self.assertLessEqual(len(result['calls']), 4)


if __name__ == '__main__':
    unittest.main()
