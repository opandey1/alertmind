"""Review-gated, fixed human mapping/UI transaction. No execution release.

Trusts the owner-controlled lab OS/root/vendor runtime, like the deployed
compact TLS operator. No Indexer writes, Server user creation, run-as login,
wildcard mapping, credential persistence or experimental attestation.
"""
import copy
import getpass
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import warnings

HERE = Path(__file__).resolve().parent
STAGE = '/root/alertmind-broker-tls-compact/human-readonly-stage'
STATE = '/root/alertmind-broker-tls-compact/human-readonly-state'
JOURNAL = STATE + '/journal.json'
BEFORE_UI = STATE + '/before-ui.bin'
AFTER_UI = STATE + '/after-ui.bin'
UI = '/etc/wazuh-dashboard/opensearch_dashboards.yml'
LABEL = 'alertmind_socanalyst_ro'
NAME = 'alertmind_socanalyst_server_ro'
PREDICATE = {'MATCH': {'user_name': 'socanalyst'}}
PAYLOAD = {'name': NAME, 'rule': PREDICATE}
OBSERVED = 'd3db272c808ddb23c7532530c096087a7b336481b6503bc783cf390111c4f046'
PINS = {
    'collect_server_inventory.py': '96e64194cbed95a5cd8526e9f76c7f38432c8061c29f9fe1c8d7239a340a030e',
    'compact_operator.py': '2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942',
}
PHASES = ('prepared', 'create-intent', 'created', 'link-intent', 'linked',
          'ui-intent', 'installed', 'running', 'rollback-intent',
          'rolled-back', 'baseline-running')


class HumanError(Exception):
    """Only fixed codes, never raw config/API/exception text."""


def need(ok, code):
    if not ok:
        raise HumanError(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def modules():
    # Conventional root-private reviewed stage, not a hostile-root sandbox.
    loaded = []
    for name, pin in PINS.items():
        path = HERE / name
        metadata = path.lstat()
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and
             (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) ==
             (0, 0, 0o400), 'SOURCE_METADATA')
        raw = path.read_bytes()
        import hashlib
        need(len(raw) <= 131072 and hashlib.sha256(raw).hexdigest() == pin, 'SOURCE_PIN')
        spec = importlib.util.spec_from_file_location('_human_' + name[:-3], path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        loaded.append(module)
    return loaded


def ui_candidate(raw):
    """Replace only the reviewed role-list span; preserve other bytes/settings."""
    import yaml

    class Loader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            event = self.peek_event()
            need(not isinstance(event, yaml.AliasEvent) and
                 getattr(event, 'anchor', None) is None, 'UI_ALIAS')
            return super().compose_node(parent, index)

        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                need(type(key) is str and key != '<<' and key not in result, 'UI_DUPLICATE')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    def locate(node, parts):
        need(isinstance(node, yaml.MappingNode), 'UI_SHAPE')
        found = []
        for key, value in node.value:
            prefix = key.value.split('.')
            if prefix == parts:
                found.append(value)
            elif len(prefix) < len(parts) and prefix == parts[:len(prefix)]:
                found.extend(locate(value, parts[len(prefix):]))
        return found

    try:
        need(0 < len(raw) <= 131072 and b'\x00' not in raw and
             b'\r' not in raw and raw.endswith(b'\n'), 'UI_TEXT')
        text = raw.decode('utf-8')
        document = yaml.compose(text, Loader=Loader)
        data = yaml.load(text, Loader=Loader)
        roles = locate(document, ['opensearch_security', 'readonly_mode', 'roles'])
        tenants = locate(document, ['opensearch_security', 'multitenancy', 'enabled'])
        need(len(roles) == len(tenants) == 1, 'UI_SETTING')
        need(isinstance(roles[0], yaml.SequenceNode) and
             all(isinstance(n, yaml.ScalarNode) and n.tag == 'tag:yaml.org,2002:str'
                 for n in roles[0].value), 'UI_ROLES')
        names = [n.value for n in roles[0].value]
        need(names and len(names) == len(set(names)) and 'kibana_read_only' in names
             and LABEL not in names and all(0 < len(n) <= 128 for n in names), 'UI_ROLES')
        need(tenants[0].tag == 'tag:yaml.org,2002:bool' and
             tenants[0].value.lower() == 'false', 'UI_MULTITENANCY')
        start = roles[0].start_mark.index
        end = (roles[0].end_mark.index if roles[0].flow_style else
               roles[0].value[-1].end_mark.index)
        replacement = json.dumps(names + [LABEL], ensure_ascii=True)
        after = (text[:start] + replacement + text[end:]).encode('utf-8')
        # Parsed diff must be exactly the selected role list, including nested form.
        parsed = yaml.load(after, Loader=Loader)
        def replace(value, parts):
            count = 0
            for key, item in list(value.items()):
                prefix = key.split('.')
                if prefix == parts:
                    need(item == names + [LABEL], 'UI_ROLES')
                    value[key] = names
                    count += 1
                elif len(prefix) < len(parts) and prefix == parts[:len(prefix)]:
                    count += replace(item, parts[len(prefix):])
            return count
        need(replace(parsed, ['opensearch_security', 'readonly_mode', 'roles']) == 1, 'UI_SETTING')
        need(parsed == data, 'UI_UNRELATED_CHANGE')
        return after
    except HumanError:
        raise
    except Exception:
        raise HumanError('UI_PARSE') from None


def initial_contract(server, snapshot, username, expected=OBSERVED):
    summary = server.summarize(snapshot['catalog'], snapshot['me'],
                               snapshot['processed'], snapshot['config'], username)
    summary['two_pass_observation_equal'] = True
    need(server.digest(summary) == expected, 'BASELINE_CHANGED')
    roles = snapshot['catalog']['roles']
    readonly = server.named(roles, 'name', 'readonly')
    admin = server.named(roles, 'name', 'administrator')
    need(readonly['rules'] == readonly['users'] == [], 'READONLY_LINKS')
    rules = snapshot['catalog']['rules']
    need(len(rules) == 2 and {server.digest(r['rule']) for r in rules} ==
         {server.digest({'FIND': {'username': 'elastic'}}),
          server.digest({'FIND': {'user_name': 'admin'}})} and
         all(r['roles'] == [admin['id']] for r in rules), 'ADMIN_RULES')
    need(server.named(snapshot['catalog']['users'], 'username', 'wazuh-wui')['id'] == 2,
         'BROKER_ID')
    return readonly['id']


class API:
    """Reader stays unchanged; separate narrow, bound writer on the same TLS client."""
    def __init__(self, server, client, username):
        self.s, self.client, self.username = server, client, username

    def snapshot(self):
        c, s = self.client, self.s
        need(c.request('GET', '/').get('api_version') == '4.14.7', 'SERVER_VERSION')
        me = c.request('GET', '/security/users/me')
        processed = c.request('GET', '/security/users/me/policies')
        config = c.request('GET', '/security/config')
        first = {k: s.fetch_collection(c, k) for k in s.COLLECTIONS}
        second = {k: s.fetch_collection(c, k) for k in s.COLLECTIONS}
        need(first == second, 'CATALOG_DRIFT')
        for path, expected in (('/security/users/me', me),
                               ('/security/users/me/policies', processed),
                               ('/security/config', config)):
            need(c.request('GET', path) == expected, 'CONTEXT_DRIFT')
        return {'catalog': first, 'me': me, 'processed': processed, 'config': config}

    @staticmethod
    def route(action, readonly_id, rule_id):
        need(type(readonly_id) is int and 0 < readonly_id < 2**31, 'ROLE_ID')
        if action == 'create':
            need(rule_id is None, 'RULE_ID')
            return 'POST', '/security/rules', PAYLOAD
        need(type(rule_id) is int and 100 <= rule_id < 2**31, 'RULE_ID')
        if action in ('link', 'unlink'):
            return ('POST' if action == 'link' else 'DELETE',
                    f'/security/roles/{readonly_id}/rules?rule_ids={rule_id}', None)
        need(action == 'delete', 'WRITE_ROUTE')
        return 'DELETE', f'/security/rules?rule_ids={rule_id}', None

    def mutate(self, action, readonly_id, rule_id):
        method, path, value = self.route(action, readonly_id, rule_id)
        c = self.client
        need(c.token is not None, 'AUTH_REQUIRED')
        c.requests += 1
        need(c.requests <= 100, 'REQUEST_LIMIT')
        body = encoded(value) if value is not None else None
        peer = c.connect()  # Same pinned peer + localhost verification BEFORE bearer.
        connection = response = None
        try:
            connection = http.client.HTTPConnection('localhost', 55000, timeout=c.timeout())
            connection.sock = peer
            headers = {'Host': 'localhost:55000', 'Accept': 'application/json',
                       'Accept-Encoding': 'identity', 'Connection': 'close',
                       'Authorization': 'Bearer ' + c.token}
            if body is not None:
                headers['Content-Type'] = 'application/json'
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            need(response.status == 200, 'WRITE_HTTP')
            need(response.getheader('Content-Encoding', 'identity') == 'identity' and
                 response.getheader('Content-Type', '').split(';')[0].strip().lower() ==
                 'application/json', 'WRITE_RESPONSE')
            data = self.s.envelope(c.read_body(response, peer))
            total, items = self.s.rows(data)
            need(total == 1 and len(items) == 1, 'WRITE_PARTIAL')
            # Never trust a response as the final state; Engine re-reads the graph.
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
            else:
                peer.close()


def projection(snapshot, before, readonly_id, rule_id, can_own):
    """Accept ONLY our exact rule/edge delta; preserve the entire unrelated graph."""
    value = copy.deepcopy(snapshot)
    matches = [r for r in value['catalog']['rules'] if r['name'] == NAME]
    need(len(matches) <= 1, 'RULE_COLLISION')
    owned = matches[0] if matches else None
    if owned is not None:
        need(can_own and type(owned['id']) is int and 100 <= owned['id'] < 2**31 and
             (rule_id is None or owned['id'] == rule_id) and owned['rule'] == PREDICATE
             and owned['roles'] in ([], [readonly_id]), 'RULE_COLLISION')
        value['catalog']['rules'].remove(owned)
        role = next((r for r in value['catalog']['roles'] if r['id'] == readonly_id), None)
        need(role is not None and role['name'] == 'readonly', 'ROLE_CHANGED')
        linked = owned['id'] in role['rules']
        need(linked == bool(owned['roles']), 'OWN_EDGE_DRIFT')
        if linked:
            role['rules'].remove(owned['id'])
    need(value == before, 'UNRELATED_GRAPH_CHANGED')
    return owned


class Engine:
    def __init__(self, host, compact, server, api, expected=OBSERVED):
        self.h, self.t, self.s, self.api, self.expected = host, compact, server, api, expected

    def secure(self, inhibited):
        h, t = self.h, self.t
        t.installed(h, t.decode_receipt(h.read(t.RECEIPT)))
        t.wiring(h, inhibited)
        for name in ('wazuh-indexer', 'wazuh-manager', 'filebeat'):
            need(h.run(['/usr/bin/systemctl', 'is-active', name]).strip() == b'active', 'SERVICE_HEALTH')
        if inhibited:
            t.stopped(h)
        else:
            need(h.info('ActiveState') == 'active' and int(h.info('MainPID')) > 0, 'DASHBOARD_HEALTH')

    def ui_read(self):
        raw = self.h.read(UI, root=False)
        meta = self.h.metadata(UI)
        # Atomic replacement cannot preserve unknown extended ACL/security metadata.
        self.h.ui_metadata()
        return raw, meta

    def preflight(self):
        need(not self.h.exists(JOURNAL), 'STATE_EXISTS')
        self.secure(False)
        snapshot = self.api.snapshot()
        readonly_id = initial_contract(self.s, snapshot, self.api.username, self.expected)
        before, meta = self.ui_read()
        return snapshot, readonly_id, before, ui_candidate(before), meta

    def save(self, state, phase):
        state = dict(state, phase=phase)
        self.h.put(JOURNAL, encoded(state), expected=self.h.read(JOURNAL)
                   if self.h.exists(JOURNAL) else None, metadata=(0o400, 0, 0))
        return state

    def prepare(self):
        snapshot, role, before, after, meta = self.preflight()
        # No permission/UI change here. Exact-only reuse handles a crash between backups.
        self.h.mkdir(STATE)
        for path, raw in ((BEFORE_UI, before), (AFTER_UI, after)):
            self.t.put_known(self.h, path, raw, (None, raw), metadata=(0o400, 0, 0))
        return self.save({'schema': 1, 'before': snapshot, 'readonly_id': role,
                          'rule_id': None, 'username': self.api.username,
                          'before_sha256': self.t.sha(before), 'after_sha256': self.t.sha(after),
                          'ui_metadata': meta, 'observed_sha256': self.expected}, 'prepared')

    def load(self):
        state = self.t.parse_json(self.h.read(JOURNAL))
        keys = {'schema', 'before', 'readonly_id', 'rule_id', 'username',
                'before_sha256', 'after_sha256', 'ui_metadata', 'observed_sha256', 'phase'}
        need(type(state) is dict and set(state) == keys and state['schema'] == 1
             and type(state['schema']) is int and state['phase'] in PHASES
             and state['username'] == self.api.username and
             state['observed_sha256'] == self.expected, 'JOURNAL')
        role = initial_contract(self.s, state['before'], self.api.username, self.expected)
        need(state['readonly_id'] == role and type(state['readonly_id']) is int and
             (state['rule_id'] is None or (type(state['rule_id']) is int and
              100 <= state['rule_id'] < 2**31)), 'JOURNAL')
        before, after = self.h.read(BEFORE_UI), self.h.read(AFTER_UI)
        need(self.t.sha(before) == state['before_sha256'] and
             self.t.sha(after) == state['after_sha256'] and after == ui_candidate(before), 'BACKUP')
        meta = state['ui_metadata']
        need(type(meta) is list and len(meta) == 3 and
             all(type(x) is int and x >= 0 for x in meta) and meta[0] <= 0o777 and
             not meta[0] & 0o022, 'JOURNAL_METADATA')
        return state, before, after

    def current(self, state):
        return projection(self.api.snapshot(), state['before'], state['readonly_id'],
                          state['rule_id'], state['phase'] != 'prepared')

    def ui_check(self, state, before, after):
        raw, meta = self.ui_read()
        need(raw in (before, after) and meta == state['ui_metadata'], 'UI_CHANGED')
        return raw

    def install(self):
        self.t.inhibit(self.h)  # Persistent before ANY Server or UI mutation.
        self.secure(True)
        state, before, after = self.load()
        need(state['phase'] not in ('rollback-intent', 'rolled-back', 'baseline-running'), 'ROLLBACK_STATE')
        self.ui_check(state, before, after)
        owned = self.current(state)
        if owned is None:
            need(state['rule_id'] is None and state['phase'] in ('prepared', 'create-intent'), 'OWN_RULE_MISSING')
            state = self.save(state, 'create-intent')
            self.api.mutate('create', state['readonly_id'], None)
            owned = self.current(state)  # Also the recovery path for a lost POST response.
            need(owned is not None and owned['roles'] == [], 'CREATE_READBACK')
        state = dict(state, rule_id=owned['id'])
        if owned['roles'] == []:
            state = self.save(state, 'created')
            state = self.save(state, 'link-intent')
            self.api.mutate('link', state['readonly_id'], state['rule_id'])
        owned = self.current(state)
        need(owned is not None and owned['roles'] == [state['readonly_id']], 'LINK_READBACK')
        state = self.save(state, 'linked')
        state = self.save(state, 'ui-intent')
        self.h.put(UI, after, expected=self.ui_check(state, before, after),
                   metadata=state['ui_metadata'], root=False)
        self.check_installed(state, before, after)
        self.save(state, 'installed')

    def check_installed(self, state, before, after):
        owned = self.current(state)
        need(owned is not None and owned['roles'] == [state['readonly_id']] and
             self.ui_check(state, before, after) == after, 'NOT_INSTALLED')

    def check(self):
        self.secure(False)
        state, before, after = self.load()
        need(state['phase'] in ('installed', 'running'), 'PHASE')
        self.check_installed(state, before, after)

    def resume(self, baseline=False):
        self.t.inhibit(self.h)
        self.secure(True)
        state, before, after = self.load()
        if baseline:
            need(state['phase'] in ('rolled-back', 'baseline-running'), 'PHASE')
            need(self.current(state) is None and
                 self.ui_check(state, before, after) == before, 'NOT_ROLLED_BACK')
        else:
            need(state['phase'] in ('installed', 'running'), 'PHASE')
            self.check_installed(state, before, after)
        try:
            self.h.remove(self.t.INHIBIT, self.t.DENY)
            self.h.control('daemon-reload')
            self.t.check(self.h)  # Original TLS guard + patch remain mandatory.
            self.h.control('start')
            self.secure(False)
            self.save(state, 'baseline-running' if baseline else 'running')
        except BaseException:
            self.t.inhibit(self.h)
            raise

    def rollback(self):
        self.t.inhibit(self.h)
        self.secure(True)
        state, before, after = self.load()
        self.ui_check(state, before, after)  # Refuse unknown UI before API writes.
        owned = self.current(state)
        # Journal ownership intent before changes; absent/half-installed states are supported.
        state = self.save(state, 'rollback-intent')
        if owned is not None:
            state = dict(state, rule_id=owned['id'])
            state = self.save(state, 'rollback-intent')
            if owned['roles']:
                self.api.mutate('unlink', state['readonly_id'], state['rule_id'])
                owned = self.current(state)
                need(owned is not None and owned['roles'] == [], 'UNLINK_READBACK')
            self.api.mutate('delete', state['readonly_id'], state['rule_id'])
        need(self.current(state) is None, 'DELETE_READBACK')
        self.h.put(UI, before, expected=self.ui_check(state, before, after),
                   metadata=state['ui_metadata'], root=False)
        need(self.ui_check(state, before, after) == before, 'UI_ROLLBACK')
        self.save(state, 'rolled-back')  # Keep inhibition/private state; no auto restart.

    def restore(self):
        # Deliberate reactivation after an accepted rollback, never an implicit retry.
        self.t.inhibit(self.h)
        self.secure(True)
        state, before, after = self.load()
        need(state['phase'] in ('rolled-back', 'baseline-running'), 'PHASE')
        need(self.current(state) is None and self.ui_check(state, before, after) == before,
             'NOT_ROLLED_BACK')
        self.save(dict(state, rule_id=None), 'prepared')
        self.install()  # Same fixed rule name/predicate, newly resolved returned ID.


def main(argv=None):
    client = password = None
    try:
        argv = sys.argv[1:] if argv is None else argv
        need(len(argv) == 1 and argv[0] in ('preflight', 'prepare', 'install', 'resume',
             'check', 'rollback', 'resume-baseline', 'restore'), 'ARGUMENTS')
        need(sys.platform == 'linux' and os.geteuid() == 0 and
             sys.stdin.isatty() and sys.stdout.isatty() and str(HERE) == STAGE, 'ROOT_STAGE_CONSOLE')
        for path in (Path('/root'), Path(STAGE).parent, Path(STAGE)):
            item = path.lstat()
            need(stat.S_ISDIR(item.st_mode) and item.st_uid == item.st_gid == 0
                 and stat.S_IMODE(item.st_mode) == 0o700, 'STAGE_DIRECTORY')
        server, compact = modules()

        class Host(compact.LinuxHost):
            def ui_metadata(self):
                import pwd
                import grp
                item = os.lstat(UI)
                need(item.st_uid in (0, pwd.getpwnam('wazuh-dashboard').pw_uid) and
                     item.st_gid in (0, grp.getgrnam('wazuh-dashboard').gr_gid) and
                     not os.listxattr(UI, follow_symlinks=False), 'UI_METADATA')

        host = Host()  # Disables core dumps, establishes private umask.
        import yaml
        connection_raw = host.read(compact.CONFIG, root=False)
        compact.configuration(connection_raw)
        connection = yaml.safe_load(connection_raw)
        host_id = next(iter(connection['hosts'][0]))
        need(type(host_id) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}', host_id), 'PUBLIC_HOST_ID')
        need(input('Type REVIEWED-RELEASED-HUMAN only for this separately approved action: ')
             == 'REVIEWED-RELEASED-HUMAN', 'RELEASE_GATE')
        client = server.Client(server.make_context())
        client.request('GET', '/')
        client.wrong_hostname_probe()
        print('PASS pinned localhost Server TLS and hostname rejection; no credentials sent yet')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Existing SERVER administrator username (not Indexer admin): ')
            password = getpass.getpass('Existing SERVER administrator password: ')
        client.deadline = time.monotonic() + 240
        client.authenticate(username, password)
        password = None
        engine = Engine(host, compact, server, API(server, client, username))
        if argv[0] == 'resume-baseline':
            engine.resume(baseline=True)
        else:
            getattr(engine, argv[0])()
        print('PASS scoped human readonly: ' + argv[0])
        print('PUBLIC Server host ID for reviewed acceptance: ' + host_id)
        print('STOP POINT: configuration check only; actual analyst acceptance and Phase 1 closure pending')
        return 0
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, HumanError) else 'IO_API_OR_TOOL'
        print('STOP scoped human readonly: ' + code + '; preserve private state; no automatic retry')
        return 1
    finally:
        password = None
        if client is not None:
            client.token = None  # Reference release, not secure erasure.


if __name__ == '__main__':
    raise SystemExit(main())
