"""Clone-only single-URL maintenance. Fixed targets; no execution release.

Private backups contain credentials: never print/upload their contents or hashes.
Trusts normal lab root/systemd/vendor runtime, not hostile-root attestation.
Never starts Dashboard. Existing production operator and active preflight unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

STAGE = '/root/alertmind-broker-tls-compact/stage'
DRIVER_SHA = 'b3f39e03dc32bd7d1de8f5a98b4f5a12dc201bc987ebcd6565c912be0da51340'
OPERATOR_SHA = '2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942'
STATE = '/root/alertmind-broker-tls-compact/endpoint-state'
BACKUP = STATE + '/original-wazuh-yml.bin'
RECEIPT = STATE + '/receipt.json'
OLD_URL = 'https://127.0.0.1'
NEW_URL = 'https://localhost'
LIMIT = 128 * 1024


class EndpointError(Exception):
    """Static codes only, including on parse/tool errors."""


def require(ok, code):
    if not ok:
        raise EndpointError(code)


def driver():
    require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX')
    path = Path(STAGE) / 'compact_clone_rehearsal.py'
    for parent in path.parents:
        value = parent.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and
                not value.st_mode & 0o022, 'STAGE_METADATA')
        if str(parent).startswith('/root/alertmind-broker-tls-compact'):
            require(value.st_gid == 0 and stat.S_IMODE(value.st_mode) == 0o700,
                    'STAGE_METADATA')
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and
            (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) == (0, 0, 0o400)
            and 0 < value.st_size <= LIMIT, 'STAGE_METADATA')
    with path.open('rb') as stream:
        raw = stream.read(LIMIT + 1)
    require(hashlib.sha256(raw).hexdigest() == DRIVER_SHA, 'DRIVER_PIN')
    result = types.ModuleType('alertmind_clone_endpoint_driver')
    result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    require(result.OPERATOR_SHA == OPERATOR_SHA, 'OPERATOR_PIN')
    return result


def dashboard_identity():
    import pwd
    import grp
    user, group = pwd.getpwnam('wazuh-dashboard'), grp.getgrnam('wazuh-dashboard')
    require(user.pw_uid > 0 and group.gr_gid > 0 and user.pw_gid == group.gr_gid,
            'CONFIG_METADATA')
    return user.pw_uid, group.gr_gid


def endpoint_host(m):
    class Host(m.LinuxHost):
        def config_no_extended_metadata(self):
            # Atomic replacement preserves mode/UID/GID, not unknown ACL/xattrs.
            require(not os.listxattr(m.CONFIG, follow_symlinks=False),
                    'CONFIG_EXTENDED_METADATA')

        def put(self, path, raw, **kwargs):
            if path == m.CONFIG:
                self.config_no_extended_metadata()
            return super().put(path, raw, **kwargs)
    return Host()


def corrected(m, raw):
    """Replace one exact scalar span, preserving every other byte, including secrets."""
    import yaml
    try:
        text = raw.decode('utf-8')
        node = yaml.compose(text, Loader=yaml.SafeLoader)

        def field(mapping, name):
            require(isinstance(mapping, yaml.MappingNode), 'CONFIG_SHAPE')
            matches = [value for key, value in mapping.value
                       if isinstance(key, yaml.ScalarNode) and key.value == name]
            require(len(matches) == 1, 'CONFIG_SHAPE')
            return matches[0]

        hosts = field(node, 'hosts')
        require(isinstance(hosts, yaml.SequenceNode) and len(hosts.value) == 1,
                'CONFIG_SHAPE')
        entry = hosts.value[0]
        require(isinstance(entry, yaml.MappingNode) and len(entry.value) == 1,
                'CONFIG_SHAPE')
        url = field(entry.value[0][1], 'url')
        require(isinstance(url, yaml.ScalarNode) and url.value == OLD_URL and
                url.style in (None, "'", '"'), 'CONFIG_URL')
        quote = url.style or ''
        start, end = url.start_mark.index, url.end_mark.index
        require(text[start:end] == quote + OLD_URL + quote, 'CONFIG_URL_TOKEN')
        result = (text[:start] + quote + NEW_URL + quote + text[end:]).encode('utf-8')
        require(0 < len(result) <= LIMIT, 'CONFIG_SIZE')
        # Shared strict parser rejects duplicates/aliases and all other mismatches.
        m.configuration(result)
        return result
    except (EndpointError, m.CompactError):
        raise
    except Exception:
        raise EndpointError('CONFIG_PARSE') from None


def baseline(m, d, host):
    d.stage(m, host)
    host.packages()
    d.health(host)
    require(all(not host.exists(p) for p in
                (m.RECEIPT, m.BACKUP, m.CERT, m.HELPER, m.GUARD)), 'TLS_ALREADY_PREPARED')
    require(host.info('KillMode') == 'control-group' and
            host.info('FragmentPath') in m.FRAGMENTS, 'UNIT_BASELINE')
    fragment = host.info('FragmentPath')
    fragment_raw = host.read(fragment)
    require(m.sha(host.read(m.CLIENT, root=False)) == m.ORIGINAL_SHA, 'ORIGINAL_CLIENT')
    host.read_source_certificate()
    host.run(['/usr/bin/openssl', 'x509', '-in', m.SOURCE_CERT, '-noout', '-checkend', '0'])
    uid, gid = dashboard_identity()
    metadata = [0o600, uid, gid]
    require(host.metadata(m.CONFIG) == metadata, 'CONFIG_METADATA')
    host.config_no_extended_metadata()
    return metadata, fragment, m.sha(fragment_raw)


def boundary(m, d, host):
    if host.exists(m.INHIBIT):
        m.stopped(host)
        m.wiring(host, True)
    else:
        d.active(host)
        m.wiring(host, False)


def save(m, host, value, phase):
    value = dict(value, phase=phase)
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    host.put(RECEIPT, raw, expected=m.present(host, RECEIPT), metadata=(0o400, 0, 0))


def apply(m, d, host):
    require(not host.exists(STATE), 'ENDPOINT_STATE_EXISTS')
    metadata, fragment, fragment_sha = baseline(m, d, host)
    boundary(m, d, host)
    original = host.read(m.CONFIG, root=False)
    replacement = corrected(m, original)
    # All compatibility checks before mutation; inhibit/stop before any config write.
    m.inhibit(host)
    require(host.read(m.CONFIG, root=False) == original and
            host.metadata(m.CONFIG) == metadata, 'CONFIG_CHANGED')
    require(host.info('FragmentPath') == fragment and
            m.sha(host.read(fragment)) == fragment_sha, 'UNIT_CHANGED')
    host.mkdir(STATE)
    host.put(BACKUP, original, expected=None, metadata=(0o400, 0, 0))
    value = {'schema': 1, 'phase': 'backed-up', 'original_sha256': m.sha(original),
             'corrected_sha256': m.sha(replacement), 'metadata': metadata,
             'fragment': fragment, 'fragment_sha256': fragment_sha}
    save(m, host, value, 'backed-up')
    host.put(m.CONFIG, replacement, expected=original, metadata=metadata, root=False)
    require(host.read(m.CONFIG, root=False) == replacement and
            host.metadata(m.CONFIG) == metadata, 'CONFIG_READBACK')
    save(m, host, value, 'applied')
    m.stopped(host)
    m.wiring(host, True)
    d.health(host)


def recovery_inputs(m, d, host):
    metadata, fragment, fragment_sha = baseline(m, d, host)
    value = m.parse_json(host.read(RECEIPT))
    require(type(value) is dict and set(value) == {
        'schema', 'phase', 'original_sha256', 'corrected_sha256', 'metadata',
        'fragment', 'fragment_sha256'} and type(value['schema']) is int and
        value['schema'] == 1 and value['phase'] in ('backed-up', 'applied', 'restored')
        and value['metadata'] == metadata and value['fragment'] == fragment and
        value['fragment_sha256'] == fragment_sha, 'ENDPOINT_RECEIPT')
    original = host.read(BACKUP)
    replacement = corrected(m, original)
    require(m.sha(original) == value['original_sha256'] and
            m.sha(replacement) == value['corrected_sha256'], 'ENDPOINT_BACKUP')
    current = host.read(m.CONFIG, root=False)
    require(current in (original, replacement), 'CONFIG_CHANGED')
    return value, original, replacement, current


def recover_apply(m, d, host):
    value, original, replacement, current = recovery_inputs(m, d, host)
    require(value['phase'] in ('backed-up', 'applied'), 'ENDPOINT_RECEIPT')
    m.inhibit(host)
    host.put(m.CONFIG, replacement, expected=current, metadata=value['metadata'], root=False)
    save(m, host, value, 'applied')
    m.stopped(host)
    m.wiring(host, True)
    d.health(host)


def restore(m, d, host):
    value, original, replacement, current = recovery_inputs(m, d, host)
    m.inhibit(host)
    host.put(m.CONFIG, original, expected=current, metadata=value['metadata'], root=False)
    save(m, host, value, 'restored')
    m.stopped(host)
    m.wiring(host, True)
    d.health(host)


def preflight(m, d, host):
    value, original, replacement, current = recovery_inputs(m, d, host)
    require(value['phase'] == 'applied' and current == replacement, 'ENDPOINT_NOT_APPLIED')
    # Never pretend a stopped service is active or relax the original preflight.
    require(host.exists(m.INHIBIT), 'INHIBITION')
    m.stopped(host)
    m.wiring(host, True)
    m.configuration(current)


ACTIONS = {'apply': apply, 'recover-apply': recover_apply,
           'restore': restore, 'preflight-inhibited': preflight}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    m, d = None, None
    try:
        require(len(argv) == 1 and argv[0] in ACTIONS, 'ARGUMENTS')
        d = driver()
        m = d.operator()
        ACTIONS[argv[0]](m, d, endpoint_host(m))
    except Exception as error:
        safe = (EndpointError,) + ((m.CompactError,) if m is not None else ()) + (
            (d.RehearsalError,) if d is not None else ())
        code = str(error) if isinstance(error, safe) else 'CHECK_OR_TOOL'
        print('STOP clone endpoint: ' + code + '; preserve private state; do not restart',
              file=sys.stderr)
        return 1
    print('PASS clone endpoint: ' + argv[0] + '; Dashboard remains stopped/inhibited')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
