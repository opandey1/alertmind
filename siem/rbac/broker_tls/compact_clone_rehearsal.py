"""Clone-only Batch B driver; NOT an execution release or production helper.

Trusts the same conventional lab administration boundary as Batch A. Fixed
paths only. No API requests, credentials, mappings, SSH or saved-object edits.
The intentional process exit and missing-trust fault are NEVER for the original VM.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types

STAGE = '/root/alertmind-broker-tls-compact/stage'
OPERATOR_SHA = 'e9a35d66d1e8e501fbee406215d4d54da3553acededffab91064b0e0b896b05c'
INTERRUPTED_EXIT = 73
LIMIT = 128 * 1024
FILES = {'candidate.cjs', 'compact_operator.py', 'bundle.json',
         'compact_clone_rehearsal.py', 'SHA256SUMS'}


class RehearsalError(Exception):
    """Static codes only; never print configuration, tool output or receipt."""


def require(ok, code):
    if not ok:
        raise RehearsalError(code)


def operator():
    require(sys.platform == 'linux' and os.geteuid() == 0, 'ROOT_LINUX')
    path = Path(STAGE) / 'compact_operator.py'
    for parent in path.parents:
        item = parent.lstat()
        require(stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and
                not item.st_mode & 0o022, 'STAGE_METADATA')
        if str(parent).startswith('/root/alertmind-broker-tls-compact'):
            require(item.st_gid == 0 and stat.S_IMODE(item.st_mode) == 0o700,
                    'STAGE_METADATA')
    item = path.lstat()
    require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and
            (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (0, 0, 0o400)
            and 0 < item.st_size <= LIMIT, 'STAGE_METADATA')
    with path.open('rb') as stream:
        raw = stream.read(LIMIT + 1)
    require(hashlib.sha256(raw).hexdigest() == OPERATOR_SHA, 'OPERATOR_PIN')
    # This is a trusted-admin diagnostic, not the deferred held-code guard.
    module = types.ModuleType('alertmind_compact_clone_operator')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def stage(m, host):
    require({p.name for p in Path(STAGE).iterdir()} == FILES, 'STAGE_FILES')
    m.stage(host)
    sums = host.read(STAGE + '/SHA256SUMS').decode('ascii').splitlines()
    require(len(sums) == 4, 'STAGE_SUMS')
    seen = set()
    for line in sums:
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-z_]+\.(?:py|cjs|json))', line)
        require(match is not None and match[2] in FILES - {'SHA256SUMS'} and
                match[2] not in seen, 'STAGE_SUMS')
        seen.add(match[2])
        require(m.sha(host.read(STAGE + '/' + match[2])) == match[1], 'STAGE_SUMS')


def health(host):
    for unit in ('wazuh-indexer', 'wazuh-manager', 'filebeat'):
        require(host.run(['/usr/bin/systemctl', 'is-active', unit]).strip() == b'active',
                'SERVICE_HEALTH')


def active(host):
    require(host.info('ActiveState') == 'active' and host.info('MainPID').isdigit()
            and int(host.info('MainPID')) > 0, 'NOT_ACTIVE')


def preflight(m, host):
    stage(m, host)
    host.packages()
    health(host)
    active(host)
    require(all(not host.exists(p) for p in
                (m.RECEIPT, m.BACKUP, m.CERT, m.HELPER, m.GUARD, m.INHIBIT)),
            'EXISTING_DEPLOYMENT')
    require(host.info('DropInPaths') == '' and host.info('KillMode') == 'control-group'
            and host.info('FragmentPath') in m.FRAGMENTS, 'UNIT_BASELINE')
    host.read(host.info('FragmentPath'))
    require(m.sha(host.read(m.CLIENT, root=False)) == m.ORIGINAL_SHA, 'ORIGINAL_CLIENT')
    m.certificate(host.read(m.SOURCE_CERT))
    host.run(['/usr/bin/openssl', 'x509', '-in', m.SOURCE_CERT,
              '-noout', '-checkend', '0'])
    m.configuration(host.read(m.CONFIG, root=False))
    # Do not print the endpoint, broker credential or credential-bearing digest.


def receipt(m, host, phase):
    value = m.decode_receipt(host.read(m.RECEIPT))
    require(value['phase'] == phase and value['helper_sha256'] == OPERATOR_SHA,
            'CHECKPOINT')
    m.baseline(host, value)
    return value


def interrupt_install(m, host):
    value = receipt(m, host, 'prepared')
    m.stopped(host)
    m.wiring(host, True)
    require(all(not host.exists(p) for p in (m.CERT, m.HELPER, m.GUARD)) and
            m.sha(host.read(m.CLIENT, root=False)) == m.ORIGINAL_SHA and
            host.metadata(m.CLIENT) == value['client_metadata'], 'CHECKPOINT')

    class InterruptHost(m.LinuxHost):
        def put(self, path, raw, **kwargs):
            super().put(path, raw, **kwargs)
            if path == m.CERT:
                # Native atomic write/fsync/readback completed. Abort the installer
                # BEFORE helper/guard/client writes, bypassing exception cleanup.
                print('EXPECTED interruption: public trust durable; exit 73', flush=True)
                os._exit(INTERRUPTED_EXIT)

    m.install(InterruptHost())
    raise RehearsalError('INTERRUPTION_NOT_REACHED')


def failed_prestart(value, path, argv, previous=''):
    # systemctl show's conventional ExecStartPre serialization. Unknown shape
    # refuses the proof; a generic start failure is not guard evidence.
    previous_entries = re.findall(r'\{([^{}]*)\}', previous)
    for body in re.findall(r'\{([^{}]*)\}', value):
        fields = {}
        for part in body.split(';'):
            key, separator, item = part.strip().partition('=')
            if separator:
                fields[key] = item.strip()
        if (body not in previous_entries and fields.get('path') == path and fields.get('argv[]') == argv and
                fields.get('ignore_errors') == 'no' and fields.get('code') == 'exited'
                and fields.get('status', '').split('/')[0] == '1'):
            return True
    return False


def denied_start(m, host, *, guard):
    previous = host.info('ExecStartPre')
    result = subprocess.run(['/usr/bin/systemctl', 'start', m.UNIT],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, cwd='/',
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    # The pinned vendor unit uses Restart=always. Stop automatic retries after
    # the attempted job, including an unexpected successful start, before proof.
    host.control('stop')
    m.stopped(host)
    require(result.returncode != 0 and len(result.stdout) <= LIMIT and
            len(result.stderr) <= LIMIT, 'START_NOT_DENIED')
    path = m.PYTHON if guard else '/bin/false'
    argv = m.PYTHON + ' -I -B ' + m.HELPER + ' check' if guard else '/bin/false'
    require(failed_prestart(host.info('ExecStartPre'), path, argv, previous), 'PRESTART_PROOF')


def prove_interruption(m, host):
    value = receipt(m, host, 'prepared')
    m.stopped(host)
    m.wiring(host, True)
    require(host.exists(m.CERT) and not host.exists(m.HELPER) and
            not host.exists(m.GUARD), 'CHECKPOINT')
    m.certificate(host.read(m.CERT))
    require(m.sha(host.read(m.CLIENT, root=False)) == m.ORIGINAL_SHA and
            host.metadata(m.CLIENT) == value['client_metadata'] and
            m.sha(host.read(m.BACKUP)) == m.ORIGINAL_SHA, 'CHECKPOINT')
    denied_start(m, host, guard=False)
    health(host)


def refuse_missing_trust(m, host):
    value = receipt(m, host, 'running')
    m.check(host)
    active(host)
    m.inhibit(host)
    m.installed(host, value)
    try:
        # Remove only the verified NEW public trust copy. Original certificate,
        # configuration and private backup are untouched. Recovery uses install.
        host.remove(m.CERT, host.read(m.CERT))
        host.remove(m.INHIBIT, m.DENY)
        host.control('daemon-reload')
        m.wiring(host, False)
        require(not host.exists(m.CERT), 'FAULT_NOT_PRESENT')
        denied_start(m, host, guard=True)
    finally:
        # Ordinary failures leave inhibition restored; on abrupt interruption,
        # the intact mandatory guard still rejects absent trust before startup.
        m.inhibit(host)
    require(not host.exists(m.CERT), 'FAULT_NOT_PRESENT')
    m.stopped(host)
    m.wiring(host, True)
    health(host)


def prove_rollback(m, host):
    value = receipt(m, host, 'rolled-back')
    m.stopped(host)
    m.wiring(host, True)
    require(all(not host.exists(p) for p in (m.CERT, m.HELPER, m.GUARD)) and
            m.sha(host.read(m.CLIENT, root=False)) == m.ORIGINAL_SHA and
            host.metadata(m.CLIENT) == value['client_metadata'] and
            m.sha(host.read(m.BACKUP)) == m.ORIGINAL_SHA, 'CHECKPOINT')
    denied_start(m, host, guard=False)
    health(host)


def final(m, host):
    receipt(m, host, 'running')
    m.check(host)
    active(host)
    health(host)


ACTIONS = {'preflight': preflight, 'interrupt-install': interrupt_install,
           'prove-interruption': prove_interruption, 'refuse-missing-trust': refuse_missing_trust,
           'prove-rollback': prove_rollback, 'final': final}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    m = None
    try:
        require(len(argv) == 1 and argv[0] in ACTIONS, 'ARGUMENTS')
        m = operator()
        ACTIONS[argv[0]](m, m.LinuxHost())
    except (RehearsalError,) as error:
        print('STOP clone rehearsal: ' + str(error), file=sys.stderr)
        return 1
    except Exception as error:
        # The pinned operator's CompactError contains static codes only. Preserve
        # useful endpoint/package refusal codes without exposing YAML/tool errors.
        code = str(error) if m is not None and isinstance(error, m.CompactError) else 'CHECK_OR_TOOL'
        print('STOP clone rehearsal: ' + code + '; retain stopped state and diagnose', file=sys.stderr)
        return 1
    print('PASS clone rehearsal: ' + argv[0])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
