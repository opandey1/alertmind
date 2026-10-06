"""Public source staging aid, run via the reviewed heredoc. No operator execution."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path('/root/alertmind-broker-tls-compact/human-readonly-stage')
NAMES = ('human_readonly_operator.py', 'collect_server_inventory.py',
         'compact_operator.py', 'human_readonly_acceptance.js', 'SHA256SUMS')
SCOPE = 'socanalyst-mapping-ui-recovery-safe-acceptance; not execution release'


def need(ok):
    if not ok:
        raise ValueError('STAGING_REFUSED')


def decode(raw, expected):
    need(len(raw) <= 262144 and hashlib.sha256(raw).hexdigest() == expected)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result
    packet = json.loads(raw, object_pairs_hook=unique)
    need(type(packet) is dict and set(packet) == {'schema', 'scope', 'review_status', 'files'}
         and type(packet['schema']) is int and packet['schema'] == 1 and
         packet['scope'] == SCOPE and packet['review_status'] == 'awaiting-focused-review'
         and type(packet['files']) is list and len(packet['files']) == len(NAMES))
    files = {}
    for entry in packet['files']:
        need(type(entry) is dict and set(entry) == {'name', 'sha256', 'base64'} and
             entry['name'] in NAMES and entry['name'] not in files)
        content = base64.b64decode(entry['base64'], validate=True)
        need(0 < len(content) <= 131072 and hashlib.sha256(content).hexdigest() == entry['sha256']
             and b'\r' not in content and content.endswith(b'\n'))
        if entry['name'].endswith('.py'):
            ast.parse(content, feature_version=(3, 10))  # Syntax only.
        files[entry['name']] = content
    sums = ''.join(hashlib.sha256(files[n]).hexdigest() + '  ' + n + '\n' for n in NAMES[:-1]).encode('ascii')
    need(files['SHA256SUMS'] == sums)
    return files


def line(tty, limit):
    value = tty.readline(limit + 2)
    need(value.endswith('\n') and len(value) <= limit + 1)
    return value[:-1]


def main():
    try:
        need(os.geteuid() == 0 and not ROOT.exists() and not ROOT.is_symlink())
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        for path in (Path('/root'), ROOT.parent):
            value = path.lstat()
            need(stat.S_ISDIR(value.st_mode) and
                 (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) == (0, 0, 0o700))
        # stdin carries source, so prompts MUST use the controlling terminal.
        with open('/dev/tty', encoding='ascii') as tty:
            need(tty.isatty())
            print('Type REVIEWED-RELEASED-HUMAN-STAGE only after focused approval and separate staging release:', flush=True)
            need(line(tty, 80) == 'REVIEWED-RELEASED-HUMAN-STAGE')
            print('Enter independently reviewed PUBLIC packet SHA-256:', flush=True)
            expected = line(tty, 80)
            need(re.fullmatch('[a-f0-9]{64}', expected) is not None)
            print('Paste wrapped PUBLIC Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:', flush=True)
            chunks, size = [], 0
            while True:
                value = line(tty, 256)
                if value == 'ALERTMIND_PUBLIC_SOURCE_END':
                    break
                need(value and re.fullmatch('[A-Za-z0-9+/=]+', value) is not None)
                size += len(value)
                need(size <= 350000)
                chunks.append(value)
        files = decode(base64.b64decode(''.join(chunks), validate=True), expected)
        ROOT.mkdir(mode=0o700)
        for name in NAMES:
            path = ROOT / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(files[name])
                stream.flush()
                os.fsync(stream.fileno())
            need(path.read_bytes() == files[name] and path.stat().st_uid == path.stat().st_gid == 0
                 and stat.S_IMODE(path.stat().st_mode) == 0o400)
        fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        print('PASS root-private human stage: five exact files; syntax only; no operator executed')
        print('PASS reviewed public packet SHA-256: ' + expected)
        print('STOP POINT: staging only; live preflight/install/restart/acceptance remain separately held')
        return 0
    except Exception:
        print('STOP: human public staging refused; preserve any stage; no operator executed')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
