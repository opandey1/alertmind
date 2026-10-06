"""Build a public review packet; never import/execute the operator or access a VM."""
import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = {
    'human_readonly_operator.py': HERE / 'human_readonly_operator.py',
    'collect_server_inventory.py': HERE / 'collect_server_inventory.py',
    'compact_operator.py': HERE / 'broker_tls/compact_operator.py',
    'human_readonly_acceptance.js': HERE / 'human_readonly_acceptance.js',
}
PINS = {
    'collect_server_inventory.py': '96e64194cbed95a5cd8526e9f76c7f38432c8061c29f9fe1c8d7239a340a030e',
    'compact_operator.py': '2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942',
}
SCOPE = 'socanalyst-mapping-ui-recovery-safe-acceptance; not execution release'


def build(output):
    payloads = {}
    for name, path in FILES.items():
        raw = path.read_bytes().replace(b'\r\n', b'\n')
        if not 0 < len(raw) <= 131072 or b'\r' in raw or not raw.endswith(b'\n'):
            raise ValueError('TEXT_SIZE')
        digest = hashlib.sha256(raw).hexdigest()
        if name in PINS and digest != PINS[name]:
            raise ValueError('REUSED_SOURCE_CHANGED')
        if name.endswith('.py'):
            ast.parse(raw, filename=name, feature_version=(3, 10))
            compile(raw, name, 'exec')  # Syntax, not execution.
        payloads[name] = raw
    payloads['SHA256SUMS'] = ''.join(hashlib.sha256(raw).hexdigest() + '  ' + name + '\n'
                                    for name, raw in payloads.items()).encode('ascii')
    packet = {'schema': 1, 'scope': SCOPE, 'review_status': 'awaiting-focused-review',
              'files': [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(),
                         'base64': base64.b64encode(raw).decode('ascii')}
                        for name, raw in payloads.items()]}
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(raw) > 262144:
        raise ValueError('PACKET_SIZE')
    with output.open('xb') as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = build(args.output)
    except Exception:
        raise SystemExit('STOP: public human packet unavailable; retain partial output') from None
    print('PASS public human readonly packet SHA-256: ' + digest)
    print('STOP POINT: build only; no staging, authentication, permission/UI or service action released')


if __name__ == '__main__':
    main()
