"""Host-only public endpoint helper packet. No credentials, VM contact or execution."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER_SHA = 'b3f39e03dc32bd7d1de8f5a98b4f5a12dc201bc987ebcd6565c912be0da51340'
OPERATOR_SHA = '2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build(output):
    for name, digest in (('compact_clone_rehearsal.py', DRIVER_SHA),
                         ('compact_operator.py', OPERATOR_SHA)):
        raw = (HERE / name).read_bytes().replace(b'\r\n', b'\n')
        if sha(raw) != digest:
            raise ValueError('BASE_CHANGED')
    helper = (HERE / 'compact_clone_endpoint.py').read_bytes().replace(b'\r\n', b'\n')
    if not 0 < len(helper) <= 128 * 1024:
        raise ValueError('SIZE')
    compile(helper, 'compact_clone_endpoint.py', 'exec')  # syntax only
    payloads = {'compact_clone_endpoint.py': helper,
                'ENDPOINT-SHA256SUMS': (sha(helper) + '  compact_clone_endpoint.py\n').encode('ascii')}
    packet = {'schema': 1, 'scope': 'isolated-clone-only; not execution release',
              'base_commit': '9dda08bf851e933077853be1aef21e0b95ac6135',
              'revision': 'clone-only-url-v1', 'review_status': 'awaiting-focused-review',
              'driver_sha256': DRIVER_SHA, 'operator_sha256': OPERATOR_SHA,
              'files': [{'name': name, 'sha256': sha(raw),
                         'base64': base64.b64encode(raw).decode('ascii')}
                        for name, raw in payloads.items()]}
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    with output.open('xb') as stream:
        stream.write(raw)
    return sha(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = build(args.output)
    except Exception:
        raise SystemExit('STOP: endpoint packet unavailable; preserve any partial output') from None
    print('PASS public endpoint packet SHA-256: ' + digest)
    print('STOP POINT: build only; no configuration/service change or execution release')


if __name__ == '__main__':
    main()
