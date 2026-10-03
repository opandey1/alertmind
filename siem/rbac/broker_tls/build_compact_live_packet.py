"""Workstation public original-VM packet builder; no helper execution or release."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIMIT = 128 * 1024
BASE_PINS = {
    'candidate.cjs': 'fe721feb8599293853e10d33823e68ff72df001be00382e3701d5da645aba28f',
    'compact_operator.py': '2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942',
    'bundle.json': '13cd780dfdffe16887a78f69aa4655f2be846485689015975b61981279615e83',
}
ENDPOINT_PIN = 'e790465fbe599c697cf0ede9d19c5fbd6a84c7f5b67576647275043b80f603eb'
BASE_COMMIT = '87d69a1d39ea728726bae599eee57682a78e10a2'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    with path.open('rb') as stream:
        raw = stream.read(LIMIT + 1)
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('SIZE')
    return raw


def build(bundle, output):
    if {p.name for p in bundle.iterdir()} != set(BASE_PINS) | {'SHA256SUMS'}:
        raise ValueError('BUNDLE_FILES')
    payloads = {name: read(bundle / name) for name in BASE_PINS}
    if any(sha(raw) != BASE_PINS[name] for name, raw in payloads.items()):
        raise ValueError('BUNDLE_PIN')
    sums = ''.join(sha(raw) + '  ' + name + '\n' for name, raw in payloads.items())
    if read(bundle / 'SHA256SUMS') != sums.encode('ascii'):
        raise ValueError('BUNDLE_SUMS')
    if read(HERE / 'compact_operator.py').replace(b'\r\n', b'\n') != payloads['compact_operator.py']:
        raise ValueError('OPERATOR_CHANGED')
    endpoint = read(HERE / 'compact_clone_endpoint.py').replace(b'\r\n', b'\n')
    if sha(endpoint) != ENDPOINT_PIN:
        raise ValueError('ENDPOINT_CHANGED')
    payloads['compact_clone_endpoint.py'] = endpoint
    payloads['compact_live_deployment.py'] = read(
        HERE / 'compact_live_deployment.py').replace(b'\r\n', b'\n')
    for name in ('compact_operator.py', 'compact_clone_endpoint.py', 'compact_live_deployment.py'):
        raw = payloads[name]
        if b'\r' in raw or not raw.endswith(b'\n'):
            raise ValueError('SOURCE_TEXT')
        compile(raw, name, 'exec')  # Syntax only; no operator/endpoint/vendor imports.
    payloads['SHA256SUMS'] = ''.join(
        sha(raw) + '  ' + name + '\n' for name, raw in payloads.items()).encode('ascii')
    packet = {'schema': 1, 'scope': 'original-vm-maintenance; not execution release',
              'base_commit': BASE_COMMIT, 'revision': 'live-facade-v1',
              'review_status': 'awaiting-focused-review', 'files': [
                  {'name': name, 'sha256': sha(raw), 'base64': base64.b64encode(raw).decode('ascii')}
                  for name, raw in payloads.items()]}
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(raw) > 256 * 1024:
        raise ValueError('PACKET_SIZE')
    with output.open('xb') as stream:
        stream.write(raw)
    return sha(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = build(args.bundle, args.output)
    except Exception:
        raise SystemExit('STOP: live packet unavailable; retain any partial output') from None
    print('PASS public original-VM packet SHA-256: ' + digest)
    print('STOP POINT: build only; no helper executed or VM action released')


if __name__ == '__main__':
    main()
