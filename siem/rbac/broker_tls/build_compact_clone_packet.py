"""Workstation-only public clone packet. Does not execute a helper or release a VM run."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIMIT = 128 * 1024
PINS = {
    'candidate.cjs': 'fe721feb8599293853e10d33823e68ff72df001be00382e3701d5da645aba28f',
    'compact_operator.py': '2200ccbe60fa347039ede8e7b627041056e21f2bdaed6755b7964e9529c48942',
    'bundle.json': '13cd780dfdffe16887a78f69aa4655f2be846485689015975b61981279615e83',
}
BASE_COMMIT = '7e53ecdda2c4df980d93588b8193c338910bb217'
OPERATOR_REVISION = 'source-certificate-reader-v2'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    with path.open('rb') as stream:
        raw = stream.read(LIMIT + 1)
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('SIZE')
    return raw


def build(bundle, output):
    if {p.name for p in bundle.iterdir()} != set(PINS) | {'SHA256SUMS'}:
        raise ValueError('BUNDLE_FILES')
    payloads = {name: read(bundle / name) for name in PINS}
    if any(sha(raw) != PINS[name] for name, raw in payloads.items()):
        raise ValueError('BUNDLE_PIN')
    sums = ''.join(sha(raw) + '  ' + name + '\n' for name, raw in payloads.items())
    if read(bundle / 'SHA256SUMS') != sums.encode('ascii'):
        raise ValueError('BUNDLE_SUMS')
    # Bind the corrected helper; its base approval is NOT approval of this revision.
    if read(HERE / 'compact_operator.py').replace(b'\r\n', b'\n') != payloads['compact_operator.py']:
        raise ValueError('OPERATOR_CHANGED')
    driver = read(HERE / 'compact_clone_rehearsal.py').replace(b'\r\n', b'\n')
    compile(driver, 'compact_clone_rehearsal.py', 'exec')  # syntax only
    payloads['compact_clone_rehearsal.py'] = driver
    sums += sha(driver) + '  compact_clone_rehearsal.py\n'
    payloads['SHA256SUMS'] = sums.encode('ascii')
    packet = {'schema': 2, 'scope': 'isolated-clone-only; not execution release',
              'operator_base_commit': BASE_COMMIT,
              'operator_revision': OPERATOR_REVISION,
              'review_status': 'awaiting-focused-review', 'files': [
                  {'name': name, 'sha256': sha(raw),
                   'base64': base64.b64encode(raw).decode('ascii')}
                  for name, raw in payloads.items()]}
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(raw) > 256 * 1024:
        raise ValueError('PACKET_SIZE')
    # Exclusive creation; partial outputs are retained, never reused/overwritten.
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
        raise SystemExit('STOP: clone packet unavailable; retain any partial output') from None
    print('PASS public clone packet SHA-256: ' + digest)
    print('STOP POINT: build only; no helper executed or VM run released')


if __name__ == '__main__':
    main()
