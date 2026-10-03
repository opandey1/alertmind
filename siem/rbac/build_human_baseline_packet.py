"""Public workstation packet only; never authenticates or releases execution."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ('collect_human_baseline.py', 'collect_server_inventory.py', 'scope-contract.json',
         'indexer-role_socanalyst_ro.json', 'indexer-role_assistant_alerts_ro.json',
         'indexer-role-mapping_socanalyst_ro.json', 'indexer-role-mapping_assistant_alerts_ro.json')
SERVER_SHA = '08ff077faa6f33a1e6bcd431c1f059ded3b753c63e975127451d5a4771e7aef5'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build(output):
    payloads = {}
    for name in FILES:
        with (HERE / name).open('rb') as stream:
            raw = stream.read(131073)
        if not 0 < len(raw) <= 131072:
            raise ValueError('PUBLIC_FILE_SIZE')
        raw = raw.replace(b'\r\n', b'\n')
        if not 0 < len(raw) <= 131072 or b'\r' in raw or not raw.endswith(b'\n'):
            raise ValueError('PUBLIC_FILE_TEXT')
        if name.endswith('.py'):
            compile(raw, name, 'exec')  # Syntax only: never import/execute helper.
        else:
            json.loads(raw)
        payloads[name] = raw
    if sha(payloads['collect_server_inventory.py']) != SERVER_SHA:
        raise ValueError('SERVER_READER_CHANGED')
    payloads['SHA256SUMS'] = ''.join(sha(raw) + '  ' + name + '\n'
                                  for name, raw in payloads.items()).encode('ascii')
    packet = {'schema': 1, 'scope': 'human-read-only-baseline; NOT Dashboard context or mutation release',
              'review_status': 'awaiting-focused-review', 'files': [
                  {'name': name, 'sha256': sha(raw), 'base64': base64.b64encode(raw).decode('ascii')}
                  for name, raw in payloads.items()]}
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(raw) > 262144:
        raise ValueError('PACKET_SIZE')
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
        raise SystemExit('STOP: baseline packet unavailable; preserve any partial output') from None
    print('PASS public human-baseline packet SHA-256: ' + digest)
    print('STOP POINT: build only; no helper executed or VM action released')


if __name__ == '__main__':
    main()
