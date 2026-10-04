"""Build reviewed public sources only; no helper, login or VM execution."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ('observe_dashboard_context.py', 'collect_server_inventory.py', 'dashboard_context_observation.js')
SERVER_SHA = '5cccc906dbf4f5470f10814f37ccc4ca849e76c36d0b45c441da95357b911e77'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build(output):
    payloads = {}
    for name in FILES:
        with (HERE / name).open('rb') as stream:
            raw = stream.read(131073)
        if not 0 < len(raw) <= 131072:
            raise ValueError('SIZE')
        raw = raw.replace(b'\r\n', b'\n')
        if b'\r' in raw or not raw.endswith(b'\n'):
            raise ValueError('TEXT')
        if name.endswith('.py'):
            compile(raw, name, 'exec')  # Syntax only, never execute collectors.
        payloads[name] = raw
    if sha(payloads['collect_server_inventory.py']) != SERVER_SHA:
        raise ValueError('SERVER_READER')
    payloads['SHA256SUMS'] = ''.join(sha(payloads[n]) + '  ' + n + '\n' for n in FILES).encode('ascii')
    packet = {'schema': 1, 'scope': 'dashboard-context-observation; NOT permission/UI mutation',
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
        raise SystemExit('STOP: public context packet unavailable; preserve partial output') from None
    print('PASS public Dashboard-context packet SHA-256: ' + digest)
    print('STOP POINT: build only; no helper, browser, authentication or VM action released')


if __name__ == '__main__':
    main()
