"""Host-only public staging bundle builder; never installs or runs the operator."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIMIT = 128 * 1024


def read(path):
    with path.open('rb') as stream:
        raw = stream.read(LIMIT + 1)
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('SIZE')
    return raw


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('JSON_DUPLICATE')
        result[key] = value
    return result


def build(candidate_directory, output):
    # Reuse the original builder's authenticated contract, without vendor execution.
    contract = json.loads(read(HERE / 'contract.json'), object_pairs_hook=unique)
    manifest = json.loads(read(candidate_directory / 'manifest.json'), object_pairs_hook=unique)
    if any(manifest.get(k) != v for k, v in contract.items()):
        raise ValueError('CANDIDATE_CONTRACT')
    candidate = read(candidate_directory / 'candidate.cjs')
    if hashlib.sha256(candidate).hexdigest() != contract['candidate_sha256']:
        raise ValueError('CANDIDATE')
    helper = read(HERE / 'compact_operator.py').replace(b'\r\n', b'\n')
    compile(helper, 'compact_operator.py', 'exec')  # syntax only, no execution
    bundle = {'schema': 1, 'candidate_sha256': contract['candidate_sha256'],
              'operator_sha256': hashlib.sha256(helper).hexdigest()}
    if output.exists() or output.is_symlink():
        raise ValueError('OUTPUT_EXISTS')
    output.mkdir()  # new directory only; preserve partial output after failure
    payloads = {'candidate.cjs': candidate, 'compact_operator.py': helper,
                'bundle.json': (json.dumps(bundle, sort_keys=True) + '\n').encode()}
    sums = []
    for name, raw in payloads.items():
        with (output / name).open('xb') as stream:
            stream.write(raw)
        sums.append(hashlib.sha256(raw).hexdigest() + '  ' + name)
    with (output / 'SHA256SUMS').open('x', encoding='ascii', newline='\n') as stream:
        stream.write('\n'.join(sums) + '\n')
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.candidate, args.output)
    except Exception:
        raise SystemExit('STOP: compact bundle unavailable; do not reuse partial output') from None
    print('PASS public compact bundle; no operator executed or live change authorized')


if __name__ == '__main__':
    main()
