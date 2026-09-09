"""Offline-only builder: reads one exact .deb, creates a NEW output directory.

Never installs, imports vendor code, connects to a service or touches /etc.
Generated files are candidates, not deployment approval. Python 3.10+.
"""
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import shutil

DEB_SHA256 = '83f472d9e5f59b28b1abb6260c466e77b99ae427ce8c5f76203d847f2f598b6f'
DEB_SIZE = 193952104
CLIENT_SHA256 = 'd691047acfa9b9a779a94251c6b813e0296eaf53b3b202e89cb56b44eee48afb'
BASE = 'usr/share/wazuh-dashboard/'
CLIENT = BASE + 'plugins/wazuhCore/server/services/server-api-client.js'
HERE = Path(__file__).resolve().parent
AGENT = '''    const httpsAgent = new _https.default.Agent({
      rejectUnauthorized: false
    });
    this._axios = _axios.default.create({
      httpsAgent
    });'''
REPLACEMENT = '''    const policy = alertmindBrokerPolicy();
    this._axios = _axios.default.create({ httpsAgent: policy.agent });
    this._axios.interceptors.request.use(policy.guard);
    this._axios.interceptors.response.use(response => response, error => {
      const safe = new Error('ALERTMIND_BROKER_REQUEST_FAILED');
      // Preserve controller HTTP semantics, not axios config/request/cause.
      if (error && error.response && Number.isInteger(error.response.status)) {
        safe.response = { status: error.response.status, data: error.response.data };
      }
      if (error && ['ECONNREFUSED', 'EPROTO', 'ECONNABORTED', 'ETIMEDOUT', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(error.code)) safe.code = error.code;
      throw safe;
    });'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transform(source, policy):
    if digest(source) != CLIENT_SHA256:
        raise ValueError('SOURCE_HASH')
    text = source.decode('utf-8')
    lines = text.splitlines(keepends=True)
    if len(lines) != 194 or not lines[-1].startswith('//# sourceMappingURL=data:application/json;charset=utf-8;base64,'):
        raise ValueError('SOURCE_MAP')
    text = ''.join(lines[:-1])  # Remove embedded unpatched sourcesContent too.
    if text.count(AGENT) != 1 or text.count('class ServerAPIClient') != 1:
        raise ValueError('SOURCE_SHAPE')
    text = text.replace(AGENT, REPLACEMENT)
    text = text.replace('class ServerAPIClient', policy.decode('utf-8') + '\nclass ServerAPIClient')
    return text.encode('utf-8')


def archive_bytes(path):
    if path.stat().st_size != DEB_SIZE:
        raise ValueError('PACKAGE_SIZE')
    raw = path.read_bytes()
    if digest(raw) != DEB_SHA256 or raw[:8] != b'!<arch>\n':
        raise ValueError('PACKAGE_HASH')
    pos = 8
    while pos < len(raw):
        header = raw[pos:pos + 60]
        size = int(header[48:58])
        name = header[:16].decode('ascii').strip().rstrip('/')
        pos += 60
        if name == 'data.tar.xz':
            return raw[pos:pos + size]
        pos += size + size % 2
    raise ValueError('PACKAGE_DATA')


def build(deb, output):
    if output.exists() or output.is_symlink():
        raise ValueError('OUTPUT_EXISTS')
    policy = (HERE / 'policy.cjs').read_bytes().replace(b'\r\n', b'\n')
    # Inflate once into an automatically deleted scratch file; random xz seeks
    # would otherwise re-inflate the large package for every dependency file.
    with tempfile.TemporaryFile() as unpacked:
        with lzma.LZMAFile(io.BytesIO(archive_bytes(deb))) as compressed:
            shutil.copyfileobj(compressed, unpacked)
        unpacked.seek(0)
        return build_from_tar(unpacked, output, policy)


def build_from_tar(unpacked, output, policy):
    with tarfile.open(fileobj=unpacked, mode='r:') as tar:
        members = {}
        for m in tar:
            n = m.name.removeprefix('./')
            if n in members:
                raise ValueError('DUPLICATE_MEMBER')
            members[n] = m

        def read(name, limit=2 * 1024 * 1024):
            m = members[name]
            if not m.isfile() or m.size > limit:
                raise ValueError('MEMBER_TYPE_SIZE')
            return tar.extractfile(m).read(limit + 1)

        original = read(CLIENT)
        candidate = transform(original, policy)
        # Resolve the actual root axios dependency graph, including nested overrides.
        roots = set()
        versions = {}

        def resolve(name, parent):
            p = PurePosixPath(parent)
            for directory in (p, *p.parents):
                if directory.name == 'node_modules':
                    continue
                root = str(directory / 'node_modules' / name)
                if root + '/package.json' in members:
                    return root
            raise ValueError('DEPENDENCY_MISSING')

        def visit(root):
            if root in roots:
                return
            roots.add(root)
            meta = json.loads(read(root + '/package.json'))
            versions[root.removeprefix(BASE)] = meta['version']
            for dep in meta.get('dependencies', {}):
                visit(resolve(dep, root))

        visit(BASE + 'node_modules/axios')
        payloads = {'original.cjs': original, 'candidate.cjs': candidate}
        for name, m in members.items():
            if m.isfile() and any(name.startswith(root + '/') for root in roots):
                rel = PurePosixPath(name.removeprefix(BASE))
                if rel.is_absolute() or '..' in rel.parts or '\\' in str(rel) or ':' in str(rel):
                    raise ValueError('MEMBER_PATH')
                payloads[str(rel)] = read(name)
        if sum(map(len, payloads.values())) > 32 * 1024 * 1024:
            raise ValueError('OUTPUT_SIZE')
        package_meta = json.loads(read(BASE + 'package.json'))
        node = read(BASE + 'node/bin/node', 100 * 1024 * 1024)
        node_header = read(BASE + 'node/include/node/node_version.h')
        node_version = '.'.join(re.search(rb'#define NODE_' + part + rb'_VERSION (\d+)', node_header)[1].decode()
                                for part in (b'MAJOR', b'MINOR', b'PATCH'))
        if node_version != '18.19.0' or digest(node) != '157f76a2eff8bbe4017cfecdac5629b9e60c7a6106fed26ab6e2cda802b89cd0':
            raise ValueError('NODE_IDENTITY')
        manifest = {
            'scope': 'offline candidate only; NOT deployed or live-accepted',
            'package_sha256': DEB_SHA256,
            'original_sha256': CLIENT_SHA256,
            'candidate_sha256': digest(candidate),
            'policy_lf_sha256': digest(policy),
            'source_map': 'removed entire final inline mapping including sourcesContent',
            'package_engines': package_meta.get('engines'),
            'packaged_linux_node_sha256': digest(node),
            'packaged_node_version': node_version,
            'packaged_node_header_sha256': digest(node_header),
            'packaged_node_executed': False,
            'dependencies': versions,
            'files': {n: {'bytes': len(b), 'sha256': digest(b)} for n, b in sorted(payloads.items())},
            'live_mutation_authorized': False,
        }
        manifest['files_digest'] = digest(json.dumps(manifest['files'], sort_keys=True, separators=(',', ':')).encode())
        contract = json.loads((HERE / 'contract.json').read_text(encoding='utf-8'))
        if any(manifest.get(k) != v for k, v in contract.items()):
            raise ValueError('CANDIDATE_CONTRACT')
        output.mkdir(parents=False)
        for name, data in payloads.items():
            p = output / name
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open('xb') as f:
                f.write(data)
        with (output / 'manifest.json').open('x', encoding='utf-8', newline='\n') as f:
            json.dump(manifest, f, indent=2)
            f.write('\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deb', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(args.deb, args.output)
    except Exception:
        raise SystemExit('STOP: offline build failed; output may be partial, do not reuse it') from None
    print('PASS offline candidate:', result['candidate_sha256'])
    print('STOP POINT: no install or live acceptance is authorized')
