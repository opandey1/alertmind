"""Run synthetic localhost TLS tests; requires cryptography and an explicit Node.

Never reads live configuration. Temporary test private keys are deleted on exit.
No connection is made until the caller explicitly supplies --run-synthetic.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile


def fixtures():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)

    def issue(name, issuer=None, expired=False, ca=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'synthetic-root' if ca else name)])
        issuer_cert, issuer_key = issuer if issuer else (None, key)
        cert = (x509.CertificateBuilder().subject_name(subject)
                .issuer_name(issuer_cert.subject if issuer_cert else subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=3))
                .not_valid_after(now + timedelta(days=-1 if expired else 2))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, True, False, False, ca, ca, False, False), True)
                .sign(issuer_key, hashes.SHA256()))
        return cert, key

    anchor = issue('localhost', ca=True)
    other = issue('localhost', ca=True)

    def encode(pair):
        cert, key = pair
        return {'cert': cert.public_bytes(serialization.Encoding.PEM).decode(),
                'key': key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()).decode()}

    return {'anchor': encode(anchor),
            'pin': anchor[0].fingerprint(hashes.SHA256()).hex(),
            'good': encode(issue('localhost', anchor)),
            'wronghost': encode(issue('wrong.invalid', anchor)),
            'untrusted': encode(issue('localhost', other)),
            'expiredPeer': encode(issue('localhost', anchor, expired=True)),
            'expiredAnchor': encode(issue('localhost', expired=True, ca=True))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--run-synthetic', action='store_true', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='alertmind-synthetic-tls-') as tmp:
        payload = Path(tmp) / 'synthetic.json'
        with payload.open('x', encoding='utf-8') as f:
            json.dump(fixtures(), f)
        result = subprocess.run([str(args.node.resolve()),
                                 str(Path(__file__).with_name('test_client.cjs')),
                                 str(args.stage.resolve()), str(payload)], check=False,
                                timeout=150)
        return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
