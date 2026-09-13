"""Root-controlled manifest/public-certificate loading, not startup authority.

No CLI, writes, subprocesses, credentials or network. The proposed manifest
destination is not installed by this library. The CA destination matches the
reviewed candidate. A trusted Python launcher/import environment is a separate
prerequisite: code cannot establish its own trust after it has been imported.
"""
import base64
import binascii
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re
from types import MappingProxyType

from . import operator_fs as fs
from .operator_core import MAX_MANIFEST, OperatorError, installed_checks, require, sha

MANIFEST_PATH = '/etc/alertmind/broker-tls/manifest.json'
CERTIFICATE_PATH = '/etc/wazuh-dashboard/certs/alertmind-server-api.pem'
CERTIFICATE_SHA256 = '5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87'
MAX_CERTIFICATE = 65536
FILES = MappingProxyType({
    'manifest': (MANIFEST_PATH, MAX_MANIFEST),
    'certificate': (CERTIFICATE_PATH, MAX_CERTIFICATE),
})


def read_bootstrap_file(label):
    """Read one fixed root:root public file, never a caller-provided live path."""
    require(type(label) is str and label in FILES, 'BOOTSTRAP_TARGET')
    path, limit = FILES[label]
    try:
        fs._platform()
        return fs._read_root_owned(PurePosixPath(path).parts[1:], limit)
    except OSError as error:
        raise OperatorError(fs._os_error_code(error)) from None


def verify_certificate_pin(raw):
    """Single PEM, strict Base64 and exact accepted DER pin. No X.509 time/SAN proof.

    The actual client must still check certificate validity and hostname at use;
    pin equality alone does not establish current expiry/revocation/TLS success.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CERTIFICATE, 'BOOTSTRAP_CERT_SIZE')
    match = re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n'
                         rb'([A-Za-z0-9+/=\r\n]+)\r?\n'
                         rb'-----END CERTIFICATE-----\r?\n?', raw)
    require(match is not None, 'BOOTSTRAP_CERT_PEM')
    encoded = match[1].replace(b'\r', b'').replace(b'\n', b'')
    try:
        der = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise OperatorError('BOOTSTRAP_CERT_PEM') from None
    require(base64.b64encode(der) == encoded, 'BOOTSTRAP_CERT_PEM')
    require(sha(der) == CERTIFICATE_SHA256, 'BOOTSTRAP_CERT_PIN')


@dataclass(frozen=True)
class Bootstrap:
    # Public bytes still do not belong in routine logs or persisted receipts.
    manifest: bytes = field(repr=False)
    certificate_pem: bytes = field(repr=False)
    checked_files: int = field(default=2, init=False)
    passes: int = field(default=2, init=False)
    startup_authorized: bool = field(default=False, init=False)


def load_bootstrap():
    """Validate two fresh passes; fail before any vendor read on bad bootstrap.

    Not an atomic snapshot, a trusted-launch proof, a startup guard or a package
    observation. No callbacks/path/CA/pin overrides are exposed by this API.
    """
    first = None
    for _ in range(2):
        manifest = read_bootstrap_file('manifest')
        installed_checks(manifest)
        certificate = read_bootstrap_file('certificate')
        verify_certificate_pin(certificate)
        current = (manifest, certificate)
        if first is None:
            first = current
        else:
            require(first == current, 'BOOTSTRAP_CHANGED')
    return Bootstrap(*first)
