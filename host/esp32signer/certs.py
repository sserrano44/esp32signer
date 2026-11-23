"""Generate a local CA and an ECDSA P-256 server certificate for <hostname>.local."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import stat
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVER_DAYS = 825  # macOS/iOS reject longer-lived TLS server certs from private roots
CA_DAYS = 3650


class CertError(RuntimeError):
    pass


def _write(path: Path, data: bytes, private: bool = False, overwrite: bool = True) -> None:
    """Write atomically through a new temp file in the same directory.

    The temp file is created with O_EXCL (mkstemp) and mode 0600, so an existing
    file's permissions or a planted symlink at `path` never receive the data; the
    rename replaces whatever was at `path`. With overwrite=False an existing
    `path` is an error (no rename over it).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            if not private:
                os.fchmod(f.fileno(), 0o644)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if overwrite:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)  # fails if path exists (including a dangling symlink)
            os.unlink(tmp)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise


def _read_private(path: Path) -> bytes:
    """Read a private key file only if it is a regular file (not a symlink) that only its owner can read."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise CertError(f"{path} is not a regular file (symlinks are refused)")
    if st.st_mode & 0o077:
        raise CertError(f"{path} is readable by other users (mode {stat.S_IMODE(st.st_mode):o}); chmod 600 it")
    if st.st_uid != os.getuid():
        raise CertError(f"{path} is owned by another user")
    return path.read_bytes()


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_or_create_ca(ca_dir: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, bool]:
    cert_p, key_p = ca_dir / "ca.pem", ca_dir / "ca.key"
    have = [p for p in (cert_p, key_p) if os.path.lexists(p)]
    if len(have) == 1:
        raise CertError(f"only {have[0]} exists in {ca_dir}: refusing to create a new CA over it. "
                        "Restore the missing file, or move the directory aside to start a new CA.")
    if have:
        cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
        key = serialization.load_pem_private_key(_read_private(key_p), password=None)
        _check_ca(cert, key, ca_dir)
        return cert, key, False
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "esp32signer local CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    # Key first: an interruption leaves a lone ca.key, which the check above refuses to overwrite.
    _write(key_p, _key_pem(key), private=True, overwrite=False)
    _write(cert_p, cert.public_bytes(serialization.Encoding.PEM), overwrite=False)
    return cert, key, True


def _check_ca(cert: x509.Certificate, key, ca_dir: Path) -> None:
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(serialization.Encoding.DER, pub) != \
            key.public_key().public_bytes(serialization.Encoding.DER, pub):
        raise CertError(f"{ca_dir}: ca.pem and ca.key do not belong together")
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as e:
        raise CertError(f"{ca_dir}/ca.pem is not a CA certificate ({e})") from e
    if not bc.ca or not ku.key_cert_sign:
        raise CertError(f"{ca_dir}/ca.pem is not a CA certificate")
    if cert.not_valid_after_utc < dt.datetime.now(dt.timezone.utc):
        raise CertError(f"{ca_dir}/ca.pem expired on {cert.not_valid_after_utc:%Y-%m-%d}")


def make_server_cert(
    hostname: str, out_dir: Path, ca_dir: Path | None = None, ips: list[str] | None = None
) -> dict[str, Path]:
    """Create <out_dir>/signer.crt + signer.key. Signed by a local CA when ca_dir is given."""
    fqdn = f"{hostname}.local"
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    sans: list[x509.GeneralName] = [x509.DNSName(fqdn)]
    for ip in ips or []:
        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])

    if ca_dir:
        ca_cert, ca_key, _ = load_or_create_ca(ca_dir)
        issuer, signer = ca_cert.subject, ca_key
    else:
        issuer, signer = subject, key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=SERVER_DAYS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        # Required by strict X.509 verification (Python >= 3.13 VERIFY_X509_STRICT).
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
    )
    cert = builder.sign(signer, hashes.SHA256())
    paths = {"cert": out_dir / "signer.crt", "key": out_dir / "signer.key"}
    _write(paths["cert"], cert.public_bytes(serialization.Encoding.PEM))
    _write(paths["key"], _key_pem(key), private=True)
    if ca_dir:
        paths["ca"] = ca_dir / "ca.pem"
    return paths
