"""Generate a local CA and an ECDSA P-256 server certificate for <hostname>.local."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVER_DAYS = 825  # macOS/iOS reject longer-lived TLS server certs from private roots
CA_DAYS = 3650


def _write(path: Path, data: bytes, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if private:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    else:
        path.write_bytes(data)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_or_create_ca(ca_dir: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, bool]:
    cert_p, key_p = ca_dir / "ca.pem", ca_dir / "ca.key"
    if cert_p.exists() and key_p.exists():
        cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
        key = serialization.load_pem_private_key(key_p.read_bytes(), password=None)
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
    _write(cert_p, cert.public_bytes(serialization.Encoding.PEM))
    _write(key_p, _key_pem(key), private=True)
    return cert, key, True


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
