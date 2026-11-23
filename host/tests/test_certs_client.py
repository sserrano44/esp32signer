"""CA state checks, private-key file handling, and the https-only client."""

import os

import pytest

from esp32signer import certs
from esp32signer.client import SignerClient


def test_new_ca_then_reuse(tmp_path):
    ca = tmp_path / "ca"
    c1, _, created = certs.load_or_create_ca(ca)
    assert created and oct((ca / "ca.key").stat().st_mode & 0o777) == "0o600"
    c2, _, created = certs.load_or_create_ca(ca)
    assert not created and c1 == c2


@pytest.mark.parametrize("missing", ["ca.pem", "ca.key"])
def test_lone_ca_file_is_never_overwritten(tmp_path, missing):
    ca = tmp_path / "ca"
    certs.load_or_create_ca(ca)
    (ca / missing).unlink()
    survivor = ca / ({"ca.pem", "ca.key"} - {missing}).pop()
    before = survivor.read_bytes()
    with pytest.raises(certs.CertError, match="refusing"):
        certs.load_or_create_ca(ca)
    assert survivor.read_bytes() == before


def test_mismatched_ca_pair_rejected(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    certs.load_or_create_ca(a)
    certs.load_or_create_ca(b)
    os.replace(b / "ca.key", a / "ca.key")
    with pytest.raises(certs.CertError, match="do not belong together"):
        certs.load_or_create_ca(a)


def test_permissive_or_symlinked_ca_key_rejected(tmp_path):
    ca = tmp_path / "ca"
    certs.load_or_create_ca(ca)
    os.chmod(ca / "ca.key", 0o644)
    with pytest.raises(certs.CertError, match="readable by other users"):
        certs.load_or_create_ca(ca)
    os.chmod(ca / "ca.key", 0o600)
    real = tmp_path / "elsewhere.key"
    os.replace(ca / "ca.key", real)
    os.symlink(real, ca / "ca.key")
    with pytest.raises(certs.CertError, match="symlink"):
        certs.load_or_create_ca(ca)


def test_server_key_never_lands_in_existing_world_readable_file(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    planted = out / "signer.key"
    planted.write_text("")
    os.chmod(planted, 0o644)
    certs.make_server_cert("signer", out, tmp_path / "ca")
    assert oct(planted.stat().st_mode & 0o777) == "0o600"


def test_server_key_does_not_follow_symlink(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    target = tmp_path / "attacker.txt"
    target.write_text("")
    os.symlink(target, out / "signer.key")
    certs.make_server_cert("signer", out, tmp_path / "ca")
    assert target.read_text() == "" and not (out / "signer.key").is_symlink()


@pytest.mark.parametrize("url", ["http://signer.local", "signer.local", "https://u:p@signer.local", "https://"])
def test_client_refuses_cleartext_or_odd_urls(url):
    with pytest.raises(ValueError):
        SignerClient(url, "t" * 43)


def test_client_https_and_explicit_insecure():
    SignerClient("https://signer.local", "t" * 43)
    SignerClient("http://127.0.0.1:8545", "t" * 43, allow_insecure=True)
