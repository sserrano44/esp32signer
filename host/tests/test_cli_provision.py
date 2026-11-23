"""Key generation ordering and backup parsing in `esp32signer provision`."""

import argparse
import os

import pytest

from esp32signer import cli

KEY = "0x" + "11" * 32
ADDR = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"


class FakeDevice:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def call(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd == self.fail_on:
            raise RuntimeError(f"{cmd} failed")
        if cmd == "generate_key":
            return {"address": ADDR, "private_key": KEY, "pending": True}
        if cmd == "confirm_key":
            assert kw["address"] == ADDR
            return {"address": ADDR}
        return {}


def args(path=None):
    return argparse.Namespace(force_key=False, key_backup_file=str(path) if path else None)


def test_backup_written_and_synced_before_confirm(tmp_path):
    path = tmp_path / "k.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    d = FakeDevice()
    cli._generate_key(d, args(path), fd)
    assert d.calls == ["generate_key", "confirm_key"]
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert cli._read_key_file(path) == KEY  # the backup round-trips into --import-key-file


def test_no_confirm_when_backup_fails(tmp_path, monkeypatch):
    path = tmp_path / "k.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    d = FakeDevice()
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        cli._generate_key(d, args(path), fd)
    assert "confirm_key" not in d.calls  # the device keeps its old key


def test_failed_generate_removes_placeholder(tmp_path):
    path = tmp_path / "k.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with pytest.raises(RuntimeError):
        cli._generate_key(FakeDevice(fail_on="generate_key"), args(path), fd)
    assert not path.exists()


def test_read_key_file_formats(tmp_path):
    raw = tmp_path / "raw"
    raw.write_text(KEY + "\n")
    assert cli._read_key_file(raw) == KEY
    two = tmp_path / "two"
    two.write_text(f"private_key={KEY}\nprivate_key={KEY}\n")
    with pytest.raises(SystemExit):
        cli._read_key_file(two)
