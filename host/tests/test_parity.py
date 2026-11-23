"""The host compiler and evaluator agree with the device (C engine in build-test/policy_cli)."""

import json
import subprocess
from decimal import Decimal
from pathlib import Path

import pytest

from esp32signer import device_regex
from esp32signer.policy_compiler import (PolicyError, canonical_json, compile_policy, evaluate,
                                         policy_instructions)

ROOT = Path(__file__).resolve().parents[2]
POLICY_CLI = ROOT / "build-test" / "policy_cli"
SELF = "0x1234567890abcdef1234567890abcdef12345678"
needs_cli = pytest.mark.skipif(not POLICY_CLI.exists(), reason="build firmware/test_host first")

HEAD = "version: 1\nchain_ids: [1]\nlimits: {max_gas: 100000, max_fee_per_gas_gwei: 1, max_priority_fee_gwei: 1}\n"
TREASURY = "0x9999999999999999999999999999999999999999"
NATIVE = HEAD + f"native_transfers: [{{to: '{TREASURY}', max_value_wei: '100'}}]\n"


def run_cli(policy: dict, txs: list) -> tuple[list[str], int]:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "p.json").write_bytes(canonical_json(policy))
        (Path(d) / "t.json").write_text(json.dumps(txs))
        r = subprocess.run([str(POLICY_CLI), f"{d}/p.json", SELF, f"{d}/t.json"], capture_output=True, text=True,
                           check=True)
    insts = int(next(l for l in r.stderr.splitlines() if l.startswith("regex_instructions")).split()[1])
    return r.stdout.splitlines(), insts


@needs_cli
@pytest.mark.parametrize("path", sorted((ROOT / "policies").glob("*.yaml")), ids=lambda p: p.name)
def test_instruction_count_matches_device(path):
    pol, _ = compile_policy(path.read_text())
    _, insts = run_cli(pol, [])
    assert policy_instructions(pol) == insts


@pytest.mark.parametrize("pattern,n", [
    ("^ab$", 5), ("^(?:ab|cd)$", 9), ("^a{3}$", 6), ("^a*$", 6), ("^[0-9a-f]{64}$", 67), ("^(ab)?$", 6),
])
def test_instruction_counts(pattern, n):
    assert device_regex.instructions(pattern) == n


@pytest.mark.parametrize("pattern", [
    r"^(a)\1$", r"^\bab$", r"^a*?$", "^a{2}?$", "^(?=a)a$", "^(?P<x>a)$", "^a{1025}$", "^ab]$", "^[ab$",
    "^a{3,2}$", "^$*$", r"^\x41$", "^(" * 65 + "a" + ")" * 65 + "$",
])
def test_device_rejects(pattern):
    with pytest.raises(device_regex.RegexError):
        device_regex.instructions(pattern)


@needs_cli
@pytest.mark.parametrize("pattern", ["^ab]$", "^a{1025}$", r"^(a)\1$", "^a{2}?$"])
def test_device_rejects_same_patterns(pattern, tmp_path):
    # Bypass compile_policy: hand the C loader a policy with the raw pattern.
    pol = {"version": 1, "chain_ids": [1], "limits": {"max_gas": 1, "max_fee_per_gas": "1",
                                                      "max_priority_fee_per_gas": "1"},
           "contracts": [{"address": TREASURY, "max_value": "0", "rules": [{"calldata": pattern}]}]}
    (tmp_path / "p.json").write_bytes(canonical_json(pol))
    (tmp_path / "t.json").write_text("[]")
    r = subprocess.run([str(POLICY_CLI), str(tmp_path / "p.json"), SELF, str(tmp_path / "t.json")],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "regex error" in r.stderr


def test_oversized_policy_rejected_before_provisioning():
    rule = "{name: r, calldata: '^(?:[0-9a-f]{64}){200}$'}"  # 200 * 64 instructions > 8192
    with pytest.raises(PolicyError, match="device regex engine"):
        compile_policy(HEAD + f"contracts: [{{address: '{TREASURY}', rules: [{rule}]}}]")


@pytest.mark.parametrize("snippet,msg", [
    ("chain_ids: [true]", "chain_ids"),
    ("chain_ids: [" + ",".join(str(i) for i in range(1, 18)) + "]", "at most 16"),
])
def test_compiler_rejects_what_device_rejects(snippet, msg):
    src = NATIVE.replace("chain_ids: [1]", snippet)
    with pytest.raises(PolicyError, match=msg):
        compile_policy(src)


def test_bool_max_gas_rejected():
    with pytest.raises(PolicyError, match="max_gas"):
        compile_policy(NATIVE.replace("max_gas: 100000", "max_gas: true"))


def test_too_many_rules_rejected():
    rules = ", ".join("{calldata: '^%02x$'}" % i for i in range(65))
    with pytest.raises(PolicyError, match="at most 64 rules"):
        compile_policy(HEAD + f"contracts: [{{address: '{TREASURY}', rules: [{rules}]}}]")


# --- exact unit conversion ---

def limit(value: str) -> str:
    pol, _ = compile_policy(HEAD.replace("max_fee_per_gas_gwei: 1", f"max_fee_per_gas_gwei: {value}")
                            + f"native_transfers: [{{to: '{TREASURY}'}}]\n")
    return pol["limits"]["max_fee_per_gas"]


def test_exact_gwei():
    assert limit("0.5") == "500000000"
    assert limit("'0.000000001'") == "1"
    assert limit("'1000000000000000000000000000000.000000001'") == str(10**39 + 1)  # > 28 digits, exact


def test_sub_wei_rejected_not_rounded():
    with pytest.raises(PolicyError, match="whole number"):
        limit("'1000000000000000000000000000000.0000000019'")  # used to round up silently
    with pytest.raises(PolicyError, match="whole number"):
        limit("0.0000000001")


def test_long_unquoted_float_rejected():
    with pytest.raises(PolicyError, match="quote it"):
        limit("0.12345678901234567")


def test_u256_overflow_rejected():
    with pytest.raises(PolicyError, match="256 bits"):
        limit(f"'{Decimal(2**256)}'")


# --- transaction parsing parity: raw JSON, as a client would send it ---

BASE = {"chainId": "0x1", "nonce": "0x0", "gas": "0x5208", "to": TREASURY, "value": "0x1"}
PARSE_CASES = [
    {**BASE, "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x1"},
    {**BASE, "gasPrice": "0x1"},
    {k: v for k, v in BASE.items() if k != "nonce"} | {"gasPrice": "0x1"},
    {k: v for k, v in BASE.items() if k != "gas"} | {"gasPrice": "0x1"},
    {k: v for k, v in BASE.items() if k != "gas"} | {"gasPrice": "0x1", "gasLimit": "0x5208"},
    {**BASE, "gasPrice": "0x1", "gasLimit": "0x5209"},
    {**BASE, "gasPrice": "0x1", "gasLimit": "0x5208"},
    {**BASE, "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x2"},
    {**BASE, "type": "0x1", "gasPrice": "0x1"},
    {**BASE, "type": "0x2", "gasPrice": "0x1", "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x1"},
    {**BASE, "type": "0x0", "maxFeePerGas": "0x1"},
    {**BASE, "gasPrice": "0x1", "data": "0x", "input": "0x00"},
    {**BASE, "gasPrice": "0x1", "data": "0x0"},
    {**BASE, "gasPrice": "0x1", "value": "-1"},
    {**BASE, "gasPrice": "0x1", "authorizationList": []},
    {**BASE, "gasPrice": "0x1", "accessList": [{"address": TREASURY, "storageKeys": []}]},
    {**BASE, "gasPrice": "0x1", "to": "0x12"},
    {**BASE, "gasPrice": "0x1", "value": "0x65"},  # 101 > max_value 100
]


@needs_cli
def test_parse_parity_with_device():
    pol, _ = compile_policy(NATIVE)
    out, _ = run_cli(pol, PARSE_CASES)
    for tx, line in zip(PARSE_CASES, out, strict=True):
        ok, reason = evaluate(pol, tx, SELF)
        assert line.startswith("ALLOW" if ok else "DENY"), f"{tx}: device {line!r} vs python {reason!r}"


def test_from_must_be_signer():
    pol, _ = compile_policy(NATIVE)
    tx = {**BASE, "gasPrice": "0x1"}
    assert evaluate(pol, {**tx, "from": SELF}, SELF)[0]
    assert not evaluate(pol, {**tx, "from": TREASURY}, SELF)[0]
