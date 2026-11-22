import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from eth_abi import encode
from eth_utils import keccak

from esp32signer.client import to_rpc_tx
from esp32signer.policy_compiler import PolicyError, canonical_json, compile_policy, evaluate, selector

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
SELF = "0x1234567890abcdef1234567890abcdef12345678"
EVIL = "0xbadbadbadbadbadbadbadbadbadbadbadbadbad0"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"


def word(addr: str) -> str:
    return addr.lower()[2:].rjust(64, "0")


def base_tx(**kw):
    tx = {"type": "0x2", "chainId": 8453, "nonce": 1, "gas": 200000, "maxFeePerGas": 10**9,
          "maxPriorityFeePerGas": 10**6, "value": 0}
    tx.update(kw)
    return tx


@pytest.fixture(scope="module")
def arb():
    pol, warns = compile_policy((POLICIES / "base-arb.example.yaml").read_text())
    assert not warns
    return pol


def book(pol_yaml: str) -> dict:
    import yaml

    return {k: v.lower() for k, v in yaml.safe_load(pol_yaml)["address_book"].items()}


def test_selector():
    assert selector("approve(address,uint256)") == "095ea7b3"
    assert selector("transfer(address, uint256)") == "a9059cbb"
    assert selector("execute(bytes,bytes[],uint256)") == "3593564c"


def test_compile_example(arb):
    assert arb["chain_ids"] == [8453]
    assert arb["limits"]["max_fee_per_gas"] == str(2 * 10**9)
    assert arb["limits"]["max_priority_fee_per_gas"] == str(5 * 10**8)
    assert arb["native_transfers"][0]["max_value"] == str(5 * 10**17)
    for c in arb["contracts"]:
        for r in c["rules"]:
            assert r["calldata"].startswith("^") and r["calldata"].endswith("$")
            assert " " not in r["calldata"] and "#" not in r["calldata"] and "{{" not in r["calldata"]
    # canonical JSON is stable
    assert canonical_json(arb) == canonical_json(json.loads(canonical_json(arb)))


def test_approve_rules(arb):
    b = book((POLICIES / "base-arb.example.yaml").read_text())
    ok = "0x095ea7b3" + word(PERMIT2) + "f" * 64
    assert evaluate(arb, base_tx(to=b["usdc"], data=ok))[0]
    assert not evaluate(arb, base_tx(to=b["usdc"], data="0x095ea7b3" + word(EVIL) + "f" * 64))[0]
    assert not evaluate(arb, base_tx(to=b["usdc"], data=ok + "00"))[0]
    assert not evaluate(arb, base_tx(to=b["usdc"], data=ok, value=1))[0]
    assert not evaluate(arb, base_tx(to=b["usdc"], data=ok, chainId=1))[0]
    assert not evaluate(arb, base_tx(to=b["usdc"], data=ok, maxFeePerGas=3 * 10**9))[0]
    assert not evaluate(arb, base_tx(to=EVIL, data=ok))[0]
    assert not evaluate(arb, base_tx(to=None, data="0x6080"))[0]
    assert not evaluate(arb, base_tx(to=b["usdc"], data=ok, type="0x4"))[0]


def v4_swap_calldata(c0: str, c1: str, hooks: str, *, actions=b"\x06\x0c\x0f", commands=b"\x10") -> str:
    """Real UniversalRouter.execute() calldata for a single-pool v4 exact-in swap."""
    pool_key = (c0, c1, 3000, 60, hooks)
    swap = encode(["((address,address,uint24,int24,address),bool,uint128,uint128,bytes)"],
                  [(pool_key, True, 10**6, 1, b"")])
    settle = encode(["address", "uint256"], [c0, 10**6])
    take = encode(["address", "uint256"], [c1, 1])
    v4_input = encode(["bytes", "bytes[]"], [actions, [swap, settle, take]])
    args = encode(["bytes", "bytes[]", "uint256"], [commands, [v4_input], 1_900_000_000])
    return "0x" + keccak(text="execute(bytes,bytes[],uint256)")[:4].hex() + args.hex()


def test_v4_swap_rule_matches_real_abi_encoding(arb):
    b = book((POLICIES / "base-arb.example.yaml").read_text())
    c0, c1 = sorted([b["usdc"], b["wars"]])
    router = b["router"]
    good = v4_swap_calldata(c0, c1, b["hooks"])
    ok, reason = evaluate(arb, base_tx(to=router, data=good))
    assert ok, reason
    # other pool / other hooks / extra command / other actions are rejected
    assert not evaluate(arb, base_tx(to=router, data=v4_swap_calldata(c0, EVIL, b["hooks"])))[0]
    assert not evaluate(arb, base_tx(to=router, data=v4_swap_calldata(c0, c1, EVIL)))[0]
    assert not evaluate(arb, base_tx(to=router, data=v4_swap_calldata(c0, c1, b["hooks"], commands=b"\x10\x04")))[0]
    # TAKE (0x0e) has an arbitrary recipient: must be rejected
    assert not evaluate(arb, base_tx(to=router, data=v4_swap_calldata(c0, c1, b["hooks"], actions=b"\x06\x0c\x0e")))[0]


def test_native(arb):
    b = book((POLICIES / "base-arb.example.yaml").read_text())
    assert evaluate(arb, base_tx(to=b["treasury"], value=5 * 10**17))[0]
    assert not evaluate(arb, base_tx(to=b["treasury"], value=5 * 10**17 + 1))[0]
    assert not evaluate(arb, base_tx(to=EVIL, value=1))[0]


def test_self_macro():
    pol, _ = compile_policy((POLICIES / "e2e-test.yaml").read_text())
    rule = pol["contracts"][0]["rules"][1]["calldata"]
    assert "{{addr:self}}" in rule
    usdc = pol["contracts"][0]["address"]
    good = "0xa9059cbb" + word(SELF) + "0" * 63 + "1"
    assert evaluate(pol, base_tx(chainId=84532, to=usdc, data=good), SELF)[0]
    assert not evaluate(pol, base_tx(chainId=84532, to=usdc, data=good), EVIL)[0]


@pytest.mark.parametrize("snippet,err", [
    ("calldata: '095ea7b3.*$'", "anchored"),
    ("calldata: '^095ea7b3.*'", "anchored"),
    ("calldata: '^{{addr:nobody}}$'", "unknown address_book"),
    ("calldata: '^{{bogus}}$'", "unknown macro"),
    ("calldata: '^(ab$'", "invalid regex"),
    ("calldata: '^(?=a)b$'", "not supported"),
    ("calldata: '^a*?$'", "not supported"),
    ("calldata: '^a$'\n        extra: 1", "unknown key"),
])
def test_rule_errors(snippet, err):
    y = f"""
version: 1
chain_ids: [1]
limits: {{max_gas: 1, max_fee_per_gas_gwei: 1, max_priority_fee_gwei: 1}}
contracts:
  - address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    rules:
      - {snippet}
"""
    with pytest.raises(PolicyError, match=err):
        compile_policy(y)


def test_top_level_errors():
    with pytest.raises(PolicyError, match="version"):
        compile_policy("version: 2\nchain_ids: [1]")
    with pytest.raises(PolicyError, match="allows nothing"):
        compile_policy("version: 1\nchain_ids: [1]\nlimits: {max_gas: 1, max_fee_per_gas_gwei: 1, max_priority_fee_gwei: 1}")
    with pytest.raises(PolicyError, match="whole number"):
        compile_policy("version: 1\nchain_ids: [1]\nlimits: {max_gas: 1, max_fee_per_gas_wei: '0.5', max_priority_fee_gwei: 1}\n"
                       "native_transfers: [{to: '0x9999999999999999999999999999999999999999'}]")
    with pytest.raises(PolicyError, match="unknown key"):
        compile_policy("version: 1\nchain_ids: [1]\nfoo: 1")


# --- Cross-check: the C device engine (built in build-test/) agrees with evaluate() ---

POLICY_CLI = ROOT / "build-test" / "policy_cli"


@pytest.mark.skipif(not POLICY_CLI.exists(), reason="build firmware/test_host first (build-test/policy_cli)")
def test_device_engine_agrees(arb, tmp_path):
    b = book((POLICIES / "base-arb.example.yaml").read_text())
    c0, c1 = sorted([b["usdc"], b["wars"]])
    txs = [
        base_tx(to=b["usdc"], data="0x095ea7b3" + word(PERMIT2) + "f" * 64),
        base_tx(to=b["usdc"], data="0x095ea7b3" + word(EVIL) + "f" * 64),
        base_tx(to=b["router"], data=v4_swap_calldata(c0, c1, b["hooks"])),
        base_tx(to=b["router"], data=v4_swap_calldata(c0, c1, b["hooks"], actions=b"\x06\x0c\x0e")),
        base_tx(to=b["permit2"], data="0x" + selector("approve(address,address,uint160,uint48)")
                + word(b["usdc"]) + word(b["router"]) + "0" * 64 + "0" * 64),
        base_tx(to=b["treasury"], value=10**17),
        base_tx(to=EVIL, value=1),
        base_tx(to=b["usdc"], data="0x095ea7b3" + word(PERMIT2) + "f" * 64, maxPriorityFeePerGas=10**9),
    ]
    pol_path = tmp_path / "p.json"
    pol_path.write_bytes(canonical_json(arb))
    tx_path = tmp_path / "txs.json"
    tx_path.write_text(json.dumps([to_rpc_tx(t) for t in txs]))
    out = subprocess.run([str(POLICY_CLI), str(pol_path), SELF, str(tx_path)], capture_output=True, text=True,
                         check=True).stdout.splitlines()
    assert len(out) == len(txs)
    for tx, line in zip(txs, out):
        want, reason = evaluate(arb, tx, SELF)
        assert line.startswith("ALLOW" if want else "DENY"), f"{line} vs python {reason}"


# --- Per-chain limits and chain-scoped entries ---

MULTI = """
version: 1
chain_ids: [8453, 42220]
limits: {max_gas: 1000000, max_fee_per_gas_gwei: 1, max_priority_fee_gwei: 0.001, rate_per_minute: 10}
chain_limits:
  42220: {max_gas: 2000000, max_fee_per_gas_gwei: 100, max_priority_fee_gwei: 5}
address_book:
  usdc_base: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
  router:    "0x6ff5693b99212da76ad316178a184ab56d299b43"
  treasury:  "0x9999999999999999999999999999999999999999"
native_transfers:
  - {to: "{{treasury}}", max_value_wei: "5", chains: [42220]}
contracts:
  - address: "{{usdc_base}}"
    chains: [8453]
    rules: [{name: approve, calldata: "^{{sel:approve(address,uint256)}}{{uint}}{{u256:42220}}$"}]
  - address: "{{router}}"
    label: router-base
    chains: [8453]
    rules: [{name: a, calldata: "^aaaaaaaa$"}]
  - address: "{{router}}"
    label: router-celo
    chains: [42220]
    rules: [{name: b, calldata: "^bbbbbbbb$"}]
"""


def mtx(chain, to, data="0x", fee=10**9, **kw):
    t = {"type": 2, "chainId": chain, "nonce": 0, "gas": 100000, "maxFeePerGas": fee,
         "maxPriorityFeePerGas": 10**6, "to": to, "value": 0, "data": data}
    t.update(kw)
    return t


def multi_cases():
    b = book(MULTI)
    approve = "0x095ea7b3" + "0" * 64 + f"{42220:064x}"
    return [
        (mtx(42220, b["router"], "0xbbbbbbbb", fee=30 * 10**9), True),
        (mtx(8453, b["router"], "0xaaaaaaaa", fee=30 * 10**9), False),   # Base fee cap
        (mtx(8453, b["router"], "0xaaaaaaaa"), True),
        (mtx(42220, b["router"], "0xbbbbbbbb", gas=1_500_000), True),    # Celo gas cap
        (mtx(8453, b["router"], "0xaaaaaaaa", gas=1_500_000), False),
        (mtx(8453, b["router"], "0xbbbbbbbb"), False),                   # rules are per chain
        (mtx(42220, b["router"], "0xaaaaaaaa"), False),
        (mtx(8453, b["usdc_base"], approve), True),
        (mtx(42220, b["usdc_base"], approve), False),                    # entry is Base-only
        (mtx(8453, b["usdc_base"], approve[:-1] + "5"), False),          # u256 pinned
        (mtx(42220, b["treasury"], value=5), True),
        (mtx(8453, b["treasury"], value=5), False),
    ]


def test_multichain_evaluate():
    pol, _ = compile_policy(MULTI)
    assert pol["chain_limits"] == [{"chain_id": 42220, "max_gas": 2000000, "max_fee_per_gas": str(100 * 10**9),
                                    "max_priority_fee_per_gas": str(5 * 10**9)}]
    assert pol["contracts"][1]["chain_ids"] == [8453]
    for tx, want in multi_cases():
        got, reason = evaluate(pol, tx, SELF)
        assert got == want, (tx, reason)


@pytest.mark.parametrize("bad,msg", [
    ("contracts:\n  - {address: '0x9999999999999999999999999999999999999999', chains: [8453], rules: [{calldata: '^00$'}]}\n"
     "  - {address: '0x9999999999999999999999999999999999999999', rules: [{calldata: '^00$'}]}", "same chain"),
    ("contracts:\n  - {address: '0x9999999999999999999999999999999999999999', chains: [1], rules: [{calldata: '^00$'}]}",
     "not in chain_ids"),
    ("chain_limits: {1: {max_gas: 1, max_fee_per_gas_gwei: 1, max_priority_fee_gwei: 1}}\n"
     "contracts:\n  - {address: '0x9999999999999999999999999999999999999999', rules: [{calldata: '^00$'}]}",
     "not in chain_ids"),
    ("chain_limits: {8453: {max_gas: 1, max_fee_per_gas_gwei: 1, max_priority_fee_gwei: 1, rate_per_minute: 1}}\n"
     "contracts:\n  - {address: '0x9999999999999999999999999999999999999999', rules: [{calldata: '^00$'}]}",
     "unknown key"),
    ("contracts:\n  - {address: '0x9999999999999999999999999999999999999999', rules: [{calldata: '^{{u256:x}}$'}]}",
     "bad integer"),
])
def test_multichain_errors(bad, msg):
    head = ("version: 1\nchain_ids: [8453, 42220]\n"
            "limits: {max_gas: 1, max_fee_per_gas_gwei: 1, max_priority_fee_gwei: 1}\n")
    with pytest.raises(PolicyError, match=msg):
        compile_policy(head + bad)


@pytest.mark.skipif(not POLICY_CLI.exists(), reason="build firmware/test_host first (build-test/policy_cli)")
def test_device_engine_agrees_multichain(tmp_path):
    pol, _ = compile_policy(MULTI)
    cases = multi_cases()
    (tmp_path / "p.json").write_bytes(canonical_json(pol))
    (tmp_path / "t.json").write_text(json.dumps([to_rpc_tx(t) for t, _ in cases]))
    out = subprocess.run([str(POLICY_CLI), str(tmp_path / "p.json"), SELF, str(tmp_path / "t.json")],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    for (tx, want), line in zip(cases, out, strict=True):
        assert line.startswith("ALLOW" if want else "DENY"), (tx, line)
