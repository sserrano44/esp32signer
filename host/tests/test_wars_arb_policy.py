"""policies/wars-arb-base-celo.yaml against real encodings and attack variants.

Checked with the Python evaluator and, when build-test/policy_cli exists, with
the C engine that runs on the device.
"""

import json
import subprocess
from pathlib import Path

import pytest
from eth_abi import encode
from eth_utils import keccak

from esp32signer.client import to_rpc_tx
from esp32signer.policy_compiler import canonical_json, compile_policy, evaluate

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policies" / "wars-arb-base-celo.yaml"
POLICY_CLI = ROOT / "build-test" / "policy_cli"
LIFI = json.loads((Path(__file__).parent / "fixtures" / "lifi_layerswap_celo_to_base.json").read_text())

SELF = "0x1111111111111111111111111111111111111111"  # the fixture was quoted for this address
EVIL = "0x2222222222222222222222222222222222222222"
WARS = "0x0dc4f92879b7670e5f4e4e6e3c801d229129d90d"
BRIDGE = "0x465e642387d3d73a57cdc1368ffa53a800ba5d47"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
BASE = dict(chain=8453, usdc="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            router="0x6ff5693b99212da76ad316178a184ab56d299b43", fee=500, ts=5)
BASE30 = {**BASE, "fee": 3000, "ts": 60}  # Base's second wARS/USDC pool (0.3%)
CELO = dict(chain=42220, usdc="0xceba9300f2b948710d2653dd7b07f33a8b32118c",
            router="0xcb695bc5d3aa22cad1e6df07801b061a05a0233a", fee=3000, ts=30)


def sel(sig):
    return keccak(text=sig)[:4].hex()


def tx(chain, to, data, fee=None, **kw):
    t = {"type": 2, "chainId": chain, "nonce": 0, "gas": 400_000, "to": to, "value": 0, "data": data,
         "maxFeePerGas": fee or (250 * 10**9 if chain == 42220 else 10**8), "maxPriorityFeePerGas": 10**6}
    t.update(kw)
    return t


def swap(c, zero_for_one, fee=None, hooks="0x" + "0" * 40, actions=b"\x06\x0c\x0f", take=None):
    tin, tout = (WARS, c["usdc"]) if zero_for_one else (c["usdc"], WARS)
    p0 = encode(["((address,address,uint24,int24,address),bool,uint128,uint128,bytes)"],
                [((WARS, c["usdc"], fee or c["fee"], c["ts"], hooks), zero_for_one, 10**18, 1, b"")])
    p1 = encode(["address", "uint256"], [tin, 10**18])
    p2 = encode(["address", "uint256"], [take or tout, 1])
    inp = encode(["bytes", "bytes[]"], [actions, [p0, p1, p2]])
    return "0x" + sel("execute(bytes,bytes[],uint256)") + encode(["bytes", "bytes[]", "uint256"],
                                                                 [b"\x10", [inp], 1_800_000_000]).hex()


def bridge(dest, rcpt=SELF, token=WARS):
    return "0x" + sel("depositForBridge(address,uint256,uint256,address,bytes32)") + encode(
        ["address", "uint256", "uint256", "address", "bytes32"], [token, 10**20, dest, rcpt, b"\0" * 32]).hex()


def approve(spender):
    return "0x095ea7b3" + spender[2:].rjust(64, "0") + "f" * 64


def p2approve(token, spender):
    return "0x" + sel("approve(address,address,uint160,uint48)") + encode(
        ["address", "address", "uint160", "uint48"], [token, spender, 2**160 - 1, 2**47]).hex()


def lifi(replace=None):
    d = LIFI["data"].lower()
    if replace:
        old, new = replace
        assert d.count(old) >= 1, old
        d = d.replace(old, new, 1)
    return d


S, E = SELF[2:], EVIL[2:]
FEE_WALLET = "c06ebbefd94032b85424d51906e2a335efae264b"

CASES = [
    # --- allowed ---
    ("base swap wARS->USDC", tx(8453, BASE["router"], swap(BASE, True)), True),
    ("base swap USDC->wARS", tx(8453, BASE["router"], swap(BASE, False)), True),
    ("base 0.3% swap wARS->USDC", tx(8453, BASE["router"], swap(BASE30, True)), True),
    ("base 0.3% swap USDC->wARS", tx(8453, BASE["router"], swap(BASE30, False)), True),
    ("base pool fee 3000 with tickSpacing 5", tx(8453, BASE["router"], swap({**BASE, "fee": 3000}, True)), False),
    ("base pool fee 500 with tickSpacing 60", tx(8453, BASE["router"], swap({**BASE30, "fee": 500}, True)), False),
    ("base pool fee 3000 tickSpacing 30 (celo's)", tx(8453, BASE["router"], swap({**BASE30, "ts": 30}, True)), False),
    ("celo router with base's 0.3% key", tx(42220, CELO["router"], swap({**CELO, "ts": 60}, True)), False),
    ("celo swap wARS->USDC", tx(42220, CELO["router"], swap(CELO, True)), True),
    ("celo swap USDC->wARS", tx(42220, CELO["router"], swap(CELO, False)), True),
    ("bridge base->celo", tx(8453, BRIDGE, bridge(42220)), True),
    ("bridge celo->base", tx(42220, BRIDGE, bridge(8453)), True),
    ("wARS approve permit2 (celo)", tx(42220, WARS, approve(PERMIT2)), True),
    ("wARS approve bridge (base)", tx(8453, WARS, approve(BRIDGE)), True),
    ("usdc approve permit2 (base)", tx(8453, BASE["usdc"], approve(PERMIT2)), True),
    ("usdc approve lifi (celo)", tx(42220, CELO["usdc"], approve(LIFI["to"].lower())), True),
    ("permit2 -> router (base)", tx(8453, PERMIT2, p2approve(BASE["usdc"], BASE["router"])), True),
    ("permit2 -> router (celo)", tx(42220, PERMIT2, p2approve(WARS, CELO["router"])), True),
    ("lifi usdc celo->base", tx(42220, LIFI["to"], lifi()), True),
    # --- denied ---
    ("base gas price at celo level", tx(8453, BASE["router"], swap(BASE, True), fee=30 * 10**9), False),
    ("celo above cap", tx(42220, CELO["router"], swap(CELO, True), fee=600 * 10**9), False),
    ("celo pool key on base router", tx(8453, BASE["router"], swap(CELO, True)), False),
    ("base router on celo", tx(42220, BASE["router"], swap(BASE, True)), False),
    ("wrong fee tier", tx(8453, BASE["router"], swap(BASE, True, fee=3000)), False),
    ("hooked pool", tx(8453, BASE["router"], swap(BASE, True, hooks=EVIL)), False),
    ("TAKE instead of TAKE_ALL", tx(8453, BASE["router"], swap(BASE, True, actions=b"\x06\x0c\x0e")), False),
    ("take other token", tx(8453, BASE["router"], swap(BASE, True, take=EVIL)), False),
    ("bridge to attacker", tx(8453, BRIDGE, bridge(42220, rcpt=EVIL)), False),
    ("bridge to other chain", tx(8453, BRIDGE, bridge(1)), False),
    ("bridge usdc", tx(8453, BRIDGE, bridge(42220, token=BASE["usdc"])), False),
    ("approve attacker", tx(8453, WARS, approve(EVIL)), False),
    ("usdc approve lifi on base", tx(8453, BASE["usdc"], approve(LIFI["to"].lower())), False),
    ("permit2 spender attacker", tx(8453, PERMIT2, p2approve(WARS, EVIL)), False),
    ("permit2 celo router on base", tx(8453, PERMIT2, p2approve(WARS, CELO["router"])), False),
    ("lifi from base", tx(8453, LIFI["to"], lifi()), False),
    ("lifi receiver attacker", tx(42220, LIFI["to"], lifi(("0" * 24 + S, "0" * 24 + E))), False),
    ("lifi refund attacker", tx(42220, LIFI["to"], lifi(("0" * 24 + S + "0" * 64, "0" * 24 + E + "0" * 64))), False),
    ("lifi fee to attacker", tx(42220, LIFI["to"], lifi((FEE_WALLET, E))), False),
    ("lifi destination call", tx(42220, LIFI["to"], lifi(("0" * 63 + "1" + "0" * 64 + "0" * 63 + "9",
                                                         "0" * 63 + "1" + "0" * 63 + "1" + "0" * 63 + "9"))), False),
    ("lifi trailing bytes", tx(42220, LIFI["to"], lifi() + "00"), False),
    ("native transfer", tx(8453, EVIL, "0x", value=1), False),
    ("usdc transfer", tx(8453, BASE["usdc"], "0xa9059cbb" + "0" * 24 + E + "f" * 64), False),
]


@pytest.fixture(scope="module")
def policy():
    pol, warnings = compile_policy(POLICY.read_text())
    assert not warnings
    return pol


@pytest.mark.parametrize("name,t,want", CASES, ids=[c[0] for c in CASES])
def test_python_evaluator(policy, name, t, want):
    got, reason = evaluate(policy, t, SELF)
    assert got == want, reason


def test_lifi_mutations_are_real():
    # The mutated LI.FI cases above must actually change the calldata.
    for name, t, _ in CASES:
        if name.startswith("lifi ") and name != "lifi from base" and name != "lifi trailing bytes" \
                and name != "lifi usdc celo->base":
            assert t["data"] != lifi(), name


@pytest.mark.skipif(not POLICY_CLI.exists(), reason="build firmware/test_host first (build-test/policy_cli)")
def test_device_engine(policy, tmp_path):
    (tmp_path / "p.json").write_bytes(canonical_json(policy))
    (tmp_path / "t.json").write_text(json.dumps([to_rpc_tx(t) for _, t, _ in CASES]))
    out = subprocess.run([str(POLICY_CLI), str(tmp_path / "p.json"), SELF, str(tmp_path / "t.json")],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    for (name, _, want), line in zip(CASES, out, strict=True):
        assert line.startswith("ALLOW" if want else "DENY"), f"{name}: {line}"
