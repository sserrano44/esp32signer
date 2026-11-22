"""The bot's encoders must produce exactly what the device policy allows."""

import json
from pathlib import Path

import pytest

from esp32signer.policy_compiler import compile_policy, evaluate
from wars_arb import config, lifi, ripio_bridge, uniswap_v4

ROOT = Path(__file__).resolve().parents[3]
POLICY, _ = compile_policy((ROOT / "policies" / "wars-arb-base-celo.yaml").read_text())
FIXTURE = json.loads((ROOT / "host" / "tests" / "fixtures" / "lifi_layerswap_celo_to_base.json").read_text())
SELF = "0x1111111111111111111111111111111111111111"


def tx(c, to, data):
    return {"type": 2, "chainId": c.chain_id, "nonce": 0, "gas": 300_000, "to": to, "value": 0, "data": data,
            "maxFeePerGas": c.max_fee_per_gas, "maxPriorityFeePerGas": c.max_priority_fee}


@pytest.mark.parametrize("c", [config.BASE, config.CELO], ids=["base", "celo"])
@pytest.mark.parametrize("zfo", [True, False])
def test_swap_allowed(c, zfo):
    data = uniswap_v4.swap_calldata(c, zfo, 123 * 10**18, 456)
    ok, reason = evaluate(POLICY, tx(c, c.router, data), SELF)
    assert ok, reason


def test_swap_on_wrong_chain_denied():
    data = uniswap_v4.swap_calldata(config.CELO, True, 1, 1)
    assert not evaluate(POLICY, tx(config.BASE, config.BASE.router, data), SELF)[0]


@pytest.mark.parametrize("zfo", [True, False])
@pytest.mark.parametrize("pool", config.BASE.pools, ids=lambda p: f"fee{p[0]}")
def test_every_base_pool_swap_allowed(pool, zfo):
    data = uniswap_v4.swap_calldata(config.BASE, zfo, 123 * 10**18, 456, pool=pool)
    ok, reason = evaluate(POLICY, tx(config.BASE, config.BASE.router, data), SELF)
    assert ok, reason


def test_base_pool_not_in_policy_denied():
    data = uniswap_v4.swap_calldata(config.BASE, True, 1, 1, pool=(10000, 200))
    assert not evaluate(POLICY, tx(config.BASE, config.BASE.router, data), SELF)[0]


@pytest.mark.parametrize("c", [config.BASE, config.CELO], ids=["base", "celo"])
def test_bridge_allowed(c):
    data = ripio_bridge.deposit_calldata(10**21, config.other(c), SELF)
    ok, reason = evaluate(POLICY, tx(c, config.RIPIO_BRIDGE, data), SELF)
    assert ok, reason


def test_policy_caps_match_bot():
    for cl in [{"chain_id": 8453, **POLICY["limits"]}] + POLICY["chain_limits"]:
        c = config.BY_ID[cl["chain_id"]]
        assert int(cl["max_fee_per_gas"]) == c.max_fee_per_gas
        assert int(cl["max_priority_fee_per_gas"]) == c.max_priority_fee
        assert cl["max_gas"] == c.max_gas


def test_pool_ids_match_chain():
    assert uniswap_v4.pool_id(config.BASE).hex().startswith("187ced7f")
    assert uniswap_v4.pool_id(config.CELO).hex().startswith("59f80a50")
    assert uniswap_v4.pool_id(config.BASE, (3000, 60)).hex().startswith("c33b0427")


def test_lifi_quote_check():
    q = {"tool": "layerswap", "transactionRequest": {"to": FIXTURE["to"], "value": "0x0", "data": FIXTURE["data"]},
         "estimate": {"toAmountMin": "497000000"}}
    received, bps = lifi.check_quote(q, SELF, 500_000_000)
    assert received == 497_000_000 and round(bps) == 60
    with pytest.raises(lifi.BadQuote, match="receiver"):
        lifi.check_quote(q, "0x2222222222222222222222222222222222222222", 500_000_000)
    assert evaluate(POLICY, tx(config.CELO, FIXTURE["to"], FIXTURE["data"]), SELF)[0]
