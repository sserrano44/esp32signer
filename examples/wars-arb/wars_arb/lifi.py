"""LI.FI USDC transfers Celo -> Base via LayerSwap.

This is the only LI.FI route the device policy allows (see
policies/wars-arb-base-celo.yaml): LI.FI offers Base -> Celo USDC only
through Squid, whose calldata carries arbitrary calls that a regex cannot
pin safely. The bot decodes every quote and checks the fields the policy
pins before asking the device to sign; the device checks them again.
"""

from __future__ import annotations

import requests
from eth_abi import decode
from eth_utils import keccak

from .chain import Chain, Sent, calldata
from .config import BASE, CELO, LIFI_DIAMOND, USDC_DECIMALS

API = "https://li.quest/v1"
FN = ("swapAndStartBridgeTokensViaLayerSwap((bytes32,string,string,address,address,address,uint256,uint256,bool,bool),"
      "(address,address,address,address,uint256,bytes,bool)[],(bytes32,address,address,bytes32,bytes,uint256))")
ARGS = ["(bytes32,string,string,address,address,address,uint256,uint256,bool,bool)",
        "(address,address,address,address,uint256,bytes,bool)[]",
        "(bytes32,address,address,bytes32,bytes,uint256)"]


class BadQuote(RuntimeError):
    pass


def quote_celo_to_base(amount: int, address: str) -> dict:
    params = {"fromChain": CELO.chain_id, "toChain": BASE.chain_id, "fromToken": CELO.usdc, "toToken": BASE.usdc,
              "fromAmount": str(amount), "fromAddress": address, "toAddress": address,
              "allowBridges": "layerswap", "slippage": "0.005"}
    r = requests.get(f"{API}/quote", params=params, timeout=30)
    if r.status_code != 200:
        raise BadQuote(f"LI.FI quote failed: {r.status_code} {r.text[:200]}")
    return r.json()


def check_quote(q: dict, address: str, amount: int) -> tuple[int, float]:
    """Verify the quote matches what we asked for. Returns (min received, total fee bps)."""
    tx = q["transactionRequest"]
    if q.get("tool") != "layerswap":
        raise BadQuote(f"unexpected bridge {q.get('tool')!r}")
    if tx["to"].lower() != LIFI_DIAMOND.lower() or int(tx.get("value", "0x0"), 16) != 0:
        raise BadQuote("unexpected target or value")
    data = bytes.fromhex(tx["data"][2:])
    if data[:4] != keccak(text=FN)[:4]:
        raise BadQuote(f"unexpected function 0x{data[:4].hex()}")
    bridge, swaps, ls = decode(ARGS, data[4:])
    me = address.lower()
    checks = {
        "sendingAssetId": bridge[4].lower() == CELO.usdc.lower(),
        "receiver": bridge[5].lower() == me,
        "destinationChainId": bridge[7] == BASE.chain_id,
        "hasDestinationCall": bridge[9] is False,
        "refundRecipient": ls[2].lower() == me,
        "single fee swap": len(swaps) == 1 and swaps[0][4] == amount,
    }
    failed = [k for k, ok in checks.items() if not ok]
    if failed:
        raise BadQuote(f"quote fields do not match: {failed}")
    received = int(q["estimate"]["toAmountMin"])
    fee_bps = (amount - received) / amount * 1e4
    return received, fee_bps


def transfer_celo_to_base(celo: Chain, amount: int, max_fee_bps: float) -> list[Sent]:
    q = quote_celo_to_base(amount, celo.address)
    received, fee_bps = check_quote(q, celo.address, amount)
    if fee_bps > max_fee_bps:
        raise BadQuote(f"LI.FI cost {fee_bps:.0f} bps > max {max_fee_bps:.0f} bps "
                       f"({amount / 10**USDC_DECIMALS:,.2f} -> {received / 10**USDC_DECIMALS:,.2f} USDC)")
    sent = []
    # Exact-amount approval, right before the transfer (LI.FI has had approval exploits).
    if celo.erc20_allowance(CELO.usdc, LIFI_DIAMOND) < amount:
        sent.append(celo.send(CELO.usdc, calldata("approve(address,uint256)", ["address", "uint256"],
                                                  [LIFI_DIAMOND, amount]), "USDC.approve(LI.FI, amount)",
                              fallback_gas=80_000))
    gas = int(q["transactionRequest"].get("gasLimit", "0x0"), 16) or None
    sent.append(celo.send(LIFI_DIAMOND, q["transactionRequest"]["data"],
                          f"LI.FI LayerSwap {amount / 10**USDC_DECIMALS:,.2f} USDC Celo -> Base "
                          f"(min {received / 10**USDC_DECIMALS:,.2f}, {fee_bps:.0f} bps)",
                          gas=gas, fallback_gas=600_000))
    return sent


def status(tx_hash: str) -> dict:
    r = requests.get(f"{API}/status", params={"txHash": tx_hash, "fromChain": CELO.chain_id,
                                               "toChain": BASE.chain_id}, timeout=20)
    r.raise_for_status()
    return r.json()  # status: NOT_FOUND | PENDING | DONE | FAILED
