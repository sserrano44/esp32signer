"""Ripio bridge (bridge.ripio.com): burn-and-mint wARS between chains.

depositForBridge burns `amount - fee` from the sender and pulls the fixed
route fee with transferFrom, so BridgeDeposit needs an allowance of `amount`.
The operator mints `amount - fee` to destRecipient on the destination chain.
Docs: https://docs.ripio.com/wfiat/bridge.md
"""

from __future__ import annotations

import os

import requests

from .chain import Chain, Sent, calldata
from .config import RIPIO_BRIDGE, WARS, ChainInfo

API = "https://bridge.ripio.com/api"


# The Base<->Celo route fee is a fixed 15 wARS. A larger value means the route
# changed or the RPC is lying; the fee is added to every transfer, so bound it.
MAX_ROUTE_FEE = 100 * 10**18


def route(chain: Chain, dest: ChainInfo) -> tuple[bool, int]:
    """(enabled, fixed fee in wARS raw units) for wARS chain -> dest."""
    return chain.call(RIPIO_BRIDGE, "routeConfigs(address,uint256)", ["address", "uint256"],
                      [WARS, dest.chain_id], ["bool", "uint256"])


def mint_capacity(dest_chain: Chain) -> int:
    """Remaining daily mint capacity on the destination chain (wARS raw units)."""
    remaining, _max, _today = dest_chain.call(RIPIO_BRIDGE, "remainingMintCapacity(address)", ["address"], [WARS],
                                              ["uint256", "uint256", "uint256"])
    return remaining


def deposit_calldata(amount: int, dest: ChainInfo, recipient: str) -> str:
    return calldata("depositForBridge(address,uint256,uint256,address,bytes32)",
                    ["address", "uint256", "uint256", "address", "bytes32"],
                    [WARS, amount, dest.chain_id, recipient, os.urandom(32)])


def bridge_wars(chain: Chain, dest: ChainInfo, amount: int) -> list[Sent]:
    """Approve exactly `amount` (if needed) and deposit. The recipient is always this signer."""
    enabled, fee = route(chain, dest)
    if not enabled:
        raise RuntimeError(f"Ripio bridge route wARS {chain.info.name} -> {dest.name} is disabled")
    if fee > MAX_ROUTE_FEE:
        raise RuntimeError(f"Ripio route fee {fee / 1e18:g} wARS is above {MAX_ROUTE_FEE / 1e18:g}")
    if amount <= fee:
        raise RuntimeError(f"bridge amount must exceed the route fee ({fee / 1e18:g} wARS)")
    sent = []
    if chain.erc20_allowance(WARS, RIPIO_BRIDGE) < amount:
        sent.append(chain.send(WARS, calldata("approve(address,uint256)", ["address", "uint256"], [RIPIO_BRIDGE, amount]),
                               "wARS.approve(RipioBridge, amount)", fallback_gas=80_000))
    sent.append(chain.send(RIPIO_BRIDGE, deposit_calldata(amount, dest, chain.address),
                           f"RipioBridge.depositForBridge({amount / 1e18:,.0f} wARS -> {dest.name})", fallback_gas=200_000))
    return sent


def status(source_tx: str, source_chain_id: int) -> dict | None:
    """Operation from the public status API, or None if not indexed yet.

    status: DETECTED, PENDING_FINALITY, READY_FOR_MINT, QUEUED_DAILY_LIMIT,
    MINTING, AWAITING_SIGNATURES, EXECUTING, COMPLETED, FAILED.
    """
    r = requests.get(f"{API}/operations/{source_tx}", params={"chainId": source_chain_id}, timeout=15)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    op = r.json().get("operation")
    if op is not None:
        check_operation(op, source_tx, source_chain_id)
    return op


def check_operation(op: dict, source_tx: str, source_chain_id: int) -> None:
    """The API's answer must be about the transfer we asked for."""
    if str(op.get("source_tx_hash", "")).lower() != source_tx.lower():
        raise RuntimeError(f"Ripio status for {source_tx} names another tx: {op.get('source_tx_hash')!r}")
    if int(op.get("source_chain_id", -1)) != source_chain_id:
        raise RuntimeError(f"Ripio status for {source_tx} names chain {op.get('source_chain_id')!r}")
