"""Uniswap v4 wARS/USDC pools: price, quotes, swap calldata, approvals.

Both pools have currency0 = wARS (lower address) and currency1 = USDC, so
zeroForOne=True sells wARS for USDC and zeroForOne=False buys wARS with USDC.
"""

from __future__ import annotations

import time

from eth_abi import encode
from eth_utils import keccak
from web3.exceptions import ContractLogicError

from .chain import Chain, calldata, selector
from .config import NO_HOOKS, PERMIT2, USDC_DECIMALS, WARS, WARS_DECIMALS, ChainInfo

# Universal Router command and v4 router actions
V4_SWAP = 0x10
SWAP_EXACT_IN_SINGLE, SETTLE_ALL, TAKE_ALL = 0x06, 0x0C, 0x0F
POOL_KEY = "(address,address,uint24,int24,address)"
MAX_UINT160 = 2**160 - 1
MAX_UINT48 = 2**48 - 1


Pool = tuple[int, int]  # (fee, tickSpacing); None below means the chain's main pool


def pool_key(c: ChainInfo, pool: Pool | None = None) -> tuple:
    fee, spacing = pool or (c.pool_fee, c.tick_spacing)
    return (WARS, c.usdc, fee, spacing, NO_HOOKS)


def pool_id(c: ChainInfo, pool: Pool | None = None) -> bytes:
    return keccak(encode([POOL_KEY], [pool_key(c, pool)]))


def pool_name(pool: Pool) -> str:
    return f"{pool[0] / 1e4:g}%"


def price_usdc_per_wars(chain: Chain, pool: Pool | None = None) -> float:
    """Mid price from slot0: USDC per 1 wARS."""
    sqrt_p, *_ = chain.call(chain.info.state_view, "getSlot0(bytes32)", ["bytes32"], [pool_id(chain.info, pool)],
                            ["uint160", "int24", "uint24", "uint24"])
    raw = (sqrt_p / 2**96) ** 2  # currency1 raw units per currency0 raw unit
    return raw * 10 ** (WARS_DECIMALS - USDC_DECIMALS)


def quote_exact_in(chain: Chain, zero_for_one: bool, amount_in: int, pool: Pool | None = None) -> int:
    """V4Quoter.quoteExactInputSingle via eth_call. Returns amountOut (raw units).

    Returns 0 when the quoter reverts, e.g. NotEnoughLiquidity: the pool cannot
    fill this size in this direction (concentrated liquidity can run out on one
    side of the current price).
    """
    try:
        out, _gas = chain.call(
            chain.info.quoter,
            f"quoteExactInputSingle(({POOL_KEY},bool,uint128,bytes))",
            [f"({POOL_KEY},bool,uint128,bytes)"],
            [(pool_key(chain.info, pool), zero_for_one, amount_in, b"")],
            ["uint256", "uint256"],
        )
    except ContractLogicError:
        return 0
    return out


def best_quote(chain: Chain, zero_for_one: bool, amount_in: int) -> tuple[int, Pool]:
    """The chain's pool that returns the most for amount_in, and that amount (0 if none can fill)."""
    return max(((quote_exact_in(chain, zero_for_one, amount_in, p), p) for p in chain.info.pools),
               key=lambda q: q[0])


def swap_calldata(c: ChainInfo, zero_for_one: bool, amount_in: int, min_out: int, deadline: int | None = None,
                  pool: Pool | None = None) -> str:
    """UniversalRouter.execute(V4_SWAP) with SWAP_EXACT_IN_SINGLE, SETTLE_ALL, TAKE_ALL.

    This exact layout is what policies/wars-arb-base-celo.yaml pins.
    """
    tin, tout = (WARS, c.usdc) if zero_for_one else (c.usdc, WARS)
    swap = encode([f"({POOL_KEY},bool,uint128,uint128,bytes)"],
                  [(pool_key(c, pool), zero_for_one, amount_in, min_out, b"")])
    settle = encode(["address", "uint256"], [tin, amount_in])
    take = encode(["address", "uint256"], [tout, min_out])
    actions = bytes([SWAP_EXACT_IN_SINGLE, SETTLE_ALL, TAKE_ALL])
    v4_input = encode(["bytes", "bytes[]"], [actions, [swap, settle, take]])
    deadline = deadline or int(time.time()) + 120
    return "0x" + (selector("execute(bytes,bytes[],uint256)")
                   + encode(["bytes", "bytes[]", "uint256"], [bytes([V4_SWAP]), [v4_input], deadline])).hex()


# ------------------------------------------------------------- approvals ---

def permit2_allowance(chain: Chain, token: str) -> tuple[int, int]:
    amount, expiration, _nonce = chain.call(
        PERMIT2, "allowance(address,address,address)", ["address", "address", "address"],
        [chain.address, token, chain.info.router], ["uint160", "uint48", "uint48"])
    return amount, expiration


def ensure_swap_approvals(chain: Chain) -> list:
    """token.approve(Permit2, max) and Permit2.approve(token, router, max, never) for wARS and USDC."""
    sent = []
    for token, name in ((WARS, "wARS"), (chain.info.usdc, "USDC")):
        if chain.erc20_allowance(token, PERMIT2) < 2**200:
            sent.append(chain.send(token, calldata("approve(address,uint256)", ["address", "uint256"],
                                                   [PERMIT2, 2**256 - 1]), f"{name}.approve(Permit2)", fallback_gas=80_000))
        amount, expiration = permit2_allowance(chain, token)
        if amount < 2**150 or expiration < time.time() + 30 * 86400:
            sent.append(chain.send(PERMIT2, calldata("approve(address,address,uint160,uint48)",
                                                     ["address", "address", "uint160", "uint48"],
                                                     [token, chain.info.router, MAX_UINT160, MAX_UINT48]),
                                   f"Permit2.approve({name}, router)", fallback_gas=80_000))
    return sent


def swap_ready(chain: Chain, min_native: int) -> str | None:
    """None if this chain can swap right now; otherwise the reason it cannot.

    Checked before every arb so a missing approval or empty gas balance on one
    chain cannot leave the other leg executed alone.
    """
    if chain.native_balance() < min_native:
        return f"{chain.info.name}: native balance below {min_native / 1e18:g} {chain.info.native} for gas"
    for token, name in ((WARS, "wARS"), (chain.info.usdc, "USDC")):
        if chain.erc20_allowance(token, PERMIT2) < 2**200:
            return f"{chain.info.name}: {name} not approved to Permit2 (run setup-approvals --live)"
        amount, expiration = permit2_allowance(chain, token)
        if amount < 2**150 or expiration < time.time() + 86400:
            return f"{chain.info.name}: Permit2 allowance for {name} to the router missing (run setup-approvals --live)"
    return None
