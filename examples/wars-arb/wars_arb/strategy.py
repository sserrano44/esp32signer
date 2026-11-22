"""Pure decision logic: no I/O, unit-tested in tests/test_strategy.py.

Amounts are raw token units (wARS 18 decimals, USDC 6 decimals) unless the
name says otherwise.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

USDC = 10**6
WARS = 10**18


def spread_bps(p_cheap: float, p_rich: float) -> float:
    return (p_rich / p_cheap - 1) * 1e4


@dataclass(frozen=True)
class Opportunity:
    cheap: str  # chain key where wARS is bought with USDC
    rich: str  # chain key where that wARS is sold for USDC
    usdc_in: int
    wars: int  # bought on cheap, sold on rich
    usdc_out: int
    gas_usdc: float
    buy_pool: object = None  # which pool each leg trades on (opaque to the strategy)
    sell_pool: object = None

    @property
    def profit_usdc(self) -> float:
        return (self.usdc_out - self.usdc_in) / USDC - self.gas_usdc


def size_trade(
    cheap: str,
    rich: str,
    ladder_usdc: list[float],
    max_trade_usdc: float,
    usdc_on_cheap: int,
    wars_on_rich: int,
    quote_buy: Callable[[int], int],  # USDC in -> wARS out on the cheap pool
    quote_sell: Callable[[int], int],  # wARS in -> USDC out on the rich pool
    gas_usdc: float,
) -> Opportunity | None:
    """Try each ladder size; return the most profitable one (or None).

    Both legs are sized from inventory already on each chain, so they can be
    sent at the same time without waiting for any bridge.
    """
    best: Opportunity | None = None
    for size in sorted(ladder_usdc):
        usdc_in = int(min(size, max_trade_usdc) * USDC)
        if usdc_in <= 0 or usdc_in > usdc_on_cheap:
            break
        wars, buy_pool = _quote(quote_buy, usdc_in)
        if wars <= 0 or wars > wars_on_rich:
            break
        usdc_out, sell_pool = _quote(quote_sell, wars)
        if usdc_out <= 0:
            break  # the rich pool cannot absorb this much wARS
        opp = Opportunity(cheap, rich, usdc_in, wars, usdc_out, gas_usdc, buy_pool, sell_pool)
        if best is None or opp.profit_usdc > best.profit_usdc:
            best = opp
        elif opp.profit_usdc < best.profit_usdc:
            break  # past the optimum: price impact now eats the spread
        if size >= max_trade_usdc:
            break
    return best


def _quote(f: Callable, amount: int) -> tuple[int, object]:
    """Quote callables return an amount, or (amount, pool) when a chain has several pools."""
    r = f(amount)
    return r if isinstance(r, tuple) else (r, None)


def min_out(amount: int, slippage_bps: float) -> int:
    return amount * int(1e4 - slippage_bps) // 10_000


@dataclass(frozen=True)
class Transfer:
    asset: str  # "wARS" | "USDC"
    src: str
    dst: str
    amount: int


def plan_wars_rebalance(wars: dict[str, int], inflight_to: dict[str, int], min_per_chain: int,
                        min_bridge: int, route_fee: int) -> Transfer | None:
    """Bridge wARS to the chain that is below `min_per_chain` (counting in-flight).

    Moves enough to even out the two chains, never leaving the source below
    its own minimum. Returns None if nothing is needed or nothing useful fits.
    """
    (a, b) = sorted(wars)
    eff = {k: wars[k] + inflight_to.get(k, 0) for k in (a, b)}
    low, high = (a, b) if eff[a] <= eff[b] else (b, a)
    if eff[low] >= min_per_chain:
        return None
    amount = (eff[high] - eff[low]) // 2 + route_fee  # the fee is taken from the bridged amount
    amount = min(amount, wars[high] - min_per_chain)  # keep the source tradable
    if amount < max(min_bridge, route_fee * 2):
        return None
    return Transfer("wARS", high, low, amount)


def plan_usdc_rebalance(usdc: dict[str, int], inflight_to: dict[str, int], min_per_chain: int,
                        min_transfer: int) -> tuple[Transfer | None, str | None]:
    """(transfer, alert). Only Celo -> Base is automated (LI.FI/LayerSwap)."""
    eff = {k: usdc[k] + inflight_to.get(k, 0) for k in usdc}
    if eff["base"] < min_per_chain:
        amount = min((eff["celo"] - eff["base"]) // 2, usdc["celo"] - min_per_chain)
        if amount >= min_transfer:
            return Transfer("USDC", "celo", "base", amount), None
        return None, "USDC low on Base and not enough spare USDC on Celo"
    if eff["celo"] < min_per_chain and usdc["base"] - min_per_chain >= min_transfer:
        return None, ("USDC low on Celo: no policy-safe route Base -> Celo (LI.FI only offers Squid); "
                      "top up Celo manually or wait for the spread to flip")
    return None, None
