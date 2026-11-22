from wars_arb.strategy import (USDC, WARS, Opportunity, min_out, plan_usdc_rebalance, plan_wars_rebalance,
                               size_trade, spread_bps)

PRICE_CHEAP = 1 / 1720  # USDC per wARS
PRICE_RICH = 1 / 1770


def amm(price, fee_bps, depth_usdc):
    """Toy constant-product pool for quote functions."""
    x = depth_usdc / price * WARS  # wARS reserve
    y = depth_usdc * USDC  # USDC reserve
    f = 1 - fee_bps / 1e4
    buy = lambda u: int(x - x * y / (y + u * f))  # USDC in -> wARS out
    sell = lambda w: int(y - x * y / (x + w * f))  # wARS in -> USDC out
    return buy, sell


def test_spread():
    assert round(spread_bps(1.0, 1.01)) == 100


def test_size_trade_picks_optimum_and_respects_inventory():
    buy, _ = amm(1 / 1770, 5, 400_000)  # wARS cheap where 1 USDC buys 1770
    _, sell = amm(1 / 1720, 30, 60_000)  # wARS rich where 1720 wARS sell for 1 USDC
    ladder = [50, 100, 250, 500, 1000, 2000, 5000]
    opp = size_trade("base", "celo", ladder, 5000, 10_000 * USDC, 10**12 * WARS, buy, sell, gas_usdc=0.1)
    assert opp is not None and opp.profit_usdc > 0
    # A deep cheap pool and a shallow rich pool: impact caps the size below the max.
    assert opp.usdc_in < 5000 * USDC
    # Inventory caps: no USDC on the cheap chain -> nothing.
    assert size_trade("base", "celo", ladder, 5000, 0, 10**12 * WARS, buy, sell, 0.1) is None
    # Not enough wARS on the rich chain for even the smallest size -> nothing.
    assert size_trade("base", "celo", ladder, 5000, 10_000 * USDC, 1000 * WARS, buy, sell, 0.1) is None


def test_size_trade_stops_when_rich_pool_has_no_liquidity():
    buy, _ = amm(1 / 1770, 5, 400_000)
    _, sell = amm(1 / 1720, 5, 400_000)
    ladder = [50, 100, 250]
    # Quoter reverts (returned as 0) at every size -> no opportunity.
    assert size_trade("celo", "base", ladder, 250, 10_000 * USDC, 10**12 * WARS, buy, lambda w: 0, 0.1) is None
    # Liquidity runs out above 100 USDC worth -> the 100 size is the best that fills.
    capped = lambda w: sell(w) if w <= 100 * 1770 * WARS else 0
    opp = size_trade("celo", "base", ladder, 250, 10_000 * USDC, 10**12 * WARS, buy, capped, 0.1)
    assert opp is not None and opp.usdc_in == 100 * USDC


def test_size_trade_records_pools():
    buy, _ = amm(1 / 1800, 30, 2_000)
    _, sell = amm(1 / 1770, 30, 100_000)
    opp = size_trade("base", "celo", [5, 10, 25], 25, 10_000 * USDC, 10**12 * WARS,
                     lambda u: (buy(u), (3000, 60)), lambda w: (sell(w), (3000, 30)), 0.0)
    assert opp is not None and opp.buy_pool == (3000, 60) and opp.sell_pool == (3000, 30)


def test_no_profit_when_flat():
    buy, sell = amm(1 / 1750, 5, 400_000)
    opp = size_trade("base", "celo", [100, 500], 500, 10_000 * USDC, 10**12 * WARS, buy, sell, 0.1)
    assert opp is not None and opp.profit_usdc < 0


def test_min_out():
    assert min_out(10_000, 30) == 9_970


def test_wars_rebalance():
    m = 300_000 * WARS
    fee = 15 * WARS
    # Base drained, Celo full -> bridge Celo -> Base about half the difference (+fee).
    t = plan_wars_rebalance({"base": 100_000 * WARS, "celo": 2_000_000 * WARS}, {}, m, 100_000 * WARS, fee)
    assert t and (t.src, t.dst) == ("celo", "base") and t.amount == 950_000 * WARS + fee
    # Already in flight -> nothing.
    assert plan_wars_rebalance({"base": 100_000 * WARS, "celo": 2_000_000 * WARS}, {"base": 900_000 * WARS},
                               m, 100_000 * WARS, fee) is None
    # Source would drop below its own minimum -> limited.
    t = plan_wars_rebalance({"base": 0, "celo": 500_000 * WARS}, {}, m, 100_000 * WARS, fee)
    assert t and t.amount == 200_000 * WARS
    # Too small to be worth it.
    assert plan_wars_rebalance({"base": 0, "celo": 350_000 * WARS}, {}, m, 100_000 * WARS, fee) is None


def test_usdc_rebalance_only_celo_to_base():
    m = 200 * USDC
    t, alert = plan_usdc_rebalance({"base": 50 * USDC, "celo": 2_000 * USDC}, {}, m, 200 * USDC)
    assert alert is None and t and (t.src, t.dst) == ("celo", "base") and t.amount == 975 * USDC
    t, alert = plan_usdc_rebalance({"base": 2_000 * USDC, "celo": 50 * USDC}, {}, m, 200 * USDC)
    assert t is None and "no policy-safe route" in alert
    assert plan_usdc_rebalance({"base": 500 * USDC, "celo": 500 * USDC}, {}, m, 200 * USDC) == (None, None)
    t, _ = plan_usdc_rebalance({"base": 50 * USDC, "celo": 2_000 * USDC}, {"base": 1_000 * USDC}, m, 200 * USDC)
    assert t is None


def test_opportunity_profit():
    o = Opportunity("base", "celo", 1000 * USDC, 0, 1010 * USDC, 0.5)
    assert o.profit_usdc == 9.5
