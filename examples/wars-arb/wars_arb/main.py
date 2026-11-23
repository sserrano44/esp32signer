"""wARS/USDC arbitrage between Uniswap v4 on Base and Celo, signed by the ESP32.

    python -m wars_arb.main status
    python -m wars_arb.main setup-approvals [--live]
    python -m wars_arb.main run [--live] [--once] [--paper-usdc 2000 --paper-wars 3000000]
    python -m wars_arb.main resume     # clear a halt after reconciling both chains

Without --live nothing is broadcast: every transaction is still built and
signed by the device, which proves the policy accepts it.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from esp32signer.client import PolicyRejected, SignerClient

from . import config, lifi, ripio_bridge, strategy, uniswap_v4
from .chain import Chain, GasTooHigh
from .inventory import Balances, InFlight, State, balances

log = logging.getLogger("wars_arb")

# Gas money each chain must hold before the bot sends an arb leg there.
MIN_NATIVE = {"base": 5 * 10**14, "celo": 5 * 10**16}  # 0.0005 ETH, 0.05 CELO


def connect(cfg: config.Config, live: bool) -> dict[str, Chain]:
    # One client (HTTP keep-alive session) per chain: the two arb legs sign concurrently.
    signers = {k: SignerClient(cfg.signer_url, cfg.signer_token, ca=cfg.signer_ca) for k in config.CHAINS}
    address = signers["base"].accounts()[0]
    log.info("signer %s at %s (%s)", address, cfg.signer_url, "LIVE" if live else "dry-run")
    return {k: Chain(info, cfg.rpc[k], signers[k], address, live) for k, info in config.CHAINS.items()}


def fmt(b: Balances) -> str:
    return " | ".join(f"{k}: {b.wars[k] / 1e18:,.0f} wARS, {b.usdc[k] / 1e6:,.2f} USDC, "
                      f"{b.native[k] / 1e18:.4f} {config.CHAINS[k].native}" for k in b.wars)


# ---------------------------------------------------------------- commands ---

def cmd_status(cfg: config.Config, args) -> None:
    chains = connect(cfg, live=False)
    any_chain = next(iter(chains.values()))
    print("device:", any_chain.signer.status())
    print("balances:", fmt(balances(chains)))
    for k, c in chains.items():
        for pool in c.info.pools:
            p = uniswap_v4.price_usdc_per_wars(c, pool)
            print(f"{c.info.name:5} {uniswap_v4.pool_name(pool):5} pool: {1 / p:,.2f} ARS/USD "
                  f"({p * 1e6:,.2f} USDC per 1M wARS)")
    for k, c in chains.items():
        dest = config.other(c.info)
        enabled, fee = ripio_bridge.route(c, dest)
        print(f"ripio bridge {c.info.name} -> {dest.name}: {'enabled' if enabled else 'DISABLED'}, fee {fee / 1e18:g} wARS")
    state = State(cfg.state_file)
    state.refresh()
    print("in flight:", state.inflight or "none")
    if state.failed:
        print("FAILED transfers (recover manually):", state.failed)
    print("HALTED:" if state.halt else "halt: none", state.halt or "")


def cmd_resume(cfg: config.Config, args) -> None:
    state = State(cfg.state_file)
    if not state.halt:
        print("not halted")
        return
    print("clearing halt:", state.halt)
    state.clear_halt()


def cmd_setup(cfg: config.Config, args) -> None:
    chains = connect(cfg, args.live)
    for c in chains.values():
        sent = uniswap_v4.ensure_swap_approvals(c)
        log.info("%s: %s", c.info.name, f"{len(sent)} approval tx(s)" if sent else "approvals already in place")


class Bot:
    def __init__(self, cfg: config.Config, args):
        self.cfg, self.args = cfg, args
        self.chains = connect(cfg, args.live)
        self.state = State(cfg.state_file)
        self.pool = ThreadPoolExecutor(2)

    def inventory(self) -> Balances:
        b = balances(self.chains)
        if not self.args.live and (self.args.paper_usdc or self.args.paper_wars):
            for k in b.wars:  # dry-run what-if: pretend each chain holds this inventory
                b.usdc[k] = int((self.args.paper_usdc or 0) * 1e6)
                b.wars[k] = int((self.args.paper_wars or 0) * 1e18)
        return b

    def step(self) -> None:
        s = self.cfg.strategy
        self.state.refresh()
        if self.state.halt:
            log.warning("HALTED (%s): not trading or rebalancing until `resume`", self.state.halt["reason"])
            return
        bal = self.inventory()
        # Mid price (USDC per wARS) of every pool on every chain.
        prices = {k: {p: uniswap_v4.price_usdc_per_wars(c, p) for p in c.info.pools} for k, c in self.chains.items()}
        log.info("ARS/USD %s | %s", " ".join(
            f"{k} {uniswap_v4.pool_name(p)} {1 / px:.2f}" for k, ps in prices.items() for p, px in ps.items()), fmt(bal))

        # Try both directions: buy wARS where some pool has it cheapest, sell where some pool pays most.
        best = None
        for cheap, rich in (("base", "celo"), ("celo", "base")):
            spread = strategy.spread_bps(min(prices[cheap].values()), max(prices[rich].values()))
            if spread < s.min_spread_bps:
                continue
            opp = strategy.size_trade(
                cheap, rich, s.ladder_usdc, s.max_trade_usdc, bal.usdc[cheap], bal.wars[rich],
                quote_buy=lambda u, c=self.chains[cheap]: uniswap_v4.best_quote(c, False, u),
                quote_sell=lambda w, c=self.chains[rich]: uniswap_v4.best_quote(c, True, w),
                gas_usdc=s.gas_cost_usdc[cheap] + s.gas_cost_usdc[rich])
            if opp is None:
                log.info("buy on %s / sell on %s (%.0f bps): no size fits the inventory or the pools' liquidity",
                         cheap, rich, spread)
            elif best is None or opp.profit_usdc > best.profit_usdc:
                best = opp
        if best is not None:
            if best.profit_usdc < s.min_profit_usdc:
                log.info("best: %.0f USDC %s -> %s, profit %.3f USDC < min %.2f", best.usdc_in / 1e6, best.cheap,
                         best.rich, best.profit_usdc, s.min_profit_usdc)
            else:
                self.execute(best)
        if self.cfg.rebalance.enabled and not self.state.halt:
            self.rebalance(self.inventory())

    def execute(self, opp: strategy.Opportunity) -> None:
        s = self.cfg.strategy
        cheap, rich = self.chains[opp.cheap], self.chains[opp.rich]
        if self.args.live:
            for c in (cheap, rich):
                why = uniswap_v4.swap_ready(c, MIN_NATIVE[c.info.key])
                if why:
                    log.warning("ARB skipped (%.2f USDC est. profit): %s", opp.profit_usdc, why)
                    return
        log.info("ARB: buy %s wARS for %.2f USDC on %s %s, sell on %s %s for %.2f USDC -> est. profit %.3f USDC",
                 f"{opp.wars / 1e18:,.0f}", opp.usdc_in / 1e6, cheap.info.name,
                 uniswap_v4.pool_name(opp.buy_pool or cheap.info.pools[0]), rich.info.name,
                 uniswap_v4.pool_name(opp.sell_pool or rich.info.pools[0]), opp.usdc_out / 1e6, opp.profit_usdc)
        # Minimum outputs leave each leg half the profit above min_profit as slack, so the
        # round trip nets at least min_profit even if both legs fill at their minimum.
        min_wars, min_usdc = strategy.leg_min_outs(opp, s.slippage_bps, s.min_profit_usdc)
        buy = uniswap_v4.swap_calldata(cheap.info, False, opp.usdc_in, min_wars, pool=opp.buy_pool)
        sell = uniswap_v4.swap_calldata(rich.info, True, opp.wars, min_usdc, pool=opp.sell_pool)
        legs = [self.pool.submit(cheap.send, cheap.info.router, buy, "swap USDC->wARS", None, 300_000),
                self.pool.submit(rich.send, rich.info.router, sell, "swap wARS->USDC", None, 300_000)]
        self.check_legs(legs)

    def check_legs(self, legs) -> None:
        """Both legs must confirm. Anything else leaves inventory one-sided: halt."""
        outcomes = []
        for name, f in zip(("buy", "sell"), legs):
            try:
                r = f.result()
                outcomes.append((name, r.ok, (r.tx_hash or "dry-run") if r.ok else f"REVERTED {r.tx_hash}"))
            except Exception as e:  # noqa: BLE001
                log.error("%s leg failed: %s", name, e)
                outcomes.append((name, False, f"error: {e}"))
        if not all(ok for _, ok, _ in outcomes):
            self.state.set_halt("arb leg did not confirm", legs={n: d for n, _, d in outcomes})

    def rebalance(self, bal: Balances) -> None:
        r = self.cfg.rebalance
        fees = {k: ripio_bridge.route(c, config.other(c.info))[1] for k, c in self.chains.items()}
        if max(fees.values()) > ripio_bridge.MAX_ROUTE_FEE:
            log.warning("Ripio route fees %s are above %.0f wARS: wARS rebalancing skipped",
                        {k: v / 1e18 for k, v in fees.items()}, ripio_bridge.MAX_ROUTE_FEE / 1e18)
            fees = None
        t = fees and strategy.plan_wars_rebalance(bal.wars, self.state.inflight_to("wARS"), int(r.wars_min * 1e18),
                                                  int(r.wars_min_bridge * 1e18), max(fees.values()))
        if t:
            src, dst = self.chains[t.src], self.chains[t.dst]
            if ripio_bridge.mint_capacity(dst) < t.amount:
                log.warning("Ripio daily mint capacity on %s is below %.0f wARS; deposit would be queued",
                            dst.info.name, t.amount / 1e18)
            log.info("REBALANCE: bridge %s wARS %s -> %s (Ripio)", f"{t.amount / 1e18:,.0f}", src.info.name, dst.info.name)
            sent = ripio_bridge.bridge_wars(src, dst.info, t.amount)
            if sent and sent[-1].tx_hash and sent[-1].ok:
                self.state.add(InFlight("ripio", "wARS", t.src, t.dst, t.amount - fees[t.src], sent[-1].tx_hash,
                                        src.info.chain_id, time.time()))

        t, alert = strategy.plan_usdc_rebalance(bal.usdc, self.state.inflight_to("USDC"), int(r.usdc_min * 1e6),
                                                int(r.usdc_min_transfer * 1e6))
        if alert:
            log.warning("ALERT: %s", alert)
        if t:
            log.info("REBALANCE: %.2f USDC Celo -> Base (LI.FI/LayerSwap)", t.amount / 1e6)
            try:
                sent = lifi.transfer_celo_to_base(self.chains["celo"], t.amount, r.lifi_max_fee_bps)
            except lifi.BadQuote as e:
                log.warning("LI.FI transfer skipped: %s", e)
                return
            if sent and sent[-1].tx_hash and sent[-1].ok:
                self.state.add(InFlight("lifi", "USDC", "celo", "base", t.amount, sent[-1].tx_hash,
                                        config.CELO.chain_id, time.time()))


def cmd_run(cfg: config.Config, args) -> None:
    if args.live and (args.paper_usdc or args.paper_wars):
        raise SystemExit("--paper-* only make sense in dry-run")
    bot = Bot(cfg, args)
    while True:
        try:
            bot.step()
        except PolicyRejected as e:
            log.error("device policy rejected a transaction: %s (is the device running "
                      "policies/wars-arb-base-celo.yaml?)", e.message)
        except GasTooHigh as e:
            log.warning("%s", e)
        except Exception:  # noqa: BLE001
            log.exception("step failed")
        if args.once:
            return
        time.sleep(cfg.strategy.poll_seconds)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="wars_arb", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-c", "--config", default=str(Path(__file__).resolve().parents[1] / "config.yaml"))
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="balances, pool prices, spread, bridge routes")
    sp = sub.add_parser("setup-approvals", help="one-time token -> Permit2 -> router approvals")
    sp.add_argument("--live", action="store_true", help="broadcast (default: sign only)")
    sp = sub.add_parser("run", help="arbitrage + rebalance loop")
    sp.add_argument("--live", action="store_true", help="broadcast (default: sign only)")
    sp.add_argument("--once", action="store_true", help="one iteration, then exit")
    sp.add_argument("--paper-usdc", type=float, help="dry-run: pretend each chain holds this much USDC")
    sp.add_argument("--paper-wars", type=float, help="dry-run: pretend each chain holds this much wARS")
    sub.add_parser("resume", help="clear a halt (after reconciling both chains)")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    for noisy in ("urllib3", "web3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    try:  # use the OS trust store (e.g. corporate TLS inspection CAs)
        import truststore
        truststore.inject_into_ssl()
    except ImportError:
        pass
    cfg = config.load(args.config)
    {"status": cmd_status, "setup-approvals": cmd_setup, "run": cmd_run, "resume": cmd_resume}[args.cmd](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
