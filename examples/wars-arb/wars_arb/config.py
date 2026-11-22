"""Chain constants (verified on-chain 2026-11) and bot configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from web3 import Web3

cs = Web3.to_checksum_address

WARS = cs("0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D")  # 18 decimals, same address on Base and Celo
PERMIT2 = cs("0x000000000022D473030F116dDEE9F6B43aC78BA3")
RIPIO_BRIDGE = cs("0x465e642387d3d73a57CDc1368fFA53A800bA5D47")  # BridgeDeposit, same on both
LIFI_DIAMOND = cs("0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE")
NO_HOOKS = "0x0000000000000000000000000000000000000000"
WARS_DECIMALS = 18
USDC_DECIMALS = 6


@dataclass(frozen=True)
class ChainInfo:
    key: str
    name: str
    chain_id: int
    usdc: str
    pool_fee: int  # Uniswap v4 pool key: currency0 = wARS, currency1 = USDC, no hooks
    tick_spacing: int
    router: str  # UniversalRouter
    quoter: str  # V4Quoter
    state_view: str
    native: str
    # Must match the device policy (policies/wars-arb-base-celo.yaml); the bot
    # clamps to these so it never asks for a signature the device will refuse.
    max_fee_per_gas: int
    max_priority_fee: int
    max_gas: int
    default_rpc: str
    explorer: str
    extra_pools: tuple[tuple[int, int], ...] = ()  # more (fee, tickSpacing) wARS/USDC pools, no hooks

    @property
    def pools(self) -> list[tuple[int, int]]:
        """Every wARS/USDC pool the bot may trade on this chain; the policy must allow each one."""
        return [(self.pool_fee, self.tick_spacing), *self.extra_pools]


BASE = ChainInfo(
    key="base", name="Base", chain_id=8453,
    usdc=cs("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
    pool_fee=500, tick_spacing=5,
    router=cs("0x6ff5693b99212da76ad316178a184ab56d299b43"),
    quoter=cs("0xE1A6C5803e3c44368b171BD680c7D32dfc92CA47"),
    state_view=cs("0xa3c0c9b65bad0b08107aa264b0f3db444b867a71"),
    native="ETH",
    max_fee_per_gas=500_000_000, max_priority_fee=50_000_000, max_gas=1_500_000,
    default_rpc="https://mainnet.base.org", explorer="https://basescan.org/tx/",
    extra_pools=((3000, 60),),  # small 0.3% pool, often priced apart from the 0.05% one
)
CELO = ChainInfo(
    key="celo", name="Celo", chain_id=42220,
    usdc=cs("0xcebA9300f2b948710d2653dD7B07f33A8B32118C"),
    pool_fee=3000, tick_spacing=30,
    router=cs("0xcb695bc5d3aa22cad1e6df07801b061a05a0233a"),
    quoter=cs("0x28566da1093609182dff2cb2a91cfd72e61d66cd"),
    state_view=cs("0xbc21f8720babf4b20d195ee5c6e99c52b76f2bfb"),
    native="CELO",
    max_fee_per_gas=500_000_000_000, max_priority_fee=5_000_000_000, max_gas=1_500_000,
    default_rpc="https://forno.celo.org", explorer="https://celoscan.io/tx/",
)
CHAINS = {c.key: c for c in (BASE, CELO)}
BY_ID = {c.chain_id: c for c in (BASE, CELO)}


def other(chain: ChainInfo) -> ChainInfo:
    return CELO if chain.key == "base" else BASE


@dataclass
class StrategyConf:
    poll_seconds: float = 15
    min_spread_bps: float = 50  # skip quoting below this gap (pool fees alone are 35 bps)
    min_profit_usdc: float = 1.0
    ladder_usdc: list[float] = field(default_factory=lambda: [50, 100, 250, 500, 1000, 2000])
    max_trade_usdc: float = 2000
    slippage_bps: float = 30
    gas_cost_usdc: dict[str, float] = field(default_factory=lambda: {"base": 0.02, "celo": 0.05})


@dataclass
class RebalanceConf:
    enabled: bool = True
    # wARS: bridge when a chain drops below this many wARS (counting in-flight).
    wars_min: float = 300_000
    wars_min_bridge: float = 100_000
    # USDC: LI.FI (LayerSwap) Celo -> Base only; see README.
    usdc_min: float = 200
    usdc_min_transfer: float = 200
    lifi_max_fee_bps: float = 60


@dataclass
class Config:
    signer_url: str
    signer_ca: str | None
    signer_token: str
    rpc: dict[str, str]
    strategy: StrategyConf
    rebalance: RebalanceConf
    state_file: Path


def load(path: str | Path) -> Config:
    path = Path(path)
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    base_dir = path.parent

    def rel(p: str | None) -> str | None:
        return str((base_dir / p).resolve()) if p and not os.path.isabs(p) else p

    s = raw.get("signer", {})
    token = os.environ.get("SIGNER_TOKEN")
    if not token and s.get("token_file"):
        token = Path(rel(s["token_file"])).read_text().strip()
    if not token:
        raise SystemExit("signer token missing: set SIGNER_TOKEN or signer.token_file")
    rpc = {k: c.default_rpc for k, c in CHAINS.items()} | (raw.get("rpc") or {})
    return Config(
        signer_url=os.environ.get("SIGNER_URL", s.get("url", "https://signer.local")),
        signer_ca=rel(os.environ.get("SIGNER_CA", s.get("ca"))),
        signer_token=token,
        rpc=rpc,
        strategy=StrategyConf(**(raw.get("strategy") or {})),
        rebalance=RebalanceConf(**(raw.get("rebalance") or {})),
        state_file=Path(rel(raw.get("state_file", "state.json"))),
    )
