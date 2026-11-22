"""Balances on both chains plus cross-chain transfers that have not landed yet."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from . import lifi, ripio_bridge
from .chain import Chain
from .config import WARS

log = logging.getLogger(__name__)


@dataclass
class InFlight:
    kind: str  # "ripio" | "lifi"
    asset: str  # "wARS" | "USDC"
    src: str
    dst: str
    amount: int  # expected to arrive (after fees)
    tx: str
    src_chain_id: int
    started: float
    status: str = "PENDING"


class State:
    def __init__(self, path: Path):
        self.path = path
        self.inflight: list[InFlight] = []
        if path.exists():
            self.inflight = [InFlight(**d) for d in json.loads(path.read_text()).get("inflight", [])]

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"inflight": [asdict(f) for f in self.inflight]}, indent=1))
        tmp.replace(self.path)

    def add(self, f: InFlight) -> None:
        self.inflight.append(f)
        self.save()

    def inflight_to(self, asset: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.inflight:
            if f.asset == asset:
                out[f.dst] = out.get(f.dst, 0) + f.amount
        return out

    def refresh(self) -> None:
        """Poll the bridge APIs and drop transfers that completed or failed."""
        keep = []
        for f in self.inflight:
            try:
                if f.kind == "ripio":
                    op = ripio_bridge.status(f.tx, f.src_chain_id)
                    f.status = op["status"] if op else "NOT_INDEXED"
                    done = f.status in ("COMPLETED", "FAILED")
                else:
                    f.status = lifi.status(f.tx).get("status", "PENDING")
                    done = f.status in ("DONE", "FAILED")
            except Exception as e:  # noqa: BLE001
                log.warning("status check for %s failed: %s", f.tx, e)
                done = False
            if done:
                (log.info if f.status in ("COMPLETED", "DONE") else log.error)(
                    "%s %s %s -> %s: %s after %.0f s", f.kind, f.asset, f.src, f.dst, f.status, time.time() - f.started)
            elif time.time() - f.started > 6 * 3600:
                log.error("%s transfer %s still %s after 6 h: check it manually", f.kind, f.tx, f.status)
                keep.append(f)
            else:
                keep.append(f)
        if len(keep) != len(self.inflight):
            self.inflight = keep
            self.save()


@dataclass
class Balances:
    wars: dict[str, int]
    usdc: dict[str, int]
    native: dict[str, int]


def balances(chains: dict[str, Chain]) -> Balances:
    return Balances(
        wars={k: c.erc20_balance(WARS) for k, c in chains.items()},
        usdc={k: c.erc20_balance(c.info.usdc) for k, c in chains.items()},
        native={k: c.native_balance() for k, c in chains.items()},
    )
