"""One chain: reads through web3, signs on the ESP32, optionally broadcasts.

The bot never holds a key. Every transaction goes through SignerClient
(eth_signTransaction), so the device policy decides what can be signed.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from eth_abi import decode, encode
from eth_utils import keccak
from web3 import Web3

from esp32signer.client import PolicyRejected, SignerClient

from .config import ChainInfo

log = logging.getLogger(__name__)


def selector(sig: str) -> bytes:
    return keccak(text=sig)[:4]


def calldata(sig: str, types: list[str], args: list) -> str:
    return "0x" + (selector(sig) + encode(types, args)).hex()


class GasTooHigh(RuntimeError):
    pass


@dataclass
class Sent:
    chain: str
    label: str
    tx_hash: str | None  # None in dry-run
    ok: bool
    gas_used: int | None = None


class Chain:
    def __init__(self, info: ChainInfo, rpc: str, signer: SignerClient, address: str, live: bool):
        self.info = info
        self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 20}))
        self.signer = signer
        self.address = Web3.to_checksum_address(address)
        self.live = live
        self._nonce: int | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ reads
    def call(self, to: str, sig: str, types: list[str], args: list, out: list[str]) -> tuple:
        data = calldata(sig, types, args)
        raw = self.w3.eth.call({"to": to, "data": data})
        return decode(out, bytes(raw))

    def erc20_balance(self, token: str) -> int:
        return self.call(token, "balanceOf(address)", ["address"], [self.address], ["uint256"])[0]

    def erc20_allowance(self, token: str, spender: str) -> int:
        return self.call(token, "allowance(address,address)", ["address", "address"], [self.address, spender],
                         ["uint256"])[0]

    def native_balance(self) -> int:
        return self.w3.eth.get_balance(self.address)

    # ------------------------------------------------------------------- fees
    def fees(self) -> tuple[int, int]:
        """EIP-1559 (maxFee, maxPriority), clamped to the device policy caps."""
        hist = self.w3.eth.fee_history(5, "latest", [50])
        base = hist["baseFeePerGas"][-1]
        tips = [r[0] for r in hist["reward"] if r]
        prio = min(max(sorted(tips)[len(tips) // 2] if tips else 0, 1_000_000), self.info.max_priority_fee)
        if base + prio > self.info.max_fee_per_gas:
            raise GasTooHigh(f"{self.info.name} base fee {base / 1e9:.3f} gwei is above the policy cap "
                             f"{self.info.max_fee_per_gas / 1e9:.3f} gwei")
        return min(2 * base + prio, self.info.max_fee_per_gas), prio

    # ------------------------------------------------------------------- send
    def _next_nonce(self) -> int:
        if self._nonce is None:
            self._nonce = self.w3.eth.get_transaction_count(self.address, "pending")
        return self._nonce

    def send(self, to: str, data: str, label: str, gas: int | None = None, fallback_gas: int = 400_000) -> Sent:
        """Sign on the device; broadcast and wait for the receipt when live.

        Gas is estimated against the chain. In dry-run the estimate often fails
        (no balance / allowance yet), so `fallback_gas` is used and the tx is
        only signed, which still proves the device policy accepts it.
        """
        with self._lock:
            max_fee, prio = self.fees()
            tx = {"type": 2, "chainId": self.info.chain_id, "from": self.address, "to": Web3.to_checksum_address(to),
                  "value": 0, "data": data, "nonce": self._next_nonce(),
                  "maxFeePerGas": max_fee, "maxPriorityFeePerGas": prio}
            if gas is None:
                try:
                    gas = int(self.w3.eth.estimate_gas(tx) * 1.25)
                except Exception as e:  # noqa: BLE001
                    if self.live:
                        raise RuntimeError(f"{self.info.name} {label}: gas estimation failed: {e}") from e
                    gas = fallback_gas
            tx["gas"] = min(gas, self.info.max_gas)
            try:
                raw = self.signer.sign_transaction(tx)
            except PolicyRejected as e:
                log.error("%s %s: device REFUSED to sign: %s", self.info.name, label, e.message)
                raise
            if not self.live:
                log.info("[dry-run] %s %s: signed by device (%d bytes), not broadcast", self.info.name, label,
                         len(raw) // 2 - 1)
                return Sent(self.info.key, label, None, True)
            try:
                h = self.w3.eth.send_raw_transaction(raw)
            except Exception:
                self._nonce = None  # resync from the node next time
                raise
            self._nonce = tx["nonce"] + 1
        log.info("%s %s: sent %s%s", self.info.name, label, self.info.explorer, h.to_0x_hex())
        try:
            rcpt = self.w3.eth.wait_for_transaction_receipt(h, timeout=180)
        except Exception:
            with self._lock:
                self._nonce = None  # dropped or stuck: re-read the pending nonce before the next send
            raise
        ok = rcpt["status"] == 1
        (log.info if ok else log.error)("%s %s: %s, gas used %d", self.info.name, label,
                                        "confirmed" if ok else "REVERTED", rcpt["gasUsed"])
        return Sent(self.info.key, label, h.to_0x_hex(), ok, rcpt["gasUsed"])
