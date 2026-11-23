"""Minimal HTTPS JSON-RPC client for the signer (eth_signTransaction).

    from esp32signer.client import SignerClient
    signer = SignerClient("https://signer.local", token=os.environ["SIGNER_TOKEN"], ca="certs/ca.pem")
    raw = signer.sign_transaction({
        "chainId": 8453, "nonce": 0, "gas": 60000,
        "maxFeePerGas": 10**9, "maxPriorityFeePerGas": 10**6,
        "to": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "value": 0, "data": "0x095ea7b3...",
    })
    w3.eth.send_raw_transaction(raw)

The device has no node access: chainId, nonce, gas and fee fields are required.
"""

from __future__ import annotations

import itertools
from typing import Any
from urllib.parse import urlparse

import requests

QUANTITY_FIELDS = {"chainId", "nonce", "gas", "gasLimit", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas",
                   "value", "type"}


class SignerError(RuntimeError):
    def __init__(self, code: int, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class PolicyRejected(SignerError):
    pass


def to_rpc_tx(tx: dict[str, Any]) -> dict[str, Any]:
    """Convert a web3/eth-account style dict (ints, bytes) into JSON-RPC form."""
    out: dict[str, Any] = {}
    for k, v in tx.items():
        if v is None:
            continue
        if k in QUANTITY_FIELDS and isinstance(v, int):
            out[k] = hex(v)
        elif k in ("data", "input") and isinstance(v, (bytes, bytearray)):
            out[k] = "0x" + bytes(v).hex()
        elif k == "accessList":
            out[k] = [
                {"address": e["address"], "storageKeys": [s if isinstance(s, str) else "0x" + bytes(s).hex()
                                                          for s in e.get("storageKeys", [])]}
                for e in v
            ]
        else:
            out[k] = v
    return out


class SignerClient:
    def __init__(self, url: str, token: str, ca: str | bool | None = None, timeout: float = 10.0,
                 allow_insecure: bool = False):
        u = urlparse(url)
        if u.username or u.password:
            raise ValueError("signer URL must not embed credentials")
        if not u.hostname or (u.scheme != "https" and not (allow_insecure and u.scheme == "http")):
            raise ValueError(f"signer URL must be https://host (got {url!r}); the bearer token would travel in clear")
        self.url = url.rstrip("/") + "/"
        self.timeout = timeout
        self._ids = itertools.count(1)
        self.session = requests.Session()  # keep-alive: avoids a TLS handshake per request
        self.session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        self.session.verify = ca if ca is not None else True

    def call(self, method: str, params: list | None = None) -> Any:
        body = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or []}
        r = self.session.post(self.url, json=body, timeout=self.timeout)
        if r.status_code == 401:
            raise SignerError(401, "unauthorized: bad or missing API token")
        r.raise_for_status()
        resp = r.json()
        if "error" in resp:
            err = resp["error"]
            cls = PolicyRejected if err.get("code") == -32003 else SignerError
            raise cls(err.get("code", 0), err.get("message", ""))
        return resp["result"]

    def accounts(self) -> list[str]:
        return self.call("eth_accounts")

    def status(self) -> dict:
        return self.call("signer_status")

    def sign_transaction(self, tx: dict[str, Any]) -> str:
        """Returns the raw signed transaction as 0x-prefixed hex."""
        return self.call("eth_signTransaction", [to_rpc_tx(tx)])
