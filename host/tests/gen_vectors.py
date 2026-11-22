"""Generate signing test vectors for the firmware host tests using eth-account.

Usage (from repo root, inside host/.venv):
    python host/tests/gen_vectors.py > firmware/test_host/vectors.json
"""

import json
import random

from eth_account import Account
from eth_utils import keccak, to_checksum_address

rng = random.Random(1337)


def h(i: int) -> str:
    return hex(i)


def rand_bytes(n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


KEYS = [
    "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
    "0x" + "00" * 31 + "01",
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",  # n-1
    "0x" + rand_bytes(32).hex(),
]

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"


def approve(spender: str, amount: int) -> str:
    return "0x095ea7b3" + spender[2:].lower().rjust(64, "0") + hex(amount)[2:].rjust(64, "0")


def txs():
    yield {  # simple 1559 transfer
        "type": 2, "chainId": 8453, "nonce": 0, "gas": 21000,
        "maxFeePerGas": 1_000_000_000, "maxPriorityFeePerGas": 1_000_000,
        "to": "0x" + "11" * 20, "value": 10**18, "data": b"",
    }
    yield {  # ERC20 approve on Base
        "type": 2, "chainId": 8453, "nonce": 7, "gas": 60000,
        "maxFeePerGas": 5_000_000_000, "maxPriorityFeePerGas": 100,
        "to": USDC, "value": 0, "data": bytes.fromhex(approve(PERMIT2, 2**256 - 1)[2:]),
    }
    yield {  # access list
        "type": 2, "chainId": 1, "nonce": 2**40, "gas": 300000,
        "maxFeePerGas": 2**70, "maxPriorityFeePerGas": 2**69,
        "to": "0x" + "ab" * 20, "value": 0, "data": rand_bytes(300),
        "accessList": [
            {"address": "0x" + "cd" * 20, "storageKeys": ["0x" + "00" * 31 + "01", "0x" + rand_bytes(32).hex()]},
            {"address": "0x" + "ef" * 20, "storageKeys": []},
        ],
    }
    yield {  # long calldata (multi-byte length prefix)
        "type": 2, "chainId": 84532, "nonce": 1, "gas": 2_000_000,
        "maxFeePerGas": 12345, "maxPriorityFeePerGas": 0,
        "to": "0x" + "22" * 20, "value": 1, "data": rand_bytes(4000),
    }
    yield {  # legacy EIP-155
        "chainId": 8453, "nonce": 3, "gas": 21000, "gasPrice": 1_000_000_000,
        "to": "0x" + "33" * 20, "value": 5, "data": b"",
    }
    yield {  # legacy with data and big chain id
        "chainId": 2**40 + 7, "nonce": 255, "gas": 100000, "gasPrice": 2**64,
        "to": "0x" + "44" * 20, "value": 0, "data": rand_bytes(56),
    }
    yield {  # one-byte data < 0x80 and value 0x7f
        "type": 2, "chainId": 10, "nonce": 127, "gas": 21000,
        "maxFeePerGas": 128, "maxPriorityFeePerGas": 127,
        "to": "0x" + "55" * 20, "value": 127, "data": b"\x01",
    }


def to_rpc(tx: dict) -> dict:
    """Convert an eth-account dict into a JSON-RPC eth_signTransaction object."""
    out = {}
    for k, v in tx.items():
        if k == "data":
            out["input" if rng.random() < 0.5 else "data"] = "0x" + v.hex()
        elif k == "accessList":
            out[k] = v
        elif k == "to":
            out[k] = v
        elif k == "type":
            out[k] = hex(v)
        else:
            out[k] = hex(v)
    return out


vectors = []
for key in KEYS:
    acct = Account.from_key(key)
    for tx in txs():
        tx["to"] = to_checksum_address(tx["to"])
        for e in tx.get("accessList", []):
            e["address"] = to_checksum_address(e["address"])
        signed = Account.sign_transaction(tx, key)
        vectors.append({
            "key": key,
            "address": acct.address,
            "tx": to_rpc(tx),
            "raw": "0x" + signed.raw_transaction.hex(),
            "hash": "0x" + signed.hash.hex(),
        })

keccak_vectors = [
    {"in": "", "out": keccak(b"").hex()},
    {"in": "616263", "out": keccak(b"abc").hex()},
]
for n in (135, 136, 137, 272, 1000):
    d = rand_bytes(n)
    keccak_vectors.append({"in": d.hex(), "out": keccak(d).hex()})

print(json.dumps({"keccak": keccak_vectors, "sign": vectors}, indent=1))
