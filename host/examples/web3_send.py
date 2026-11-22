"""Build a transaction with web3.py, sign it on the ESP32, broadcast it.

    pip install web3
    export SIGNER_URL=https://signer.local SIGNER_TOKEN=... SIGNER_CA=certs/ca/ca.pem
    export RPC_URL=https://sepolia.base.org
    python host/examples/web3_send.py

The bot keeps doing everything it did before (nonce management, gas
estimation, simulation); only the signing step goes to the device, which
enforces the policy.
"""

import os

from web3 import Web3

from esp32signer.client import SignerClient

w3 = Web3(Web3.HTTPProvider(os.environ["RPC_URL"]))
signer = SignerClient(os.environ["SIGNER_URL"], os.environ["SIGNER_TOKEN"], ca=os.environ.get("SIGNER_CA"))
me = Web3.to_checksum_address(signer.accounts()[0])

USDC = Web3.to_checksum_address("0x036CbD53842c5426634e7929541eC2318f3dCF7e")  # Base Sepolia
PERMIT2 = "000000000022d473030f116ddee9f6b43ac78ba3"
data = "0x095ea7b3" + PERMIT2.rjust(64, "0") + "f" * 64  # approve(Permit2, max)

base_fee = w3.eth.get_block("latest")["baseFeePerGas"]
tx = {
    "type": 2,
    "chainId": w3.eth.chain_id,
    "from": me,
    "to": USDC,
    "value": 0,
    "data": data,
    "nonce": w3.eth.get_transaction_count(me, "pending"),
    "maxPriorityFeePerGas": 1_000_000,
    "maxFeePerGas": 2 * base_fee + 1_000_000,
}
tx["gas"] = w3.eth.estimate_gas(tx)

raw = signer.sign_transaction(tx)  # raises PolicyRejected if the policy says no
h = w3.eth.send_raw_transaction(raw)
print("sent", h.hex())
print(w3.eth.wait_for_transaction_receipt(h)["status"])
