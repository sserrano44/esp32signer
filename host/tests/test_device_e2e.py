"""End-to-end tests against a real device provisioned with policies/e2e-test.yaml.

    export SIGNER_URL=https://signer.local SIGNER_TOKEN=... SIGNER_CA=certs/ca/ca.pem
    pytest -m hardware tests/test_device_e2e.py -v
"""

import os

import pytest
import requests
from eth_account import Account

from esp32signer.client import PolicyRejected, SignerClient, SignerError

URL, TOKEN = os.environ.get("SIGNER_URL"), os.environ.get("SIGNER_TOKEN")
CA = os.environ.get("SIGNER_CA") or (False if os.environ.get("SIGNER_INSECURE") else None)

pytestmark = [
    pytest.mark.hardware,
    pytest.mark.skipif(not (URL and TOKEN), reason="set SIGNER_URL and SIGNER_TOKEN"),
]

USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
TREASURY = "0x9999999999999999999999999999999999999999"
EVIL = "0xbadbadbadbadbadbadbadbadbadbadbadbadbad0"


def word(a: str) -> str:
    return a.lower()[2:].rjust(64, "0")


@pytest.fixture(scope="module")
def signer():
    return SignerClient(URL, TOKEN, ca=CA)


@pytest.fixture(scope="module")
def address(signer):
    return signer.accounts()[0]


def tx(**kw):
    t = {"type": 2, "chainId": 84532, "nonce": 0, "gas": 60000, "maxFeePerGas": 10**9,
         "maxPriorityFeePerGas": 10**6, "value": 0, "to": USDC,
         "data": "0x095ea7b3" + word(PERMIT2) + "f" * 64}
    t.update(kw)
    return t


def test_auth_required():
    verify = CA if CA is not None else True
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_accounts", "params": []}
    assert requests.post(URL, json=body, verify=verify, timeout=10).status_code == 401
    r = requests.post(URL, json=body, verify=verify, timeout=10, headers={"Authorization": "Bearer " + "x" * 43})
    assert r.status_code == 401


def test_status(signer, address):
    st = signer.status()
    assert st["address"] == address


def test_sign_allowed_approve(signer, address):
    raw = signer.sign_transaction(tx(nonce=1))
    assert Account.recover_transaction(raw) == address


def test_sign_allowed_legacy_native(signer, address):
    raw = signer.sign_transaction({"chainId": 84532, "nonce": 2, "gas": 21000, "gasPrice": 10**9,
                                   "to": TREASURY, "value": 10**15, "data": "0x"})
    assert Account.recover_transaction(raw) == address


@pytest.mark.parametrize("bad,why", [
    (dict(data="0x095ea7b3" + word(EVIL) + "f" * 64), "matched no rule"),
    (dict(data="0x095ea7b3" + word(PERMIT2) + "f" * 64 + "00"), "matched no rule"),
    (dict(chainId=8453), "chainId"),
    (dict(maxFeePerGas=6 * 10**9), "fee per gas"),
    (dict(maxPriorityFeePerGas=2 * 10**9, maxFeePerGas=3 * 10**9), "priority fee"),
    (dict(gas=600000), "max_gas"),
    (dict(to=EVIL), "not whitelisted"),
    (dict(to=TREASURY, data="0x", value=10**17), "exceeds max_value"),
])
def test_policy_rejections(signer, bad, why):
    with pytest.raises(PolicyRejected, match=why):
        signer.sign_transaction(tx(**bad))


def test_eip7702_rejected(signer):
    # Refused by the delegation field itself...
    with pytest.raises(SignerError, match="authorizationList"):
        signer.sign_transaction(tx(type=4, authorizationList=[]))
    # ...and by the type alone.
    with pytest.raises(SignerError, match="unsupported transaction type"):
        signer.sign_transaction(tx(type=4))
    with pytest.raises(SignerError, match="unsupported transaction type"):
        signer.sign_transaction(tx(type=1))


def test_from_mismatch(signer):
    with pytest.raises(SignerError, match="from"):
        signer.sign_transaction(tx(**{"from": EVIL}))


def test_rate_limit(signer):
    """Policy allows 12/min; a burst must eventually be throttled."""
    with pytest.raises(PolicyRejected, match="rate limit"):
        for n in range(20):
            signer.sign_transaction(tx(nonce=100 + n))
