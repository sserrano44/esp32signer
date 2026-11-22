# esp32signer

An ESP32-S3 Super Mini acting as a **policy-enforcing Ethereum transaction signer**.
Your bot keeps doing everything it already does (nonces, gas, simulation), but
signing goes over HTTPS to the device via standard `eth_signTransaction`. The
device signs **only** transactions that match a default-deny policy:
whitelisted contracts, calldata regexes, native-transfer recipients, chain IDs,
gas/fee caps and a rate limit. If the bot's machine is compromised, the attacker
can't make the device sign a withdrawal to their own address.

```
 trading bot ──HTTPS + Bearer token──▶ ESP32-S3 (signer.local)
   │  eth_signTransaction(tx)              │ parse tx → policy check → secp256k1 sign
   │◀──────── raw signed tx ───────────────┘   (or JSON-RPC error -32003 "rejected by policy")
   └─▶ eth_sendRawTransaction → Base RPC
```

## Layout

| Path | What |
|---|---|
| `firmware/` | ESP-IDF v5.5 project (target `esp32s3`) |
| `firmware/components/ethcore` | keccak, RLP, tx parsing/encoding, signing (portable C) |
| `firmware/components/policy` | policy engine + linear-time regex (portable C) |
| `firmware/components/secp256k1` | vendored bitcoin-core libsecp256k1 v0.7.1 |
| `firmware/components/store` | NVS storage (encrypted in release builds) |
| `firmware/main` | button/LED, USB provisioning, WiFi, mDNS, HTTPS, JSON-RPC |
| `firmware/test_host` | host unit tests (signatures byte-identical to eth-account) |
| `host/` | Python CLI: provisioning, policy compiler, certs, client |
| `policies/` | example policies |
| `examples/wars-arb/` | example bot: wARS/USDC arbitrage Base ↔ Celo with Ripio bridge and LI.FI rebalancing |
| `docs/` | [PROVISIONING](docs/PROVISIONING.md), [POLICY](docs/POLICY.md), [SECURITY](docs/SECURITY.md), [HARDENING](docs/HARDENING.md) |

## Quick start

```sh
# 1. Host tooling
cd host && python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]" && cd ..

# 2. Build & flash firmware (development config, no eFuses touched)
. ~/esp/esp-idf/export.sh
cd firmware && idf.py set-target esp32s3 && idf.py -p /dev/cu.usbmodemXXXX flash && cd ..

# 3. TLS certificate for signer.local, signed by a local CA
esp32signer gen-cert --hostname signer --ca-dir certs/ca --out-dir certs

# 4. Enter provision mode: press BOOT within 3 s of reset (LED solid blue),
#    then provision everything in one go
esp32signer provision --port /dev/cu.usbmodemXXXX --generate-key \
    --policy policies/base-arb.example.yaml \
    --wifi-ssid MyWifi --wifi-pass '...' --hostname signer \
    --cert certs/signer.crt --tls-key certs/signer.key
#    → prints the private key ONCE (back it up offline) and a new API token
esp32signer reboot --port /dev/cu.usbmodemXXXX     # LED turns green

# 5. Use it
export SIGNER_URL=https://signer.local SIGNER_TOKEN=... SIGNER_CA=certs/ca/ca.pem
esp32signer status
```

From Python:

```python
from esp32signer.client import SignerClient
signer = SignerClient("https://signer.local", token, ca="certs/ca/ca.pem")
raw = signer.sign_transaction(tx)          # tx built by web3.py, incl. chainId/nonce/gas/fees
w3.eth.send_raw_transaction(raw)
```

Any client that speaks JSON-RPC works (ethers/viem/web3.py custom signer). See
`host/examples/web3_send.py`. Supported methods: `eth_signTransaction`,
`eth_accounts`, `signer_status`. Transaction types 0x0 (EIP-155) and 0x2
(EIP-1559) only; 0x1, 0x3 and **0x4 (EIP-7702)** are always refused.

## LED

| LED | Meaning |
|---|---|
| blinking white (3 s after boot) | press BOOT now to enter provision mode |
| solid blue | provision mode (USB console) |
| blinking yellow | connecting to WiFi |
| dim green | ready; short white flash = transaction signed |
| blinking red | error / not provisioned (hold BOOT 5 s to provision) |

## Tests

```sh
cmake -S firmware/test_host -B build-test && cmake --build build-test && ctest --test-dir build-test
cd host && source .venv/bin/activate && pytest                  # + cross-checks against the C engine
SIGNER_URL=... SIGNER_TOKEN=... SIGNER_CA=... pytest -m hardware   # device provisioned with policies/e2e-test.yaml
```
