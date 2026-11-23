# wARS/USDC arbitrage: Base ↔ Celo

This is an example bot that trades the price gap for wARS between two Uniswap v4
pools, one on Base and one on Celo. It rebalances inventory with the
[Ripio bridge](https://docs.ripio.com/wfiat/bridge.md) for wARS and with LI.FI for USDC.

The bot never holds a private key. Every transaction is signed by the ESP32
signer, and the signer only signs what `policies/wars-arb-base-celo.yaml`
allows. If the machine running this bot is compromised, an attacker still
can't send funds anywhere except back to the signer's own address on either chain.

| | Base | Celo |
|---|---|---|
| Pools (Uniswap v4, no hooks) | wARS/USDC 0.05%, about $850k (`0x187ced7f…7265`)<br>wARS/USDC 0.3%, small (`0xc33b0427…80cc`) | wARS/USDC 0.30%, about $130k (`0x59f80a50…239c`) |

The bot quotes every pool in both directions and trades the pair of pools that pays most.

## How it works

Every `poll_seconds`, the bot:

1. Reads both pool prices from `StateView.getSlot0`.
2. Checks the gap. If wARS is at least `min_spread_bps` cheaper on one chain, it
   picks a trade size from `ladder_usdc` using the V4Quoter. For each size it
   quotes buying wARS with USDC on the cheap chain, then quotes selling that wARS
   on the expensive chain, and keeps the size with the best profit after gas.
   Each size is limited by the USDC already on the cheap chain and the wARS
   already on the expensive chain.
3. If the profit is at least `min_profit_usdc`, it sends both swaps at the same
   time, one per chain. Each swap's `amountOutMinimum` gives that leg half of
   the profit above `min_profit_usdc` as slack, capped at `slippage_bps`. Even
   if both legs fill at their minimum, the round trip still nets `min_profit_usdc`.
   If either leg reverts or its outcome is unknown, the bot **halts** (see below).
4. Rebalances:
   - **wARS:** when a chain falls below `wars_min`, counting transfers still in
     flight, the bot calls `depositForBridge` on the chain with more wARS and
     sends it to its own address. The Ripio route fee is a fixed 15 wARS.
     Progress is tracked through `bridge.ripio.com/api/operations`.
   - **USDC:** when Base falls below `usdc_min`, the bot moves USDC from Celo to
     Base through LI.FI using LayerSwap. Before signing, it decodes the quote and
     checks that the receiver, refund recipient and destination match what it
     asked for. The cost is computed from the signed calldata (the encoded LI.FI
     fee and `minAmount`), not only from the quote's estimate. The transfer is skipped
     if the cost is above `lifi_max_fee_bps`. The bot approves exactly the amount
     being sent and revokes the approval if the transfer fails.

In-flight transfers are saved in `state.json`. A status API answer only counts if
it names the transfer that was asked about. A transfer reported FAILED is kept
in `state.json` under `failed` and halts the bot.

### Halt and resume

The bot halts when something needs a person: an arb where one leg did not
confirm, which leaves inventory one-sided, or a failed bridge transfer. The halt is
saved in `state.json`, so it survives restarts. While halted, the bot neither
trades nor rebalances. `status` shows why it halted. Check both chains, then:

```sh
python -m wars_arb.main resume
```

### Moving USDC from Base to Celo

The bot can't do this automatically. LI.FI only offers this direction through
Squid, and Squid's calldata contains arbitrary calls that no regex can check
safely, so the policy doesn't allow it. CCTP doesn't support Celo either.

USDC builds up on Base when wARS trades higher on Celo. In that case the bot logs
an `ALERT`. You can top up Celo yourself, or wait until wARS trades higher on
Base again: those trades move USDC back to Celo.

## Setup

1. **Install** the bot's dependencies into the host virtual environment:
   ```sh
   cd host && source .venv/bin/activate && pip install -e ".[bot]"
   ```
2. **Load the policy on the signer.** Hold BOOT for 5 s until the LED turns blue, then run:
   ```sh
   esp32signer provision --port /dev/cu.usbmodemXXXX --policy policies/wars-arb-base-celo.yaml
   esp32signer reboot --port /dev/cu.usbmodemXXXX
   ```
   This needs firmware with per-chain policy support (`chain_limits` and `chains`).
3. **Configure the bot:**
   ```sh
   cd examples/wars-arb && cp config.example.yaml config.yaml
   ```
   Then edit the RPC URLs and the signer CA and token paths. For production, use your own RPC endpoints.
4. **Fund the signer address**, which `python -m wars_arb.main status` prints, on both chains:
   - ETH on Base and CELO on Celo for gas.
   - USDC and wARS on both chains. Each chain needs enough of both for one leg
     of the largest trade.
5. **Send the one-time approvals:** wARS and USDC to Permit2, then Permit2 to the
   UniversalRouter, on each chain.
   ```sh
   python -m wars_arb.main setup-approvals          # signs only: checks the policy accepts them
   python -m wars_arb.main setup-approvals --live
   ```

## Running

```sh
python -m wars_arb.main status                        # balances, prices, gap, bridge routes
python -m wars_arb.main run --once                    # dry run: build and sign, never broadcast
python -m wars_arb.main run --once --paper-usdc 2000 --paper-wars 3000000   # what-if with fake inventory
python -m wars_arb.main run --live                    # trade for real
```

By default the bot runs dry. In dry-run mode every transaction is still built and
signed by the device, so the device log shows it accepted them, but nothing is broadcast.

## What the policy still allows

A compromised bot is limited to the following:

- **Swapping at a bad price** in the pinned pools, because the device does not check
  `amountOutMinimum`. Keep inventory sized to what you can afford to lose to a
  sandwich or a manipulated pool.
- **Trusting the RPC.** Prices, quotes, balances and receipts all come from one
  RPC per chain. A malicious RPC can fake a quote, or drop one leg, so the other leg
  executes alone. The halt stops this after the first time; it doesn't prevent it.
  Use RPC endpoints you trust.
- **Wasting gas**, up to the per-chain caps × `rate_per_minute` (30/min).
- **Bridging** wARS between Base and Celo, and USDC from Celo to Base, always to the signer itself.
  The LI.FI/LayerSwap path depends on LI.FI's backend signature and on LayerSwap
  delivering to that receiver. That is an off-chain trust assumption, so keep
  `usdc_min_transfer` moderate.

## Tests

```sh
cd examples/wars-arb && python -m pytest -q          # strategy, and encodings checked against the policy
cd host && pytest -q tests/test_wars_arb_policy.py    # policy vs real calldata and attack variants (Python + C engine)
```
