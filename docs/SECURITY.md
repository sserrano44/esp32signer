# Security model

## Goal

The trading host may be fully compromised. Even then, the attacker must not be
able to move funds to an address they control. At most, they can do what the
policy already allows.

## Trust boundaries

| Component | Trusted? | Notes |
|---|---|---|
| ESP32 firmware + stored policy | yes | The only place the key lives |
| Provisioning machine | yes, while provisioning | Clean or airgapped; it sees the key on generate/import |
| Trading host | **no** | Holds the API token; can request any signature |
| LAN | **no** | TLS plus a bearer token; the policy still applies to any valid request |
| Person pressing BOOT | yes | Physical presence gates every config change |

## What protects what

- **Policy enforcement on the device.** A default-deny allowlist of
  destinations, calldata regexes, values, chains, fee caps and a rate limit.
  Txs are parsed and re-encoded by the device, so what it checks is exactly
  what it signs.
- **No remote configuration.** The network interface exposes only
  `eth_signTransaction`, `eth_accounts` and `signer_status`. Changing the key,
  policy, WiFi, cert or token needs provision mode, which needs the BOOT button
  and USB.
- **API token.** Required on every request. The device stores only its sha256
  and compares in constant time. After 10 consecutive failures it backs off up
  to 30 s per attempt.
- **TLS.** ECDSA P-256 certificate with a SAN for `<hostname>.local`; clients
  should verify it against your local CA.
- **Key handling.** The key is read from NVS only while signing and is zeroed
  after use. Signing uses libsecp256k1 (constant time, RFC6979, low-s) with a
  blinded context. `wipe` physically erases the signer partition.

## Residual risks (read these)

1. **Bad trades within policy.** An attacker controlling the host can submit
   allowed swaps with `amountOutMinimum = 0` and sandwich them, or trade
   against a pool they've skewed. A regex can't express "fair price".
   Mitigations:
   - Keep only working capital on the signer address and sweep profits to a
     treasury (a whitelisted native/ERC20 transfer).
   - Keep the rate limit tight.
   - Pin specific pools (pool key) in the regex.
   - For strong guarantees, route swaps through your own executor contract
     that enforces an on-chain oracle or slippage bound, and whitelist only
     that contract.
2. **Gas burn.** Allowed txs with maximal fees waste funds, up to
   `max_gas × max_fee_per_gas × rate`. Keep the caps realistic for the chain.
3. **Denial of service.** The host or anyone on the LAN can flood requests,
   trigger the auth backoff, or unplug the device. It fails closed: nothing
   gets signed.
4. **USB access before hardening.** In the development build, anyone with USB
   access can reflash the firmware and read the key out of flash. Power the
   device from a USB charger, not the trading machine, and apply
   [HARDENING](HARDENING.md) before using real funds.
5. **Provisioning on a dirty machine.** A compromised provisioning machine sees
   a generated or imported key and could upload its own policy. Provision only
   from a clean or airgapped machine.
6. **Approvals are long-lived.** An approval you whitelist, e.g. Permit2 →
   router, stays usable even if you later tighten the policy. Revoke on-chain
   when you change strategy.
7. **Physical theft** of a hardened device: secure boot, flash encryption and
   secure download mode make key extraction hard, but not impossible against a
   lab-grade attacker. Keep balances proportionate.
