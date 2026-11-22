# Policy

The policy is **default deny**. A transaction is signed only if every check
below passes. The device evaluates them in this order:

1. Type is 0x0 (EIP-155 legacy) or 0x2 (EIP-1559). Contract creation and types
   0x1/0x3/0x4 are always refused; that includes EIP-7702, which would let a
   signature delegate the whole account.
2. `chainId` ∈ `chain_ids`.
3. `gas` ≤ `max_gas`, fee per gas (`maxFeePerGas` or `gasPrice`) ≤ cap, and priority fee ≤ cap.
   The caps come from `limits`, or from that chain's `chain_limits` entry if it has one.
4. Destination (only entries that apply to this `chainId` are considered):
   - If `data` is empty and `to` is in `native_transfers`: `value` ≤ its `max_value`.
   - Else if `to` is in `contracts`: `value` ≤ its `max_value` **and** the calldata
     fully matches at least one of its rules.
   - Otherwise refuse.
5. Rate limit: a token bucket of `rate_per_minute`. Only allowed transactions consume tokens.

A rejection returns JSON-RPC error `-32003` with the reason, e.g.
`rejected by policy: calldata (selector 0x095ea7b3) matched no rule for contract usdc`.

## Writing a policy

Write YAML and compile it to canonical JSON (`esp32signer compile-policy`).
`provision --policy` does this automatically. See
`policies/base-arb.example.yaml` for a complete example and the docstring in
`host/esp32signer/policy_compiler.py` for the full schema.

```yaml
contracts:
  - address: "{{usdc}}"
    label: usdc
    rules:
      - name: approve-permit2
        calldata: "^{{sel:approve(address,uint256)}}{{addr:permit2}}{{uint}}$"
```

### Several chains

One policy can cover several chains. Two optional fields scope it per chain:

```yaml
chain_ids: [8453, 42220]
limits:                          # defaults, and the only place for rate_per_minute
  max_gas: 1500000
  max_fee_per_gas_gwei: 0.5
  max_priority_fee_gwei: 0.05
  rate_per_minute: 30
chain_limits:                    # per-chain override of max_gas and the fee caps
  42220: {max_gas: 1500000, max_fee_per_gas_gwei: 500, max_priority_fee_gwei: 5}
contracts:
  - address: "{{permit2}}"       # same address, different rules per chain
    chains: [8453]
    rules: [...]
  - address: "{{permit2}}"
    chains: [42220]
    rules: [...]
```

- An entry without `chains` applies on every chain in `chain_ids`.
- The same address may appear more than once only if the `chains` sets don't overlap.
- Without `chain_limits`, one gas cap has to fit the most expensive chain. On a
  cheap chain that lets a compromised client burn far more gas than it ever needs.

`policies/wars-arb-base-celo.yaml` is a complete two-chain example.

### Calldata regexes

- They match against the **lowercase hex** calldata without `0x`, e.g.
  `095ea7b3000…`. Every byte is two characters, so an ABI word is 64 characters.
- They must be anchored `^…$`. Matching is **always full**, so appended data never passes.
- Supported syntax: literals, `.`, `[...]`, `[^...]`, `(...)`, `(?:...)`, `|`,
  `* + ?`, `{n}`, `{n,}`, `{n,m}`, and `\d \w \s`. Not supported: lookarounds,
  backreferences, lazy quantifiers.
- The engine is a Pike VM: matching time is linear in the calldata length, so
  there's no catastrophic backtracking. A per-match step budget turns
  pathological patterns into denials.
- Whitespace and `#` comments inside patterns are stripped by the compiler, so
  long patterns can be written one ABI word per line.

Macros:

| Macro | Expands to |
|---|---|
| `{{addr:NAME}}` | 64-hex left-padded address word from `address_book` (or `self`) |
| `{{hex:NAME}}` | 40-hex address |
| `{{uint}}` | `[0-9a-f]{64}` (any word) |
| `{{u256:N}}` | the word for the fixed integer N, e.g. `{{u256:8453}}`, `{{u256:0x40}}` |
| `{{sel:fn(types)}}` | 4-byte selector |
| `{{self}}` / `{{addr:self}}` | the signer address, filled in on the device |

### Pitfalls

- **Pin every address argument.** `approve(spender, …)` with `{{uint}}` as the
  spender lets anyone be approved, and that's a drain. The same goes for
  `transfer(to, …)` and any router `recipient`.
- **Router calldata is nested ABI.** The UniversalRouter example pins the
  command list (`V4_SWAP` only) and the action list (`SWAP_EXACT_IN_SINGLE`,
  `SETTLE_ALL`, `TAKE_ALL`). With those actions the output always goes to
  `msg.sender`. Allowing `TAKE` (0x0e), `SWEEP` or `TRANSFER` commands would
  reintroduce an arbitrary recipient.
- **Test with real calldata from your bot** before deploying:
  ```sh
  esp32signer test-policy policies/my.yaml captured-txs.json --self-address 0xYourSigner
  ```
  `test-policy` uses the same semantics as the device, and `host/tests` checks
  that it agrees with the C engine.

## Limits

16 chain IDs, 64 native transfer entries, 128 contracts, 64 rules per contract,
8192 compiled instructions per rule, 16384 in total, and 16 KB of calldata.
`provision` reports the instruction count.
