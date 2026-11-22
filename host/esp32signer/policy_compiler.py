"""Compile a human-friendly YAML policy into the canonical JSON the device enforces.

YAML schema (see policies/*.example.yaml):

    version: 1
    name: my-policy                      # optional
    chain_ids: [8453]
    limits:
      max_gas: 3000000
      max_fee_per_gas_gwei: 5            # or max_fee_per_gas_wei: "5000000000"
      max_priority_fee_gwei: 1           # or max_priority_fee_per_gas_wei: "..."
      rate_per_minute: 120               # 0 / omitted = unlimited
    chain_limits:                        # optional per-chain override of max_gas / fee caps
      42220: {max_gas: 2000000, max_fee_per_gas_gwei: 100, max_priority_fee_gwei: 5}
    address_book:                        # host-side names, used by macros
      usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    native_transfers:
      - to: "{{treasury}}"               # address, {{name}} or {{self}}
        max_value_eth: "0.5"             # or max_value_wei: "..." (default 0)
        label: treasury
    contracts:
      - address: "{{usdc}}"
        label: usdc
        max_value_wei: "0"               # default 0
        chains: [8453]                   # optional: only on these chains (default: all)
        rules:
          - name: approve-permit2
            calldata: "^{{sel:approve(address,uint256)}}{{addr:permit2}}{{uint}}$"

Calldata regexes are matched against the lowercase hex calldata (no 0x),
must be anchored ^...$, and always match the FULL calldata.

Macros in calldata:
    {{addr:NAME}}   64-hex left-padded address word (NAME from address_book, or self)
    {{hex:NAME}}    40-hex address without padding
    {{uint}}        any 32-byte word: [0-9a-f]{64}
    {{u256:N}}      the 32-byte word for the fixed integer N (decimal or 0x hex)
    {{sel:SIG}}     4-byte selector of a function signature, e.g. transfer(address,uint256)
    {{self}}        40-hex signer address (expanded on the device)
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from typing import Any

import yaml
from eth_utils import keccak

GWEI = 10**9
ETH = 10**18
UINT_RE = "[0-9a-f]{64}"
MACRO_RE = re.compile(r"\{\{([^{}]*)\}\}")
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

TOP_KEYS = {"version", "name", "chain_ids", "limits", "chain_limits", "address_book", "native_transfers", "contracts"}
LIMIT_KEYS = {
    "max_gas",
    "max_fee_per_gas_gwei",
    "max_fee_per_gas_wei",
    "max_priority_fee_gwei",
    "max_priority_fee_per_gas_wei",
    "rate_per_minute",
}
CHAIN_LIMIT_KEYS = LIMIT_KEYS - {"rate_per_minute"}
NATIVE_KEYS = {"to", "max_value_eth", "max_value_wei", "label", "chains"}
CONTRACT_KEYS = {"address", "label", "max_value_eth", "max_value_wei", "rules", "chains"}
RULE_KEYS = {"name", "calldata"}


class PolicyError(ValueError):
    pass


def _check_keys(obj: Any, allowed: set[str], where: str) -> None:
    if not isinstance(obj, dict):
        raise PolicyError(f"{where}: must be a mapping")
    unknown = set(obj) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}")


def _to_wei(value: Any, unit: int, where: str) -> int:
    try:
        d = Decimal(str(value))
    except Exception as e:  # noqa: BLE001
        raise PolicyError(f"{where}: not a number: {value!r}") from e
    wei = d * unit
    if wei < 0 or wei != wei.to_integral_value():
        raise PolicyError(f"{where}: must be a non-negative whole number of wei")
    return int(wei)


def _wei_field(obj: dict, eth_key: str | None, wei_key: str, unit: int, where: str, required: bool) -> int:
    has_eth = eth_key is not None and eth_key in obj
    if has_eth and wei_key in obj:
        raise PolicyError(f"{where}: give either {eth_key} or {wei_key}, not both")
    if has_eth:
        return _to_wei(obj[eth_key], unit, f"{where}.{eth_key}")
    if wei_key in obj:
        return _to_wei(obj[wei_key], 1, f"{where}.{wei_key}")
    if required:
        raise PolicyError(f"{where}: missing {eth_key or wei_key}")
    return 0


def selector(signature: str) -> str:
    return keccak(text=signature.replace(" ", ""))[:4].hex()


class _Ctx:
    def __init__(self, book: dict[str, str]):
        self.book = book

    def address(self, value: Any, where: str) -> str:
        if not isinstance(value, str):
            raise PolicyError(f"{where}: address must be a string")
        m = re.fullmatch(r"\{\{\s*([A-Za-z0-9_\-]+)\s*\}\}", value)
        if m:
            name = m.group(1)
            if name == "self":
                return "{{self}}"
            if name not in self.book:
                raise PolicyError(f"{where}: unknown address_book entry {name!r}")
            return self.book[name]
        if not ADDR_RE.match(value):
            raise PolicyError(f"{where}: invalid address {value!r}")
        return value.lower()

    def calldata(self, pattern: Any, where: str) -> str:
        if not isinstance(pattern, str):
            raise PolicyError(f"{where}: calldata must be a string")
        # Verbose mode: '#' comments and all whitespace are stripped, so long
        # patterns can be written one ABI word per line in a YAML block scalar.
        pattern = "".join(re.sub(r"\s+", "", line.split("#", 1)[0]) for line in pattern.splitlines())

        def sub(m: re.Match) -> str:
            body = m.group(1).strip()
            if body in ("self", "addr:self"):
                return "{{" + body + "}}"  # expanded on the device
            if body in ("uint", "word"):
                return UINT_RE
            kind, _, arg = body.partition(":")
            if kind == "u256" and arg:
                try:
                    n = int(arg, 0)
                except ValueError:
                    raise PolicyError(f"{where}: bad integer in {{{{u256:{arg}}}}}") from None
                if not 0 <= n < 2**256:
                    raise PolicyError(f"{where}: {{{{u256:{arg}}}}} out of range")
                return f"{n:064x}"
            if kind == "sel" and arg:
                return selector(arg)
            if kind in ("addr", "hex") and arg:
                if arg not in self.book:
                    raise PolicyError(f"{where}: unknown address_book entry {arg!r}")
                h = self.book[arg][2:]
                return h.rjust(64, "0") if kind == "addr" else h
            raise PolicyError(f"{where}: unknown macro {{{{{body}}}}}")

        out = MACRO_RE.sub(sub, pattern)
        if not (out.startswith("^") and out.endswith("$") and not out.endswith("\\$")):
            raise PolicyError(f"{where}: calldata regex must be anchored: start with ^ and end with $")
        # Sanity-compile with Python's engine (device compiles again, authoritatively).
        probe = out.replace("{{addr:self}}", "0" * 64).replace("{{self}}", "0" * 40)
        try:
            re.compile(probe)
        except re.error as e:
            raise PolicyError(f"{where}: invalid regex: {e}") from e
        for bad, why in (("(?=", "lookahead"), ("(?!", "lookahead"), ("(?<", "lookbehind/named group"),
                         ("\\b", "word boundary"), ("*?", "lazy quantifier"), ("+?", "lazy quantifier")):
            if bad in probe:
                raise PolicyError(f"{where}: {why} is not supported by the device regex engine")
        return out


def _limits(lim: Any, where: str, keys: set[str]) -> dict:
    _check_keys(lim, keys, where)
    max_gas = lim.get("max_gas")
    if not isinstance(max_gas, int) or max_gas <= 0:
        raise PolicyError(f"{where}.max_gas must be a positive integer")
    return {
        "max_gas": max_gas,
        "max_fee_per_gas": str(_wei_field(lim, "max_fee_per_gas_gwei", "max_fee_per_gas_wei", GWEI, where, True)),
        "max_priority_fee_per_gas": str(
            _wei_field(lim, "max_priority_fee_gwei", "max_priority_fee_per_gas_wei", GWEI, where, True)
        ),
    }


def _chains(entry: dict, chain_ids: list[int], where: str) -> list[int] | None:
    """Optional per-entry chain restriction; None = all chains."""
    if "chains" not in entry:
        return None
    ch = entry["chains"]
    if not isinstance(ch, list) or not ch or not all(isinstance(c, int) for c in ch):
        raise PolicyError(f"{where}.chains must be a non-empty list of chain ids")
    if len(set(ch)) != len(ch):
        raise PolicyError(f"{where}.chains contains duplicates")
    for c in ch:
        if c not in chain_ids:
            raise PolicyError(f"{where}.chains: {c} is not in chain_ids")
    return sorted(ch)


def _overlaps(a: list[int] | None, b: list[int] | None) -> bool:
    return a is None or b is None or bool(set(a) & set(b))


def compile_policy(src: str | dict) -> tuple[dict, list[str]]:
    """Return (canonical_policy_dict, warnings)."""
    doc = yaml.safe_load(src) if isinstance(src, str) else src
    warnings: list[str] = []
    _check_keys(doc, TOP_KEYS, "policy")
    if doc.get("version") != 1:
        raise PolicyError("policy: version must be 1")

    book_raw = doc.get("address_book") or {}
    if not isinstance(book_raw, dict):
        raise PolicyError("address_book must be a mapping")
    book: dict[str, str] = {}
    for name, addr in book_raw.items():
        if name == "self":
            raise PolicyError("address_book: 'self' is reserved")
        if not isinstance(addr, str) or not ADDR_RE.match(addr):
            raise PolicyError(f"address_book.{name}: invalid address {addr!r}")
        book[str(name)] = addr.lower()
    ctx = _Ctx(book)

    chain_ids = doc.get("chain_ids")
    if not isinstance(chain_ids, list) or not chain_ids or not all(isinstance(c, int) and c > 0 for c in chain_ids):
        raise PolicyError("chain_ids must be a non-empty list of positive integers")
    if len(set(chain_ids)) != len(chain_ids):
        raise PolicyError("chain_ids contains duplicates")

    lim = doc.get("limits")
    limits = _limits(lim, "limits", LIMIT_KEYS)
    rate = lim.get("rate_per_minute", 0)
    if not isinstance(rate, int) or rate < 0 or rate > 100000:
        raise PolicyError("limits.rate_per_minute must be an integer 0..100000")
    if rate == 0:
        warnings.append("limits.rate_per_minute is 0 (unlimited)")
    if rate:
        limits["rate_per_minute"] = rate

    chain_limits = []
    cl = doc.get("chain_limits") or {}
    if not isinstance(cl, dict):
        raise PolicyError("chain_limits must be a mapping of chain id -> limits")
    for cid, l in sorted(cl.items()):
        if not isinstance(cid, int) or cid not in chain_ids:
            raise PolicyError(f"chain_limits: {cid!r} is not in chain_ids")
        chain_limits.append({"chain_id": cid, **_limits(l, f"chain_limits.{cid}", CHAIN_LIMIT_KEYS)})

    natives = []
    seen: list[tuple[str, list[int] | None]] = []
    for i, n in enumerate(doc.get("native_transfers") or []):
        where = f"native_transfers[{i}]"
        _check_keys(n, NATIVE_KEYS, where)
        to = ctx.address(n.get("to"), f"{where}.to")
        chains = _chains(n, chain_ids, where)
        if any(a == to and _overlaps(ch, chains) for a, ch in seen):
            raise PolicyError(f"{where}: duplicate address on the same chain")
        seen.append((to, chains))
        entry = {"to": to, "max_value": str(_wei_field(n, "max_value_eth", "max_value_wei", ETH, where, False))}
        if n.get("label"):
            entry["label"] = str(n["label"])[:47]
        if chains is not None:
            entry["chain_ids"] = chains
        natives.append(entry)

    contracts = []
    seen = []
    for i, c in enumerate(doc.get("contracts") or []):
        where = f"contracts[{i}]"
        _check_keys(c, CONTRACT_KEYS, where)
        addr = ctx.address(c.get("address"), f"{where}.address")
        chains = _chains(c, chain_ids, where)
        if any(a == addr and _overlaps(ch, chains) for a, ch in seen):
            raise PolicyError(f"{where}: duplicate address on the same chain")
        seen.append((addr, chains))
        rules_in = c.get("rules")
        if not isinstance(rules_in, list) or not rules_in:
            raise PolicyError(f"{where}: rules must be a non-empty list")
        rules = []
        for j, r in enumerate(rules_in):
            rwhere = f"{where}.rules[{j}]"
            _check_keys(r, RULE_KEYS, rwhere)
            cd = ctx.calldata(r.get("calldata"), rwhere)
            if re.search(r"(?<!\\)[A-F]", re.sub(r"\[[^\]]*\]", "", cd.replace("{{addr:self}}", ""))):
                warnings.append(f"{rwhere}: uppercase hex in pattern never matches (calldata is lowercase)")
            rule = {"calldata": cd}
            if r.get("name"):
                rule["name"] = str(r["name"])[:47]
            rules.append(rule)
        entry = {
            "address": addr,
            "max_value": str(_wei_field(c, "max_value_eth", "max_value_wei", ETH, where, False)),
            "rules": rules,
        }
        if c.get("label"):
            entry["label"] = str(c["label"])[:47]
        if chains is not None:
            entry["chain_ids"] = chains
        contracts.append(entry)

    if not natives and not contracts:
        raise PolicyError("policy allows nothing: add native_transfers or contracts")

    out: dict[str, Any] = {"version": 1, "chain_ids": chain_ids, "limits": limits}
    if chain_limits:
        out["chain_limits"] = chain_limits
    if doc.get("name"):
        out["name"] = str(doc["name"])
    if natives:
        out["native_transfers"] = natives
    if contracts:
        out["contracts"] = contracts
    return out, warnings


def _qty(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    return int(v, 16) if isinstance(v, str) and v.lower().startswith("0x") else int(v)


def evaluate(policy: dict, tx: dict, self_address: str | None = None) -> tuple[bool, str]:
    """Mirror of the device's policy_check (minus rate limiting) for offline testing.

    `tx` is a JSON-RPC style transaction (hex quantities or ints).
    """
    selfhex = (self_address or "0x" + "0" * 40).lower()[2:]

    def addr(a: str) -> str:
        return "0x" + selfhex if a == "{{self}}" else a.lower()

    ttype = _qty(tx.get("type")) if tx.get("type") is not None else (2 if "maxFeePerGas" in tx else 0)
    if ttype not in (0, 2):
        return False, f"transaction type 0x{ttype:x} not allowed"
    chain = _qty(tx.get("chainId"))
    if chain not in policy["chain_ids"]:
        return False, f"chainId {chain} not allowed"
    lim = next((cl for cl in policy.get("chain_limits", []) if cl["chain_id"] == chain), policy["limits"])

    def on_chain(entry: dict) -> bool:
        return chain in entry.get("chain_ids", [chain])

    if _qty(tx.get("gas", tx.get("gasLimit"))) > lim["max_gas"]:
        return False, "gas exceeds max_gas"
    fee = _qty(tx.get("maxFeePerGas") if ttype == 2 else tx.get("gasPrice"))
    if fee > int(lim["max_fee_per_gas"]):
        return False, "fee per gas exceeds cap"
    if ttype == 2 and _qty(tx.get("maxPriorityFeePerGas")) > int(lim["max_priority_fee_per_gas"]):
        return False, "priority fee exceeds cap"
    to = tx.get("to")
    if not to:
        return False, "contract creation not allowed"
    to = to.lower()
    data = (tx.get("input") or tx.get("data") or "0x").lower()[2:]
    value = _qty(tx.get("value"))
    if not data:
        for n in policy.get("native_transfers", []):
            if on_chain(n) and addr(n["to"]) == to:
                if value > int(n["max_value"]):
                    return False, "value exceeds max_value for native transfer"
                return True, f"native_transfer:{n.get('label', to)}"
    for c in policy.get("contracts", []):
        if not on_chain(c) or addr(c["address"]) != to:
            continue
        label = c.get("label", to)
        if value > int(c["max_value"]):
            return False, f"value exceeds max_value for contract {label}"
        for r in c["rules"]:
            pat = r["calldata"].replace("{{addr:self}}", selfhex.rjust(64, "0")).replace("{{self}}", selfhex)
            if re.fullmatch(pat, data):
                return True, f"{label}:{r.get('name', 'rule')}"
        return False, f"calldata (selector 0x{data[:8]}) matched no rule for contract {label}"
    return False, f"destination {to} not whitelisted"


def canonical_json(policy: dict) -> bytes:
    return json.dumps(policy, separators=(",", ":"), sort_keys=True).encode()


def policy_sha256(policy: dict) -> str:
    return hashlib.sha256(canonical_json(policy)).hexdigest()
