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
from decimal import Decimal, Inexact, InvalidOperation, localcontext
from typing import Any

import yaml
from eth_utils import keccak

from . import device_regex

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


# Firmware limits (firmware/components/policy/include/policy.h): checked here
# so compile-policy fails before provisioning, not on the device.
MAX_CHAIN_IDS = 16
MAX_NATIVE = 64
MAX_CONTRACTS = 128
MAX_RULES_PER_CONTRACT = 64
MAX_TOTAL_INSTS = 16384
U256 = 2**256


class PolicyError(ValueError):
    pass


def _is_int(v: Any) -> bool:
    """A YAML integer. bool is an int subclass in Python but serializes as true/false."""
    return isinstance(v, int) and not isinstance(v, bool)


def _check_keys(obj: Any, allowed: set[str], where: str) -> None:
    if not isinstance(obj, dict):
        raise PolicyError(f"{where}: must be a mapping")
    unknown = set(obj) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}")


def _to_wei(value: Any, unit: int, where: str) -> int:
    """Exact decimal -> wei. Never rounds: a limit is either exactly representable or rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise PolicyError(f"{where}: not a number: {value!r}")
    if isinstance(value, float):
        # Unquoted YAML decimals arrive as binary floats. repr() gives the shortest
        # decimal that round-trips, which is what was written for up to 15 digits.
        text = repr(value)
        if len(Decimal(text).as_tuple().digits) > 15:
            raise PolicyError(f"{where}: {value!r} has too many digits for an unquoted number; quote it")
    else:
        text = str(value).strip()
    try:
        d = Decimal(text)  # exact for any string
        with localcontext() as ctx:
            ctx.prec = 200
            ctx.traps[Inexact] = True
            wei = d * unit
    except (InvalidOperation, Inexact, ValueError) as e:
        raise PolicyError(f"{where}: not an exact number: {value!r}") from e
    if not wei.is_finite() or wei < 0 or wei != wei.to_integral_value():
        raise PolicyError(f"{where}: must be a non-negative whole number of wei")
    if wei >= U256:
        raise PolicyError(f"{where}: does not fit in 256 bits")
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
        self.insts = 0  # total compiled regex size, as the device counts it

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
        # The device's grammar and size limits (device_regex mirrors regex.c), then
        # Python's engine, which evaluate() uses.
        probe = out.replace("{{addr:self}}", "0" * 64).replace("{{self}}", "0" * 40)
        try:
            self.insts += device_regex.instructions(probe)
        except device_regex.RegexError as e:
            raise PolicyError(f"{where}: not supported by the device regex engine: {e}") from e
        try:
            re.compile(probe)
        except re.error as e:
            raise PolicyError(f"{where}: invalid regex: {e}") from e
        return out


def _limits(lim: Any, where: str, keys: set[str]) -> dict:
    _check_keys(lim, keys, where)
    max_gas = lim.get("max_gas")
    if not _is_int(max_gas) or max_gas <= 0 or max_gas >= 2**53:
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
    if not isinstance(ch, list) or not ch or not all(_is_int(c) for c in ch):
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
    if not isinstance(chain_ids, list) or not chain_ids or not all(_is_int(c) and 0 < c <= 2**53 for c in chain_ids):
        raise PolicyError("chain_ids must be a non-empty list of positive integers")
    if len(chain_ids) > MAX_CHAIN_IDS:
        raise PolicyError(f"chain_ids: at most {MAX_CHAIN_IDS} (device limit)")
    if len(set(chain_ids)) != len(chain_ids):
        raise PolicyError("chain_ids contains duplicates")

    lim = doc.get("limits")
    limits = _limits(lim, "limits", LIMIT_KEYS)
    rate = lim.get("rate_per_minute", 0)
    if not _is_int(rate) or rate < 0 or rate > 100000:
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
        if not _is_int(cid) or cid not in chain_ids:
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
        if len(rules_in) > MAX_RULES_PER_CONTRACT:
            raise PolicyError(f"{where}: at most {MAX_RULES_PER_CONTRACT} rules per contract (device limit)")
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
    if len(natives) > MAX_NATIVE:
        raise PolicyError(f"native_transfers: at most {MAX_NATIVE} entries (device limit)")
    if len(contracts) > MAX_CONTRACTS:
        raise PolicyError(f"contracts: at most {MAX_CONTRACTS} entries (device limit)")
    if ctx.insts > MAX_TOTAL_INSTS:
        raise PolicyError(f"policy regexes too large ({ctx.insts} instructions, device max {MAX_TOTAL_INSTS})")

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


class _Deny(Exception):
    pass


_HEX_QTY = re.compile(r"0[xX][0-9a-fA-F]{1,64}")
_HEX_DATA = re.compile(r"0[xX](?:[0-9a-fA-F]{2})*")
_FORBIDDEN_TX = ("authorizationList", "blobVersionedHashes", "maxFeePerBlobGas", "blobs")


def _qty(tx: dict, key: str) -> int | None:
    """Like the firmware's get_qty: None if absent/null; hex string or a JSON-safe integer."""
    v = tx.get(key)
    if v is None:
        return None
    if _is_int(v) and 0 <= v < U256:  # Python ints (callers convert JSON first)
        return v
    if isinstance(v, str) and _HEX_QTY.fullmatch(v):
        return int(v, 16)
    raise _Deny(f"invalid {key}")


def _addr(v: Any, key: str) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not ADDR_RE.match(v):
        raise _Deny(f"invalid '{key}' address")
    return v.lower()


def normalize_tx(tx: dict, self_address: str | None = None) -> dict:
    """Parse a JSON-RPC transaction the way the device does (tx_json.c + rpc.c).

    Returns {type, chain, gas, max_fee, max_prio, to, value, data}; raises _Deny.
    """
    if not isinstance(tx, dict):
        raise _Deny("transaction must be an object")
    for k in _FORBIDDEN_TX:
        if k in tx:
            raise _Deny(f"field '{k}' is not supported")
    mf, mp, gp = _qty(tx, "maxFeePerGas"), _qty(tx, "maxPriorityFeePerGas"), _qty(tx, "gasPrice")
    t = _qty(tx, "type")
    if t is not None:
        if t not in (0, 2):
            raise _Deny("unsupported transaction type (only 0x0 and 0x2 are allowed)")
    elif mf is not None or mp is not None:
        t = 2
    elif gp is not None:
        t = 0
    else:
        raise _Deny("missing fee fields (maxFeePerGas/maxPriorityFeePerGas or gasPrice)")
    if t == 2:
        if mf is None or mp is None:
            raise _Deny("type 0x2 requires maxFeePerGas and maxPriorityFeePerGas")
        if gp is not None:
            raise _Deny("gasPrice not allowed with type 0x2")
        if mp > mf:
            raise _Deny("maxPriorityFeePerGas exceeds maxFeePerGas")
    else:
        if gp is None:
            raise _Deny("type 0x0 requires gasPrice")
        if mf is not None or mp is not None:
            raise _Deny("EIP-1559 fee fields not allowed with type 0x0")
        mf = gp
    chain = _qty(tx, "chainId")
    if not chain or chain > 2**53:
        raise _Deny("chainId is required")
    if _qty(tx, "nonce") is None:
        raise _Deny("nonce is required")
    gas, gas_limit = _qty(tx, "gas"), _qty(tx, "gasLimit")
    if gas is not None and gas_limit is not None and gas != gas_limit:
        raise _Deny("'gas' and 'gasLimit' differ")
    gas = gas if gas is not None else gas_limit
    if gas is None:
        raise _Deny("gas is required")
    value = _qty(tx, "value") or 0
    to = _addr(tx.get("to"), "to")
    frm = _addr(tx.get("from"), "from")
    if frm is not None and self_address and frm != self_address.lower():
        raise _Deny("'from' is not the signer address")
    data_in, data_d = tx.get("input"), tx.get("data")
    if data_in is not None:
        if data_d is not None and (not isinstance(data_d, str) or data_d.lower() != str(data_in).lower()):
            raise _Deny("'data' and 'input' differ")
        data = data_in
    else:
        data = data_d if data_d is not None else "0x"
    if not isinstance(data, str) or not _HEX_DATA.fullmatch(data):
        raise _Deny("invalid 'input'/'data'")
    al = tx.get("accessList")
    if al is not None:
        if not isinstance(al, list):
            raise _Deny("invalid accessList")
        if t == 0 and al:
            raise _Deny("accessList not allowed with type 0x0")
    return {"type": t, "chain": chain, "gas": gas, "max_fee": mf, "max_prio": mp, "to": to, "value": value,
            "data": data[2:].lower()}


def evaluate(policy: dict, tx: dict, self_address: str | None = None) -> tuple[bool, str]:
    """Mirror of the device's policy_check (minus rate limiting) for offline testing.

    `tx` is a JSON-RPC style transaction (hex quantities or ints).
    """
    selfhex = (self_address or "0x" + "0" * 40).lower()[2:]

    def addr(a: str) -> str:
        return "0x" + selfhex if a == "{{self}}" else a.lower()

    try:
        t = normalize_tx(tx, self_address)
    except _Deny as e:
        return False, f"parse: {e}"
    chain = t["chain"]
    if chain not in policy["chain_ids"]:
        return False, f"chainId {chain} not allowed"
    lim = next((cl for cl in policy.get("chain_limits", []) if cl["chain_id"] == chain), policy["limits"])

    def on_chain(entry: dict) -> bool:
        return chain in entry.get("chain_ids", [chain])

    if t["gas"] > lim["max_gas"]:
        return False, "gas exceeds max_gas"
    if t["max_fee"] > int(lim["max_fee_per_gas"]):
        return False, "fee per gas exceeds cap"
    if t["type"] == 2 and t["max_prio"] > int(lim["max_priority_fee_per_gas"]):
        return False, "priority fee exceeds cap"
    to = t["to"]
    if not to:
        return False, "contract creation not allowed"
    data, value = t["data"], t["value"]
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


def policy_instructions(policy: dict) -> int:
    """Total compiled regex size of a compiled policy, as the device counts it."""
    return sum(device_regex.instructions(r["calldata"].replace("{{addr:self}}", "0" * 64).replace("{{self}}", "0" * 40))
               for c in policy.get("contracts", []) for r in c["rules"])


def canonical_json(policy: dict) -> bytes:
    return json.dumps(policy, separators=(",", ":"), sort_keys=True).encode()


def policy_sha256(policy: dict) -> str:
    return hashlib.sha256(canonical_json(policy)).hexdigest()
