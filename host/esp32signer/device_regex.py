"""The device regex dialect: grammar and compiled size, mirrored from
firmware/components/policy/regex.c so `compile-policy` rejects what the device
would reject, before provisioning.

Supported: literals, `.`, `[...]` / `[^...]` with ranges, `\\d \\w \\s`,
escapes of `.[]()|*+?{}^$\\-/`, `(...)` and `(?:...)`, `|`, `* + ? {n} {n,} {n,m}`
(n, m <= 1024), `^ $`. No lazy quantifiers, lookaround, backreferences or other
escapes.
"""

from __future__ import annotations

REGEX_MAX_INSTS = 8192  # per pattern, including the final MATCH
REGEX_MAX_REPEAT = 1024
MAX_DEPTH = 64
_META = set(".[]()|*+?{}^$\\-/")  # may be escaped
_NOT_PLAIN = set("()[].^$\\*+?{}|")
_QUANT = set("*+?{")
_SHORTHAND = set("dws")


class RegexError(ValueError):
    pass


class _Parser:
    """Recursive descent over the same grammar as regex.c; returns instruction counts directly.

    Each parse_* returns (insts, kind) where kind is "anchor" for ^/$ (which
    cannot be quantified) and "atom" otherwise.
    """

    def __init__(self, s: str):
        self.s, self.i, self.depth = s, 0, 0

    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < len(self.s) else ""

    def fail(self, msg: str):
        raise RegexError(f"{msg} (at offset {self.i})")

    def parse(self) -> int:
        n = self.alt()
        if self.i < len(self.s):
            self.fail("unbalanced )")
        return n + 1  # + MATCH

    def alt(self) -> int:
        n, alts = self.cat(), 1
        while self.peek() == "|":
            self.i += 1
            n += self.cat()
            alts += 1
        return n + 2 * (alts - 1)  # SPLIT + JMP per alternative but the last

    def cat(self) -> int:
        n = 0
        while self.peek() and self.peek() not in "|)":
            c = self.peek()
            if c not in _NOT_PLAIN and self.peek(1) not in _QUANT:  # "" (end) is not a quantifier
                self.i += 1  # unquantified literal
                n += 1
            else:
                n += self.repeat()
        return n

    def repeat(self) -> int:
        n, kind = self.atom()
        while True:
            q = self.peek()
            if q == "*":
                lo, hi = 0, -1
                self.i += 1
            elif q == "+":
                lo, hi = 1, -1
                self.i += 1
            elif q == "?":
                lo, hi = 0, 1
                self.i += 1
            elif q == "{":
                self.i += 1
                lo = self.integer()
                if self.peek() == "}":
                    hi = lo
                elif self.peek() == ",":
                    self.i += 1
                    hi = -1 if self.peek() == "}" else self.integer()
                else:
                    self.fail("bad {} quantifier")
                if self.peek() != "}":
                    self.fail("missing }")
                self.i += 1
                if hi != -1 and hi < lo:
                    self.fail("{n,m} with m < n")
            else:
                return n
            if self.peek() == "?":
                self.fail("lazy quantifiers are not supported")
            if kind == "anchor":
                self.fail("quantifier on anchor")
            n = lo * n + (n + 2 if hi == -1 else (hi - lo) * (n + 1))
            kind = "atom"

    def integer(self) -> int:
        start, v = self.i, 0
        while self.peek() and self.peek() in "0123456789":
            v = v * 10 + int(self.peek())
            self.i += 1
            if v > REGEX_MAX_REPEAT:
                self.fail(f"repeat count exceeds {REGEX_MAX_REPEAT}")
        if self.i == start:
            self.fail("expected number in {}")
        return v

    def atom(self) -> tuple[int, str]:
        c = self.peek()
        if c == "(":
            self.depth += 1
            if self.depth > MAX_DEPTH:
                self.fail("groups nested too deeply")
            self.i += 1
            if self.peek() == "?":
                if self.peek(1) != ":":
                    self.fail("only (?:...) groups are supported")
                self.i += 2
            n = self.alt()
            if self.peek() != ")":
                self.fail("missing )")
            self.i += 1
            self.depth -= 1
            return n, "atom"
        if c == "[":
            self.char_class()
            return 1, "atom"
        if c == ".":
            self.i += 1
            return 1, "atom"
        if c in "^$":
            self.i += 1
            return 1, "anchor"
        if c == "\\":
            e = self.peek(1)
            if not e:
                self.fail("trailing backslash")
            self.i += 2
            if e not in _SHORTHAND and e not in _META:
                self.fail(f"unsupported escape \\{e}")
            return 1, "atom"
        if c in "*+?{":
            self.fail("quantifier without operand")
        if c in ")|" or not c:
            self.fail("unexpected end of expression")
        if c in "]}":
            self.fail(f"unescaped '{c}'")
        self.i += 1
        return 1, "atom"

    def char_class(self) -> None:
        self.i += 1  # [
        if self.peek() == "^":
            self.i += 1
        first = True
        while self.peek() and (self.peek() != "]" or first):
            if self.peek() == "\\":
                e = self.peek(1)
                if not e:
                    self.fail("trailing backslash")
                self.i += 2
                if e in _SHORTHAND:
                    first = False
                    continue
                if e not in _META:
                    self.fail(f"unsupported escape \\{e}")
                lo = e
            else:
                lo = self.peek()
                self.i += 1
            if self.peek() == "-" and self.peek(1) and self.peek(1) != "]":
                self.i += 1
                if self.peek() == "\\":
                    e = self.peek(1)
                    if not e or e not in _META:
                        self.fail("bad range escape")
                    hi = e
                    self.i += 2
                else:
                    hi = self.peek()
                    self.i += 1
                if ord(hi) < ord(lo):
                    self.fail("bad character range")
            first = False
        if self.peek() != "]":
            self.fail("unterminated character class")
        self.i += 1


def instructions(pattern: str) -> int:
    """Compiled size on the device (instructions, including MATCH). Raises RegexError
    for syntax the device rejects or a pattern larger than REGEX_MAX_INSTS."""
    if any(ord(ch) > 0x7F for ch in pattern):
        raise RegexError("non-ASCII characters are not supported")
    n = _Parser(pattern).parse()
    if n > REGEX_MAX_INSTS:
        raise RegexError(f"pattern compiles to more than {REGEX_MAX_INSTS} instructions ({n})")
    return n
