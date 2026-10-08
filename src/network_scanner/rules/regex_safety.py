"""A conservative check that a rule's regular expression cannot backtrack catastrophically.

Python's `re` has no timeout, so a pattern that backtracks exponentially would hang the scan
the moment a hostile banner meets it. Instead of trying to prove a pattern safe, this module
accepts only a small, closed subset of the syntax and applies structural limits (PLAN.md
risk R4):

- printable ASCII only (anything else is written as `\\xHH`);
- literals, `.`, `^`, `$`, `\\b`, the escapes `\\d \\D \\s \\S \\w \\W`, escaped punctuation,
  `\\xHH`, `\\t \\n \\r`, character classes, `(...)` and `(?:...)` groups and `|`;
- the quantifiers `* + ? {m} {m,} {m,n}` with counts of at most `MAX_REGEX_REPEAT`, each
  optionally lazy;
- never backreferences, lookaround, conditionals, atomic or possessive forms, named groups,
  inline flags or comments;
- a group that can repeat more than once (`*`, `+`, or `{m,n}` with n above 1) may not
  contain a quantifier that can repeat more than once, or an alternation (this is what makes
  `(a+)+` and `(a|aa)*` exponential);
- at most `MAX_REGEX_LARGE_REPEATS` unbounded or large repeats in one pattern, which bounds
  sequences such as `.*.*.*x` to a cubic number of steps;
- a pattern length cap, and a pattern is only ever run on the first `MAX_REGEX_INPUT_CHARS`
  characters of its input.

This is a structural filter, not a proof of linear time. It rejects some harmless patterns
on purpose, and a pattern it accepts can still be slow in the polynomial sense.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass

from network_scanner.core.limits import (
    MAX_REGEX_GROUP_DEPTH,
    MAX_REGEX_INPUT_CHARS,
    MAX_REGEX_LARGE_REPEATS,
    MAX_REGEX_PATTERN_CHARS,
    MAX_REGEX_REPEAT,
    REGEX_SMALL_REPEAT,
)

_HEX = frozenset("0123456789abcdefABCDEF")
_CLASS_ESCAPES = frozenset("dDsSwW")
_CONTROL_ESCAPES = {"t": "\t", "n": "\n", "r": "\r"}
_CLASS_DOUBLED = frozenset("&~|")  # `&&`, `~~` and `||` are set operations `re` warns about
_BRACES = re.compile(r"\{([0-9]{1,4})(?:(,)([0-9]{1,4})?)?\}")


class UnsafeRegex(ValueError):
    """The pattern is outside the accepted subset. `position` is a 0-based index."""

    def __init__(self, reason: str, position: int) -> None:
        super().__init__(f"{reason} (at position {position})")
        self.reason = reason
        self.position = position


@dataclass(slots=True)
class _Shape:
    """What a sub-pattern contains, for the nested-repeat rule."""

    repeats: bool = False  # contains a quantifier that can repeat more than once
    alternates: bool = False  # contains an alternation

    def absorb(self, other: _Shape) -> None:
        self.repeats = self.repeats or other.repeats
        self.alternates = self.alternates or other.alternates


class _Checker:
    def __init__(self, pattern: str) -> None:
        self.text = pattern
        self.at = 0
        self.large_repeats = 0

    def fail(self, reason: str, position: int | None = None) -> UnsafeRegex:
        return UnsafeRegex(reason, self.at if position is None else position)

    def peek(self, offset: int = 0) -> str:
        index = self.at + offset
        return self.text[index] if index < len(self.text) else ""

    # -- grammar ---------------------------------------------------------------------
    def alternation(self, depth: int) -> _Shape:
        shape = _Shape()
        while True:
            shape.absorb(self.sequence(depth))
            if self.peek() != "|":
                return shape
            self.at += 1
            shape.alternates = True

    def sequence(self, depth: int) -> _Shape:
        shape = _Shape()
        while self.peek() not in ("", "|", ")"):
            start = self.at
            atom_shape, repeatable = self.atom(depth)
            shape.absorb(self.quantifier(atom_shape, repeatable, start))
        return shape

    def atom(self, depth: int) -> tuple[_Shape, bool]:
        """Parse one atom; returns its shape and whether a quantifier may follow it."""
        char = self.peek()
        if char == "(":
            return self.group(depth), True
        if char == "[":
            self.character_class()
            return _Shape(), True
        if char == "\\":
            return _Shape(), self.escape()
        if char in ("^", "$"):
            self.at += 1
            return _Shape(), False
        if char in ("*", "+", "?", "{"):
            raise self.fail("nothing to repeat")
        if char == "}":
            raise self.fail("an unescaped '}' is ambiguous; write \\}")
        self.require_printable(char)
        self.at += 1
        return _Shape(), True

    def require_printable(self, char: str) -> None:
        if not " " <= char <= "~":
            raise self.fail("only printable ASCII is accepted; write other characters as \\xHH")

    def group(self, depth: int) -> _Shape:
        if depth >= MAX_REGEX_GROUP_DEPTH:
            raise self.fail(f"groups nested more than {MAX_REGEX_GROUP_DEPTH} deep")
        self.at += 1  # '('
        if self.peek() == "?":
            self.group_prefix()
        shape = self.alternation(depth + 1)
        if self.peek() != ")":
            raise self.fail("unbalanced parenthesis")
        self.at += 1
        return shape

    def group_prefix(self) -> None:
        rest = self.text[self.at + 1 :]
        if rest.startswith(":"):
            self.at += 2
        elif rest.startswith(("=", "!", "<=", "<!")):
            raise self.fail("lookaround is not allowed")
        elif rest.startswith(("P", "<")):
            raise self.fail("named groups and backreferences are not allowed")
        elif rest.startswith("("):
            raise self.fail("conditional patterns are not allowed")
        elif rest.startswith(">"):
            raise self.fail("atomic groups are not allowed")
        elif rest.startswith("#"):
            raise self.fail("comments are not allowed")
        else:
            raise self.fail("inline flags and unknown group forms are not allowed")

    def character_class(self) -> None:
        self.at += 1  # '['
        if self.peek() == "^":
            self.at += 1
        if self.peek() in ("", "]"):
            raise self.fail("empty or ambiguous character class")
        while self.peek() != "]":
            low = self.class_member()
            if self.peek() == "-" and self.peek(1) not in ("", "]"):
                self.at += 1
                high = self.class_member()
                if low is None or high is None or ord(low) > ord(high):
                    raise self.fail("invalid range in a character class")
        self.at += 1  # ']'

    def class_member(self) -> str | None:
        """Parse one class member; returns its character, or None for a class escape."""
        char = self.peek()
        if char == "":
            raise self.fail("unbalanced bracket")
        if char == "\\":
            if self.peek(1) == "b":
                raise self.fail("\\b inside a character class is a backspace; not allowed")
            return self.escape_body()
        if char == "[" or (char in _CLASS_DOUBLED and self.peek(1) == char):
            raise self.fail(f"write {char!r} as \\{char} inside a character class")
        self.require_printable(char)
        self.at += 1
        return char

    def escape(self) -> bool:
        """Parse an escape outside a class; returns whether a quantifier may follow."""
        if self.peek(1) == "b":
            self.at += 2
            return False
        self.escape_body()
        return True

    def escape_body(self) -> str | None:
        """Parse a backslash escape; returns the character it stands for, None for \\d etc."""
        following = self.peek(1)
        if following == "":
            raise self.fail("a pattern may not end with a backslash")
        if following.isdigit():
            raise self.fail("backreferences are not allowed")
        if following in _CLASS_ESCAPES:
            self.at += 2
            return None
        if following in _CONTROL_ESCAPES:
            self.at += 2
            return _CONTROL_ESCAPES[following]
        if following == "x":
            digits = self.text[self.at + 2 : self.at + 4]
            if len(digits) != 2 or not set(digits) <= _HEX:
                raise self.fail("\\x needs exactly two hexadecimal digits")
            self.at += 4
            return chr(int(digits, 16))
        if following.isascii() and following.isalnum():
            raise self.fail(f"the escape \\{following} is not allowed")
        self.require_printable(following)
        self.at += 2
        return following

    def quantifier(self, atom_shape: _Shape, repeatable: bool, start: int) -> _Shape:
        present, high = self.read_bounds()
        if not present:
            return atom_shape
        if not repeatable:
            raise self.fail("this element cannot be repeated", start)
        repeats_more_than_once = high is None or high > 1
        if repeats_more_than_once:
            if atom_shape.repeats or atom_shape.alternates:
                raise self.fail(
                    "a repeated group may not contain a quantifier or an alternation", start
                )
            if high is None or high > REGEX_SMALL_REPEAT:
                self.large_repeats += 1
                if self.large_repeats > MAX_REGEX_LARGE_REPEATS:
                    raise self.fail(
                        f"more than {MAX_REGEX_LARGE_REPEATS} unbounded or large repeats", start
                    )
        if self.peek() == "?":  # lazy form
            self.at += 1
        if self.peek() == "+":
            raise self.fail("possessive quantifiers are not allowed")
        if self.peek() in ("*", "?", "{"):
            raise self.fail("a quantifier cannot be followed by another quantifier")
        return _Shape(atom_shape.repeats or repeats_more_than_once, atom_shape.alternates)

    def read_bounds(self) -> tuple[bool, int | None]:
        """Consume a quantifier if there is one; returns (found, largest count or None)."""
        char = self.peek()
        if char in ("*", "+"):
            self.at += 1
            return True, None
        if char == "?":
            self.at += 1
            return True, 1
        if char != "{":
            return False, None
        match = _BRACES.match(self.text, self.at)
        if match is None:
            raise self.fail("malformed repeat; an unescaped '{' is not allowed")
        low = int(match.group(1))
        if match.group(2) is None:  # {m}
            high: int | None = low
        elif match.group(3) is None:  # {m,}
            high = None
        else:
            high = int(match.group(3))
        if low > MAX_REGEX_REPEAT or (high is not None and high > MAX_REGEX_REPEAT):
            raise self.fail(f"a repeat count above {MAX_REGEX_REPEAT} is not allowed")
        if high is not None and low > high:
            raise self.fail("the minimum of a repeat is above its maximum")
        self.at = match.end()
        return True, high


def check_pattern(pattern: str) -> None:
    """Raise `UnsafeRegex` unless `pattern` is inside the accepted subset."""
    if not pattern:
        raise UnsafeRegex("the pattern is empty", 0)
    if len(pattern) > MAX_REGEX_PATTERN_CHARS:
        raise UnsafeRegex(f"the pattern is longer than {MAX_REGEX_PATTERN_CHARS} characters", 0)
    checker = _Checker(pattern)
    checker.alternation(0)
    if checker.at < len(pattern):  # only an unmatched ')' stops the top-level parse early
        raise checker.fail("unbalanced parenthesis")


def compile_safe(pattern: str) -> re.Pattern[str]:
    """Check `pattern`, then compile it. Use the result only through `search_bounded`."""
    check_pattern(pattern)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # a FutureWarning about ambiguous sets is a refusal
            return re.compile(pattern)
    except (re.error, Warning) as exc:
        raise UnsafeRegex(f"the pattern does not compile cleanly ({exc})", 0) from None


def search_bounded(compiled: re.Pattern[str], text: str) -> bool:
    """True if `compiled` matches within the first `MAX_REGEX_INPUT_CHARS` characters of `text`."""
    return compiled.search(text[:MAX_REGEX_INPUT_CHARS]) is not None
