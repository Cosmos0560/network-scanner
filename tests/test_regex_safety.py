from __future__ import annotations

import re

import pytest

from network_scanner.core.limits import (
    MAX_REGEX_COST,
    MAX_REGEX_INPUT_CHARS,
    MAX_REGEX_PATTERN_CHARS,
    MAX_REGEX_REPEAT,
)
from network_scanner.rules.regex_safety import (
    UnsafeRegex,
    check_pattern,
    compile_safe,
    search_bounded,
)

ACCEPTED = [
    r"^SSH-[0-9]\.[0-9]+-",
    r"^220[ -].*(FTP|ftp)",
    r"^\+OK",
    r"^\* OK .*IMAP",
    r"login:",
    r"^RFB [0-9]{3}\.[0-9]{3}$",
    r"(?:nginx|Apache)/[0-9.]+",
    r"[a-z]{1,16}",
    r"\bfoo\b",
    r"a{2,5}b",
    r"a+?b*?",
    r"x?y??",
    r"[^abc\]]",
    r"[a-z0-9._-]+",
    r"[\d\s\w]+",
    r"[ -~]",
    r"\x41\x42",
    r"\t\r\n",
    r"\.\*\+\?\(\)\[\]\{\}\|\^\$\\",
    r"(a|b)c",
    r"(a|b)?c",
    r"((ab)c)d",
    r".*.*x",  # two unbounded repeats fit the budget
    "a?" * 16 + "a" * 16,  # sixteen optional items: 2^16 choices, within the budget
    r"(a|b)(c|d)(e|f)(g|h)(i|j)(k|l)(m|n)(o|p)",  # 2^8 choices
    r"a{0,255}",
    r"(ab){1,2}",
    r"(ab)?",
    r"[-a]",
    r"[a-]",
]


@pytest.mark.parametrize("pattern", ACCEPTED)
def test_patterns_inside_the_subset_are_accepted_and_compile(pattern: str) -> None:
    check_pattern(pattern)
    assert compile_safe(pattern).pattern == pattern


HOSTILE = [
    # catastrophic backtracking, the classic shapes
    (r"(a+)+$", "may not contain a quantifier"),
    (r"(a*)*b", "may not contain a quantifier"),
    (r"(a|aa)+$", "may not contain a quantifier or an alternation"),
    (r"(a|a)*", "may not contain a quantifier or an alternation"),
    (r"(.*a){20}", "may not contain a quantifier"),
    (r"(\d+)*", "may not contain a quantifier"),
    (r"^(([a-z])+.)+[A-Z]([a-z])+$", "may not contain a quantifier"),
    (r"(x+x+)+y", "may not contain a quantifier"),
    (r"((a)|(b))+", "may not contain a quantifier or an alternation"),
    (r"(?:a+){2,}", "may not contain a quantifier"),
    # polynomial blow-up through too many large repeats
    (r".*.*.*x", f"can backtrack too much (estimate above {MAX_REGEX_COST})"),
    (r".*.*.*.*x", "can backtrack too much"),
    (r"a{20,}b{20,}c{20,}d{20,}", "can backtrack too much"),
    (r"[a-z]{1,17}[a-z]{1,17}[a-z]{1,17}[a-z]{1,17}[a-z]{1,17}", "can backtrack too much"),
    # exponential through a sequence, which the nesting rule does not see
    ("a?" * 17 + "a" * 17, "can backtrack too much"),
    ("(a|a)" * 17, "can backtrack too much"),
    ("(a|b|c)" * 11, "can backtrack too much"),  # 3^11 choices
    # constructs outside the subset
    (r"(a)\1", "backreferences"),
    (r"\1", "backreferences"),
    (r"(?P<n>a)(?P=n)", "named groups"),
    (r"(?P<n>a)", "named groups"),
    (r"(?<n>a)", "named groups"),
    (r"(?=a)", "lookaround"),
    (r"(?!a)", "lookaround"),
    (r"(?<=a)b", "lookaround"),
    (r"(?<!a)b", "lookaround"),
    (r"(?i)abc", "inline flags"),
    (r"(?s:a)", "inline flags"),
    (r"(?(1)a|b)", "conditional"),
    (r"(?>a+)", "atomic"),
    (r"(?#comment)", "comments"),
    (r"a*+", "possessive"),
    (r"a++", "possessive"),
    (r"a?+", "possessive"),
    (r"a**", "followed by another quantifier"),
    (r"a*{2}", "followed by another quantifier"),
    (r"a{2}{3}", "followed by another quantifier"),
    (r"a*??", "followed by another quantifier"),
    (r"\A", r"\A is not allowed"),
    (r"\Z", r"\Z is not allowed"),
    (r"\B", r"\B is not allowed"),
    (r"\N{DASH}", r"\N is not allowed"),
    ("\\" + "u0041", "\\" + "u is not allowed"),  # built by hand: a \u escape of the pattern
    (r"\xZZ", "two hexadecimal digits"),
    (r"\x4", "two hexadecimal digits"),
    ("\\", "end with a backslash"),
    # malformed or ambiguous
    ("", "empty"),
    ("*a", "nothing to repeat"),
    ("+a", "nothing to repeat"),
    ("?a", "nothing to repeat"),
    ("{2}a", "nothing to repeat"),
    ("a|*", "nothing to repeat"),
    ("^*", "cannot be repeated"),
    ("$+", "cannot be repeated"),
    (r"\b+", "cannot be repeated"),
    ("a{", "malformed repeat"),
    ("a{x}", "malformed repeat"),
    ("a{1,2,3}", "malformed repeat"),
    ("a{3,2}", "minimum"),
    (f"a{{{MAX_REGEX_REPEAT + 1}}}", "repeat count above"),
    (f"a{{1,{MAX_REGEX_REPEAT + 1}}}", "repeat count above"),
    ("a}", "unescaped '}'"),
    ("(a", "unbalanced"),
    ("a)", "unbalanced"),
    ("(a))", "unbalanced"),
    ("[a", "unbalanced"),
    ("[]", "empty or ambiguous"),
    ("[]a]", "empty or ambiguous"),
    ("[^]", "empty or ambiguous"),
    ("[z-a]", "invalid range"),
    (r"[\d-z]", "invalid range"),
    (r"[a-\d]", "invalid range"),
    ("[[a]", "write '[' as"),
    ("[a&&b]", "write '&' as"),
    ("[a||b]", "write '|' as"),
    ("[a~~b]", "write '~' as"),
    (r"[\b]", "backspace"),
    (r"[\q]", r"\q is not allowed"),
    ("\u00e9", "printable ASCII"),
    ("a\x00b", "printable ASCII"),
    ("a\nb", "printable ASCII"),
    ("[\u00e9]", "printable ASCII"),
    ("\\\u00e9", "printable ASCII"),
    ("(" * 7 + "a" + ")" * 7, "nested more than"),
    ("x" * (MAX_REGEX_PATTERN_CHARS + 1), "longer than"),
]


@pytest.mark.parametrize(("pattern", "fragment"), HOSTILE, ids=lambda v: repr(v)[:40])
def test_hostile_or_malformed_patterns_are_refused_with_a_specific_reason(
    pattern: str, fragment: str
) -> None:
    with pytest.raises(UnsafeRegex) as caught:
        check_pattern(pattern)
    assert fragment in str(caught.value)
    assert 0 <= caught.value.position <= len(pattern)


def test_the_position_points_at_the_offending_part() -> None:
    with pytest.raises(UnsafeRegex) as caught:
        check_pattern("ab(c+)+d")
    assert caught.value.position == 2  # the start of the repeated group
    with pytest.raises(UnsafeRegex) as backref:
        check_pattern(r"ab\1")
    assert backref.value.position == 2


def test_a_pattern_of_exactly_the_maximum_length_is_accepted() -> None:
    check_pattern("x" * MAX_REGEX_PATTERN_CHARS)


def test_a_set_difference_that_re_warns_about_is_refused_at_compile_time() -> None:
    check_pattern("[+--]")  # the structural check accepts it (the range + to -) ...
    with pytest.raises(UnsafeRegex, match="does not compile cleanly"):
        compile_safe("[+--]")  # ... but `re` warns about it, and a warning is a refusal


def test_every_accepted_pattern_is_also_valid_for_re() -> None:
    for pattern in ACCEPTED:
        re.compile(pattern)  # the subset never accepts something `re` itself rejects


def test_search_only_looks_at_the_leading_characters() -> None:
    compiled = compile_safe("needle")
    assert search_bounded(compiled, "x" * 10 + "needle")
    assert not search_bounded(compiled, "x" * MAX_REGEX_INPUT_CHARS + "needle")
    assert search_bounded(compiled, "x" * (MAX_REGEX_INPUT_CHARS - 6) + "needle")


def test_the_worst_accepted_patterns_finish_on_the_longest_inputs() -> None:
    """The budget keeps a pattern that backtracks as much as it may cheap on 256 characters."""
    quadratic = compile_safe(r".*.*x")
    assert not search_bounded(quadratic, "a" * 10_000)  # only the first 256 characters are used
    optional = compile_safe("a?" * 16 + "a" * 16)
    assert search_bounded(optional, "a" * 16)
    assert not search_bounded(optional, "a" * 15)
    branches = compile_safe("(a|b)" * 8)
    assert not search_bounded(branches, "a" * 7)


def test_the_cost_estimate_counts_every_choice() -> None:
    check_pattern("a?" * 16)  # 2^16
    with pytest.raises(UnsafeRegex, match="backtrack too much"):
        check_pattern("a?" * 17)  # 2^17 is over the budget
    check_pattern(r"[0-9]{3}\.[0-9]{3}\.[0-9]{3}")  # exact counts make no choice
    check_pattern(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")  # 3^4
