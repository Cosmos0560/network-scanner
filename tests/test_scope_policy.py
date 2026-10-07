from __future__ import annotations

import asyncio
import itertools
from collections.abc import Iterable, Iterator

import pytest

from fakes import FakeResolver
from network_scanner.core.errors import ReasonCode, ResolutionError, ScopeRefusal
from network_scanner.core.limits import DEFAULT_LIMITS, MAX_DNS_ANSWERS, RESOLVE_TIMEOUT_S, Limits
from network_scanner.core.model import AddressClass, Family, ResolvedTarget, TargetKind
from network_scanner.scope.parser import parse_ip
from network_scanner.scope.policy import ScopeOptions, decide_address, plan_targets
from network_scanner.scope.scopefile import parse_scope_text

R = ReasonCode
C = AddressClass

PUBLIC_SCOPE = parse_scope_text("8.8.8.0/24\n1.1.1.1\n2606:4700::/120\n")
OPEN = ScopeOptions(allow_public=True, scope_file=PUBLIC_SCOPE)


def plan(
    targets: Iterable[str],
    *,
    options: ScopeOptions | None = None,
    resolver: FakeResolver | None = None,
    limits: Limits = DEFAULT_LIMITS,
    confirm: object = None,
) -> tuple[ResolvedTarget, ...]:
    return asyncio.run(
        plan_targets(
            targets,
            options=options or ScopeOptions(),
            limits=limits,
            resolver=resolver or FakeResolver(),
            confirm=confirm,  # type: ignore[arg-type]
        )
    )


def refusal_of(targets: Iterable[str], **kwargs: object) -> ScopeRefusal:
    with pytest.raises(ScopeRefusal) as caught:
        plan(targets, **kwargs)  # type: ignore[arg-type]
    return caught.value


def addresses(result: tuple[ResolvedTarget, ...]) -> list[str]:
    return [t.address for t in result]


# -- decide_address -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "address_class"),
    [
        ("127.0.0.1", C.LOOPBACK),
        ("::1", C.LOOPBACK),
        ("10.1.2.3", C.PRIVATE),
        ("172.16.0.1", C.PRIVATE),
        ("192.168.1.1", C.PRIVATE),
        ("fd12::1", C.UNIQUE_LOCAL),
        ("fe80::1", C.LINK_LOCAL_V6),
        ("fe80::1%eth0", C.LINK_LOCAL_V6),
    ],
)
@pytest.mark.parametrize(
    "options",
    [ScopeOptions(), OPEN, ScopeOptions(allow_public=True)],
    ids=["default", "open", "flag"],
)
def test_the_default_scope_is_allowed_whatever_the_options(
    text: str, address_class: AddressClass, options: ScopeOptions
) -> None:
    decision = decide_address(parse_ip(text), options)
    assert (decision.allowed, decision.address_class, decision.reason_code) == (
        True,
        address_class,
        None,
    )


@pytest.mark.parametrize(
    ("text", "address_class", "reason"),
    [
        ("0.0.0.0", C.UNSPECIFIED, R.ALWAYS_REFUSED),
        ("::", C.UNSPECIFIED, R.ALWAYS_REFUSED),
        ("224.0.0.1", C.MULTICAST, R.ALWAYS_REFUSED),
        ("ff02::1", C.MULTICAST, R.ALWAYS_REFUSED),
        ("255.255.255.255", C.BROADCAST, R.ALWAYS_REFUSED),
        ("240.0.0.1", C.RESERVED, R.ALWAYS_REFUSED),
        ("169.254.169.254", C.LINK_LOCAL_V4, R.ALWAYS_REFUSED),
        ("192.0.2.1", C.DOCUMENTATION, R.ALWAYS_REFUSED),
        ("198.51.100.1", C.DOCUMENTATION, R.ALWAYS_REFUSED),
        ("203.0.113.1", C.DOCUMENTATION, R.ALWAYS_REFUSED),
        ("2001:db8::1", C.DOCUMENTATION, R.ALWAYS_REFUSED),
        ("198.18.0.1", C.BENCHMARK, R.ALWAYS_REFUSED),
        ("::ffff:10.0.0.1", C.EMBEDDED_IPV4, R.EMBEDDED_IPV4),
        ("::10.0.0.1", C.EMBEDDED_IPV4, R.EMBEDDED_IPV4),
        ("64:ff9b::a00:1", C.EMBEDDED_IPV4, R.EMBEDDED_IPV4),
        ("2002:a00:1::", C.EMBEDDED_IPV4, R.EMBEDDED_IPV4),
        ("2001:0:4136:e378::1", C.EMBEDDED_IPV4, R.EMBEDDED_IPV4),
    ],
)
@pytest.mark.parametrize("options", [ScopeOptions(), OPEN], ids=["default", "open"])
def test_always_refused_addresses_stay_refused_with_every_option(
    text: str, address_class: AddressClass, reason: ReasonCode, options: ScopeOptions
) -> None:
    everything = ScopeOptions(allow_public=True, assume_yes=True, scope_file=options.scope_file)
    for opts in (options, everything):
        decision = decide_address(parse_ip(text), opts)
        assert (decision.allowed, decision.address_class, decision.reason_code) == (
            False,
            address_class,
            reason,
        )


def test_a_public_address_needs_the_flag_and_a_scope_file_entry() -> None:
    target = parse_ip("8.8.8.8")
    assert decide_address(target, ScopeOptions()).reason_code is R.PUBLIC_NOT_ALLOWED
    assert decide_address(target, ScopeOptions(assume_yes=True)).reason_code is R.PUBLIC_NOT_ALLOWED
    assert (
        decide_address(target, ScopeOptions(allow_public=True)).reason_code is R.NOT_IN_SCOPE_FILE
    )
    only_file = ScopeOptions(scope_file=PUBLIC_SCOPE)
    assert decide_address(target, only_file).reason_code is R.PUBLIC_NOT_ALLOWED
    elsewhere = ScopeOptions(allow_public=True, scope_file=parse_scope_text("9.9.9.9\n"))
    assert decide_address(target, elsewhere).reason_code is R.NOT_IN_SCOPE_FILE
    allowed = decide_address(target, OPEN)
    assert (allowed.allowed, allowed.address_class, allowed.reason_code) == (True, C.PUBLIC, None)


def test_cgnat_is_public_and_needs_the_full_gate() -> None:
    cgnat = parse_ip("100.64.0.1")
    assert decide_address(cgnat, ScopeOptions()).reason_code is R.PUBLIC_NOT_ALLOWED
    assert decide_address(cgnat, ScopeOptions(allow_public=True)).reason_code is R.NOT_IN_SCOPE_FILE
    listed = ScopeOptions(allow_public=True, scope_file=parse_scope_text("100.64.0.0/24\n"))
    assert decide_address(cgnat, listed).allowed


# -- literal targets ------------------------------------------------------------------------------


def test_a_mixed_list_of_default_scope_targets_is_pinned_in_order() -> None:
    result = plan(["127.0.0.1", "192.168.1.0/30", "10.0.0.8-10", "::1", "fe80::1%eth0"])
    assert addresses(result) == [
        "127.0.0.1",
        "192.168.1.1",
        "192.168.1.2",
        "10.0.0.8",
        "10.0.0.9",
        "10.0.0.10",
        "::1",
        "fe80::1%eth0",
    ]
    assert [t.family for t in result] == [Family.IPV4] * 6 + [Family.IPV6] * 2
    assert result[1].origin_spec.raw == "192.168.1.0/30"
    assert result[1].origin_spec.kind is TargetKind.CIDR
    assert result[0].display_name == "127.0.0.1"


def test_duplicate_addresses_are_scanned_once() -> None:
    result = plan(["10.0.0.1", "10.0.0.1-3", "10.0.0.2"])
    assert addresses(result) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert result[0].origin_spec.raw == "10.0.0.1"  # the first mention wins


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        # ambiguous and malformed forms
        ("2130706433", R.AMBIGUOUS_NUMERIC),
        ("0x7f.0.0.1", R.AMBIGUOUS_NUMERIC),
        ("0177.0.0.1", R.AMBIGUOUS_NUMERIC),
        ("127.1", R.AMBIGUOUS_NUMERIC),
        ("010.0.0.1", R.AMBIGUOUS_NUMERIC),
        ("192.168.1.5/24", R.CIDR_HOST_BITS),
        ("fd00::1%eth0", R.INVALID_ZONE_ID),
        ("10.0.0.9-10.0.0.1", R.INVALID_RANGE),
        ("exa_mple.com", R.INVALID_HOSTNAME),
        ("a\x00b", R.INVALID_CHARACTERS),
        ("a" * 300, R.TARGET_TOO_LONG),
        # embedded IPv4, whichever way it is written
        ("::ffff:10.0.0.1", R.EMBEDDED_IPV4),
        ("::ffff:a00:1", R.EMBEDDED_IPV4),
        ("::10.0.0.1", R.EMBEDDED_IPV4),
        ("64:ff9b::10.0.0.1", R.EMBEDDED_IPV4),
        ("2002:c000:204::1", R.EMBEDDED_IPV4),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", R.EMBEDDED_IPV4),
        # always-refused classes
        ("0.0.0.0", R.ALWAYS_REFUSED),
        ("::", R.ALWAYS_REFUSED),
        ("224.0.0.251", R.ALWAYS_REFUSED),
        ("ff02::fb", R.ALWAYS_REFUSED),
        ("255.255.255.255", R.ALWAYS_REFUSED),
        ("240.0.0.1", R.ALWAYS_REFUSED),
        ("169.254.169.254", R.ALWAYS_REFUSED),
        ("192.0.2.5", R.ALWAYS_REFUSED),
        ("198.51.100.5", R.ALWAYS_REFUSED),
        ("203.0.113.5", R.ALWAYS_REFUSED),
        ("198.18.0.5", R.ALWAYS_REFUSED),
        ("2001:db8::5", R.ALWAYS_REFUSED),
        ("fec0::1", R.ALWAYS_REFUSED),
        # public without permission
        ("8.8.8.8", R.PUBLIC_NOT_ALLOWED),
        ("100.64.0.1", R.PUBLIC_NOT_ALLOWED),
        ("2606:4700::1", R.PUBLIC_NOT_ALLOWED),
        # a block with a refused address in it refuses the whole target
        ("169.254.169.252/30", R.ALWAYS_REFUSED),
        ("192.0.2.0/30", R.ALWAYS_REFUSED),
        ("0.0.0.250-0.0.0.252", R.ALWAYS_REFUSED),
    ],
)
def test_every_bypass_is_refused_with_its_reason_code(target: str, reason: ReasonCode) -> None:
    assert refusal_of([target]).reason_code is reason


def test_a_refusal_names_the_target_and_the_offending_address() -> None:
    error = refusal_of(["10.0.0.1", "169.254.169.252/30"])
    assert error.target == "169.254.169.252/30"
    assert "169.254.169.253 is in class link_local_v4" in error.detail


def test_one_bad_target_refuses_the_whole_run() -> None:
    error = refusal_of(["127.0.0.1", "10.0.0.1", "8.8.8.8", "192.168.0.1"])
    assert error.reason_code is R.PUBLIC_NOT_ALLOWED
    assert error.target == "8.8.8.8"


def test_the_first_problem_in_input_order_is_reported() -> None:
    assert refusal_of(["127.1", "8.8.8.8"]).reason_code is R.AMBIGUOUS_NUMERIC
    assert refusal_of(["8.8.8.8", "127.1"]).reason_code is R.AMBIGUOUS_NUMERIC  # grammar first


def test_a_hostile_target_is_sanitised_in_the_refusal() -> None:
    error = refusal_of(["\x1b[31m127.0.0.1\r\n"])
    assert not any(c in str(error) for c in "\x1b\r\n")


# -- caps: arithmetic first, nothing materialised -----------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["10.0.0.0/8", "0.0.0.0/0", "::/0", "fd00::/8", "10.0.0.0/23", "10.0.0.1-10.0.255.255"],
)
def test_oversized_blocks_are_refused_by_arithmetic(target: str) -> None:
    error = refusal_of([target])
    assert error.reason_code is R.TOO_MANY_TARGETS


def test_the_target_cap_is_exact() -> None:
    assert len(plan(["10.0.0.0/24"])) == 254
    limits = Limits(max_targets=254)
    assert len(plan(["10.0.0.0/24"], limits=limits)) == 254
    assert refusal_of(["10.0.0.0/24"], limits=Limits(max_targets=253)).reason_code is (
        R.TOO_MANY_TARGETS
    )
    assert refusal_of(
        ["10.0.0.0/24", "10.0.1.1-3"], limits=Limits(max_targets=256)
    ).reason_code is (R.TOO_MANY_TARGETS)


def test_a_huge_lazy_list_is_rejected_after_looking_at_only_the_cap_plus_one() -> None:
    seen = 0

    def endless() -> Iterator[str]:
        nonlocal seen
        for raw in itertools.repeat("10.0.0.1"):
            seen += 1
            yield raw

    error = refusal_of(endless())
    assert error.reason_code is R.TOO_MANY_TARGETS
    assert seen == DEFAULT_LIMITS.max_targets + 1


def test_a_million_entry_list_does_not_get_expanded() -> None:
    error = refusal_of(["10.0.0.0/30"] * 1_000_000)
    assert error.reason_code is R.TOO_MANY_TARGETS


def test_a_list_at_the_ceiling_is_accepted_when_the_limit_allows_it() -> None:
    limits = Limits(max_targets=4096)
    result = plan([f"10.0.{n}.0/24" for n in range(16)], limits=limits)
    assert len(result) == 16 * 254
    assert addresses(result)[0] == "10.0.0.1"
    assert addresses(result)[-1] == "10.0.15.254"


def test_no_targets_is_a_refusal() -> None:
    assert refusal_of([]).reason_code is R.NO_TARGETS


# -- public addresses: flag, scope file and confirmation --------------------------------------


def test_public_targets_need_all_three_conditions() -> None:
    asked: list[tuple[str, ...]] = []

    def confirm(addresses_: tuple[str, ...]) -> bool:
        asked.append(addresses_)
        return True

    assert refusal_of(["8.8.8.8"], confirm=confirm).reason_code is R.PUBLIC_NOT_ALLOWED
    flag_only = ScopeOptions(allow_public=True)
    assert refusal_of(["8.8.8.8"], options=flag_only, confirm=confirm).reason_code is (
        R.NOT_IN_SCOPE_FILE
    )
    assert asked == []  # the user is never asked about something that is refused anyway

    result = plan(["8.8.8.8", "10.0.0.1"], options=OPEN, confirm=confirm)
    assert addresses(result) == ["8.8.8.8", "10.0.0.1"]
    assert asked == [("8.8.8.8",)]


def test_a_whole_public_block_must_be_inside_the_scope_file() -> None:
    assert len(plan(["8.8.8.0/29"], options=OPEN, confirm=lambda _: True)) == 6
    error = refusal_of(["8.8.7.254/31"], options=OPEN, confirm=lambda _: True)
    assert error.reason_code is R.NOT_IN_SCOPE_FILE


def test_non_interactive_public_scans_need_yes() -> None:
    assert refusal_of(["8.8.8.8"], options=OPEN).reason_code is R.CONFIRMATION_REQUIRED
    yes = ScopeOptions(allow_public=True, assume_yes=True, scope_file=PUBLIC_SCOPE)
    assert addresses(plan(["8.8.8.8"], options=yes)) == ["8.8.8.8"]


def test_yes_skips_the_prompt() -> None:
    yes = ScopeOptions(allow_public=True, assume_yes=True, scope_file=PUBLIC_SCOPE)

    def must_not_be_called(_: tuple[str, ...]) -> bool:
        raise AssertionError("the prompt must not be shown with --yes")

    assert addresses(plan(["8.8.8.8"], options=yes, confirm=must_not_be_called)) == ["8.8.8.8"]


def test_declining_the_prompt_refuses_the_run() -> None:
    error = refusal_of(["8.8.8.8", "1.1.1.1"], options=OPEN, confirm=lambda _: False)
    assert error.reason_code is R.CONFIRMATION_DECLINED


def test_the_prompt_lists_every_public_address_once_and_only_those() -> None:
    asked: list[tuple[str, ...]] = []

    def confirm(addresses_: tuple[str, ...]) -> bool:
        asked.append(addresses_)
        return True

    plan(
        ["10.0.0.1", "8.8.8.0/30", "8.8.8.1", "1.1.1.1", "2606:4700::1"],
        options=OPEN,
        confirm=confirm,
    )
    assert asked == [("8.8.8.1", "8.8.8.2", "1.1.1.1", "2606:4700::1")]


def test_a_plan_without_public_addresses_never_prompts() -> None:
    def must_not_be_called(_: tuple[str, ...]) -> bool:
        raise AssertionError("no public address, no prompt")

    assert len(plan(["10.0.0.1"], options=OPEN, confirm=must_not_be_called)) == 1


# -- hostnames --------------------------------------------------------------------------------


def test_a_hostname_is_resolved_once_pinned_and_sorted() -> None:
    resolver = FakeResolver({"lab.example": ("192.168.1.20", "10.0.0.5", "::1", "10.0.0.5")})
    result = plan(["Lab.Example"], resolver=resolver)
    assert addresses(result) == ["10.0.0.5", "192.168.1.20", "::1"]
    assert {t.display_name for t in result} == {"lab.example"}
    assert result[0].origin_spec.kind is TargetKind.HOSTNAME
    assert result[0].origin_spec.raw == "Lab.Example"
    assert resolver.calls == [("lab.example", RESOLVE_TIMEOUT_S)]


def test_a_name_mentioned_twice_is_resolved_once() -> None:
    resolver = FakeResolver({"a.example": ("10.0.0.1",), "b.example": ("10.0.0.1", "10.0.0.2")})
    result = plan(["a.example", "A.EXAMPLE", "b.example"], resolver=resolver)
    assert addresses(result) == ["10.0.0.1", "10.0.0.2"]
    assert [name for name, _ in resolver.calls] == ["a.example", "b.example"]


def test_hostnames_are_resolved_after_all_literals_are_decided() -> None:
    resolver = FakeResolver({"a.example": ("10.0.0.1",)})
    assert refusal_of(["a.example", "8.8.8.8"], resolver=resolver).reason_code is (
        R.PUBLIC_NOT_ALLOWED
    )
    assert resolver.calls == []  # a doomed run makes no DNS queries


@pytest.mark.parametrize(
    "answers",
    [
        ("10.0.0.1", "8.8.8.8"),
        ("8.8.8.8", "10.0.0.1"),
        ("127.0.0.1", "169.254.169.254"),
        ("10.0.0.1", "224.0.0.1"),
        ("10.0.0.1", "::ffff:10.0.0.2"),
        ("10.0.0.1", "192.0.2.1"),
        ("192.168.1.1", "8.8.8.8", "10.0.0.1"),
    ],
)
def test_one_bad_answer_refuses_the_whole_hostname(answers: tuple[str, ...]) -> None:
    resolver = FakeResolver({"lab.example": answers})
    assert refusal_of(["lab.example"], resolver=resolver).reason_code is R.MIXED_DNS_ANSWERS


def test_an_answer_is_refused_unless_it_has_full_authorisation_even_with_all_the_flags() -> None:
    yes = ScopeOptions(allow_public=True, assume_yes=True, scope_file=PUBLIC_SCOPE)
    # A private plus an authorised public answer is fine: every answer passed on its own.
    authorised = FakeResolver({"lab.example": ("10.0.0.1", "8.8.8.8")})
    assert addresses(plan(["lab.example"], options=yes, resolver=authorised)) == [
        "8.8.8.8",
        "10.0.0.1",
    ]  # answers are sorted numerically
    # 9.9.9.9 is not in the scope file, 169.254.169.254 can never be unlocked.
    for answers in (("8.8.8.8", "9.9.9.9"), ("10.0.0.1", "169.254.169.254")):
        resolver = FakeResolver({"p.example": answers})
        error = refusal_of(["p.example"], options=yes, resolver=resolver)
        assert error.reason_code is R.MIXED_DNS_ANSWERS


@pytest.mark.parametrize(
    ("answers", "reason"),
    [
        (("8.8.8.8", "8.8.4.4"), R.PUBLIC_NOT_ALLOWED),
        (("169.254.169.254",), R.ALWAYS_REFUSED),
        (("::ffff:10.0.0.1",), R.EMBEDDED_IPV4),
        (("224.0.0.1", "224.0.0.2"), R.ALWAYS_REFUSED),
    ],
)
def test_when_every_answer_is_refused_the_first_reason_is_reported(
    answers: tuple[str, ...], reason: ReasonCode
) -> None:
    resolver = FakeResolver({"x.example": answers})
    assert refusal_of(["x.example"], resolver=resolver).reason_code is reason


def test_a_public_hostname_works_with_the_full_gate() -> None:
    resolver = FakeResolver({"ok.example": ("8.8.8.8", "8.8.8.9")})
    result = plan(["ok.example"], options=OPEN, resolver=resolver, confirm=lambda _: True)
    assert addresses(result) == ["8.8.8.8", "8.8.8.9"]
    assert refusal_of(["ok.example"], options=OPEN, resolver=resolver).reason_code is (
        R.CONFIRMATION_REQUIRED
    )


@pytest.mark.parametrize(
    "outcome",
    [ResolutionError("nx"), TimeoutError(), OSError("gaierror"), ()],
    ids=["resolution-error", "timeout", "oserror", "no-answers"],
)
def test_resolution_failures_refuse_the_run(outcome: BaseException | tuple[str, ...]) -> None:
    resolver = FakeResolver({"lab.example": outcome})
    assert refusal_of(["lab.example"], resolver=resolver).reason_code is R.DNS_FAILURE


def test_an_unknown_name_is_a_dns_failure() -> None:
    assert refusal_of(["nowhere.example"]).reason_code is R.DNS_FAILURE


def test_the_answer_cap_is_eight() -> None:
    eight = tuple(f"10.0.0.{n}" for n in range(1, MAX_DNS_ANSWERS + 1))
    assert len(plan(["lab.example"], resolver=FakeResolver({"lab.example": eight}))) == 8
    nine = (*eight, "10.0.0.9")
    error = refusal_of(["lab.example"], resolver=FakeResolver({"lab.example": nine}))
    assert error.reason_code is R.TOO_MANY_DNS_ANSWERS


def test_duplicate_answers_count_toward_the_answer_cap() -> None:
    nine_copies = ("10.0.0.1",) * (MAX_DNS_ANSWERS + 1)
    error = refusal_of(["lab.example"], resolver=FakeResolver({"lab.example": nine_copies}))
    assert error.reason_code is R.TOO_MANY_DNS_ANSWERS


@pytest.mark.parametrize(
    "bad_answer",
    [
        "evil.example",
        "127.1",
        "0x7f.0.0.1",
        "10.0.0.0/8",
        "10.0.0.1-5",
        "fe80::1%eth0",
        "",
        "10.0.0.1 ",
        "\x1b[31m10.0.0.1",
        "::g",
    ],
)
def test_garbage_dns_answers_refuse_the_name(bad_answer: str) -> None:
    resolver = FakeResolver({"lab.example": ("10.0.0.1", bad_answer)})
    assert refusal_of(["lab.example"], resolver=resolver).reason_code is R.INVALID_DNS_ANSWER


def test_resolved_addresses_count_against_the_target_cap() -> None:
    resolver = FakeResolver({"lab.example": ("10.0.0.1", "10.0.0.2", "10.0.0.3")})
    error = refusal_of(["lab.example"], resolver=resolver, limits=Limits(max_targets=2))
    assert error.reason_code is R.TOO_MANY_TARGETS


def test_answers_are_never_trusted_to_be_ordered_or_unique() -> None:
    first = plan(["lab.example"], resolver=FakeResolver({"lab.example": ("10.0.0.2", "10.0.0.1")}))
    second = plan(["lab.example"], resolver=FakeResolver({"lab.example": ("10.0.0.1", "10.0.0.2")}))
    assert first == second
