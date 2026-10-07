"""Scope policy (PLAN.md sections 4.2, 4.4 and 4.5): the decision and the fail-closed plan.

`decide_address` is pure. `plan_targets` turns the raw target strings of one run into the
final list of pinned addresses, or raises `ScopeRefusal` for the first problem it finds.
Nothing here opens a connection: a plan is complete, and every target decided, before the
first connection of the run can be made. Resolution goes through the injected `Resolver`
and, when public addresses are involved, confirmation goes through an injected callable.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from network_scanner.core.errors import ReasonCode, ResolutionError, ScopeRefusal
from network_scanner.core.interfaces import Resolver
from network_scanner.core.limits import MAX_DNS_ANSWERS, RESOLVE_TIMEOUT_S, Limits
from network_scanner.core.model import AddressClass, ResolvedTarget, ScopeDecision
from network_scanner.scope.classify import ALWAYS_REFUSED, DEFAULT_ALLOWED, classify
from network_scanner.scope.parser import (
    Address,
    HostnameTarget,
    count_addresses,
    expand,
    parse_ip,
    parse_target,
)
from network_scanner.scope.scopefile import ScopeFile

Confirm = Callable[[tuple[str, ...]], bool]
"""Asks the user to confirm scanning these public addresses; True means yes."""


@dataclass(frozen=True, slots=True)
class ScopeOptions:
    allow_public: bool = False  # --allow-public
    assume_yes: bool = False  # --yes
    scope_file: ScopeFile | None = None


def decide_address(address: Address, options: ScopeOptions) -> ScopeDecision:
    """Decide one address. For a public address that passes, confirmation is still due."""
    address_class = classify(address)
    if address_class in ALWAYS_REFUSED:
        reason = (
            ReasonCode.EMBEDDED_IPV4
            if address_class is AddressClass.EMBEDDED_IPV4
            else ReasonCode.ALWAYS_REFUSED
        )
        return ScopeDecision(False, address_class, reason)
    if address_class in DEFAULT_ALLOWED:
        return ScopeDecision(True, address_class, None)
    if not options.allow_public:
        return ScopeDecision(False, address_class, ReasonCode.PUBLIC_NOT_ALLOWED)
    if options.scope_file is None or not options.scope_file.contains(address):
        return ScopeDecision(False, address_class, ReasonCode.NOT_IN_SCOPE_FILE)
    return ScopeDecision(True, address_class, None)


def _refuse(decision: ScopeDecision, raw: str, address: Address) -> ScopeRefusal:
    reason = decision.reason_code or ReasonCode.ALWAYS_REFUSED
    return ScopeRefusal(reason, raw, f"{address.text} is in class {decision.address_class.value}")


async def _resolve(
    target: HostnameTarget, options: ScopeOptions, resolver: Resolver
) -> list[Address]:
    """Resolve once, pin every answer, and refuse the whole name if any answer is refused."""
    raw = target.raw
    try:
        answers = await resolver.resolve(target.name, timeout=RESOLVE_TIMEOUT_S)
    except (ResolutionError, TimeoutError, OSError):
        raise ScopeRefusal(ReasonCode.DNS_FAILURE, raw, "the name did not resolve") from None
    if not answers:
        raise ScopeRefusal(ReasonCode.DNS_FAILURE, raw, "the name has no addresses")
    if len(answers) > MAX_DNS_ANSWERS:
        raise ScopeRefusal(
            ReasonCode.TOO_MANY_DNS_ANSWERS, raw, f"more than {MAX_DNS_ANSWERS} answers"
        )
    addresses: dict[tuple[int, int, str], Address] = {}
    for answer in answers:
        try:
            address = parse_ip(answer)
        except ScopeRefusal as refusal:
            raise ScopeRefusal(
                ReasonCode.INVALID_DNS_ANSWER,
                raw,
                f"an answer is not a plain IP address ({refusal.reason_code.value})",
            ) from None
        if address.zone is not None:
            raise ScopeRefusal(ReasonCode.INVALID_DNS_ANSWER, raw, "an answer carries a zone id")
        addresses[address.sort_key()] = address
    pinned = [addresses[key] for key in sorted(addresses)]
    decisions = [decide_address(address, options) for address in pinned]
    refused = [(a, d) for a, d in zip(pinned, decisions, strict=True) if not d.allowed]
    if not refused:
        return pinned
    if len(refused) < len(pinned):
        raise ScopeRefusal(
            ReasonCode.MIXED_DNS_ANSWERS,
            raw,
            f"{len(refused)} of {len(pinned)} answers are refused; no partial scan",
        )
    raise _refuse(refused[0][1], raw, refused[0][0])


async def plan_targets(
    raw_targets: Iterable[str],
    *,
    options: ScopeOptions,
    limits: Limits,
    resolver: Resolver,
    confirm: Confirm | None = None,
) -> tuple[ResolvedTarget, ...]:
    """Validate, count, resolve and decide every target; return the pinned scan list.

    Raises `ScopeRefusal` for the first problem found. Stages run in this order, each in
    input order: grammar and count, literal addresses, hostnames, confirmation. The number of
    targets is
    computed arithmetically and checked before anything is expanded, so a /8 or a list of a
    million entries is rejected after at most `limits.max_targets + 1` entries were looked at.
    Duplicates are counted before they are removed. `confirm` is called at most once, after
    everything else has passed, and only if public addresses are in the plan and `--yes` was
    not given; with no `confirm` (no terminal) such a plan is refused.
    """
    parsed = []
    total = 0
    for raw in raw_targets:
        target = parse_target(raw)
        total += count_addresses(target)
        if total > limits.max_targets:
            raise ScopeRefusal(
                ReasonCode.TOO_MANY_TARGETS, raw, f"more than {limits.max_targets} targets"
            )
        parsed.append(target)
    if not parsed:
        raise ScopeRefusal(ReasonCode.NO_TARGETS, "", "no targets were given")

    # Literal addresses are decided first, then names are resolved, so a run that is going to
    # be refused anyway makes no DNS queries. Each distinct name is resolved once.
    found: list[list[Address]] = []
    for target in parsed:
        addresses: list[Address] = []
        if not isinstance(target, HostnameTarget):
            for address in expand(target):
                decision = decide_address(address, options)
                if not decision.allowed:
                    raise _refuse(decision, target.raw, address)
                addresses.append(address)
        found.append(addresses)
    resolved_names: dict[str, list[Address]] = {}
    for index, target in enumerate(parsed):
        if isinstance(target, HostnameTarget):
            if target.name not in resolved_names:
                resolved_names[target.name] = await _resolve(target, options, resolver)
            found[index] = resolved_names[target.name]

    plan: dict[str, tuple[ResolvedTarget, AddressClass]] = {}
    for target, addresses in zip(parsed, found, strict=True):
        display = target.name if isinstance(target, HostnameTarget) else ""
        for address in addresses:
            if address.text not in plan:
                resolved = ResolvedTarget(
                    display_name=display or address.text,
                    address=address.text,
                    family=address.family,
                    origin_spec=target.spec,
                )
                plan[address.text] = (resolved, classify(address))
    if len(plan) > limits.max_targets:
        raise ScopeRefusal(
            ReasonCode.TOO_MANY_TARGETS,
            "",
            f"names resolved to more than {limits.max_targets} addresses",
        )

    public = tuple(text for text, (_, cls) in plan.items() if cls is AddressClass.PUBLIC)
    if public and not options.assume_yes:
        if confirm is None:
            raise ScopeRefusal(
                ReasonCode.CONFIRMATION_REQUIRED,
                "",
                "public targets need --yes, or an interactive terminal to confirm",
            )
        if not confirm(public):
            raise ScopeRefusal(ReasonCode.CONFIRMATION_DECLINED, "", "confirmation declined")
    return tuple(resolved for resolved, _ in plan.values())
