"""Pure domain-risk scoring with no I/O or clock reads."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from math import isfinite
from typing import Generic, TypeVar

import idna
import tldextract
from disposable_email_domains import blocklist as DISPOSABLE
from free_email_domains import whitelist as FREEMAIL
from rapidfuzz.distance import Levenshtein

EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
EXTRACT("example.com")

REVIEW_AT = 30
BLOCK_AT = 70
TYPOSQUAT_MAX_DISTANCE = 2
DEFAULT_FREEMAIL_DOMAINS = frozenset(FREEMAIL)


def registrable(hostname: str) -> str:
    return EXTRACT(hostname).top_domain_under_public_suffix


class ReasonCode(StrEnum):
    AGE_LT_30D = "AGE_LT_30D"
    AGE_LT_90D = "AGE_LT_90D"
    AGE_LT_1Y = "AGE_LT_1Y"
    AGE_GT_3Y = "AGE_GT_3Y"
    AGE_UNKNOWN = "AGE_UNKNOWN"
    TYPOSQUAT = "TYPOSQUAT"
    DISPOSABLE_EMAIL = "DISPOSABLE_EMAIL"
    FREE_EMAIL = "FREE_EMAIL"
    EMAIL_DOMAIN_MISMATCH = "EMAIL_DOMAIN_MISMATCH"
    NO_MX = "NO_MX"
    MX_UNKNOWN = "MX_UNKNOWN"
    NO_MAIL_AUTH = "NO_MAIL_AUTH"
    NO_WEBSITE = "NO_WEBSITE"
    DOMAIN_NOT_RESOLVABLE = "DOMAIN_NOT_RESOLVABLE"


class Lane(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class LookupStatus(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    RESOLVED = "resolved"
    FAILED = "failed"


WEIGHTS: dict[ReasonCode, int] = {
    ReasonCode.AGE_LT_30D: 50,
    ReasonCode.AGE_LT_90D: 30,
    ReasonCode.AGE_LT_1Y: 10,
    ReasonCode.AGE_GT_3Y: -10,
    ReasonCode.AGE_UNKNOWN: 8,
    ReasonCode.TYPOSQUAT: 40,
    ReasonCode.DISPOSABLE_EMAIL: 40,
    ReasonCode.NO_MX: 25,
    ReasonCode.MX_UNKNOWN: 8,
    ReasonCode.NO_MAIL_AUTH: 10,
    ReasonCode.NO_WEBSITE: 20,
    ReasonCode.FREE_EMAIL: 15,
    ReasonCode.EMAIL_DOMAIN_MISMATCH: 10,
    ReasonCode.DOMAIN_NOT_RESOLVABLE: 40,
}

T = TypeVar("T")


@dataclass(frozen=True)
class Fact(Generic[T]):
    value: T | None
    status: LookupStatus

    def __post_init__(self) -> None:
        if self.status is not LookupStatus.RESOLVED and self.value is not None:
            raise ValueError(f"{self.status.value} fact cannot carry a value")

    @property
    def known(self) -> bool:
        return self.status is LookupStatus.RESOLVED and self.value is not None


@dataclass(frozen=True)
class Signal:
    code: ReasonCode
    points: int
    detail: str = ""


@dataclass(frozen=True)
class EmailFacts:
    address: str
    domain: str
    is_disposable: bool
    is_freemail: bool


@dataclass(frozen=True)
class DomainFacts:
    domain: str
    as_of: datetime
    created: Fact[datetime]
    domain_exists: Fact[bool]
    has_mx: Fact[bool]
    has_website: Fact[bool]
    has_mail_auth: Fact[bool]
    email: EmailFacts | None = None

    def __post_init__(self) -> None:
        if self.created.known:
            created_is_aware = self.created.value.utcoffset() is not None
            as_of_is_aware = self.as_of.utcoffset() is not None
            if created_is_aware != as_of_is_aware:
                raise ValueError("created and as_of must have the same timezone awareness")

    @property
    def network_facts(self) -> tuple[Fact, ...]:
        return (
            self.created,
            self.domain_exists,
            self.has_mx,
            self.has_website,
            self.has_mail_auth,
        )

    @property
    def confidence(self) -> float:
        attempted = tuple(
            fact
            for fact in self.network_facts
            if fact.status is not LookupStatus.NOT_ATTEMPTED
        )
        if not attempted:
            return 1.0
        resolved = sum(fact.status is LookupStatus.RESOLVED for fact in attempted)
        return resolved / len(attempted)

    @property
    def all_resolved(self) -> bool:
        return all(fact.known for fact in self.network_facts)


@dataclass(frozen=True)
class Config:
    brands: tuple[str, ...] = ()
    freemail_domains: frozenset[str] = DEFAULT_FREEMAIL_DOMAINS
    per_lookup_timeout: float = 5.0

    def __post_init__(self) -> None:
        if not isfinite(self.per_lookup_timeout) or self.per_lookup_timeout <= 0:
            raise ValueError("per_lookup_timeout must be finite and positive")


@dataclass(frozen=True)
class Assessment:
    reasons: tuple[Signal, ...]
    confidence: float
    all_resolved: bool

    def __init__(self, *args, **kwargs) -> None:
        raise TypeError("Assessment instances are created by score()")

    @classmethod
    def _compute(
        cls,
        reasons: tuple[Signal, ...],
        confidence: float,
        all_resolved: bool,
    ) -> "Assessment":
        assessment = object.__new__(cls)
        object.__setattr__(assessment, "reasons", reasons)
        object.__setattr__(assessment, "confidence", confidence)
        object.__setattr__(assessment, "all_resolved", all_resolved)
        return assessment

    @property
    def score(self) -> int:
        return max(0, sum(signal.points for signal in self.reasons))

    @property
    def lane(self) -> Lane:
        if self.score >= BLOCK_AT:
            return Lane.BLOCK
        if self.score >= REVIEW_AT:
            return Lane.REVIEW
        return Lane.ALLOW if self.all_resolved else Lane.REVIEW

    @property
    def codes(self) -> list[ReasonCode]:
        return [signal.code for signal in self.reasons]


def _signal(code: ReasonCode, detail: str = "") -> Signal:
    return Signal(code=code, points=WEIGHTS[code], detail=detail)


def _fold(hostname: str) -> str:
    try:
        return idna.decode(hostname)
    except idna.IDNAError:
        return hostname


def _check_age(facts: DomainFacts) -> Signal | None:
    if facts.created.status is LookupStatus.NOT_ATTEMPTED:
        return None
    if not facts.created.known:
        return _signal(ReasonCode.AGE_UNKNOWN, "no RDAP or WHOIS creation date")

    created = facts.created.value
    if created.tzinfo is None:
        created = created.replace(tzinfo=facts.as_of.tzinfo)
    days = (facts.as_of - created).days
    if days < 30:
        return _signal(ReasonCode.AGE_LT_30D, f"{days}d old")
    if days < 90:
        return _signal(ReasonCode.AGE_LT_90D, f"{days}d old")
    if days < 365:
        return _signal(ReasonCode.AGE_LT_1Y, f"{days}d old")
    if days > 3 * 365:
        return _signal(ReasonCode.AGE_GT_3Y, f"{days}d old")
    return None


def _check_infrastructure(facts: DomainFacts) -> list[Signal]:
    signals: list[Signal] = []
    if facts.has_mx.known and facts.has_mx.value is False:
        signals.append(_signal(ReasonCode.NO_MX, "no MX records"))
    elif facts.has_mx.status is LookupStatus.FAILED:
        signals.append(_signal(ReasonCode.MX_UNKNOWN, "DNS lookup failed"))
    elif (
        facts.has_mx.known
        and facts.has_mx.value is True
        and facts.has_mail_auth.known
        and facts.has_mail_auth.value is False
    ):
        signals.append(_signal(ReasonCode.NO_MAIL_AUTH, "MX present, no SPF/DMARC"))

    if facts.has_website.known and facts.has_website.value is False:
        signals.append(_signal(ReasonCode.NO_WEBSITE, "no A/AAAA records"))
    return signals


def _check_typosquat(facts: DomainFacts, config: Config) -> Signal | None:
    candidate = _fold(registrable(facts.domain))
    targets = tuple((brand, _fold(registrable(brand))) for brand in config.brands)
    if any(candidate == target for _, target in targets):
        return None
    for brand, target in targets:
        distance = Levenshtein.distance(
            candidate,
            target,
            score_cutoff=TYPOSQUAT_MAX_DISTANCE,
        )
        if distance <= TYPOSQUAT_MAX_DISTANCE:
            return _signal(ReasonCode.TYPOSQUAT, f"resembles {brand}")
    return None


def _check_email(facts: DomainFacts) -> list[Signal]:
    if facts.email is None:
        return []

    email = facts.email
    signals: list[Signal] = []
    if email.is_disposable:
        signals.append(_signal(ReasonCode.DISPOSABLE_EMAIL, email.domain))
    if email.is_freemail:
        signals.append(_signal(ReasonCode.FREE_EMAIL, email.domain))
    if _fold(registrable(email.domain)) != _fold(registrable(facts.domain)):
        signals.append(_signal(ReasonCode.EMAIL_DOMAIN_MISMATCH, email.domain))
    return signals


def classify_email(address: str | None, config: Config | None = None) -> EmailFacts | None:
    if not address or "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].lower().strip()
    if not domain:
        return None
    config = config or Config()
    return EmailFacts(
        address=address,
        domain=domain,
        is_disposable=domain in DISPOSABLE,
        is_freemail=domain in config.freemail_domains,
    )


def score(facts: DomainFacts, config: Config | None = None) -> Assessment:
    config = config or Config()
    signals: list[Signal] = []

    not_registered = facts.domain_exists.known and facts.domain_exists.value is False
    if not_registered:
        signals.append(_signal(ReasonCode.DOMAIN_NOT_RESOLVABLE, "NXDOMAIN"))
    else:
        signals.extend(_check_infrastructure(facts))
        age = _check_age(facts)
        if age is not None:
            signals.append(age)

    typo = _check_typosquat(facts, config)
    if typo is not None:
        signals.append(typo)
    signals.extend(_check_email(facts))

    return Assessment._compute(
        reasons=tuple(sorted(signals, key=lambda signal: signal.points, reverse=True)),
        confidence=facts.confidence,
        all_resolved=facts.all_resolved,
    )
