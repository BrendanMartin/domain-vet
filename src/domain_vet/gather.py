"""Synchronous fact gathering over cancellable async I/O."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import asyncwhois
import asyncwhois.errors
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import idna
import whodap
import whodap.errors

from domain_vet.core import (
    EXTRACT,
    Config,
    DomainFacts,
    Fact,
    LookupStatus,
    classify_email,
)

DNS_UNKNOWN = (dns.resolver.NoNameservers, dns.exception.Timeout)
AGE_NOT_FOUND = (asyncwhois.errors.NotFoundError, whodap.errors.NotFoundError)
AGE_UNKNOWN = (
    asyncwhois.errors.WhoIsError,
    whodap.errors.RateLimitError,
    whodap.errors.BadStatusCode,
    whodap.errors.MalformedQueryError,
    whodap.errors.RDAPConformanceException,
    httpx.HTTPError,
    OSError,
)


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip()
    if not value or "@" in value:
        raise ValueError(f"not a usable domain: {raw!r}")
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        hostname = (parsed.hostname or "").rstrip(".")
        normalized = idna.encode(hostname, uts46=True).decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise ValueError(f"not a usable domain: {raw!r}") from None
    labels = normalized.split(".")
    if len(normalized) > 253 or len(labels) < 2 or labels[-1].isdigit():
        raise ValueError(f"not a usable domain: {raw!r}")
    return normalized


@dataclass(frozen=True)
class DnsFacts:
    domain_exists: Fact[bool]
    has_mx: Fact[bool]
    has_website: Fact[bool]
    has_mail_auth: Fact[bool]


async def _query(resolver, name: str, rdtype: str):
    try:
        return list(await resolver.resolve(name, rdtype)), True
    except dns.resolver.NXDOMAIN:
        return None, False
    except dns.resolver.NoAnswer:
        return [], True
    except DNS_UNKNOWN:
        return None, None


def _resolved(value):
    return Fact(value, LookupStatus.RESOLVED)


def _failed():
    return Fact(None, LookupStatus.FAILED)


async def _gather_dns(domain: str, resolver) -> DnsFacts:
    mx, ipv4, ipv6, apex_txt, dmarc_txt = await asyncio.gather(
        _query(resolver, domain, "MX"),
        _query(resolver, domain, "A"),
        _query(resolver, domain, "AAAA"),
        _query(resolver, domain, "TXT"),
        _query(resolver, f"_dmarc.{domain}", "TXT"),
    )

    apex_votes = (mx, ipv4, ipv6, apex_txt)
    if any(exists is True for _, exists in apex_votes):
        domain_exists = _resolved(True)
    elif sum(exists is False for _, exists in apex_votes) >= 2:
        return DnsFacts(
            domain_exists=_resolved(False),
            has_mx=_resolved(False),
            has_website=_resolved(False),
            has_mail_auth=_resolved(False),
        )
    else:
        domain_exists = _failed()

    mx_records, ipv4_records, ipv6_records = mx[0], ipv4[0], ipv6[0]
    apex_records, dmarc_records = apex_txt[0], dmarc_txt[0]
    has_mx = _resolved(bool(mx_records)) if mx_records is not None else _failed()

    if any(records for records in (ipv4_records, ipv6_records)):
        has_website = _resolved(True)
    elif ipv4_records is not None and ipv6_records is not None:
        has_website = _resolved(False)
    else:
        has_website = _failed()

    text = f"{_txt(apex_records)} {_txt(dmarc_records)}".lower()
    if "v=spf1" in text or "v=dmarc1" in text:
        has_mail_auth = _resolved(True)
    elif apex_records is not None and dmarc_records is not None:
        has_mail_auth = _resolved(False)
    else:
        has_mail_auth = _failed()

    return DnsFacts(
        domain_exists=domain_exists,
        has_mx=has_mx,
        has_website=has_website,
        has_mail_auth=has_mail_auth,
    )


def _txt(records) -> str:
    values = []
    for record in records or []:
        if hasattr(record, "strings"):
            values.append(b"".join(record.strings).decode("utf-8", "replace"))
        else:
            values.append(str(record))
    return " ".join(values)


async def _attempt_age(
    attempt,
    domain: str,
    *,
    allow_missing_rdap_server: bool = False,
) -> tuple[Fact[datetime] | None, bool]:
    try:
        _, parsed = await attempt(domain, tldextract_obj=EXTRACT)
    except AGE_NOT_FOUND:
        return None, True
    except AGE_UNKNOWN:
        return None, False
    except NotImplementedError:
        if not allow_missing_rdap_server:
            raise
        return None, False
    created = parsed.get("created")
    if not isinstance(created, datetime):
        return None, False
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return _resolved(created), False


async def _gather_age(domain: str, config: Config, *, rdap=None, whois=None) -> Fact:
    not_found = False
    if rdap is None:
        try:
            async with httpx.AsyncClient(timeout=config.per_lookup_timeout) as http_client:
                client = await whodap.DNSClient.new_aio_client(httpx_client=http_client)
                result, not_found = await _attempt_age(
                    _bind_rdap(client), domain, allow_missing_rdap_server=True
                )
        except httpx.HTTPError:
            result = None
    else:
        result, not_found = await _attempt_age(
            rdap, domain, allow_missing_rdap_server=True
        )
    if result is not None:
        return result

    result, whois_not_found = await _attempt_age(whois or _bind_whois(config), domain)
    if result is not None:
        return result
    return _resolved(None) if not_found or whois_not_found else _failed()


def _bind_rdap(client):
    async def call(domain, **kwargs):
        return await asyncwhois.aio_rdap(domain, whodap_client=client, **kwargs)

    return call


def _bind_whois(config: Config):
    async def call(domain, **kwargs):
        return await asyncwhois.aio_whois(
            domain,
            timeout=config.per_lookup_timeout,
            **kwargs,
        )

    return call


async def _gather(domain: str, config: Config) -> tuple[DnsFacts, Fact]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = config.per_lookup_timeout
    dns_facts, created = await asyncio.gather(
        _gather_dns(domain, resolver),
        _gather_age(domain, config),
    )
    return dns_facts, created


def gather_facts(
    domain: str,
    email: str | None = None,
    config: Config | None = None,
) -> DomainFacts:
    config = config or Config()
    normalized = normalize_domain(domain)
    dns_facts, created = asyncio.run(_gather(normalized, config))
    return DomainFacts(
        domain=normalized,
        as_of=datetime.now(UTC),
        created=created,
        domain_exists=dns_facts.domain_exists,
        has_mx=dns_facts.has_mx,
        has_website=dns_facts.has_website,
        has_mail_auth=dns_facts.has_mail_auth,
        email=classify_email(email, config),
    )
