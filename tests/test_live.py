"""Live contract rigs for every external seam replaced by the offline suite."""

import asyncwhois
import asyncwhois.errors
import dns.asyncresolver
import dns.resolver
import json
from datetime import datetime
from pathlib import Path
import pytest

from domain_vet import Config, Lane, LookupStatus, gather_facts, score
from domain_vet.gather import _gather_age, _gather_dns

pytestmark = pytest.mark.live
CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" / "live_contracts.json").read_text()
)


async def test_dns_seam_against_real_resolver():
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = Config().per_lookup_timeout
    domain = CONTRACT["dns"]["domain"]
    for query in CONTRACT["dns"]["queries"].values():
        if query["outcome"] == "NoAnswer":
            with pytest.raises(dns.resolver.NoAnswer):
                await resolver.resolve(query["name"], query["rdtype"])
            continue
        records = await resolver.resolve(query["name"], query["rdtype"])
        actual = [
            [chunk.decode() for chunk in record.strings]
            if hasattr(record, "strings")
            else str(record)
            for record in records
        ]
        assert sorted(actual) == sorted(query["records"])

    nxdomain = CONTRACT["dns"]["nxdomain"]
    for query in nxdomain["queries"]:
        with pytest.raises(dns.resolver.NXDOMAIN):
            await resolver.resolve(query["name"], query["rdtype"])

    facts = await _gather_dns(domain, resolver)
    assert facts.domain_exists.value is True
    assert facts.has_mx.value is False
    assert facts.has_website.value is True
    assert facts.has_mail_auth.value is True


async def test_rdap_seam_against_real_registry():
    async def fail_if_whois_runs(domain, **kwargs):
        raise AssertionError("RDAP fell back to WHOIS")

    created = await _gather_age(
        CONTRACT["age"]["domain"], Config(), whois=fail_if_whois_runs
    )
    assert created.status is LookupStatus.RESOLVED
    assert created.value == datetime.fromisoformat(CONTRACT["age"]["created"])


async def test_whois_fallback_against_real_registry():
    async def unavailable_rdap(domain, **kwargs):
        raise asyncwhois.errors.QueryError("exercise WHOIS fallback")

    created = await _gather_age(
        CONTRACT["age"]["domain"],
        Config(),
        rdap=unavailable_rdap,
    )
    assert created.status is LookupStatus.RESOLVED
    assert created.value == datetime.fromisoformat(CONTRACT["age"]["created"])


def test_unregistered_domain_is_detected():
    facts = gather_facts(CONTRACT["dns"]["nxdomain"]["domain"])
    assert facts.domain_exists.value is False
    assert facts.created.status is LookupStatus.RESOLVED
    assert facts.created.value is None


def test_end_to_end_established_domain_allows():
    assessment = score(gather_facts("google.com", "someone@google.com"))
    assert assessment.lane is Lane.ALLOW
