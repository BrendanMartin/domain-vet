import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import asyncwhois.errors
import dns.exception
import dns.resolver
import httpx
import pytest
import whodap.errors

import domain_vet
from domain_vet import Config, Fact, LookupStatus
from domain_vet.gather import (
    _gather,
    _gather_age,
    _gather_dns,
    agather_facts,
    gather_facts,
    normalize_domain,
)

CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" / "live_contracts.json").read_text()
)
WHEN = datetime.fromisoformat(CONTRACT["age"]["created"])


class StubResolver:
    def __init__(self, answers, default=None):
        self.answers = answers
        self.default = default if default is not None else dns.resolver.NoAnswer()
        self.peak_in_flight = 0
        self._in_flight = 0

    async def resolve(self, qname, rdtype, **kwargs):
        self._in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self._in_flight)
        try:
            await asyncio.sleep(0)
            outcome = self.answers.get((str(qname), str(rdtype)), self.default)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        finally:
            self._in_flight -= 1


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("  example.com  ", "example.com"),
        ("example.com.", "example.com"),
        ("http://example.com/path", "example.com"),
        ("https://example.com", "example.com"),
        ("faß.de", "xn--fa-hia.de"),
    ],
)
def test_normalize_accepts_common_forms(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "acme .com", "@@@", "http://", "127.0.0.1", "a@example.com"],
)
def test_normalize_raises_on_unusable_input(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


async def test_all_records_present():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): ["1.2.3.4"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
        }
    )
    result = await _gather_dns("example.com", resolver)
    assert result.domain_exists.value is True
    assert result.has_mx.value is True
    assert result.has_website.value is True
    assert result.has_mail_auth.value is True


async def test_stub_resolver_replays_captured_contract():
    domain = CONTRACT["dns"]["domain"]
    queries = CONTRACT["dns"]["queries"]
    answers = {
        (query["name"], query["rdtype"]): (
            dns.resolver.NoAnswer()
            if query["outcome"] == "NoAnswer"
            else _txt_records(query["records"])
            if query["rdtype"] == "TXT"
            else query["records"]
        )
        for query in queries.values()
    }
    resolver = StubResolver(answers)
    result = await _gather_dns(domain, resolver)
    assert result.domain_exists == _resolved(True)
    assert result.has_mx == _resolved(False)
    assert result.has_website == _resolved(True)
    assert result.has_mail_auth == _resolved(True)


async def test_no_answer_is_absent_not_unknown():
    no_answer = CONTRACT["dns"]["queries"]["MX"]
    result = await _gather_dns(
        no_answer["name"],
        StubResolver({(no_answer["name"], "A"): ["1.2.3.4"]}),
    )
    assert result.has_mx == _resolved(False)


async def test_no_address_answers_mean_no_website():
    result = await _gather_dns("example.com", StubResolver({}))
    assert result.has_website == _resolved(False)


async def test_no_txt_answers_mean_no_mail_auth():
    result = await _gather_dns("example.com", StubResolver({}))
    assert result.has_mail_auth == _resolved(False)


async def test_dmarc_is_read_from_the_dmarc_subdomain():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "TXT"): ["unrelated"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    assert (await _gather_dns("example.com", resolver)).has_mail_auth.value is True


async def test_spf_at_apex_also_counts_as_mail_auth():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "TXT"): ["v=spf1 -all"],
        }
    )
    assert (await _gather_dns("example.com", resolver)).has_mail_auth.value is True


async def test_ipv6_only_domain_has_a_website():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "AAAA"): ["2001:db8::1"],
        }
    )
    assert (await _gather_dns("example.com", resolver)).has_website.value is True


async def test_one_failed_record_does_not_discard_the_others():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): ["1.2.3.4"],
            ("_dmarc.example.com", "TXT"): dns.exception.Timeout(),
            ("example.com", "TXT"): dns.exception.Timeout(),
        }
    )
    result = await _gather_dns("example.com", resolver)
    assert result.has_mx.value is True
    assert result.has_website.value is True
    assert result.has_mail_auth.status is LookupStatus.FAILED


async def test_partial_address_failure_is_unknown_not_absent():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): dns.exception.Timeout(),
        }
    )
    result = await _gather_dns("example.com", resolver)
    assert result.has_website.status is LookupStatus.FAILED


async def test_partial_mail_auth_failure_is_unknown_not_absent():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "TXT"): dns.exception.Timeout(),
        }
    )
    result = await _gather_dns("example.com", resolver)
    assert result.has_mail_auth.status is LookupStatus.FAILED


async def test_txt_byte_chunks_are_joined_without_a_separator():
    class TxtRecord:
        strings = (b"v=spf", b"1 -all")

    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "TXT"): [TxtRecord()],
        }
    )
    result = await _gather_dns("example.com", resolver)
    assert result.has_mail_auth.value is True


async def test_nxdomain_requires_corroboration():
    resolver = StubResolver(
        {
            ("example.com", "MX"): dns.resolver.NXDOMAIN(),
            ("example.com", "A"): ["1.2.3.4"],
        }
    )
    assert (await _gather_dns("example.com", resolver)).domain_exists.value is not False


async def test_nxdomain_on_every_apex_query_is_not_registered():
    nxdomain = CONTRACT["dns"]["nxdomain"]
    resolver = StubResolver(
        {
            (query["name"], query["rdtype"]): dns.resolver.NXDOMAIN()
            for query in nxdomain["queries"]
        },
        default=dns.exception.Timeout(),
    )
    result = await _gather_dns(
        nxdomain["domain"], resolver
    )
    assert result.domain_exists == _resolved(False)
    assert result.has_mx == _resolved(False)
    assert result.has_website == _resolved(False)
    assert result.has_mail_auth == _resolved(False)


async def test_missing_dmarc_does_not_imply_a_missing_domain():
    resolver = StubResolver(
        {
            ("example.com", "MX"): ["mx1"],
            ("example.com", "A"): ["1.2.3.4"],
            ("_dmarc.example.com", "TXT"): dns.resolver.NXDOMAIN(),
        }
    )
    assert (await _gather_dns("example.com", resolver)).domain_exists.value is True


async def test_all_dns_queries_run_concurrently():
    resolver = StubResolver(
        {("example.com", "MX"): ["mx1"], ("example.com", "A"): ["1.2.3.4"]}
    )
    await _gather_dns("example.com", resolver)
    assert resolver.peak_in_flight == 5


async def test_lookup_failure_is_unknown():
    resolver = StubResolver({("example.com", "MX"): dns.resolver.NoNameservers()})
    result = await _gather_dns("example.com", resolver)
    assert result.has_mx.status is LookupStatus.FAILED


async def test_lifetime_timeout_is_unknown():
    timeout = dns.resolver.LifetimeTimeout(timeout=1, errors=[])
    resolver = StubResolver({("example.com", "MX"): timeout})
    result = await _gather_dns("example.com", resolver)
    assert result.has_mx.status is LookupStatus.FAILED


async def test_one_nxdomain_with_other_queries_unknown_is_not_corroborated():
    resolver = StubResolver(
        {("example.com", "MX"): dns.resolver.NXDOMAIN()},
        default=dns.exception.Timeout(),
    )
    result = await _gather_dns("example.com", resolver)
    assert result.domain_exists.status is LookupStatus.FAILED


async def test_unexpected_dns_exception_is_not_laundered():
    resolver = StubResolver({("example.com", "MX"): KeyError("bug")})
    with pytest.raises(KeyError):
        await _gather_dns("example.com", resolver)


async def ok_age(domain, **kwargs):
    return "raw", {"created": WHEN}


def failing_age(exc):
    async def call(domain, **kwargs):
        raise exc

    return call


async def test_rdap_success_skips_whois():
    called = []

    async def whois_spy(domain, **kwargs):
        called.append(domain)
        return "raw", {"created": WHEN}

    result = await _gather_age("example.com", Config(), rdap=ok_age, whois=whois_spy)
    assert result.value == WHEN
    assert called == []


async def test_naive_creation_date_is_normalized_to_utc():
    naive = datetime(2020, 1, 1)

    async def age(domain, **kwargs):
        return "raw", {"created": naive}

    result = await _gather_age("example.com", Config(), rdap=age, whois=ok_age)
    assert result.value == naive.replace(tzinfo=UTC)


async def test_falls_back_to_whois():
    result = await _gather_age(
        "example.com",
        Config(),
        rdap=failing_age(asyncwhois.errors.QueryError("no rdap")),
        whois=ok_age,
    )
    assert result.value == WHEN


async def test_both_failing_is_unknown():
    error = asyncwhois.errors.QueryError("x")
    result = await _gather_age(
        "example.com", Config(), rdap=failing_age(error), whois=failing_age(error)
    )
    assert result.status is LookupStatus.FAILED


async def test_not_found_is_a_resolved_negative():
    error = asyncwhois.errors.NotFoundError("nope")
    result = await _gather_age(
        "example.com", Config(), rdap=failing_age(error), whois=failing_age(error)
    )
    assert result == _resolved(None)


async def test_whodap_not_found_is_a_resolved_negative():
    error = whodap.errors.NotFoundError("nope")
    result = await _gather_age(
        "example.com", Config(), rdap=failing_age(error), whois=failing_age(error)
    )
    assert result == _resolved(None)


@pytest.mark.parametrize(
    "error",
    [
        whodap.errors.RateLimitError("slow down"),
        whodap.errors.BadStatusCode("bad status"),
        whodap.errors.MalformedQueryError("malformed"),
        asyncwhois.errors.GeneralError("no server"),
        httpx.ConnectError("network"),
        OSError("network"),
        TimeoutError(),
    ],
)
async def test_expected_age_io_failures_are_unknown(error):
    result = await _gather_age(
        "example.com", Config(), rdap=failing_age(error), whois=failing_age(error)
    )
    assert result.status is LookupStatus.FAILED


async def test_missing_rdap_server_falls_back_to_whois():
    result = await _gather_age(
        "example.com",
        Config(),
        rdap=failing_age(NotImplementedError("no RDAP server")),
        whois=ok_age,
    )
    assert result.value == WHEN


async def test_unexpected_whois_not_implemented_is_not_laundered():
    with pytest.raises(NotImplementedError):
        await _gather_age(
            "example.com",
            Config(),
            rdap=failing_age(asyncwhois.errors.QueryError("no rdap")),
            whois=failing_age(NotImplementedError("bug")),
        )


async def test_unexpected_age_exception_is_not_laundered():
    with pytest.raises(ValueError):
        await _gather_age(
            "example.com",
            Config(),
            rdap=failing_age(ValueError("bug")),
            whois=failing_age(ValueError("bug")),
        )


async def test_default_rdap_client_owns_timeout_and_closes(monkeypatch):
    observed = {}
    dns_client = object()

    class FakeHttpClient:
        async def __aenter__(self):
            observed["entered"] = True
            return self

        async def __aexit__(self, *args):
            observed["closed"] = True

    def make_http_client(*, timeout):
        observed["timeout"] = timeout
        return FakeHttpClient()

    async def make_dns_client(*, httpx_client):
        observed["httpx_client"] = httpx_client
        return dns_client

    async def rdap(domain, **kwargs):
        observed["whodap_client"] = kwargs["whodap_client"]
        return "raw", {"created": WHEN}

    monkeypatch.setattr("domain_vet.gather.httpx.AsyncClient", make_http_client)
    monkeypatch.setattr(
        "domain_vet.gather.whodap.DNSClient.new_aio_client", make_dns_client
    )
    monkeypatch.setattr("domain_vet.gather.asyncwhois.aio_rdap", rdap)

    result = await _gather_age("example.com", Config(per_lookup_timeout=2.5))
    assert result.value == WHEN
    assert observed == {
        "entered": True,
        "timeout": 2.5,
        "httpx_client": observed["httpx_client"],
        "whodap_client": dns_client,
        "closed": True,
    }


async def test_whois_receives_exact_configured_timeout(monkeypatch):
    observed = {}

    async def whois(domain, **kwargs):
        observed["timeout"] = kwargs["timeout"]
        return "raw", {"created": WHEN}

    monkeypatch.setattr("domain_vet.gather.asyncwhois.aio_whois", whois)
    result = await _gather_age(
        "example.com",
        Config(per_lookup_timeout=2.5),
        rdap=failing_age(asyncwhois.errors.QueryError("no rdap")),
    )
    assert result.value == WHEN
    assert observed["timeout"] == 2.5


async def test_dns_and_age_start_concurrently(monkeypatch):
    in_flight = 0
    peak = 0

    class Resolver:
        lifetime = None

    resolver = Resolver()

    async def overlap(result):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0)
        in_flight -= 1
        return result

    async def dns(domain, supplied_resolver):
        assert supplied_resolver is resolver
        return await overlap("dns")

    async def age(domain, config):
        return await overlap("age")

    def make_resolver():
        return resolver

    monkeypatch.setattr("domain_vet.gather.dns.asyncresolver.Resolver", make_resolver)
    monkeypatch.setattr("domain_vet.gather._gather_dns", dns)
    monkeypatch.setattr("domain_vet.gather._gather_age", age)

    assert await _gather("example.com", Config()) == ("dns", "age")
    assert peak == 2
    assert resolver.lifetime == Config().per_lookup_timeout


async def test_agather_facts_assembles_inside_running_event_loop(monkeypatch):
    async def fake_dns(domain, resolver):
        from domain_vet.gather import DnsFacts

        return DnsFacts(
            domain_exists=_resolved(True),
            has_mx=_resolved(True),
            has_website=_resolved(True),
            has_mail_auth=_resolved(True),
        )

    async def fake_age(domain, config, **kwargs):
        return _resolved(WHEN)

    monkeypatch.setattr("domain_vet.gather._gather_dns", fake_dns)
    monkeypatch.setattr("domain_vet.gather._gather_age", fake_age)

    config = Config(freemail_domains=frozenset({"mail.example"}))
    facts = await agather_facts("Example.com", "a@mail.example", config)
    assert facts.domain == "example.com"
    assert facts.created.value == WHEN
    assert facts.email.is_freemail is True
    assert facts.confidence == 1.0
    assert facts.as_of is not None


def test_gather_facts_delegates_to_async_entry_point(monkeypatch):
    expected = object()

    async def fake_gather(domain, email=None, config=None):
        assert (domain, email, config) == ("Example.com", "a@example.com", None)
        return expected

    monkeypatch.setattr("domain_vet.gather.agather_facts", fake_gather)
    assert gather_facts("Example.com", "a@example.com") is expected


def test_gather_facts_rejects_unusable_input():
    with pytest.raises(ValueError):
        gather_facts("")


def test_gather_entry_points_are_exported_from_package_root():
    assert domain_vet.agather_facts is agather_facts
    assert domain_vet.gather_facts is gather_facts


def _resolved(value):
    return Fact(value, LookupStatus.RESOLVED)


def _txt_records(records):
    return [
        SimpleNamespace(strings=tuple(chunk.encode() for chunk in chunks))
        for chunks in records
    ]
