from datetime import UTC, datetime, timedelta
from math import inf, nan

import pytest

from domain_vet import Config, Lane, ReasonCode, score
from domain_vet.core import (
    Assessment,
    DomainFacts,
    EmailFacts,
    Fact,
    LookupStatus,
    classify_email,
    registrable,
)

NOW = datetime(2026, 8, 28, tzinfo=UTC)


def known(value):
    return Fact(value=value, status=LookupStatus.RESOLVED)


def unknown():
    return Fact(value=None, status=LookupStatus.FAILED)


def not_attempted():
    return Fact(value=None, status=LookupStatus.NOT_ATTEMPTED)


def facts(
    domain="example.com",
    *,
    age=None,
    mx=None,
    web=None,
    auth=None,
    exists=None,
    email=None,
    as_of=NOW,
):
    return DomainFacts(
        domain=domain,
        as_of=as_of,
        created=age if age is not None else known(NOW - timedelta(days=5 * 365)),
        domain_exists=exists if exists is not None else known(True),
        has_mx=mx if mx is not None else known(True),
        has_website=web if web is not None else known(True),
        has_mail_auth=auth if auth is not None else known(True),
        email=email,
    )


def test_established_domain_allows():
    assessment = score(facts())
    assert assessment.lane is Lane.ALLOW
    assert ReasonCode.AGE_GT_3Y in assessment.codes


def test_new_domain_scores_age():
    assessment = score(facts(age=known(NOW - timedelta(days=5))))
    assert ReasonCode.AGE_LT_30D in assessment.codes
    assert assessment.lane is not Lane.ALLOW


@pytest.mark.parametrize(
    "days, expected",
    [
        (5, ReasonCode.AGE_LT_30D),
        (60, ReasonCode.AGE_LT_90D),
        (200, ReasonCode.AGE_LT_1Y),
        (5 * 365, ReasonCode.AGE_GT_3Y),
    ],
)
def test_age_buckets_are_exclusive(days, expected):
    assessment = score(facts(age=known(NOW - timedelta(days=days))))
    age_codes = {code for code in assessment.codes if code.name.startswith("AGE_")}
    assert age_codes == {expected}


def test_age_boundaries_use_as_of_not_wall_clock():
    domain_facts = facts(age=known(NOW - timedelta(days=29)), as_of=NOW)
    assert ReasonCode.AGE_LT_30D in score(domain_facts).codes
    assert score(domain_facts) == score(domain_facts)


def test_failed_lookup_forces_review():
    assessment = score(facts(mx=unknown()))
    assert assessment.confidence < 1.0
    assert assessment.lane is Lane.REVIEW


def test_resolved_lookup_without_a_value_forces_review():
    assessment = score(facts(age=Fact(None, LookupStatus.RESOLVED)))
    assert assessment.lane is Lane.REVIEW


def test_all_unknown_never_allows():
    assessment = score(
        DomainFacts(
            domain="x.com",
            as_of=NOW,
            created=unknown(),
            domain_exists=unknown(),
            has_mx=unknown(),
            has_website=unknown(),
            has_mail_auth=unknown(),
        )
    )
    assert assessment.confidence == 0.0
    assert assessment.lane is not Lane.ALLOW


def test_confidence_uses_only_attempted_facts():
    domain_facts = DomainFacts(
        domain="x.com",
        as_of=NOW,
        created=known(NOW - timedelta(days=365)),
        domain_exists=unknown(),
        has_mx=not_attempted(),
        has_website=not_attempted(),
        has_mail_auth=not_attempted(),
    )
    assert domain_facts.confidence == 0.5


def test_no_attempted_facts_have_full_confidence():
    domain_facts = DomainFacts(
        domain="x.com",
        as_of=NOW,
        created=not_attempted(),
        domain_exists=not_attempted(),
        has_mx=not_attempted(),
        has_website=not_attempted(),
        has_mail_auth=not_attempted(),
    )
    assert domain_facts.confidence == 1.0
    assert domain_facts.all_resolved is False
    assert score(domain_facts).lane is Lane.REVIEW


@pytest.mark.parametrize(
    ("created", "as_of"),
    [
        (datetime(2020, 1, 1), NOW),
        (datetime(2020, 1, 1, tzinfo=UTC), datetime(2026, 8, 28)),
    ],
)
def test_mixed_timezone_awareness_is_rejected(created, as_of):
    with pytest.raises(ValueError, match="same timezone awareness"):
        facts(age=known(created), as_of=as_of)


@pytest.mark.parametrize("status", [LookupStatus.FAILED, LookupStatus.NOT_ATTEMPTED])
def test_unresolved_fact_cannot_carry_a_value(status):
    with pytest.raises(ValueError, match="cannot carry a value"):
        Fact(True, status)


def test_assessment_can_only_be_created_by_score():
    with pytest.raises(TypeError, match="created by score"):
        Assessment(reasons=(), confidence=1.0, all_resolved=True)


def test_low_confidence_does_not_downgrade_block():
    assessment = score(
        facts(
            age=known(NOW - timedelta(days=3)),
            mx=Fact(False, LookupStatus.RESOLVED),
            web=Fact(False, LookupStatus.RESOLVED),
            auth=unknown(),
        )
    )
    assert assessment.lane is Lane.BLOCK


def test_mail_auth_requires_known_present_mx():
    assessment = score(
        facts(
            mx=not_attempted(),
            auth=Fact(False, LookupStatus.RESOLVED),
        )
    )
    assert ReasonCode.NO_MAIL_AUTH not in assessment.codes


def test_missing_mail_auth_with_present_mx_is_risky():
    assessment = score(
        facts(
            mx=Fact(True, LookupStatus.RESOLVED),
            auth=Fact(False, LookupStatus.RESOLVED),
        )
    )
    assert ReasonCode.NO_MAIL_AUTH in assessment.codes


def test_nxdomain_reports_one_code():
    assessment = score(facts(exists=Fact(False, LookupStatus.RESOLVED), age=unknown()))
    assert ReasonCode.DOMAIN_NOT_RESOLVABLE in assessment.codes
    for suppressed in (ReasonCode.NO_MX, ReasonCode.NO_WEBSITE, ReasonCode.NO_MAIL_AUTH):
        assert suppressed not in assessment.codes


def test_nxdomain_does_not_also_emit_age_unknown():
    assessment = score(facts(exists=Fact(False, LookupStatus.RESOLVED), age=unknown()))
    assert ReasonCode.AGE_UNKNOWN not in assessment.codes


def test_nxdomain_alone_lands_in_review_not_block():
    assessment = score(facts(exists=Fact(False, LookupStatus.RESOLVED), age=unknown()))
    assert assessment.lane is Lane.REVIEW


def test_score_floors_at_zero():
    assert score(facts()).score >= 0


def test_reasons_sorted_most_suspicious_first():
    assessment = score(
        facts(age=known(NOW - timedelta(days=5)), mx=Fact(False, LookupStatus.RESOLVED))
    )
    points = [signal.points for signal in assessment.reasons]
    assert points == sorted(points, reverse=True)


def test_lane_cannot_contradict_score():
    assessment = score(
        facts(
            age=known(NOW - timedelta(days=1)),
            mx=Fact(False, LookupStatus.RESOLVED),
            web=Fact(False, LookupStatus.RESOLVED),
        )
    )
    assert assessment.lane is Lane.BLOCK
    with pytest.raises(AttributeError):
        assessment.lane = Lane.ALLOW


def test_disposable_email_signal():
    email = EmailFacts("a@x.com", "x.com", is_disposable=True, is_freemail=False)
    assert ReasonCode.DISPOSABLE_EMAIL in score(facts(email=email)).codes


def test_freemail_and_mismatch_both_fire():
    email = EmailFacts("a@gmail.com", "gmail.com", is_disposable=False, is_freemail=True)
    codes = score(facts("acme.com", email=email)).codes
    assert ReasonCode.FREE_EMAIL in codes
    assert ReasonCode.EMAIL_DOMAIN_MISMATCH in codes


def test_matching_email_domain_has_no_mismatch():
    email = EmailFacts("a@acme.com", "acme.com", is_disposable=False, is_freemail=False)
    assert ReasonCode.EMAIL_DOMAIN_MISMATCH not in score(facts("acme.com", email=email)).codes


def test_matching_unicode_email_domain_has_no_mismatch():
    email = classify_email("user@faß.de")
    assert ReasonCode.EMAIL_DOMAIN_MISMATCH not in score(
        facts("xn--fa-hia.de", email=email)
    ).codes


def test_freemail_domains_are_consumer_overridable():
    config = Config(freemail_domains=frozenset({"mail.example"}))
    assert classify_email("a@mail.example", config).is_freemail is True
    assert classify_email("a@gmail.com", config).is_freemail is False


@pytest.mark.parametrize("timeout", [0, -1, nan, inf])
def test_lookup_timeout_must_be_finite_and_positive(timeout):
    with pytest.raises(ValueError, match="finite and positive"):
        Config(per_lookup_timeout=timeout)


def test_typosquat_detects_substitution():
    config = Config(brands=("example.com",))
    assert ReasonCode.TYPOSQUAT in score(facts("exarnple.com"), config).codes


def test_typosquat_ignores_the_brand_itself():
    config = Config(brands=("example.com",))
    assert ReasonCode.TYPOSQUAT not in score(facts("example.com"), config).codes


def test_typosquat_ignores_exact_brand_after_near_match():
    config = Config(brands=("examples.com", "example.com"))
    assert ReasonCode.TYPOSQUAT not in score(facts("example.com"), config).codes


def test_typosquat_ignores_distant_domain():
    config = Config(brands=("example.com",))
    assert ReasonCode.TYPOSQUAT not in score(facts("totallyunrelated.org"), config).codes


def test_typosquat_folds_idna2008_punycode():
    config = Config(brands=("fass.com",))
    assert ReasonCode.TYPOSQUAT in score(facts("xn--fa-hia.com"), config).codes


def test_registrable_strips_subdomains():
    assert registrable("mail.example.co.uk") == "example.co.uk"


def test_extractor_never_fetches_the_public_suffix_list():
    from domain_vet.core import EXTRACT

    assert EXTRACT.suffix_list_urls == ()
