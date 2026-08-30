"""Explainable onboarding-risk scoring for customer domains."""

from importlib.metadata import version

from domain_vet.core import (
    Assessment,
    Config,
    DomainFacts,
    EmailFacts,
    Fact,
    Lane,
    LookupStatus,
    ReasonCode,
    Signal,
    score,
)
from domain_vet.gather import agather_facts, gather_facts

__version__ = version("domain-vet")
__all__ = [
    "Assessment",
    "Config",
    "DomainFacts",
    "EmailFacts",
    "Fact",
    "Lane",
    "LookupStatus",
    "ReasonCode",
    "Signal",
    "score",
    "agather_facts",
    "gather_facts",
]
