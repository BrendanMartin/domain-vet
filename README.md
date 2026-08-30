# domain-vet

Score how suspicious a customer's domain is at signup, with explainable reason codes.

## Quickstart

```python
from domain_vet import Config, gather_facts, score

config = Config(brands=("acme-supply.com",))
facts = gather_facts("acme-supply.com", "buyer@acme-supply.com", config)
assessment = score(facts, config)

assessment.lane        # Lane.ALLOW | Lane.REVIEW | Lane.BLOCK
assessment.codes       # list[ReasonCode]
assessment.confidence  # 1.0 when every attempted lookup resolved
```

Inside an existing event loop:

```python
from domain_vet import Config, agather_facts, score

config = Config(brands=("acme-supply.com",))
facts = await agather_facts("acme-supply.com", "buyer@acme-supply.com", config)
assessment = score(facts, config)
```

The exact lane and codes depend on live DNS and registry responses. A complete,
established domain with a matching email domain normally returns `Lane.ALLOW`; lookup
failures or incomplete facts force at least `Lane.REVIEW`.

Gathering performs network I/O; scoring is pure and deterministic over `DomainFacts`.
Consumers can gather in one step, store or inspect the facts, and score separately.

**Gate on `lane` and `codes`.** The integer score and `Signal.detail` text are
implementation details.

## Install

From a checkout:

```console
uv pip install .
```

## Behavior

- Failed or deliberately skipped facts cannot produce `allow`; unknown is never clean.
- Review volume therefore tracks lookup success rate. Measure it before tuning signals.
- `gather_facts()` accepts a domain or URL and is the synchronous `asyncio.run()` wrapper.
  Event-loop callers await `agather_facts()` with the same arguments instead. Both raise
  `ValueError` for unusable input and use the same concurrent lookup pipeline.
- Disposable-domain membership comes from the fixed dataset installed with
  `disposable-email-domains`; it is shared provider intelligence rather than consumer
  policy. Freemail membership remains replaceable through `Config.freemail_domains`.
- Dependency refresh controls the packaged disposable and default freemail datasets.
  V1 accepts lockfile staleness and provides no automatic update cadence or freshness
  guarantee.
- DNS and registration-age lookups run concurrently. `per_lookup_timeout` bounds each
  transport, but there is no aggregate timeout for the whole gather.
- The package has no domain-reputation signal because no free source permits the intended
  commercial use.
- Weights and thresholds are module constants until measured outcomes justify tuning.

## Core Contracts

- `LookupStatus.RESOLVED` records a completed lookup, including an authoritative absence;
  `FAILED` records an attempted lookup without a result; `NOT_ATTEMPTED` records work
  deliberately skipped.
- Confidence is the fraction of attempted network facts that resolved. With no attempted
  facts it is `1.0`, but incomplete facts still force `review`.
- `Config` carries `brands`, `freemail_domains`, and `per_lookup_timeout`. A supplied
  `freemail_domains` set replaces the package default; pass the same config to gathering
  and scoring so email classification and brand checks use one policy.
- Authoritative absence (`NoAnswer`, corroborated `NXDOMAIN`, registry not-found) is a
  resolved negative fact. Transient or indeterminate lookup failures become `FAILED`;
  unexpected defects propagate.
- Corroborated apex `NXDOMAIN` resolves `domain_exists`, `has_mx`, `has_website`, and
  `has_mail_auth` to `False`; scoring reports only `DOMAIN_NOT_RESOLVABLE` for that cause.
- Email/site mismatch comparison folds IDNA2008-equivalent registrable domains, so a
  Unicode email domain such as `faß.de` matches the normalized `xn--fa-hia.de` site.

## Public API

The package root exports `Assessment`, `Config`, `DomainFacts`, `EmailFacts`, `Fact`,
`Lane`, `LookupStatus`, `ReasonCode`, `Signal`, `agather_facts`, `gather_facts`, and
`score`.

```python
async def agather_facts(
    domain: str,
    email: str | None = None,
    config: Config | None = None,
) -> DomainFacts: ...

def gather_facts(
    domain: str,
    email: str | None = None,
    config: Config | None = None,
) -> DomainFacts: ...

def score(facts: DomainFacts, config: Config | None = None) -> Assessment: ...
```

Synchronous callers use `gather_facts()`, which invokes `asyncio.run()`; callers already
inside an event loop await `agather_facts()`. Both entry points use the same concurrent
pipeline and classify email with the installed disposable dataset plus the default or
consumer-replaced freemail set. Dependency refresh is the only v1 freshness mechanism
for the packaged datasets; v1 provides no automatic update cadence or freshness
guarantee.

## Development checks

```console
uv run pytest -v
uv run pytest --run-live tests/test_live.py -v
```

The first command stays offline and skips tests marked `live`. The second exercises real
DNS, RDAP, and WHOIS contracts and therefore requires network access.
