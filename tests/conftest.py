import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "live: hits the real network")


def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="run tests that hit the real network",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-live"):
        return
    skip = pytest.mark.skip(reason="needs --run-live (real network)")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)
