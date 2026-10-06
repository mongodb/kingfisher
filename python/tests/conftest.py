"""Keep compiled rule caches isolated from the developer's normal cache."""
import pytest


@pytest.fixture(autouse=True)
def isolated_rule_cache(tmp_path_factory, monkeypatch):
    # Keep caches outside source fixtures and let the native API assign leaf ownership
    # even when an elevated Windows token defaults to Administrators ownership.
    cache = tmp_path_factory.mktemp("rule-cache") / "compiled"
    monkeypatch.setenv("KF_RULE_CACHE_DIR", str(cache))
