"""Provider selectors and offline preparation; provider requests stay local."""
import json
import random
import string

import pytest

from kingfisher_sdk import Revoker, Rules, Validator
from test_resolved_credentials import ACCOUNT, TOKEN, provider, rules_file


def catalog(tmp_path, extra=()):
    path = rules_file(tmp_path)
    definitions = json.loads(path.read_text(encoding="utf-8"))
    primary = definitions["rules"][0]
    primary["id"] = "custom.github-pat"
    primary["name"] = "GitHub personal access token"
    definitions["rules"].extend(extra)
    path.write_text(json.dumps(definitions), encoding="utf-8")
    return Rules([path], builtins=False)


def sibling(*, rule_id="custom.github-oauth", name="GitHub OAuth token", revocation=True):
    definition = {"id": rule_id, "name": name,
                  "pattern": r"\b(demo_[a-z0-9]{16})\b",
                  "depends_on_rule": [{"rule_id": "acme.account", "variable": "ACCOUNT",
                                       "within": "2L"}],
                  "validation": {"type": "Http", "content": {"request": {
                      "method": "GET", "url": "{{ ENDPOINT }}/identity",
                      "headers": {"Authorization": "Bearer {{ TOKEN }}", "X-Account": "{{ ACCOUNT }}"},
                      "response_matcher": [{"type": "StatusMatch", "status": [200]}]}}}}
    if revocation:
        definition["revocation"] = {"type": "Http", "content": {"request": {
            "method": "DELETE", "url": "{{ ENDPOINT }}/token",
            "headers": {"Authorization": "Bearer {{ TOKEN }}", "X-Account": "{{ ACCOUNT }}"},
            "response_matcher": [{"type": "StatusMatch", "status": [204]}]}}}
    return definition


def test_selector_precedence_names_and_boundaries(tmp_path):
    rules = catalog(tmp_path, [sibling(), sibling(rule_id="custom.githubish-token"),
                               sibling(rule_id="custom.github-pat.extra")])
    assert rules.resolve("custom.github-pat") == ["custom.github-pat"]
    assert rules.resolve("GITHUB PERSONAL ACCESS TOKEN") == ["custom.github-pat"]
    expected = ["custom.github-oauth", "custom.github-pat", "custom.github-pat.extra"]
    assert rules.resolve("github") == expected
    assert rules.resolve("GitHub") == expected
    assert rules.resolve("custom.github") == expected
    assert rules.resolve("github-pat") == ["custom.github-pat", "custom.github-pat.extra"]
    for selector in ("git", "*github*", "github*", "github-oauh", "unknown"):
        with pytest.raises(ValueError, match="unknown provider selector"):
            rules.resolve(selector)
    with pytest.raises(ValueError, match="did you mean"):
        rules.resolve("github-oauh")
    for selector in ("", " github", "github "):
        with pytest.raises(ValueError, match="nonempty"):
            rules.resolve(selector)
    with pytest.raises(TypeError, match="string"):
        rules.resolve(42)


def test_ambiguous_display_name_requires_id(tmp_path):
    rules = catalog(tmp_path, [sibling(name="GitHub personal access token")])
    with pytest.raises(ValueError, match="ambiguous rule name"):
        rules.resolve("GitHub personal access token")
    assert rules.resolve("custom.github-pat") == ["custom.github-pat"]


def test_builtin_github_family_and_veles_namespace():
    rules = Rules()
    expected = sorted(rule["id"] for rule in rules.metadata()
                      if rule["id"].startswith("betterleaks.github-"))
    assert len(expected) > 1
    assert rules.resolve("github") == expected
    assert rules.resolve("betterleaks.github-pat") == ["betterleaks.github-pat"]
    # Ordered alphabet placeholders are intentionally filtered by the catalog.
    token = "ghp_" + "".join(random.Random(42).sample(string.ascii_letters + string.digits, 36))
    plan = Revoker(rules).prepare(token, provider="github")
    assert list(plan.rule_ids) == expected
    assert plan.candidate_rule_ids == ("betterleaks.github-pat",)
    veles_id = "veles.secrets/slackappconfigaccesstoken"
    assert rules.resolve(veles_id) == [veles_id]
    assert rules.resolve("slackappconfigaccesstoken") == [veles_id]


@pytest.mark.parametrize("selector", ["github", "custom.github-pat", "GitHub personal access token", None])
@pytest.mark.parametrize("visible_helper", [False, True])
def test_prepare_preserves_pair_and_excludes_unrelated_requests(tmp_path, selector, visible_helper):
    rules = catalog(tmp_path, [sibling(rule_id="custom.other-token")])
    if visible_helper:
        path = tmp_path / "multipart.yml"
        definitions = json.loads(path.read_text(encoding="utf-8"))
        definitions["rules"][1]["visible"] = True
        path.write_text(json.dumps(definitions), encoding="utf-8")
        rules = Rules([path], builtins=False)
    with provider() as (endpoint, calls):
        revoker = Revoker(rules)
        plan = revoker.prepare(ACCOUNT + "\n" + TOKEN, provider=selector)
        assert calls == []  # Preparation must stay offline.
        assert TOKEN not in repr(plan) and ACCOUNT not in repr(plan)
        assert plan.candidate_rule_ids == (("custom.github-pat", "custom.other-token")
                                           if selector is None else ("custom.github-pat",))
        results = plan.validate(Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True))
        assert all(result.revocation_ready for result in results)
        assert len(calls) == len(results)  # No unrelated check or mutation.
        assert all(method == "GET" for method, _ in calls)
        result = next(result for result in results if result.finding.rule_id == "custom.github-pat")
        assert result.credential.components[0].secret == ACCOUNT
        with pytest.raises(ValueError, match="confirm=True"):
            revoker.revoke(result)
        assert revoker.revoke(result, confirm=True).revoked
        assert calls[-1] == ("DELETE", "/token")


def test_overlapping_candidates_are_all_returned_without_winner(tmp_path):
    rules = catalog(tmp_path, [sibling()])
    with provider() as (endpoint, calls):
        plan = Revoker(rules).prepare(ACCOUNT + "\n" + TOKEN, provider="github")
        assert plan.candidate_rule_ids == ("custom.github-oauth", "custom.github-pat")
        results = plan.validate(Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True))
        assert {result.finding.rule_id for result in results} == set(plan.candidate_rule_ids)
        assert all(result.revocation_ready for result in results)
        assert calls == [("GET", "/identity"), ("GET", "/identity")]


def test_no_match_or_unsupported_rule_never_contacts_provider(tmp_path):
    rules = catalog(tmp_path, [sibling(rule_id="custom.other-token", revocation=False)])
    with provider() as (_, calls):
        revoker = Revoker(rules)
        for data, selector in (("no credential", "github"), (TOKEN, "custom.other-token")):
            plan = revoker.prepare(data, provider=selector)
            assert plan.rule_ids
            assert plan.candidate_rule_ids == ()
            assert plan.validate() == []
        assert calls == []


def test_bare_token_does_not_invent_missing_companion(tmp_path):
    rules = catalog(tmp_path)
    with provider() as (endpoint, calls):
        plan = Revoker(rules).prepare(TOKEN.encode(), provider="github")
        # Preparation retains unresolved candidates for named input diagnostics,
        # while normal scanning continues to suppress missing required companions.
        candidate, = plan.candidates
        assert candidate.missing_inputs[0].variable == "ACCOUNT"
        assert candidate.missing_inputs[0].rule_id == "acme.account"
        assert not candidate.ready_for_validation
        results = plan.validate(Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True))
        result, = results
        assert not result.revocation_ready
        assert result.input_diagnostics[0].variable == "ACCOUNT"
        assert calls == []


@pytest.mark.parametrize("extractor", [
    {"type": "JsonPath", "path": "$.{{ FIELD }}"},
    {"type": "Regex", "pattern": "{{ FIELD }}=(.*)"},
    {"type": "Header", "name": "X-{{ FIELD }}"},
])
def test_extractor_only_missing_inputs_block_revocation(tmp_path, extractor):
    path = rules_file(tmp_path)
    definitions = json.loads(path.read_text(encoding="utf-8"))
    final = definitions["rules"][0]["revocation"]["content"]["request"]
    lookup = definitions["rules"][0]["validation"]["content"]["request"]
    definitions["rules"][0]["revocation"] = {"type": "HttpMultiStep", "content": {
        "steps": [{"request": lookup, "extract": {"KEY_ID": extractor}}, {"request": final}]}}
    path.write_text(json.dumps(definitions), encoding="utf-8")
    with provider() as (endpoint, calls):
        revoker = Revoker(Rules([path], builtins=False))
        plan = revoker.prepare(ACCOUNT + "\n" + TOKEN, variables={"ENDPOINT": endpoint})
        assert calls == []
        assert plan.candidates[0].ready_for_validation
        issue, = plan.candidates[0].input_diagnostics
        assert (issue.stage, issue.code, issue.variable) == ("revocation", "missing_variable", "FIELD")
        result, = plan.validate(Validator(allow_internal_ips=True))
        assert result.outcome == "verified_active"
        assert not result.revocation_ready
        status, = revoker.revoke_many([result], confirm=True)
        assert status.outcome == "skipped"
        assert calls == [("GET", "/identity")]
