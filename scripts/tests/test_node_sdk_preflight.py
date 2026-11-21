"""Exercise automatic npm release planning without uploads or live credentials."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("node_sdk_preflight", ROOT / "scripts/check-node-sdk-release.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
HEAD = "a" * 40
BASE = "b" * 40
VERSION = "1.2.3"


def environment(**updates):
    return {"GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "mongodb/kingfisher",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": HEAD, **updates}


def response(payload=None, status=200):
    if payload is None:
        payload = {"name": preflight.PACKAGE, "version": VERSION}
    result = io.BytesIO(json.dumps(payload).encode() if isinstance(payload, dict) else payload)
    result.status = status
    return result


class RegistryTests(unittest.TestCase):
    def test_existing_version_is_checked_with_read_only_get(self):
        with patch.object(preflight.urllib.request, "urlopen", return_value=response()) as fetch:
            self.assertTrue(preflight.version_exists(VERSION))
        request = fetch.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, f"https://registry.npmjs.org/{preflight.PACKAGE}/{VERSION}")
        self.assertEqual(fetch.call_args.kwargs["timeout"], 15)

    def test_only_404_means_unused_and_registry_errors_fail_closed(self):
        for status in (404, 401, 403, 429, 503):
            error = urllib.error.HTTPError("https://registry.npmjs.org", status, "error", {}, None)
            with self.subTest(status=status), patch.object(
                    preflight.urllib.request, "urlopen", side_effect=error) as fetch, \
                    patch.object(preflight.time, "sleep"):
                if status == 404:
                    self.assertFalse(preflight.version_exists(VERSION))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        preflight.version_exists(VERSION)
                self.assertEqual(fetch.call_count, 3 if status in (429, 503) else 1)

    def test_bounded_network_retries_then_recovery(self):
        for error in (urllib.error.URLError("offline"), TimeoutError("timeout"), OSError("reset")):
            with self.subTest(error=error), patch.object(
                    preflight.urllib.request, "urlopen", side_effect=error) as fetch, \
                    patch.object(preflight.time, "sleep") as sleep:
                with self.assertRaises(type(error)):
                    preflight.version_exists(VERSION)
                self.assertEqual(fetch.call_count, 3)
                self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])
        with patch.object(preflight.urllib.request, "urlopen", side_effect=[
                urllib.error.URLError("offline"), response()]), patch.object(preflight.time, "sleep"):
            self.assertTrue(preflight.version_exists(VERSION))

    def test_unexpected_or_oversized_metadata_cannot_reserve_another_version(self):
        for payload in ({}, {"name": "other", "version": VERSION},
                        {"name": preflight.PACKAGE, "version": "9.9.9"}, b"invalid json", b" " * (1024 * 1024 + 1)):
            with self.subTest(payload=str(payload)[:100]), patch.object(
                    preflight.urllib.request, "urlopen", return_value=response(payload)):
                with self.assertRaises(ValueError):
                    preflight.version_exists(VERSION)


class PublishedSourceTests(unittest.TestCase):
    def fixtures(self, ref="refs/heads/main"):
        digest = bytes(range(64))
        metadata = {"dist": {"integrity": "sha512-" + base64.b64encode(digest).decode()}}
        statement = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": f"pkg:npm/{preflight.PACKAGE}@{VERSION}", "digest": {"sha512": digest.hex()}}],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {"workflow": {"ref": ref, "repository": "https://github.com/mongodb/kingfisher",
                                                          "path": ".github/workflows/node-sdk.yml"}},
                    "internalParameters": {"github": {"event_name": "push"}},
                    "resolvedDependencies": [{"uri": f"git+https://github.com/mongodb/kingfisher@{ref}",
                                               "digest": {"gitCommit": BASE}}]},
                "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}}}}
        return metadata, statement

    def source(self, metadata, statement, manifest_version=VERSION):
        attestation = {"predicateType": statement["predicateType"], "bundle": {"dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement).encode()).decode()}}}
        with patch.object(preflight, "registry_json", return_value={"attestations": [attestation]}) as fetch, \
                patch.object(preflight.sdk, "git", side_effect=lambda _root, *args:
                    '[package]\nname = "kingfisher-python"\nversion = "1.5.0"\n'
                    if args[0] == "show" and "kingfisher-python" in args[1] else
                    '[package]\nname = "kingfisher-bin"\nversion = "2.14.0"\n') as git, \
                patch.object(preflight.releases, "npm_version", return_value=manifest_version):
            result = preflight.published_source(ROOT, metadata, VERSION)
            fetch.assert_called_once_with(
                f"https://registry.npmjs.org/-/npm/v1/attestations/{preflight.PACKAGE}@{VERSION}")
            git.assert_any_call(ROOT, "cat-file", "-e", f"{BASE}^{{commit}}")
            return result

    def test_exact_tarball_provenance_records_main_and_tag_release_baselines(self):
        for ref in ("refs/heads/main", f"refs/tags/npm-v{VERSION}"):
            with self.subTest(ref=ref):
                self.assertEqual(self.source(*self.fixtures(ref)), BASE)

    def test_coordinator_or_sibling_tag_provenance_cannot_change_npm_trust(self):
        for workflow in ("node-sdk.yml", "release.yml"):
            for ref in ("refs/heads/main", f"refs/tags/npm-v{VERSION}", "refs/tags/v2.14.0", "refs/tags/python-v1.5.0"):
                metadata, statement = self.fixtures(ref)
                statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["path"] = f".github/workflows/{workflow}"
                with self.subTest(workflow=workflow, ref=ref):
                    if workflow == "node-sdk.yml" and ref in ("refs/heads/main", f"refs/tags/npm-v{VERSION}"):
                        self.assertEqual(self.source(metadata, statement), BASE)
                    else:
                        with self.assertRaisesRegex(ValueError, "trusted workflow"):
                            self.source(metadata, statement)

    def test_manual_provenance_only_supports_the_original_node_workflow_at_an_npm_tag(self):
        for workflow, ref, allowed in (("node-sdk.yml", f"refs/tags/npm-v{VERSION}", True),
                                       ("release.yml", "refs/heads/main", False),
                                       ("release.yml", "refs/tags/v2.14.0", False),
                                       ("node-sdk.yml", "refs/heads/main", False),
                                       ("node-sdk.yml", "refs/tags/v2.14.0", False),
                                       ("node-sdk.yml", "refs/tags/python-v1.5.0", False),
                                       ("release.yml", f"refs/tags/npm-v{VERSION}", False)):
            metadata, statement = self.fixtures(ref)
            definition = statement["predicate"]["buildDefinition"]
            definition["externalParameters"]["workflow"]["path"] = f".github/workflows/{workflow}"
            definition["internalParameters"]["github"]["event_name"] = "workflow_dispatch"
            with self.subTest(workflow=workflow, ref=ref):
                if allowed:
                    self.assertEqual(self.source(metadata, statement), BASE)
                else:
                    with self.assertRaisesRegex(ValueError, "trusted workflow"):
                        self.source(metadata, statement)

    def test_manual_npm_tag_provenance_still_requires_the_committed_sdk_version(self):
        for ref in ("refs/tags/npm-v9.9.9", f"refs/tags/npm-v{VERSION}-rc.1", f"refs/tags/npm-v{VERSION}+build"):
            metadata, statement = self.fixtures(ref)
            statement["predicate"]["buildDefinition"]["internalParameters"]["github"]["event_name"] = "workflow_dispatch"
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "tag"):
                self.source(metadata, statement)

    def test_different_package_digest_identity_workflow_or_source_is_rejected(self):
        metadata, original = self.fixtures()
        changes = [
            (("subject", 0, "name"), "pkg:npm/other@1.2.3"),
            (("subject", 0, "digest", "sha512"), "0" * 128),
            (("predicate", "buildDefinition", "externalParameters", "workflow", "repository"), "https://github.com/fork/kingfisher"),
            (("predicate", "buildDefinition", "externalParameters", "workflow", "ref"), "refs/heads/development"),
            (("predicate", "buildDefinition", "externalParameters", "workflow", "path"), ".github/workflows/other.yml"),
            (("predicate", "buildDefinition", "internalParameters", "github", "event_name"), "pull_request"),
            (("predicate", "runDetails", "builder", "id"), "self-hosted"),
            (("predicate", "buildDefinition", "resolvedDependencies", 0, "uri"), "git+https://github.com/fork/kingfisher@refs/heads/main"),
            (("predicate", "buildDefinition", "resolvedDependencies", 0, "digest", "gitCommit"), "0" * 40),
        ]
        for path, value in changes:
            statement = copy.deepcopy(original)
            parent = statement
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.source(metadata, statement)
        with self.assertRaisesRegex(ValueError, "manifests"):
            self.source(metadata, original, manifest_version="9.9.9")

    def test_missing_provenance_or_unavailable_source_fails_closed(self):
        metadata, _ = self.fixtures()
        with patch.object(preflight, "registry_json", return_value={"attestations": []}), \
                self.assertRaisesRegex(ValueError, "recorded SLSA source"):
            preflight.published_source(ROOT, metadata, VERSION)
        error = urllib.error.HTTPError("https://registry.npmjs.org", 404, "not found", {}, None)
        with patch.object(preflight.urllib.request, "urlopen", side_effect=error), \
                self.assertRaises(urllib.error.HTTPError):
            preflight.published_source(ROOT, metadata, VERSION)


class PublicationSourceTests(unittest.TestCase):
    def source(self, env=None, checkout=HEAD, failure=None, event=None, main=HEAD):
        def git(_root, *args):
            if failure and args[0] == failure:
                raise subprocess.CalledProcessError(1, ["git", *args])
            if args == ("rev-parse", "HEAD"):
                return checkout
            if args == ("rev-parse", "refs/remotes/origin/main"):
                return main
            if args[0] == "show":
                name, version = (("kingfisher-python", "1.5.0") if "kingfisher-python" in args[1]
                                 else ("kingfisher-bin", "2.14.0"))
                return f'[package]\nname = "{name}"\nversion = "{version}"\n'
            return ""
        with patch.object(preflight.sdk, "git", side_effect=git) as git_command:
            result = preflight.publication_source(ROOT, env or environment(), VERSION, event)
        return result, git_command.call_args_list

    def test_upstream_main_and_matching_sdk_tag_are_pinned_and_ancestry_checked(self):
        for ref in ("refs/heads/main", f"refs/tags/npm-v{VERSION}"):
            result, calls = self.source(environment(GITHUB_REF=ref))
            self.assertTrue(result)
            self.assertIn((ROOT, "fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"),
                          [call.args for call in calls])
            self.assertIn((ROOT, "merge-base", "--is-ancestor", HEAD, HEAD),
                          [call.args for call in calls])

    def test_no_other_event_repository_or_ref_can_publish(self):
        for updates in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                        {"GITHUB_REPOSITORY": "fork/kingfisher"}, {"GITHUB_REF": "refs/heads/development"},
                        {"GITHUB_REF": "refs/heads/feature/main"}, {"GITHUB_REF": "refs/tags/release-v1.2.3"}):
            with self.subTest(updates=updates):
                result, calls = self.source(environment(**updates))
                self.assertFalse(result)
                self.assertEqual(calls, [])

    def test_sibling_tags_use_their_own_manifest_versions_and_main_ancestry(self):
        for tag in ("v2.14.0", "python-v1.5.0"):
            with self.subTest(tag=tag):
                result, calls = self.source(environment(GITHUB_REF=f"refs/tags/{tag}"))
                self.assertTrue(result)
                self.assertTrue(any(call.args[1] == "show" for call in calls))
                self.assertTrue(any(call.args[1] == "merge-base" for call in calls))
        for tag in ("v9.9.9", "python-v9.9.9", "python-v1.5.0+build"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "tag"):
                self.source(environment(GITHUB_REF=f"refs/tags/{tag}"))

    def test_guarded_manual_uses_current_main_and_python_expected_version(self):
        env = environment(GITHUB_EVENT_NAME="workflow_dispatch")
        inputs = {"publish": "true", "expected_sha": HEAD, "expected_version": "1.5.0"}
        self.assertTrue(self.source(env, event={"inputs": inputs})[0])
        for key, value in (("expected_sha", BASE), ("expected_sha", HEAD[:7]), ("expected_version", VERSION)):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, key):
                self.source(env, event={"inputs": {**inputs, key: value}})
        with self.assertRaisesRegex(ValueError, "current upstream main SHA"):
            self.source(env, event={"inputs": inputs}, main=BASE)
        with self.assertRaisesRegex(ValueError, "refs/heads/main"):
            self.source({**env, "GITHUB_REF": f"refs/tags/npm-v{VERSION}"}, event={"inputs": inputs})
        result, calls = self.source(env, event={"inputs": {**inputs, "crates_only": True}})
        self.assertFalse(result)
        self.assertTrue(any(call.args[1] == "fetch" for call in calls))

    def test_wrong_tag_checkout_or_unmerged_source_is_rejected(self):
        for updates in ({"GITHUB_SHA": ""}, {"GITHUB_SHA": "a" * 7}, {"GITHUB_SHA": BASE},
                        {"GITHUB_REF": "refs/tags/npm-v9.9.9"}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.source(environment(**updates))
        for failure in ("fetch", "merge-base"):
            with self.subTest(failure=failure), self.assertRaises(subprocess.CalledProcessError):
                self.source(failure=failure)


class WorkflowPlanTests(unittest.TestCase):
    def plan(self, *, publish=True, changed=False, exists=False, published_changed=None, env=None):
        with patch.object(preflight, "publication_source", return_value=publish), \
                patch.object(preflight, "compare_source", return_value=changed), \
                patch.object(preflight, "version_metadata", return_value={} if exists else None) as lookup, \
                patch.object(preflight, "published_source", return_value=BASE), \
                patch.object(preflight.sdk, "git", return_value=HEAD), \
                patch.object(preflight, "runtime_changed", return_value=(
                    changed if published_changed is None else published_changed)) as compare:
            result = preflight.workflow_plan(ROOT, env or environment(), {"before": BASE}, VERSION)
            if exists and (publish or changed):
                compare.assert_called_once_with(ROOT, BASE, HEAD)
        return result, lookup.call_count

    def test_new_version_builds_then_publishes(self):
        for changed in (False, True):
            plan, lookups = self.plan(changed=changed)
            self.assertEqual(plan, {"build": True, "publish": True, "version": VERSION})
            self.assertEqual(lookups, 1)

    def test_unchanged_already_published_version_is_noop_before_builds(self):
        plan, _ = self.plan(exists=True)
        self.assertEqual(plan, {"build": False, "publish": False, "version": VERSION})

    def test_reusing_a_published_version_for_changed_inputs_is_rejected(self):
        for publish in (False, True):
            with self.subTest(publish=publish), self.assertRaisesRegex(ValueError, "bump SDK version"):
                self.plan(publish=publish, changed=True, exists=True)

    def test_successful_release_rerun_and_main_tag_race_are_noops(self):
        # push.before includes the successful version bump; the recorded released
        # source has no drift. Replaying that immutable event must still succeed.
        plan, _ = self.plan(exists=True, changed=True, published_changed=False)
        self.assertEqual(plan, {"build": False, "publish": False, "version": VERSION})

    def test_later_unrelated_push_and_tag_cannot_hide_unreleased_runtime_drift(self):
        for ref in ("refs/heads/main", f"refs/tags/npm-v{VERSION}"):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "bump SDK version"):
                self.plan(exists=True, changed=False, published_changed=True,
                          env=environment(GITHUB_REF=ref))

    def test_real_git_history_compares_published_source_not_previous_push(self):
        with tempfile.TemporaryDirectory(prefix="npm history ") as temporary:
            root = Path(temporary)
            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args], check=True,
                                      capture_output=True, text=True).stdout.strip()
            git("init", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            (root / "javascript").mkdir()
            source = root / "javascript/index.cjs"
            def commit(message):
                git("add", ".")
                git("-c", "core.hooksPath=", "-c", "commit.gpgSign=false", "commit", "-m", message)
                return git("rev-parse", "HEAD")
            source.write_text("old SDK")
            initial = commit("previous SDK")
            source.write_text("released SDK")
            released = commit("successful release")
            with patch.object(preflight, "publication_source", return_value=True), \
                    patch.object(preflight, "version_metadata", return_value={}), \
                    patch.object(preflight, "published_source", return_value=released):
                rerun = preflight.workflow_plan(root, environment(GITHUB_SHA=released), {"before": initial}, VERSION)
                self.assertEqual(rerun, {"build": False, "publish": False, "version": VERSION})
                source.write_text("unreleased runtime change")
                changed = commit("missing version bump")
                (root / "README.md").write_text("unrelated docs")
                later = commit("unrelated later main push")
                with self.assertRaisesRegex(ValueError, "bump SDK version"):
                    preflight.workflow_plan(root, environment(GITHUB_SHA=later), {"before": changed}, VERSION)

    def test_test_only_runs_always_build_and_never_publish(self):
        for changed in (False, True):
            plan, lookups = self.plan(publish=False, changed=changed)
            self.assertEqual(plan, {"build": True, "publish": False, "version": VERSION})
            self.assertEqual(lookups, int(changed))

    def test_malformed_base_cannot_skip_runtime_comparison(self):
        for env, event in ((environment(), {}), (environment(), {"before": "0" * 40}),
                           (environment(GITHUB_EVENT_NAME="pull_request"), {})):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, "base SHA"):
                preflight.compare_source(ROOT, env, event)

    def test_main_and_pr_comparison_use_exact_base_and_checkout(self):
        for env, event in ((environment(), {"before": BASE}),
                           (environment(GITHUB_EVENT_NAME="pull_request"),
                            {"pull_request": {"base": {"sha": BASE}}})):
            with patch.object(preflight.sdk, "git", return_value=HEAD), \
                    patch.object(preflight, "runtime_changed", return_value=True) as changed:
                self.assertTrue(preflight.compare_source(ROOT, env, event))
                changed.assert_called_once_with(ROOT, BASE, HEAD)

    def test_local_metadata_validation_precedes_release_plan_and_emits_outputs(self):
        with tempfile.TemporaryDirectory(prefix="npm preflight ") as temporary:
            event = Path(temporary) / "event.json"
            output = Path(temporary) / "output"
            event.write_text(json.dumps({"before": BASE}), encoding="utf-8")
            with patch.dict(os.environ, {**environment(), "GITHUB_EVENT_PATH": str(event),
                                         "GITHUB_OUTPUT": str(output)}, clear=True), \
                    patch.object(preflight.sdk, "git", return_value=HEAD), \
                    patch.object(preflight.releases, "npm_version", return_value=VERSION) as validate, \
                    patch.object(preflight, "workflow_plan", return_value={
                        "build": True, "publish": True, "version": VERSION}):
                self.assertEqual(preflight.main(["--github-event"]), 0)
            validate.assert_called_once_with(ROOT, HEAD)
            self.assertEqual(output.read_text(), f"build=true\npublish=true\nversion={VERSION}\n")


    def test_read_only_mode_never_emits_publication_authorization(self):
        with tempfile.TemporaryDirectory(prefix="npm local preflight ") as temporary:
            output = Path(temporary) / "output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True), \
                    patch.object(preflight.sdk, "git", return_value=HEAD), \
                    patch.object(preflight.releases, "npm_version", return_value=VERSION), \
                    patch.object(preflight, "version_exists", return_value=False), \
                    patch.object(preflight, "workflow_plan") as workflow:
                self.assertEqual(preflight.main([]), 0)
                workflow.assert_not_called()
            self.assertIn("publish=false\n", output.read_text())


class RuntimeComparisonTests(unittest.TestCase):
    def test_only_node_and_shared_packaged_inputs_are_relevant(self):
        for path in ("javascript/index.cjs", "javascript/index.d.ts", "javascript/lib/controls.cjs",
                     "javascript/README.md", "javascript/npm/darwin-arm64/package.json",
                     "javascript/scripts/build.cjs", "javascript/scripts/collect-artifacts.cjs",
                     "crates/kingfisher-node/src/lib.rs", "crates/kingfisher-node/build.rs",
                     "crates/kingfisher-scanner/src/scanner.rs", "crates/kingfisher-rules/generated/builtin-rules.gz",
                     ".cargo/config.toml", "rust-toolchain.toml", "THIRD_PARTY_NOTICES", ".gitattributes",
                     "javascript/.npmignore", "javascript/scripts/targets.cjs", "javascript/scripts/pack-release.cjs",
                     "crates/kingfisher-rules/LICENSE", "third-party/kingfisher-vectorscan/NOTICE",
                     "third-party/kingfisher-vectorscan/LICENSE-VECTORSCAN",
                     "third-party/kingfisher-vectorscan/LICENSE-APACHE", "third-party/kingfisher-vectorscan/LICENSE-MIT"):
            with self.subTest(path=path):
                self.assertTrue(preflight.packaged_path(path))
        for path in ("src/scan_audit.rs", "docs/JAVASCRIPT.md", "javascript/tests/publishing.test.cjs",
                     "javascript/scripts/publish-packages.cjs", "crates/kingfisher-python/Cargo.toml",
                     "crates/kingfisher-python/src/lib.rs", "python/kingfisher_sdk/__init__.py"):
            with self.subTest(path=path):
                self.assertFalse(preflight.packaged_path(path))

    def test_cargo_closure_is_rooted_at_node_not_python_or_cli(self):
        lock = {"package": [
            {"name": "kingfisher-node", "version": VERSION, "dependencies": ["shared"]},
            {"name": "shared", "version": "1.0.0"},
            {"name": "kingfisher-python", "version": "1.6.0", "dependencies": ["python-only"]},
            {"name": "python-only", "version": "1.0.0"},
        ]}
        selected = preflight.sdk.lock_dependencies(lock, "kingfisher-node")
        self.assertEqual({identity[0] for identity in selected}, {"kingfisher-node", "shared"})
        changed = {"package": [dict(item) for item in lock["package"]]}
        changed["package"][3]["version"] = "2.0.0"
        self.assertEqual(selected, preflight.sdk.lock_dependencies(changed, "kingfisher-node"))
        changed["package"][1]["version"] = "1.0.1"
        self.assertNotEqual(selected, preflight.sdk.lock_dependencies(changed, "kingfisher-node"))

    def test_manifest_comparison_ignores_development_only_metadata(self):
        before = {"name": preflight.PACKAGE, "version": VERSION, "engines": {"node": ">=22"},
                  "private": True, "scripts": {"test": "old"}, "devDependencies": {"typescript": "5"}}
        after = {**before, "scripts": {"test": "new"}, "devDependencies": {"typescript": "6"}}
        for runtime_change in (False, True):
            if runtime_change:
                after["engines"] = {"node": ">=24"}
            def git(_root, *args):
                if args[0] == "diff":
                    return "javascript/package.json\0"
                return json.dumps(before if args[-1].startswith(BASE) else after)
            with self.subTest(runtime_change=runtime_change), patch.object(preflight.sdk, "git", side_effect=git):
                self.assertEqual(preflight.runtime_changed(ROOT, BASE, HEAD), runtime_change)

    def test_build_staging_and_lifecycle_commands_require_a_new_version(self):
        before = {"name": preflight.PACKAGE, "version": VERSION, "scripts": {}}
        for command in ("build", "prepare:package", "prepare:platforms", "collect:artifacts", "pack:release"):
            for prefix in ("", "pre", "post"):
                after = {**before, "scripts": {f"{prefix}{command}": "changed"}}
                def git(_root, *args):
                    if args[0] == "diff":
                        return "javascript/package.json\0"
                    return json.dumps(before if args[-1].startswith(BASE) else after)
                with self.subTest(command=f"{prefix}{command}"), patch.object(preflight.sdk, "git", side_effect=git):
                    self.assertTrue(preflight.runtime_changed(ROOT, BASE, HEAD))

    def test_cli_only_lock_churn_is_ignored_but_node_closure_drift_is_not(self):
        before = {"package": [{"name": "kingfisher-node", "version": VERSION, "dependencies": ["shared"]},
                              {"name": "shared", "version": "1.0.0"},
                              {"name": "cli-only", "version": "1.0.0"}]}
        after = {"package": [dict(package) for package in before["package"]]}
        after["package"][2]["version"] = "2.0.0"
        for runtime_change in (False, True):
            if runtime_change:
                after["package"][1]["version"] = "1.0.1"
            with self.subTest(runtime_change=runtime_change), \
                    patch.object(preflight.sdk, "git", return_value="Cargo.lock\0"), \
                    patch.object(preflight.sdk, "committed_toml", side_effect=[before, after]):
                self.assertEqual(preflight.runtime_changed(ROOT, BASE, HEAD), runtime_change)

    def test_cli_only_root_manifest_edits_do_not_require_npm_bump(self):
        before = {"package": {"version": "2.0.0"}, "dependencies": {"cli": "1"}}
        after = {"package": {"version": "2.1.0"}, "dependencies": {"cli": "2"}}
        with patch.object(preflight.sdk, "git", return_value="Cargo.toml\0"), \
                patch.object(preflight.sdk, "committed_toml", side_effect=[before, after]):
            self.assertFalse(preflight.runtime_changed(ROOT, BASE, HEAD))
        after["profile"] = {"node-release": {"lto": True}}
        with patch.object(preflight.sdk, "git", return_value="Cargo.toml\0"), \
                patch.object(preflight.sdk, "committed_toml", side_effect=[before, after]):
            self.assertTrue(preflight.runtime_changed(ROOT, BASE, HEAD))


if __name__ == "__main__":
    unittest.main()
