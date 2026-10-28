"""Read-only SDK preflight and early release DAG regression tests."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sdk_preflight", ROOT / "scripts/check-sdk-release.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
HEAD = "a" * 40
BASE = "b" * 40
VERSION = "1.5.0"


def response(payload=b'{"urls": []}', status=200):
    result = io.BytesIO(payload)
    result.status = status
    return result


def environment(event="workflow_dispatch", **updates):
    values = {"GITHUB_EVENT_NAME": event, "GITHUB_REPOSITORY": "mongodb/kingfisher",
              "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": HEAD, "GITHUB_RUN_ATTEMPT": "1"}
    values.update(updates)
    return values


def manual_event(**updates):
    inputs = {"publish": "true", "expected_sha": HEAD, "expected_version": VERSION}
    inputs.update(updates)
    return {"inputs": inputs}


class RegistryTests(unittest.TestCase):
    def test_existing_empty_or_yanked_release_is_reserved(self):
        for payload in (b'{"urls": []}', b'{"urls": [{"yanked": true}]}'):
            with self.subTest(payload=payload), patch.object(
                    preflight.urllib.request, "urlopen", return_value=response(payload)) as fetch:
                self.assertTrue(preflight.version_exists(VERSION))
                request = fetch.call_args.args[0]
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(request.full_url,
                                 f"https://pypi.org/pypi/kingfisher-secret-scanner/{VERSION}/json")
                self.assertEqual(fetch.call_args.kwargs["timeout"], 15)

    def test_only_404_means_unused(self):
        for status in (404, 403, 503):
            error = urllib.error.HTTPError("https://pypi.org", status, "error", {}, None)
            with self.subTest(status=status), patch.object(
                    preflight.urllib.request, "urlopen", side_effect=error) as fetch, \
                    patch.object(preflight.time, "sleep"):
                if status == 404:
                    self.assertFalse(preflight.version_exists(VERSION))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        preflight.version_exists(VERSION)
                self.assertEqual(fetch.call_count, 3 if status == 503 else 1)

    def test_network_failures_are_bounded_and_fail_closed(self):
        for error in (urllib.error.URLError("offline"), TimeoutError("timeout"), OSError("reset")):
            with self.subTest(error=error), patch.object(
                    preflight.urllib.request, "urlopen", side_effect=error) as fetch, \
                    patch.object(preflight.time, "sleep") as sleep:
                with self.assertRaises(type(error)):
                    preflight.version_exists(VERSION)
                self.assertEqual(fetch.call_count, 3)
                self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_transient_failure_retries_then_accepts_404(self):
        missing = urllib.error.HTTPError("https://pypi.org", 404, "missing", {}, None)
        with patch.object(preflight.urllib.request, "urlopen", side_effect=[
                urllib.error.URLError("offline"), missing]), patch.object(preflight.time, "sleep") as sleep:
            self.assertFalse(preflight.version_exists(VERSION))
            sleep.assert_called_once_with(1)

    def test_unexpected_success_status_is_not_unused(self):
        with patch.object(preflight.urllib.request, "urlopen", return_value=response(status=204)):
            with self.assertRaisesRegex(ValueError, "Unexpected PyPI"):
                preflight.version_exists(VERSION)

    def test_orchestrator_interface_infers_manifest_and_requires_new(self):
        version = preflight.sdk_version()
        for exists in (False, True):
            with self.subTest(exists=exists), patch.object(preflight, "version_exists", return_value=exists) as query, \
                    patch.dict(preflight.os.environ, {}, clear=True), patch("builtins.print"):
                if exists:
                    with self.assertRaisesRegex(ValueError, "already exists.*bump SDK version"):
                        preflight.main(["--require-new", "--expected-version", version])
                else:
                    self.assertEqual(preflight.main(["--require-new", "--expected-version", version]), 0)
                query.assert_called_once_with(version)
        with patch.object(preflight, "version_exists", return_value=False) as query, \
                patch.dict(preflight.os.environ, {}, clear=True), patch("builtins.print"):
            self.assertEqual(preflight.main([]), 0)
            query.assert_called_once_with(version)

    def test_workflow_outputs_are_written_only_after_successful_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            output = Path(temporary) / "outputs"
            event.write_text(json.dumps(manual_event()), encoding="utf-8")
            env = environment(GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(output))
            with patch.dict(preflight.os.environ, env, clear=True), \
                    patch.object(preflight, "workflow_plan", return_value={
                        "build": True, "publish": True, "version": VERSION}):
                self.assertEqual(preflight.main(["--github-event"]), 0)
            self.assertEqual(output.read_text(encoding="utf-8"),
                             f"build=true\npublish=true\nversion={VERSION}\n")
            with patch.dict(preflight.os.environ, env, clear=True), \
                    patch.object(preflight, "workflow_plan", side_effect=ValueError("already exists")):
                with self.assertRaisesRegex(ValueError, "already exists"):
                    preflight.main(["--github-event"])
            self.assertEqual(output.read_text(encoding="utf-8"),
                             f"build=true\npublish=true\nversion={VERSION}\n")

    def test_expected_version_mismatch_fails_before_registry_access(self):
        with patch.object(preflight, "version_exists") as query:
            with self.assertRaisesRegex(ValueError, "Expected SDK version"):
                preflight.main(["--require-new", "--expected-version", "0.0.0"])
            query.assert_not_called()
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check-sdk-release.py"),
                                 "--require-new", "--expected-version", "0.0.0"],
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SDK release preflight failed", result.stderr)


class PublicationSourceTests(unittest.TestCase):
    def source(self, env=None, event=None, main=HEAD, checkout=HEAD):
        def git(_root, *args):
            if args == ("rev-parse", "HEAD"):
                return checkout
            if args == ("rev-parse", "refs/remotes/origin/main"):
                return main
            return ""
        with patch.object(preflight, "git", side_effect=git) as command:
            plan = preflight.publication_source(ROOT, env or environment(), event or manual_event(), VERSION)
            return plan, command.call_args_list

    def test_manual_publication_requires_upstream_main_and_exact_sha_version(self):
        invalid = [
            (environment(GITHUB_REPOSITORY="fork/kingfisher"), manual_event(), "upstream"),
            (environment(GITHUB_REF="refs/heads/feature"), manual_event(), "refs/heads/main"),
            (environment(), manual_event(expected_sha=BASE), "expected_sha"),
            (environment(), manual_event(expected_sha=HEAD[:7]), "expected_sha"),
            (environment(), manual_event(expected_version="1.4.0"), "expected_version"),
            (environment(), manual_event(expected_version=""), "expected_version"),
            (environment(GITHUB_SHA=BASE), manual_event(), "pinned GITHUB_SHA"),
        ]
        for env, event, message in invalid:
            with self.subTest(env=env, event=event), self.assertRaisesRegex(ValueError, message):
                self.source(env, event)

    def test_valid_manual_publish_checks_main_history_and_current_tip(self):
        result, commands = self.source()
        self.assertEqual(result, (True, True))
        arguments = [call.args[1:] for call in commands]
        self.assertIn(("fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"), arguments)
        self.assertIn(("merge-base", "--is-ancestor", HEAD, HEAD), arguments)
        with self.assertRaisesRegex(ValueError, "current upstream main SHA"):
            self.source(main=BASE)

    def test_unmerged_source_and_failed_fetch_fail_closed(self):
        for failed in ("fetch", "merge-base"):
            def git(_root, *args):
                if args[0] == failed:
                    raise subprocess.CalledProcessError(1, ["git", *args])
                return HEAD
            with self.subTest(failed=failed), patch.object(preflight, "git", side_effect=git):
                with self.assertRaises(subprocess.CalledProcessError):
                    preflight.publication_source(ROOT, environment(), manual_event(), VERSION)

    def test_tag_version_must_match_and_source_must_be_merged(self):
        env = environment("push", GITHUB_REF=f"refs/tags/python-v{VERSION}")
        result, commands = self.source(env, {"before": BASE})
        self.assertEqual(result, (True, False))
        self.assertTrue(any(call.args[1:3] == ("merge-base", "--is-ancestor") for call in commands))
        with self.assertRaisesRegex(ValueError, "tag must match"):
            self.source(environment("push", GITHUB_REF="refs/tags/python-v0.0.0"))

    def test_default_manual_and_fork_push_never_authorize_publish(self):
        for env, event in ((environment(), manual_event(publish="false")),
                           (environment("push", GITHUB_REPOSITORY="fork/kingfisher"), {})):
            with self.subTest(env=env), patch.object(preflight, "git") as git:
                self.assertEqual(preflight.publication_source(ROOT, env, event, VERSION), (False, False))
                git.assert_not_called()


class WorkflowPlanTests(unittest.TestCase):
    def plan(self, env=None, manual=False, exists=False, changed=False, same=False, publish=True):
        with patch.object(preflight, "publication_source", return_value=(publish, manual)), \
                patch.object(preflight, "version_exists", return_value=exists), \
                patch.object(preflight, "compare_source", return_value=(changed, same)), \
                patch.object(preflight, "git", return_value=HEAD), patch("builtins.print"):
            return preflight.workflow_plan(ROOT, env or environment("push"), {}, VERSION)

    def test_manual_existing_version_is_fatal_even_on_rerun(self):
        for attempt in ("1", "2"):
            with self.subTest(attempt=attempt), self.assertRaisesRegex(ValueError, "already exists.*bump SDK version"):
                self.plan(environment(GITHUB_RUN_ATTEMPT=attempt), manual=True, exists=True)

    def test_manual_new_version_builds_and_publishes(self):
        self.assertEqual(self.plan(environment(), manual=True),
                         {"build": True, "publish": True, "version": VERSION})

    def test_automatic_unchanged_existing_version_noops_before_builds(self):
        result = self.plan(exists=True, same=True)
        self.assertFalse(result["build"])
        self.assertFalse(result["publish"])

    def test_automatic_changed_runtime_without_bump_fails_early(self):
        with self.assertRaisesRegex(ValueError, "bump SDK version"):
            self.plan(exists=True, changed=True, same=True)
        self.assertTrue(self.plan(changed=True, same=False)["publish"])

    def test_bumping_to_another_published_version_and_whole_rerun_fail_closed(self):
        for attempt in ("1", "2"):
            env = environment("push", GITHUB_RUN_ATTEMPT=attempt)
            for same in (False, True):
                with self.subTest(attempt=attempt, same=same), self.assertRaisesRegex(ValueError, "bump SDK version"):
                    self.plan(env, exists=True, changed=True, same=same)
            self.assertFalse(self.plan(env, exists=True, changed=False)["build"])

    def test_pr_tests_keep_building_but_reject_runtime_changes_with_used_version(self):
        env = environment("pull_request")
        for exists, changed, same in ((True, False, True), (False, True, True), (False, True, False)):
            with self.subTest(exists=exists, changed=changed, same=same):
                plan = self.plan(env, publish=False, exists=exists, changed=changed, same=same)
                self.assertTrue(plan["build"])
                self.assertFalse(plan["publish"])
        for same in (True, False):
            with self.subTest(same=same), self.assertRaisesRegex(ValueError, "bump SDK version"):
                self.plan(env, publish=False, exists=True, changed=True, same=same)

    def test_registry_error_never_emits_a_successful_plan(self):
        with patch.object(preflight, "publication_source", return_value=(True, True)), \
                patch.object(preflight, "version_exists", side_effect=urllib.error.URLError("offline")):
            with self.assertRaises(urllib.error.URLError):
                preflight.workflow_plan(ROOT, environment(), manual_event(), VERSION)

    def test_early_workflow_dag_guards_both_expensive_jobs_and_manual_publish(self):
        workflow = (ROOT / ".github/workflows/python-sdk.yml").read_text(encoding="utf-8")
        triggers = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:\n    inputs:\n      publish:", triggers)
        self.assertIn("type: boolean\n        default: false", triggers)
        self.assertIn("expected_sha:", triggers)
        self.assertIn("expected_version:", triggers)
        precheck = workflow.split("  preflight:\n", 1)[1].split("  wheels:\n", 1)[0]
        self.assertIn("fetch-depth: 0", precheck)
        self.assertIn("ref: ${{ github.sha }}", precheck)
        self.assertIn("python3 scripts/check-sdk-release.py --github-event", precheck)
        self.assertNotIn("id-token: write", precheck)
        self.assertNotIn("environment:", precheck)
        for job in ("wheels", "source"):
            block = workflow.split(f"  {job}:\n", 1)[1].split("    steps:\n", 1)[0]
            self.assertIn("needs: preflight", block)
            self.assertIn("if: needs.preflight.outputs.build == 'true'", block)
        plan = workflow.split("  plan-publish:\n", 1)[1].split("  publish:\n", 1)[0]
        self.assertIn("needs.preflight.outputs.publish == 'true'", plan)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.publish", plan)
        self.assertIn("needs: [preflight, wheels, source, cache-portability]", plan)
        self.assertIn("scripts/plan-python-sdk-publish.py", plan)


class SourceComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "SDK fixture")
        self.git("config", "user.email", "sdk@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "commit.gpgsign", "false")
        hooks = self.root / "fixture-hooks"
        hooks.mkdir()
        self.git("config", "core.hooksPath", hooks.as_posix())
        self.write(preflight.MANIFEST, '[package]\nname = "kingfisher-python"\nversion = "1.5.0"\n')
        self.write("Cargo.toml", '[package]\nversion = "2.14.0"\n[workspace.dependencies]\nserde = "1"\n')
        self.write("pyproject.toml", '[project]\nrequires-python = ">=3.10"\n')
        self.write("Cargo.lock", self.lock())
        self.base = self.commit()

    def git(self, *args):
        return preflight.git(self.root, *args)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    @staticmethod
    def lock(cli="1.0.0", core="1.0.0"):
        return ('version = 4\n[[package]]\nname = "kingfisher-python"\nversion = "1.5.0"\n'
                'dependencies = ["kingfisher-core"]\n[[package]]\nname = "kingfisher-core"\n'
                f'version = "{core}"\n[[package]]\nname = "cli-only"\nversion = "{cli}"\n')

    def core_metadata_recovery(self):
        commits = []
        for version in ("1.0.4", "1.0.5"):
            self.write("crates/kingfisher-core/Cargo.toml",
                       f'[package]\nname = "kingfisher-core"\nversion = "{version}"\n')
            for name, path, package_version in (
                    ("kingfisher-bin", "Cargo.toml", "2.14.0"),
                    ("kingfisher-rules", "crates/kingfisher-rules/Cargo.toml", "2.0.0"),
                    ("kingfisher-scanner", "crates/kingfisher-scanner/Cargo.toml", "2.0.0")):
                self.write(path, f'[package]\nname = "{name}"\nversion = "{package_version}"\n'
                           '[dependencies]\n'
                           f'kingfisher-core = {{ version = "{version}", path = "core" }}\n')
            self.write("Cargo.lock", self.lock(core=version))
            inputs = {path: hashlib.sha256((self.root / path).read_bytes()).hexdigest()
                      for path in ("Cargo.toml", "Cargo.lock", "crates/kingfisher-rules/Cargo.toml")}
            self.write("crates/kingfisher-rules/generated/provenance.json", json.dumps({
                "generator_input_sha256": inputs, "artifact_sha256": {"bundle": "unchanged"},
            }))
            commits.append(self.commit())
        return commits

    def test_verified_core_metadata_recovery_does_not_require_sdk_release(self):
        base, head = self.core_metadata_recovery()
        self.assertFalse(preflight.runtime_changed(self.root, base, head))
        for kind, event in (("push", {"before": base}),
                            ("pull_request", {"pull_request": {"base": {"sha": base}}})):
            with self.subTest(event=kind), \
                    patch.object(preflight, "publication_source", return_value=(kind == "push", False)), \
                    patch.object(preflight, "version_exists", return_value=True):
                plan = preflight.workflow_plan(self.root, environment(kind, GITHUB_SHA=head), event, VERSION)
                self.assertEqual(plan, {"build": kind == "pull_request", "publish": False, "version": VERSION})

    def test_core_metadata_recovery_does_not_hide_runtime_changes(self):
        base, _ = self.core_metadata_recovery()
        self.write("crates/kingfisher-core/src/lib.rs", "// changed runtime implementation\n")
        self.assertTrue(preflight.runtime_changed(self.root, base, self.commit()))

    def test_core_metadata_recovery_does_not_hide_dependency_changes(self):
        base, _ = self.core_metadata_recovery()
        path = "crates/kingfisher-core/Cargo.toml"
        manifest = (self.root / path).read_text(encoding="utf-8")
        self.write(path, manifest + '\n[dependencies]\nnew-dependency = "1"\n')
        self.assertTrue(preflight.runtime_changed(self.root, base, self.commit()))

    def test_core_metadata_recovery_requires_matching_provenance(self):
        base, _ = self.core_metadata_recovery()
        path = "crates/kingfisher-rules/generated/provenance.json"
        provenance = json.loads((self.root / path).read_text(encoding="utf-8"))
        provenance["generator_input_sha256"]["crates/kingfisher-rules/Cargo.toml"] = "stale"
        self.write(path, json.dumps(provenance))
        self.assertTrue(preflight.runtime_changed(self.root, base, self.commit()))

    def test_meaningful_python_native_shared_and_rule_inputs(self):
        for path in ("python/kingfisher_sdk/inputs.py", "python/src/module.py",
                     "crates/kingfisher-python/src/lib.rs", "crates/kingfisher-core/src/lib.rs",
                     "crates/kingfisher-scanner/src/git.rs", "crates/kingfisher-rules/build.rs",
                     "crates/kingfisher-rules/build_support/betterleaks.rs",
                     "crates/kingfisher-rules/data/custom.yml",
                     "crates/kingfisher-rules/generated/builtin-rules.gz"):
            with self.subTest(path=path):
                base = self.git("rev-parse", "HEAD")
                self.write(path, "new runtime input\n")
                head = self.commit()
                self.assertTrue(preflight.runtime_changed(self.root, base, head))

    def test_docs_tests_examples_and_cli_changes_do_not_require_sdk_bump(self):
        for path in ("docs/PYPI.md", "python/README.md", "python/tests/test_scan.py",
                     "python/examples/scan.py", "src/main.rs", "crates/kingfisher-scanner/tests/git.rs",
                     "crates/kingfisher-core/README.md", "crates/kingfisher-rules/generated/provenance.json"):
            self.write(path, "not a runtime input\n")
        self.write("Cargo.toml", '[package]\nversion = "2.15.0"\n[workspace.dependencies]\nserde = "1"\n')
        self.write("Cargo.lock", self.lock(cli="2.0.0"))
        self.write("pyproject.toml", '[project]\nrequires-python = ">=3.10"\n[tool.pytest.ini_options]\naddopts = "-q"\n')
        self.assertFalse(preflight.runtime_changed(self.root, self.base, self.commit()))

    def test_lock_sdk_dependencies_and_workspace_dependencies_are_compared(self):
        self.write("Cargo.lock", self.lock(core="1.0.1"))
        head = self.commit()
        self.assertTrue(preflight.runtime_changed(self.root, self.base, head))
        self.write("Cargo.toml", '[package]\nversion = "2.14.0"\n[workspace.dependencies]\nserde = "2"\n')
        self.assertTrue(preflight.runtime_changed(self.root, head, self.commit()))

    def test_dependency_overrides_and_workspace_resolver_change_sdk_inputs(self):
        for extra in ('[patch.crates-io]\nserde = { path = "vendor/serde" }\n',
                      '[replace]\n"serde:1.0.0" = { path = "vendor/serde" }\n',
                      '[workspace]\nresolver = "3"\n'):
            with self.subTest(extra=extra):
                self.write("Cargo.toml", '[package]\nversion = "2.14.0"\n'
                           '[workspace.dependencies]\nserde = "1"\n' + extra)
                self.assertTrue(preflight.runtime_changed(self.root, self.base, self.commit()))

    def test_push_before_and_pr_base_compare_committed_versions_not_worktree(self):
        self.write("python/kingfisher_sdk/scan.py", "runtime change\n")
        head = self.commit()
        # A dirty local bump must not satisfy the committed base/head comparison.
        self.write(preflight.MANIFEST, '[package]\nversion = "9.9.9"\n')
        for kind, event in (("push", {"before": self.base}),
                            ("pull_request", {"pull_request": {"base": {"sha": self.base}}})):
            with self.subTest(kind=kind):
                self.assertEqual(preflight.compare_source(self.root, kind, event, head, VERSION), (True, True))

    def test_deleted_runtime_input_is_detected(self):
        self.write("python/kingfisher_sdk/old.py", "runtime\n")
        base = self.commit()
        self.git("rm", "python/kingfisher_sdk/old.py")
        self.assertTrue(preflight.runtime_changed(self.root, base, self.commit()))

    def test_unicode_and_newline_runtime_paths_trigger_existing_version_guard(self):
        # Git's default core.quotePath output must not hide non-ASCII SDK paths.
        paths = ["python/kingfisher_sdk/秘密.py", "python/kingfisher_sdk/space name.py"]
        if sys.platform != "win32":
            # Windows filenames cannot contain newlines; NUL parsing is portable.
            paths.append("python/kingfisher_sdk/new\nline.py")
        for path in paths:
            self.write(path, "runtime change\n")
        head = self.commit()
        self.assertTrue(preflight.runtime_changed(self.root, self.base, head))
        with patch.object(preflight, "publication_source", return_value=(False, False)), \
                patch.object(preflight, "version_exists", return_value=True):
            with self.assertRaisesRegex(ValueError, "bump SDK version"):
                preflight.workflow_plan(self.root, environment("pull_request"),
                                        {"pull_request": {"base": {"sha": self.base}}}, VERSION)

    def test_manifest_identity_stable_version_and_lock_match_are_required(self):
        self.assertEqual(preflight.sdk_version(self.root), VERSION)
        for package, version, message in (("wrong-name", VERSION, "named kingfisher-python"),
                                          ("kingfisher-python", "", "stable x.y.z"),
                                          ("kingfisher-python", "1.5.0rc1", "stable x.y.z"),
                                          ("kingfisher-python", "01.5.0", "stable x.y.z"),
                                          ("kingfisher-python", "1.4.2", "Cargo.lock SDK entry")):
            self.write(preflight.MANIFEST, f'[package]\nname = "{package}"\nversion = "{version}"\n')
            with self.subTest(package=package, version=version), self.assertRaisesRegex(ValueError, message):
                preflight.sdk_version(self.root)

    def test_worktree_version_cannot_replace_committed_source_version(self):
        with self.assertRaisesRegex(ValueError, "pinned committed source"):
            preflight.compare_source(self.root, "push", {"before": self.base}, self.base, "9.9.9")

    def test_missing_baseline_fails_closed(self):
        for event in ({}, {"before": "0" * 40}, {"before": "deadbeef"}):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, "committed push.before"):
                preflight.compare_source(self.root, "push", event, self.base, VERSION)


if __name__ == "__main__":
    unittest.main()
