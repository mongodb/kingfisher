"""Offline npm cross-run publication authorization; every remote write is mocked."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]


def helper(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cohort = helper("check-node-sdk-cohort")
dispatcher = helper("dispatch-node-sdk")
HEAD, MAIN, TAG_OBJECT = "a" * 40, "b" * 40, "c" * 40
VERSION = "1.0.2"
NPM_REF = "refs/tags/npm-v1.0.2"
REPOSITORY = {"full_name": cohort.UPSTREAM, "id": 42}


def parent_environment(ref="refs/heads/main", event="push", **updates):
    return {"GITHUB_REPOSITORY": cohort.UPSTREAM, "GITHUB_SHA": HEAD,
            "GITHUB_REF": ref, "GITHUB_EVENT_NAME": event,
            "GITHUB_WORKFLOW_REF": f"{cohort.UPSTREAM}/{cohort.RELEASE_WORKFLOW}@{ref}",
            "GITHUB_RUN_ID": "71", "GITHUB_RUN_ATTEMPT": "2", "GH_TOKEN": "mock-token",
            "NPM_VERSION": VERSION, "NPM_ARTIFACT_ID": "222", **updates}


def child_environment(**updates):
    return {**parent_environment(NPM_REF, "workflow_dispatch"),
            "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": f"{cohort.UPSTREAM}/{cohort.NODE_WORKFLOW}@{NPM_REF}", **updates}


def parent_event(**inputs):
    return {"repository": dict(REPOSITORY), "before": MAIN, "inputs": inputs}


def child_event(**updates):
    return parent_event(**{"publish": "true", "release_run_id": "71", "release_run_attempt": "2",
                           "expected_sha": HEAD, "artifact_id": "222", **updates})


def git_result(_root, *args):
    if args == ("rev-parse", "HEAD"):
        return HEAD
    if args == ("rev-parse", "refs/remotes/origin/main"):
        return MAIN
    if args[0] == "show":
        path = args[1].split(":", 1)[1]
        if path == "javascript/package.json":
            return json.dumps({"name": "kingfisher-secret-scanner", "version": VERSION})
        if path == "Cargo.toml":
            return '[package]\nname = "kingfisher-bin"\nversion = "2.14.0"\n'
        if path == "crates/kingfisher-python/Cargo.toml":
            return '[package]\nname = "kingfisher-python"\nversion = "1.5.0"\n'
        raise AssertionError(f"Unexpected committed manifest: {path}")
    if args[0] in {"fetch", "merge-base"}:
        return ""
    raise AssertionError(f"Unexpected git operation: {args}")


class GitHub:
    def __init__(self):
        self.workflow = {"id": 17, "path": cohort.RELEASE_WORKFLOW}
        self.run = {"id": 71, "run_attempt": 2, "workflow_id": 17,
                    "path": cohort.RELEASE_WORKFLOW, "repository": dict(REPOSITORY),
                    "head_repository": dict(REPOSITORY), "head_sha": HEAD,
                    "head_branch": "main", "event": "push", "status": "in_progress", "conclusion": None}
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in cohort.GATE_JOBS] + [
                         {"name": cohort.DISPATCH_JOB, "status": "in_progress", "conclusion": None}]
        self.artifact = {"id": 222, "name": cohort.ARTIFACT_NAME, "expired": False,
                         "digest": "sha256:" + "d" * 64,
                         "workflow_run": {"id": 71, "head_sha": HEAD,
                                          "repository_id": 42, "head_repository_id": 42}}
        self.tag = {"ref": NPM_REF, "object": {"type": "commit", "sha": HEAD}}
        self.annotated = {}
        self.tag_reads = []
        self.calls = []
        self.history = {}

    def __call__(self, path, token):
        self.calls.append((path, token))
        prefix = f"/repos/{cohort.UPSTREAM}"
        if path == f"{prefix}/actions/workflows/release.yml":
            result = self.workflow
        elif path == f"{prefix}/actions/runs/71":
            result = self.run
        elif path.startswith(f"{prefix}/actions/runs/71/attempts/") and "/jobs?" in path:
            page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0])
            attempt = int(path.split("/attempts/", 1)[1].split("/", 1)[0])
            jobs = self.jobs if attempt == self.run["run_attempt"] else self.history.get(attempt, [])
            result = {"jobs": jobs[(page - 1) * 100:page * 100]}
        elif path == f"{prefix}/actions/artifacts/222":
            result = self.artifact
        elif path == f"{prefix}/git/ref/tags/npm-v1.0.2":
            result = self.tag_reads.pop(0) if self.tag_reads else self.tag
            if result is None:
                raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)
        elif path.startswith(f"{prefix}/git/tags/"):
            result = self.annotated[path.rsplit("/", 1)[1]]
        else:
            raise AssertionError(f"Unexpected GitHub request: {path}")
        return copy.deepcopy(result)


class CohortTests(unittest.TestCase):
    def setUp(self):
        self.api = GitHub()
        self.git = self.enterContext(patch.object(cohort.source, "git", side_effect=git_result))

    def validate(self, env=None, event=None):
        return cohort.validate_cohort(ROOT, env or child_environment(), event or child_event(), api=self.api)

    def test_running_parent_allows_child_without_waiting_for_parent_completion(self):
        result = self.validate()
        self.assertEqual(result, {"run_id": "71", "artifact_id": "222", "artifact_digest": "sha256:" + "d" * 64})
        calls = [call.args[1:] for call in self.git.call_args_list]
        self.assertIn(("fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"), calls)
        self.assertIn(("merge-base", "--is-ancestor", HEAD, MAIN), calls)
        self.assertFalse(any(call[0] in {"push", "tag", "update-ref", "checkout"} for call in calls))

    def test_completed_successful_parent_and_dispatcher_are_valid(self):
        self.api.run.update(status="completed", conclusion="success")
        self.api.jobs[-1].update(status="completed", conclusion="success")
        self.validate()

    def test_false_or_absent_publish_never_authorizes(self):
        for publish in (False, "false", "TRUE", "1", None, 1):
            with self.subTest(publish=publish), self.assertRaisesRegex(ValueError, "authorized upstream"):
                self.validate(event=child_event(publish=publish))

    def test_wrong_parent_workflow_repository_sha_event_or_attempt_rejected(self):
        invalid = [("id", 72), ("run_attempt", 1), ("workflow_id", 18), ("path", cohort.NODE_WORKFLOW),
                   ("head_sha", MAIN), ("event", "pull_request"),
                   ("repository", {"id": 99, "full_name": "fork/kingfisher"}),
                   ("head_repository", {"id": 99, "full_name": "fork/kingfisher"}),
                   ("head_repository", {"id": 99, "full_name": cohort.UPSTREAM})]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                self.api = GitHub()
                self.api.run[key] = value
                with self.assertRaisesRegex(ValueError, "exact upstream"):
                    self.validate()

    def test_wrong_workflow_registration_cannot_use_matching_path(self):
        self.api.workflow["id"] = 999
        with self.assertRaisesRegex(ValueError, "exact upstream"):
            self.validate()

    def test_failed_cancelled_timed_out_or_incomplete_parent_rejected(self):
        for status, conclusion in [("completed", "failure"), ("completed", "cancelled"),
                                   ("completed", "timed_out"), ("completed", None),
                                   ("in_progress", "failure"), ("queued", None)]:
            with self.subTest(status=status, conclusion=conclusion):
                self.api.run.update(status=status, conclusion=conclusion)
                with self.assertRaisesRegex(ValueError, "Producer release run"):
                    self.validate()

    def test_each_gate_requires_exact_unique_completed_success(self):
        for index in range(2):
            for status, conclusion in [("completed", "skipped"), ("completed", "failure"),
                                       ("completed", "cancelled"), ("in_progress", None)]:
                with self.subTest(index=index, status=status, conclusion=conclusion):
                    self.api = GitHub()
                    self.api.jobs[index].update(status=status, conclusion=conclusion)
                    with self.assertRaisesRegex(ValueError, "Producer gate"):
                        self.validate()
        self.api = GitHub()
        self.api.jobs.append(copy.deepcopy(self.api.jobs[0]))
        with self.assertRaisesRegex(ValueError, "exactly once"):
            self.validate()

    def test_dispatcher_must_not_be_absent_skipped_failed_or_duplicated(self):
        for jobs in [[], [{"name": cohort.DISPATCH_JOB, "status": "completed", "conclusion": "skipped"}],
                     [{"name": cohort.DISPATCH_JOB, "status": "completed", "conclusion": "failure"}],
                     [{"name": cohort.DISPATCH_JOB, "status": "queued", "conclusion": None}]]:
            with self.subTest(jobs=jobs):
                self.api = GitHub()
                self.api.jobs = self.api.jobs[:2] + jobs
                with self.assertRaisesRegex(ValueError, "npm dispatcher"):
                    self.validate()
        self.api = GitHub()
        self.api.jobs.append(copy.deepcopy(self.api.jobs[-1]))
        with self.assertRaisesRegex(ValueError, "npm dispatcher"):
            self.validate()

    def test_jobs_pagination_uses_only_requested_attempt(self):
        self.api.jobs = [{"name": f"build {index}", "status": "completed", "conclusion": "success"}
                         for index in range(100)] + self.api.jobs
        self.validate()
        paths = [path for path, _ in self.api.calls if "/jobs?" in path]
        self.assertEqual(len(paths), 2)
        self.assertTrue(all("/attempts/2/jobs?" in path for path in paths))
        self.assertTrue(paths[-1].endswith("page=2"))

    def test_failed_handoff_rerun_reuses_successful_prerequisites_from_prior_attempt(self):
        self.api.history[1] = copy.deepcopy(self.api.jobs)
        self.api.history[1][-1].update(status="completed", conclusion="failure")
        self.api.jobs = [self.api.jobs[-1]]
        self.validate()
        self.assertEqual(sum("/attempts/1/jobs?" in path for path, _ in self.api.calls), 1)

    def test_effective_gates_can_span_attempts_without_trusting_older_dispatcher(self):
        self.api.history[1] = copy.deepcopy(self.api.jobs[:1])
        self.api.jobs = self.api.jobs[1:]
        self.validate()
        self.api.history[1].append(self.api.jobs.pop())
        with self.assertRaisesRegex(ValueError, "npm dispatcher"):
            self.validate()

    def test_rerun_cannot_fall_back_past_a_present_non_success_or_duplicate_gate(self):
        for status, conclusion in [("completed", "failure"), ("completed", "skipped"),
                                   ("completed", "cancelled"), ("queued", None)]:
            with self.subTest(status=status, conclusion=conclusion):
                self.api = GitHub()
                self.api.history[1] = copy.deepcopy(self.api.jobs)
                self.api.jobs[0].update(status=status, conclusion=conclusion)
                with self.assertRaisesRegex(ValueError, "Producer gate"):
                    self.validate()
                self.assertFalse(any("/attempts/1/" in path for path, _ in self.api.calls))
        self.api = GitHub()
        self.api.history[1] = copy.deepcopy(self.api.jobs)
        self.api.jobs.append(copy.deepcopy(self.api.jobs[0]))
        with self.assertRaisesRegex(ValueError, "exactly once"):
            self.validate()

    def test_rerun_search_stops_at_newest_historical_failure(self):
        self.api.run["run_attempt"] = 3
        self.api.history[1] = copy.deepcopy(self.api.jobs)
        self.api.history[2] = copy.deepcopy(self.api.jobs[:2])
        self.api.history[2][0].update(conclusion="failure")
        self.api.jobs = [self.api.jobs[-1]]
        with self.assertRaisesRegex(ValueError, "Producer gate"):
            self.validate(event=child_event(release_run_attempt="3"))
        self.assertFalse(any("/attempts/1/" in path for path, _ in self.api.calls))

    def test_rerun_rejects_missing_gates_and_stale_authorization(self):
        self.api.jobs = [self.api.jobs[-1]]
        with self.assertRaisesRegex(ValueError, "Producer gate"):
            self.validate()
        self.api = GitHub()
        self.api.history[1] = [self.api.jobs.pop(1)]
        with self.assertRaisesRegex(ValueError, "authorization cannot predate"):
            self.validate()

    def test_attempt_metadata_cannot_claim_jobs_from_another_attempt(self):
        self.api.jobs[0]["run_attempt"] = 1
        with self.assertRaisesRegex(ValueError, "different run attempt"):
            self.validate()

    def test_own_workflow_ref_event_pin_and_checkout_must_match(self):
        for updates in [{"GITHUB_REPOSITORY": "fork/kingfisher"}, {"GITHUB_SHA": MAIN},
                        {"GITHUB_SHA": HEAD[:7]}, {"GITHUB_SHA": "0" * 40},
                        {"GITHUB_EVENT_NAME": "push"}, {"GITHUB_REF": "refs/heads/main"},
                        {"GITHUB_REF": "refs/tags/npm-v9.9.9"},
                        {"GITHUB_WORKFLOW_REF": f"{cohort.UPSTREAM}/{cohort.RELEASE_WORKFLOW}@{NPM_REF}"}]:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.validate(env=child_environment(**updates))
        with self.assertRaisesRegex(ValueError, "expected_sha"):
            self.validate(event=child_event(expected_sha=MAIN))

    def test_unmerged_source_fails_before_artifact_download(self):
        def fail_merge(root, *args):
            if args[0] == "merge-base":
                raise subprocess.CalledProcessError(1, ["git", *args])
            return git_result(root, *args)
        self.git.side_effect = fail_merge
        with self.assertRaises(subprocess.CalledProcessError):
            self.validate()
        self.assertEqual(self.api.calls, [])

    def test_positive_identifiers_reject_injection_zero_booleans_and_whitespace(self):
        for key in ("release_run_id", "release_run_attempt", "artifact_id"):
            for value in (None, True, 0, "0", "../71", "71\n", "-1", "1.0", "01"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.validate(event=child_event(**{key: value}))

    def test_wrong_artifact_id_name_owner_sha_expiry_or_digest_rejected(self):
        for key, value in [("id", 333), ("name", "other-staging"), ("expired", True),
                           ("expired", None), ("digest", "sha256:bad"), ("digest", "sha512:" + "d" * 128),
                           ("workflow_run", {"id": 72, "head_sha": HEAD}),
                           ("workflow_run", {"id": 71, "head_sha": MAIN}),
                           ("workflow_run", {"id": 71, "head_sha": HEAD, "repository_id": 99})]:
            with self.subTest(key=key, value=value):
                self.api = GitHub()
                self.api.artifact[key] = value
                with self.assertRaisesRegex(ValueError, "artifact"):
                    self.validate()

    def test_digest_is_optional_but_not_arbitrary_output_text(self):
        self.api.artifact.pop("digest")
        self.assertEqual(self.validate(), {"run_id": "71", "artifact_id": "222"})
        self.api.artifact["digest"] = "sha256:" + "d" * 64 + "\nother=untrusted"
        with self.assertRaisesRegex(ValueError, "digest"):
            self.validate()

    def test_missing_or_moved_remote_tag_fails_closed(self):
        for tag in (None, {"ref": NPM_REF, "object": {"type": "commit", "sha": MAIN}}):
            with self.subTest(tag=tag):
                self.api.tag = tag
                with self.assertRaisesRegex(ValueError, "current remote npm"):
                    self.validate()

    def test_annotated_tag_is_peeled_without_trusting_returned_urls(self):
        self.api.tag["object"] = {"type": "tag", "sha": TAG_OBJECT, "url": "https://untrusted.invalid/"}
        self.api.annotated[TAG_OBJECT] = {"sha": TAG_OBJECT, "object": {"type": "commit", "sha": HEAD}}
        self.validate()
        self.assertTrue(all(path.startswith(f"/repos/{cohort.UPSTREAM}/") for path, _ in self.api.calls))

    def test_malformed_cyclic_blob_or_wrong_ref_tags_rejected(self):
        for tag in [{"ref": NPM_REF + "-other", "object": {"type": "commit", "sha": HEAD}},
                    {"ref": NPM_REF, "object": {"type": "blob", "sha": HEAD}},
                    {"ref": NPM_REF, "object": {"type": "commit", "sha": "0" * 40}}]:
            with self.subTest(tag=tag):
                self.api.tag = tag
                with self.assertRaises(ValueError):
                    self.validate()
        self.api.tag = {"ref": NPM_REF, "object": {"type": "tag", "sha": TAG_OBJECT}}
        self.api.annotated[TAG_OBJECT] = {"sha": TAG_OBJECT, "object": {"type": "tag", "sha": TAG_OBJECT}}
        with self.assertRaisesRegex(ValueError, "cycles"):
            self.validate()

    def test_only_tag_ref_404_is_missing_other_http_errors_propagate(self):
        for code in (403, 429, 500):
            api = Mock(side_effect=urllib.error.HTTPError("url", code, "error", {}, None))
            with self.subTest(code=code), self.assertRaises(urllib.error.HTTPError):
                cohort.remote_tag_commit("npm-v1.0.2", "token", api=api)

    def test_outputs_are_written_only_after_validation(self):
        with tempfile.TemporaryDirectory(prefix="npm cohort ") as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(json.dumps(child_event()), encoding="utf-8")
            output = Path(temporary) / "outputs.txt"
            env = {**child_environment(), "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(output)}
            with patch.dict(os.environ, env, clear=True), patch.object(
                    cohort, "validate_cohort", return_value={"run_id": "71", "artifact_id": "222"}), patch("builtins.print"):
                self.assertEqual(cohort.main([]), 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "run_id=71\nartifact_id=222\n")
            with patch.dict(os.environ, env, clear=True), patch.object(
                    cohort, "validate_cohort", side_effect=ValueError("bad")), self.assertRaises(ValueError):
                cohort.main([])
            self.assertEqual(output.read_text(encoding="utf-8"), "run_id=71\nartifact_id=222\n")


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.api = GitHub()
        self.git = self.enterContext(patch.object(dispatcher.cohort.source, "git", side_effect=git_result))
        self.plan = self.enterContext(patch.object(dispatcher.node, "workflow_plan",
                                                  return_value={"publish": True, "version": VERSION}))
        self.runner = Mock(return_value=SimpleNamespace(stdout=json.dumps({"workflow_run_id": 101})))
        self.enterContext(patch("builtins.print"))

    def dispatch(self, env=None, event=None):
        return dispatcher.dispatch(ROOT, env or parent_environment(), event or parent_event(),
                                   api=self.api, runner=self.runner)

    def test_dispatch_uses_exact_existing_tag_payload_api_and_returned_run(self):
        result = self.dispatch()
        self.assertEqual(result, {"dispatched": True, "run_id": "101"})
        self.assertEqual(self.runner.call_count, 2)
        post, watch = self.runner.call_args_list
        self.assertIn("POST", post.args[0])
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", post.args[0])
        self.assertTrue(any(item.endswith("/workflows/node-sdk.yml/dispatches") for item in post.args[0]))
        self.assertEqual(json.loads(post.kwargs["input"]), {
            "ref": "npm-v1.0.2", "return_run_details": True,
            "inputs": {"publish": True, "release_run_id": "71", "release_run_attempt": "2",
                       "expected_sha": HEAD, "artifact_id": "222"}})
        self.assertEqual(watch.args[0], ["gh", "run", "watch", "101", "--repo", cohort.UPSTREAM,
                                        "--exit-status", "--interval", "30"])
        self.assertEqual(post.kwargs["env"]["GH_HOST"], "github.com")
        self.assertEqual(self.plan.call_args.args, (ROOT, parent_environment(), parent_event(), VERSION))

    def test_main_cli_and_python_skip_absent_or_other_sha_tag_without_any_write(self):
        for ref in ("refs/heads/main", "refs/tags/v2.14.0", "refs/tags/python-v1.5.0"):
            for tag in (None, {"ref": NPM_REF, "object": {"type": "commit", "sha": MAIN}}):
                with self.subTest(ref=ref, tag=tag):
                    self.api.tag = tag
                    self.api.run["head_branch"] = ref.removeprefix("refs/heads/").removeprefix("refs/tags/")
                    self.assertFalse(self.dispatch(env=parent_environment(ref))["dispatched"])
        self.runner.assert_not_called()
        self.plan.assert_not_called()

    def test_original_npm_tag_push_dispatches_same_sha(self):
        self.api.run["head_branch"] = "npm-v1.0.2"
        self.assertTrue(self.dispatch(env=parent_environment(NPM_REF))["dispatched"])

    def test_original_npm_tag_push_missing_or_moved_is_error(self):
        self.api.run["head_branch"] = "npm-v1.0.2"
        for tag in (None, {"ref": NPM_REF, "object": {"type": "commit", "sha": MAIN}}):
            with self.subTest(tag=tag):
                self.api.tag = tag
                with self.assertRaisesRegex(ValueError, "triggering npm tag"):
                    self.dispatch(env=parent_environment(NPM_REF))
        self.runner.assert_not_called()

    def test_tag_race_before_post_is_skip_for_main_but_error_for_own_tag(self):
        for ref in ("refs/heads/main", NPM_REF):
            with self.subTest(ref=ref):
                self.api = GitHub()
                self.api.run["head_branch"] = ref.removeprefix("refs/heads/").removeprefix("refs/tags/")
                self.api.tag_reads = [self.api.tag, {"ref": NPM_REF, "object": {"type": "commit", "sha": MAIN}}]
                if ref == NPM_REF:
                    with self.assertRaisesRegex(ValueError, "triggering npm tag"):
                        self.dispatch(env=parent_environment(ref))
                else:
                    self.assertFalse(self.dispatch(env=parent_environment(ref))["dispatched"])
        self.runner.assert_not_called()

    def test_concurrently_published_unchanged_version_is_noop(self):
        self.plan.return_value = {"publish": False, "version": VERSION}
        self.assertEqual(self.dispatch(), {"dispatched": False, "reason": "already-published"})
        self.runner.assert_not_called()

    def test_source_or_registry_drift_error_does_not_dispatch(self):
        self.plan.side_effect = ValueError("must bump SDK version")
        with self.assertRaisesRegex(ValueError, "bump SDK version"):
            self.dispatch()
        self.runner.assert_not_called()

    def test_fork_wrong_pin_version_or_workflow_never_dispatch(self):
        for updates in [{"GITHUB_REPOSITORY": "fork/kingfisher"}, {"GITHUB_SHA": MAIN},
                        {"GITHUB_SHA": "0" * 40}, {"NPM_VERSION": "9.9.9"},
                        {"GITHUB_WORKFLOW_REF": f"{cohort.UPSTREAM}/{cohort.NODE_WORKFLOW}@refs/heads/main"}]:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.dispatch(env=parent_environment(**updates))
        self.runner.assert_not_called()

    def test_bad_parent_gate_or_artifact_never_dispatch(self):
        for corruption in ("gate", "dispatcher", "artifact"):
            with self.subTest(corruption=corruption):
                self.api = GitHub()
                if corruption == "gate":
                    self.api.jobs[0]["conclusion"] = "failure"
                elif corruption == "dispatcher":
                    self.api.jobs[-1].update(status="completed", conclusion="skipped")
                else:
                    self.api.artifact["workflow_run"]["head_sha"] = MAIN
                with self.assertRaises(ValueError):
                    self.dispatch()
        self.runner.assert_not_called()

    def test_build_only_and_crates_recovery_never_authorize_npm(self):
        def current_main(root, *args):
            if args == ("rev-parse", "refs/remotes/origin/main"):
                return HEAD
            return git_result(root, *args)
        self.git.side_effect = current_main
        for inputs in ({}, {"publish": "false"}, {"crates_only": "true", "expected_sha": HEAD}):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(ValueError, "normal SDK"):
                self.dispatch(env=parent_environment(event="workflow_dispatch"), event=parent_event(**inputs))
        self.runner.assert_not_called()

    def test_guarded_manual_main_and_legacy_manual_cli_are_preserved(self):
        for ref, inputs in [("refs/heads/main", {"publish": "true", "expected_sha": HEAD,
                                                "expected_version": "1.5.0"}),
                            ("refs/tags/v2.14.0", {"publish": "false"})]:
            with self.subTest(ref=ref):
                self.api.run.update(event="workflow_dispatch", head_branch=ref.removeprefix(
                    "refs/heads/").removeprefix("refs/tags/"))
                def main(root, *args):
                    if args == ("rev-parse", "refs/remotes/origin/main") and ref == "refs/heads/main":
                        return HEAD
                    return git_result(root, *args)
                self.git.side_effect = main
                self.assertTrue(self.dispatch(env=parent_environment(ref, "workflow_dispatch"),
                                              event=parent_event(**inputs))["dispatched"])

    def test_missing_wrong_or_unsafe_dispatch_response_does_not_watch(self):
        for value in (None, 0, True, "../101", "101\n"):
            with self.subTest(value=value):
                self.runner.reset_mock()
                self.runner.return_value = SimpleNamespace(stdout=json.dumps({"workflow_run_id": value}))
                with self.assertRaisesRegex(ValueError, "workflow_run_id"):
                    self.dispatch()
                self.assertEqual(self.runner.call_count, 1)

    def test_dispatch_and_child_failures_propagate(self):
        for fail_watch in (False, True):
            with self.subTest(fail_watch=fail_watch):
                self.runner.side_effect = ([SimpleNamespace(stdout=json.dumps({"workflow_run_id": 101})),
                                             subprocess.CalledProcessError(1, ["gh", "run", "watch"])]
                                            if fail_watch else subprocess.CalledProcessError(1, ["gh", "api"]))
                with self.assertRaises(subprocess.CalledProcessError):
                    self.dispatch()


class GitHubTransportTests(unittest.TestCase):
    def test_metadata_uses_fixed_host_get_api_version_and_token(self):
        response = io.BytesIO(b'{"ok":true}')
        with patch.object(cohort.urllib.request, "urlopen", return_value=response) as get:
            self.assertEqual(cohort.github_json(f"/repos/{cohort.UPSTREAM}/actions/runs/71", "token"), {"ok": True})
        request = get.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertTrue(request.full_url.startswith("https://api.github.com/repos/mongodb/kingfisher/"))
        self.assertEqual(request.get_header("Authorization"), "Bearer token")
        self.assertEqual(request.get_header("X-github-api-version"), "2026-03-10")

    def test_external_paths_and_oversized_metadata_rejected(self):
        with patch.object(cohort.urllib.request, "urlopen") as get:
            with self.assertRaisesRegex(ValueError, "upstream"):
                cohort.github_json("https://untrusted.invalid/", "token")
            get.assert_not_called()
        with patch.object(cohort.urllib.request, "urlopen", return_value=io.BytesIO(b" " * (8 * 1024 * 1024 + 1))):
            with self.assertRaisesRegex(ValueError, "size limit"):
                cohort.github_json(f"/repos/{cohort.UPSTREAM}/actions/runs/71", "token")


if __name__ == "__main__":
    unittest.main()
