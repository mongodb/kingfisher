"""Central release source authorization, without builds or network mutations."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_source", ROOT / "scripts/check-release-source.py")
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
HEAD, MAIN = "a" * 40, "b" * 40
VERSIONS = {"cli": "2.14.0", "python": "1.5.0", "npm": "1.0.2"}


def environment(**updates):
    return {"GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": source.UPSTREAM,
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": HEAD, **updates}


def manual(**updates):
    return {"inputs": {"publish": "true", "expected_sha": HEAD,
                       "expected_version": VERSIONS["python"], **updates}}


class SourceTests(unittest.TestCase):
    def plan(self, env=None, event=None, main=MAIN, checkout=HEAD, failure=None):
        def git(_root, *args):
            if failure == args[0]:
                raise subprocess.CalledProcessError(1, ["git", *args])
            if args == ("rev-parse", "HEAD"):
                return checkout
            if args == ("rev-parse", "refs/remotes/origin/main"):
                return main
            if args[0] == "show":
                path = args[1].split(":", 1)[1]
                kind = next(kind for kind, (manifest, _) in source.MANIFESTS.items() if manifest == path)
                package = {"name": source.MANIFESTS[kind][1], "version": VERSIONS[kind]}
                return json.dumps(package) if kind == "npm" else (
                    f'[package]\nname = "{package["name"]}"\nversion = "{package["version"]}"\n')
            return ""
        with patch.object(source, "git", side_effect=git) as command:
            result = source.source_plan(ROOT, env or environment(), event or {})
        return result, [call.args[1:] for call in command.call_args_list]

    def test_main_and_all_exact_release_tags_authorize_all_sdk_routes(self):
        refs = ["refs/heads/main", *(source.PREFIXES[kind] + version for kind, version in VERSIONS.items())]
        for ref in refs:
            with self.subTest(ref=ref):
                plan, calls = self.plan(environment(GITHUB_REF=ref))
                self.assertEqual(plan, {"tag": "v2.14.0", "publish": True,
                                       "cli-release": ref == "refs/tags/v2.14.0"})
                self.assertIn(("fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"), calls)
                self.assertIn(("merge-base", "--is-ancestor", HEAD, MAIN), calls)
                self.assertFalse(any(call[0] in {"push", "tag", "commit", "checkout"} for call in calls))

    def test_pin_and_supported_tag_mismatches_fail_closed(self):
        for sha in ("", HEAD[:7], "0" * 40, MAIN):
            with self.subTest(sha=sha), self.assertRaisesRegex(ValueError, "pinned GITHUB_SHA"):
                self.plan(environment(GITHUB_SHA=sha))
        for prefix in source.PREFIXES.values():
            for suffix in ("9.9.9", "1.2.3-rc.1", "1.2.3+build", "01.2.3", "1.2", ""):
                with self.subTest(prefix=prefix, suffix=suffix), self.assertRaisesRegex(ValueError, "tag"):
                    self.plan(environment(GITHUB_REF=prefix + suffix))

    def test_guarded_manual_publish_requires_current_main_and_python_version(self):
        env = environment(GITHUB_EVENT_NAME="workflow_dispatch")
        plan, _ = self.plan(env, manual(), main=HEAD)
        self.assertEqual(plan, {"tag": "v2.14.0", "cli-release": False, "publish": True})
        invalid = [(manual(expected_sha=MAIN), "expected_sha"),
                   (manual(expected_sha=HEAD[:7]), "expected_sha"),
                   (manual(expected_version="1.0.0"), "expected_version"),
                   (manual(expected_version=""), "expected_version")]
        for event, message in invalid:
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, message):
                self.plan(env, event, main=HEAD)
        with self.assertRaisesRegex(ValueError, "current upstream main SHA"):
            self.plan(env, manual())
        with self.assertRaisesRegex(ValueError, "refs/heads/main"):
            self.plan(environment(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF="refs/tags/v2.14.0"), manual())
        with self.assertRaisesRegex(ValueError, "upstream"):
            self.plan(environment(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY="fork/repo"), manual())

    def test_existing_cli_tag_manual_completion_keeps_default_dispatch_entry_point(self):
        env = environment(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF="refs/tags/v2.14.0")
        for event in ({}, {"inputs": {}}, {"inputs": {"publish": False}}, {"inputs": {"publish": "false"}}):
            with self.subTest(event=event):
                plan, calls = self.plan(env, event)
                self.assertEqual(plan, {"tag": "v2.14.0", "cli-release": True, "publish": True})
                self.assertIn(("fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"), calls)
                self.assertIn(("merge-base", "--is-ancestor", HEAD, MAIN), calls)
        for change in ({"GITHUB_SHA": MAIN}, {"GITHUB_SHA": HEAD[:7]}, {"GITHUB_REF": "refs/tags/v9.9.9"},
                       {"GITHUB_REF": "refs/tags/v2.14.0-rc.1"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.plan({**env, **change})
        for failure in ("fetch", "merge-base"):
            with self.subTest(failure=failure), self.assertRaises(subprocess.CalledProcessError):
                self.plan(env, failure=failure)
        plan, _ = self.plan({**env, "GITHUB_REPOSITORY": "fork/kingfisher"})
        self.assertFalse(plan["publish"])
        for ref in ("refs/heads/main", "refs/tags/python-v1.5.0", "refs/tags/npm-v1.0.2"):
            with self.subTest(ref=ref):
                plan, calls = self.plan({**env, "GITHUB_REF": ref})
                self.assertFalse(plan["publish"])
                self.assertFalse(plan["cli-release"])
                self.assertFalse(any(call[0] == "fetch" for call in calls))

    def test_fork_pr_development_and_default_dispatch_are_build_only(self):
        for env, event in ((environment(GITHUB_REPOSITORY="fork/kingfisher"), {}),
                           (environment(GITHUB_EVENT_NAME="pull_request"), {}),
                           (environment(GITHUB_REF="refs/heads/development"), {}),
                           (environment(GITHUB_EVENT_NAME="workflow_dispatch"), {}),
                           (environment(GITHUB_EVENT_NAME="workflow_dispatch"), manual(publish="false")),
                           (environment(GITHUB_REF="refs/tags/unrelated"), {})):
            with self.subTest(env=env, event=event):
                plan, calls = self.plan(env, event)
                self.assertFalse(plan["publish"])
                self.assertFalse(plan["cli-release"])
                self.assertFalse(any(call[0] == "fetch" for call in calls))

    def test_npm_prerelease_and_build_tags_preserve_existing_semver_policy(self):
        for version in ("0.2.0-rc.1", "1.2.3+build.5", "2.0.0-beta.2+sha.abc"):
            with self.subTest(version=version), patch.dict(VERSIONS, {"npm": version}):
                plan, _ = self.plan(environment(GITHUB_REF=f"refs/tags/npm-v{version}"))
                self.assertTrue(plan["publish"])
                self.assertFalse(plan["cli-release"])

    def test_crates_recovery_pins_current_main_without_authorizing_sdk_publication(self):
        env = environment(GITHUB_EVENT_NAME="workflow_dispatch")
        for value in (True, "true"):
            event = {"inputs": {"crates_only": value, "expected_sha": HEAD}}
            plan, calls = self.plan(env, event, main=HEAD)
            self.assertFalse(plan["publish"])
            self.assertFalse(plan["cli-release"])
            self.assertTrue(any(call[0] == "fetch" for call in calls))
            with self.assertRaisesRegex(ValueError, "current upstream main SHA"):
                self.plan(env, event)
            with self.assertRaisesRegex(ValueError, "expected_sha"):
                self.plan(env, {"inputs": {"crates_only": value}}, main=HEAD)

    def test_sdk_recovery_pins_main_without_authorizing_ordinary_publishers(self):
        env = environment(GITHUB_EVENT_NAME="workflow_dispatch")
        for value in (True, "true"):
            for publish in (True, "true", False, "false"):
                with self.subTest(sdk_only=value, publish=publish):
                    event = manual(sdk_only=value, publish=publish)
                    plan, calls = self.plan(env, event, main=HEAD)
                    self.assertFalse(plan["publish"])
                    self.assertFalse(plan["cli-release"])
                    self.assertIn(("fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"), calls)
                    with self.assertRaisesRegex(ValueError, "current upstream main SHA"):
                        self.plan(env, event)
                    with self.assertRaisesRegex(ValueError, "expected_sha"):
                        self.plan(env, {"inputs": {"sdk_only": value}}, main=HEAD)
        with self.assertRaisesRegex(ValueError, "refs/heads/main"):
            self.plan({**env, "GITHUB_REF": "refs/tags/v2.14.0"}, manual(sdk_only=True), main=HEAD)

    def test_fetch_ancestry_and_invalid_main_fail_closed(self):
        for failure in ("fetch", "merge-base"):
            with self.subTest(failure=failure), self.assertRaises(subprocess.CalledProcessError):
                self.plan(failure=failure)
        with self.assertRaisesRegex(ValueError, "upstream main SHA"):
            self.plan(main="")

    def test_outputs_are_emitted_only_after_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            event, output = Path(temporary) / "event.json", Path(temporary) / "outputs"
            event.write_text("{}", encoding="utf-8")
            env = environment(GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(output))
            plan = {"tag": "v2.14.0", "cli-release": True, "publish": True}
            with patch.dict(os.environ, env, clear=True), patch.object(source, "source_plan", return_value=plan), \
                    patch("builtins.print"):
                self.assertEqual(source.main(["--github-event"]), 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "tag=v2.14.0\ncli-release=true\npublish=true\n")
            with patch.dict(os.environ, env, clear=True), patch.object(source, "source_plan", side_effect=ValueError("bad")):
                with self.assertRaises(ValueError):
                    source.main([])
            self.assertEqual(output.read_text(encoding="utf-8"), "tag=v2.14.0\ncli-release=true\npublish=true\n")


class RealGitSourceTests(unittest.TestCase):
    def test_fresh_fetch_proves_merged_source_and_rejects_unmerged_or_stale_manual(self):
        with tempfile.TemporaryDirectory(prefix="release source ") as temporary, patch.dict(
                os.environ, {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_COUNT": "0"}):
            root = Path(temporary) / "source checkout"
            root.mkdir()
            def git(*args):
                return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                                      text=True, encoding="utf-8").stdout.strip()
            git("init", "-b", "main")
            for key, value in (("user.name", "Release Source Tests"), ("user.email", "release@example.com"),
                               ("commit.gpgsign", "false"), ("tag.gpgsign", "false"), ("core.autocrlf", "false")):
                git("config", key, value)
            for kind, (path, name) in source.MANIFESTS.items():
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                package = {"name": name, "version": VERSIONS[kind]}
                file.write_text(json.dumps(package) if kind == "npm" else (
                    f'[package]\nname = "{name}"\nversion = "{VERSIONS[kind]}"\n'), encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "prepared versions")
            head = git("rev-parse", "HEAD")
            remote = Path(temporary) / "upstream repository.git"
            git("clone", "--bare", root.as_posix(), remote.as_posix())
            git("remote", "add", "origin", remote.as_posix())
            env = environment(GITHUB_SHA=head, GITHUB_REF="refs/tags/python-v1.5.0")
            self.assertTrue(source.source_plan(root, env, {})["publish"])
            cli_dispatch = environment(GITHUB_SHA=head, GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF="refs/tags/v2.14.0")
            self.assertTrue(source.source_plan(root, cli_dispatch, {})["cli-release"])
            dispatch = environment(GITHUB_SHA=head, GITHUB_EVENT_NAME="workflow_dispatch")
            event = manual(expected_sha=head)
            self.assertTrue(source.source_plan(root, dispatch, event)["publish"])
            # An unmerged commit cannot authorize a supported tag.
            git("commit", "--allow-empty", "-m", "unmerged source")
            unmerged = git("rev-parse", "HEAD")
            with self.assertRaises(subprocess.CalledProcessError):
                source.source_plan(root, {**env, "GITHUB_SHA": unmerged}, {})
            with self.assertRaises(subprocess.CalledProcessError):
                source.source_plan(root, {**cli_dispatch, "GITHUB_SHA": unmerged}, {})
            git("push", "origin", "main")
            # A previously merged checkout is valid for a tag, not a manual retry
            # after main advances. No tag or remote mutation occurs in the helper.
            git("checkout", "--detach", head)
            self.assertTrue(source.source_plan(root, env, {})["publish"])
            self.assertTrue(source.source_plan(root, cli_dispatch, {})["cli-release"])
            with self.assertRaisesRegex(ValueError, "current upstream main SHA"):
                source.source_plan(root, dispatch, event)


if __name__ == "__main__":
    unittest.main()
