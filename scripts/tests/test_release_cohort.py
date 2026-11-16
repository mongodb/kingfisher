"""Offline release-cohort contracts; intentionally standard-library-only.

This is not a YAML implementation. The small reader accepts the indented job
mappings and literal/flow ``needs`` lists used by these workflows, rejecting
unsupported dependency syntax. actionlint remains responsible for full YAML and
GitHub expression validation. The expression model below handles only the small
boolean subset used by the release barriers, without eval/exec or network calls.
"""
import ast
import fnmatch
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
BUILD_GATES = {
    "validate-release", "tests", "linux-x64", "linux-arm64", "windows",
    "macos-x64", "macos-arm64", "node-sdk", "python-sdk", "prepare-crates",
    "prepare-pypi",
}
PUBLISHERS = {
    "publish-node-sdk", "publish-python-sdk", "publish-crates",
    "publish-pypi", "publish-docker",
}


def field(body, name, indent=4):
    """Return a field's scalar or indented body, without neighboring fields."""
    matches = list(re.finditer(rf"(?m)^{' ' * indent}{re.escape(name)}:[ \t]*(.*)$", body))
    if not matches:
        return None
    if len(matches) != 1:
        raise AssertionError(f"Duplicate field: {name}")
    match = matches[0]
    value = match.group(1).split(" #", 1)[0].strip()
    continuation = []
    for line in body[match.end():].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        continuation.append(line.strip())
    if value in (">", ">-", "|", "|-"):
        return " ".join(continuation)
    return "\n".join(([value] if value else []) + continuation)


def dependencies(body):
    value = field(body, "needs")
    if value is None:
        return set()
    if value.startswith("[") and value.endswith("]"):
        items = value[1:-1].split(",")
    elif value.startswith("-"):
        items = [line.removeprefix("-").strip() for line in value.splitlines()]
    else:
        items = [value]
    result = set()
    for item in items:
        item = item.strip().strip("\"'")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", item) or item in result:
            raise AssertionError(f"Unsupported/duplicate dependency: {value!r}")
        result.add(item)
    return result


def permission_levels(body, indent=4):
    """Read the literal permission maps used here; None means inherit."""
    value = field(body, "permissions", indent)
    if value is None:
        return None
    if value == "{}":
        return {}
    levels = {"none": 0, "read": 1, "write": 2}
    result = {}
    for line in value.splitlines():
        line = line.split(" #", 1)[0].rstrip()
        match = re.fullmatch(r"([a-z-]+): (none|read|write)", line)
        if match is None or match[1] in result:
            raise AssertionError(f"Unsupported/duplicate permission: {line!r}")
        result[match[1]] = levels[match[2]]
    return result


def action_options(body, action):
    """Read with: options of the ordinary six-space workflow steps used here."""
    for step in re.split(r"(?m)^      - ", body):
        if re.search(rf"(?m)^\s*uses: {re.escape(action)}@", step):
            options = field(step, "with", indent=8)
            if options is None:
                raise AssertionError(f"Missing options for {action}")
            yield options


class Workflow:
    def __init__(self, text):
        self.text = text
        prefix, separator, body = text.partition("\njobs:\n")
        if not separator:
            raise AssertionError("Missing block-style jobs mapping")
        self.header = prefix
        matches = list(re.finditer(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*$", body))
        if len(matches) != len(re.findall(r"(?m)^  [^ #\s][^\n]*:", body)):
            raise AssertionError("Unsupported job declaration")
        self.jobs = {}
        for index, match in enumerate(matches):
            name = match.group(1)
            if name in self.jobs:
                raise AssertionError(f"Duplicate job: {name}")
            end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
            self.jobs[name] = body[match.end():end]
        if not self.jobs:
            raise AssertionError("Empty jobs mapping")
        self.needs = {name: dependencies(job) for name, job in self.jobs.items()}
        for name, needed in self.needs.items():
            if needed - self.jobs.keys():
                raise AssertionError(f"Unknown dependencies for {name}: {needed}")
        for name in self.jobs:
            self.ancestors(name)

    @classmethod
    def load(cls, name):
        return cls((WORKFLOWS / name).read_text(encoding="utf-8"))

    def ancestors(self, name, visiting=frozenset()):
        if name in visiting:
            raise AssertionError(f"Dependency cycle at {name}")
        result = set(self.needs[name])
        for dependency in self.needs[name]:
            result.update(self.ancestors(dependency, visiting | {name}))
        return result


def expression_value(expression, context, results, cancelled=False):
    """Evaluate a deliberately limited, fail-closed GitHub boolean expression."""
    expression = expression.strip().removeprefix("${{").removesuffix("}}").strip()
    token = r"'[^']*'|\"[^\"]*\"|(?:needs\.[\w-]+\.(?:result|outputs\.[\w-]+)|(?:github|inputs)\.[\w-]+)"
    expression = re.sub(token, lambda m: m[0] if m[0][0] in "'\"" else f"lookup({m[0]!r})", expression)
    expression = re.sub(r"!(?!=)", " not ", expression.replace("&&", " and ").replace("||", " or "))
    tree = ast.parse(expression.strip(), mode="eval")

    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool)):
            return node.value
        if isinstance(node, ast.Name) and node.id in ("true", "false"):
            return node.id == "true"
        if isinstance(node, ast.BoolOp):
            values = [bool(visit(value)) for value in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not visit(node.operand)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = visit(node.left), visit(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
            arguments = [visit(argument) for argument in node.args]
            if node.func.id == "lookup" and len(arguments) == 1:
                key = arguments[0]
                if key.startswith("needs.") and key.endswith(".result"):
                    return results[key.split(".")[1]]
                if key not in context:
                    raise AssertionError(f"Missing expression context: {key}")
                return context[key]
            if not arguments:
                if node.func.id == "always":
                    return True
                if node.func.id == "cancelled":
                    return cancelled
                if node.func.id == "success":
                    return all(value == "success" for value in results.values())
            if node.func.id == "startsWith" and len(arguments) == 2:
                return arguments[0].startswith(arguments[1])
        raise AssertionError(f"Unsupported expression node: {ast.dump(node)}")

    return bool(visit(tree))


def job_runs(workflow, name, context, results, cancelled=False):
    condition = field(workflow.jobs[name], "if") or "true"
    # GitHub implicitly adds success() unless an explicit status check is used.
    if not re.search(r"\b(?:always|cancelled|success|failure)\s*\(", condition):
        if any(results[dependency] != "success" for dependency in workflow.needs[name]):
            return False
        if cancelled:
            return False
    return expression_value(condition, context, results, cancelled)


class ReleaseCohortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = Workflow.load("release.yml")

    def context(self, cli=False, recovery=False):
        return {
            "github.repository": "mongodb/kingfisher",
            "github.event_name": "workflow_dispatch" if recovery else "push",
            "inputs.crates_only": recovery,
            "inputs.publish": False,
            "needs.validate-release.outputs.cli-release": str(cli).lower(),
            "needs.validate-release.outputs.publish": str(not recovery).lower(),
            "needs.node-sdk.outputs.publish": str(not recovery).lower(),
            "needs.python-sdk.outputs.publish": str(not recovery).lower(),
        }

    def results(self, cli=False, recovery=False):
        results = dict.fromkeys(self.release.jobs, "success")
        results["validate-crates-recovery"] = "success" if recovery else "skipped"
        results["release"] = "success" if cli else "skipped"
        return results

    def test_coordinator_runs_on_main_and_all_release_tag_families(self):
        triggers = self.release.header.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertRegex(triggers, r"branches:\s*\[main\]")
        self.assertRegex(triggers, r'tags:\s*\["v\*", "python-v\*", "npm-v\*"\]')
        self.assertNotRegex(triggers, r"(?m)^    paths(?:-ignore)?:")
        self.assertIn("workflow_dispatch:", triggers)

    def test_every_build_gate_is_mandatory_before_a_public_release(self):
        self.assertEqual(self.release.needs["release-ready"], BUILD_GATES)
        self.assertIsNone(field(self.release.jobs["release-ready"], "if"))
        self.assertEqual(field(self.release.jobs["release-ready"], "permissions"), "{}")
        self.assertIn("release-ready", self.release.needs["release"])
        self.assertNotIn("always()", field(self.release.jobs["release"], "if") or "")
        for name in BUILD_GATES | {"release-ready"}:
            with self.subTest(job=name):
                self.assertNotIn("continue-on-error:", self.release.jobs[name])
        for sink in PUBLISHERS | {"release"}:
            with self.subTest(sink=sink):
                ancestors = self.release.ancestors(sink)
                self.assertTrue(BUILD_GATES <= ancestors, ancestors)
                self.assertIn("release-ready", ancestors)
                if sink != "release":
                    self.assertIn("publish-ready", ancestors)

    def test_publication_capabilities_are_confined_to_gated_sinks(self):
        for name, body in self.release.jobs.items():
            permissions = field(body, "permissions") or ""
            writes_public_state = re.search(r"(?:contents|packages|attestations): write", permissions)
            publishes_archives = re.search(r"(?:phase: publish|gh release edit|publish-crates\.py[^\n]* --publish)", body)
            if writes_public_state or publishes_archives:
                self.assertIn(name, PUBLISHERS | {"release"}, name)
        for filename in ("node-sdk.yml", "python-sdk.yml", "pypi.yml"):
            workflow = Workflow.load(filename)
            for name, body in workflow.jobs.items():
                has_publication = re.search(r"(?:npm run publish:registry|pypa/gh-action-pypi-publish@)", body)
                if has_publication:
                    self.assertEqual(name, "publish", filename)
                    if filename == "node-sdk.yml":
                        self.assertIn("inputs.release_run_id != ''", field(body, "if"))
                        self.assertEqual(workflow.needs[name], {"cohort"})
                    else:
                        self.assertIn("inputs.phase == 'publish'", field(body, "if"))
        self.assertIn("environment: npm", Workflow.load("node-sdk.yml").jobs["publish"])
        self.assertIn("name: pypi-sdk", Workflow.load("python-sdk.yml").jobs["publish"])
        self.assertNotIn("id-token: write", Workflow.load("pypi.yml").jobs["build-wheels"])

    def test_each_failed_cancelled_or_skipped_build_blocks_every_public_sink(self):
        for cli, recovery in ((False, False), (True, False), (False, True)):
            context = self.context(cli, recovery)
            for dependency in BUILD_GATES:
                for status in ("failure", "cancelled", "skipped"):
                    with self.subTest(cli=cli, recovery=recovery, gate=dependency, status=status):
                        results = self.results(cli, recovery)
                        results[dependency] = status
                        self.assertFalse(job_runs(self.release, "release-ready", context, results))
                        results["release-ready"] = "skipped"
                        self.assertFalse(job_runs(self.release, "release", context, results))
                        results["release"] = "skipped"
                        self.assertFalse(job_runs(self.release, "publish-ready", context, results))
                        results["publish-ready"] = "skipped"
                        for sink in PUBLISHERS:
                            self.assertFalse(job_runs(self.release, sink, context, results), sink)

    def test_always_barrier_accepts_only_intentional_release_skip(self):
        for cli, recovery in ((False, False), (True, False), (False, True)):
            context, results = self.context(cli, recovery), self.results(cli, recovery)
            self.assertTrue(job_runs(self.release, "release-ready", context, results))
            self.assertTrue(job_runs(self.release, "publish-ready", context, results))
            self.assertFalse(job_runs(self.release, "publish-ready", context, results, cancelled=True))
            context["github.repository"] = "fork/kingfisher"
            self.assertFalse(job_runs(self.release, "publish-ready", context, results))
        context, results = self.context(cli=True), self.results(cli=True)
        for status in ("failure", "cancelled", "skipped"):
            results["release"] = status
            self.assertFalse(job_runs(self.release, "publish-ready", context, results))
        context, results = self.context(), self.results()
        results["release"] = "success"
        self.assertFalse(job_runs(self.release, "publish-ready", context, results))
        for barrier in ("release-ready", "publish-ready"):
            for status in ("failure", "cancelled", "skipped"):
                results = self.results()
                results[barrier] = status
                if barrier == "release-ready":
                    self.assertFalse(job_runs(self.release, "publish-ready", context, results))
                    results["publish-ready"] = "skipped"
                for sink in PUBLISHERS:
                    self.assertFalse(job_runs(self.release, sink, context, results), (barrier, status, sink))

    def test_recovery_revalidates_metadata_and_reruns_the_same_build_cohort(self):
        context, results = self.context(recovery=True), self.results(recovery=True)
        self.assertEqual(self.release.needs["prepare-crates"], {"validate-release", "validate-crates-recovery"})
        self.assertTrue(job_runs(self.release, "prepare-crates", context, results))
        self.assertTrue(job_runs(self.release, "publish-crates", context, results))
        for sink in PUBLISHERS - {"publish-crates"}:
            self.assertFalse(job_runs(self.release, sink, context, results), sink)
        for gate in ("validate-release", "validate-crates-recovery"):
            for status in ("failure", "cancelled", "skipped"):
                results = self.results(recovery=True)
                results[gate] = status
                self.assertFalse(job_runs(self.release, "prepare-crates", context, results))
        for status in ("failure", "cancelled", "skipped"):
            results = self.results(recovery=True)
            results["validate-crates-recovery"] = status
            self.assertFalse(job_runs(self.release, "publish-ready", context, results))
            self.assertFalse(job_runs(self.release, "publish-crates", context, results))
        body = self.release.jobs["publish-crates"]
        self.assertIn("scripts/check-crates-recovery.py", body)
        self.assertIn("name: crates-registry-staging", body)
        self.assertNotIn("cargo package", body)
        self.assertLess(body.index("scripts/check-crates-recovery.py"), body.index("rust-lang/crates-io-auth-action@"))

    def test_sdk_build_and_publish_are_separate_same_revision_calls(self):
        for sdk in ("node-sdk", "python-sdk"):
            with self.subTest(sdk=sdk):
                workflow = Workflow.load(f"{sdk}.yml")
                build = self.release.jobs[sdk]
                publish = self.release.jobs[f"publish-{sdk}"]
                self.assertEqual(field(build, "uses"), f"./.github/workflows/{sdk}.yml")
                self.assertIn("phase: build", field(build, "with"))
                if sdk == "node-sdk":
                    self.assertIsNone(field(publish, "uses"), "npm must keep its original top-level workflow identity")
                    self.assertIn("scripts/dispatch-node-sdk.py", publish)
                    self.assertIn("actions: write", field(publish, "permissions"))
                    self.assertNotIn("id-token: write", field(publish, "permissions"))
                    self.assertNotIn("contents: write", field(publish, "permissions"))
                else:
                    self.assertEqual(field(publish, "uses"), f"./.github/workflows/{sdk}.yml")
                    self.assertIn("phase: publish", field(publish, "with"))
                    self.assertIn("publish: true", field(publish, "with"))
                    self.assertIn("expected_sha:", field(publish, "with"))
                    self.assertIn("id-token: write", field(publish, "permissions"))
                self.assertIn("id-token: write", field(build, "permissions"))
                # Caller permissions are only a ceiling; build jobs never receive OIDC.
                self.assertNotIn("id-token: write", workflow.header)
                for name, job in workflow.jobs.items():
                    if name != "publish":
                        self.assertNotIn("id-token: write", job, name)
                        self.assertNotIn("environment:", job, name)
                publisher = workflow.jobs["publish"]
                self.assertIn("id-token: write", field(publisher, "permissions"))
                self.assertIn("inputs.publish", field(publisher, "if"))
                self.assertIn("ref: ${{ github.sha }}", publisher)
                if sdk == "node-sdk":
                    self.assertEqual(workflow.needs["publish"], {"cohort"})
                    self.assertIn("scripts/check-node-sdk-cohort.py", workflow.jobs["cohort"])
                    self.assertIn("scripts/check-node-sdk-cohort.py", publisher)
                    self.assertIn("inputs.release_run_id != ''", field(publisher, "if"))
                else:
                    self.assertFalse(workflow.needs["publish"], "publish must not depend on phase-skipped build jobs")
                    self.assertIn("inputs.phase == 'publish'", field(publisher, "if"))
                    self.assertIn("scripts/check-release-source.py", publisher)
        node = Workflow.load("node-sdk.yml")
        python = Workflow.load("python-sdk.yml")
        self.assertEqual(node.needs["verify"], {"package"})
        self.assertTrue({"source", "build", "package"} <= node.ancestors("verify"))
        self.assertTrue({"preflight", "wheels", "source", "cache-portability"} <= python.ancestors("plan-publish"))
        # Registry no-ops may skip publication, never the full coordinator build.
        self.assertIn("inputs.phase == 'build'", field(node.jobs["build"], "if"))
        for name in ("wheels", "source"):
            self.assertIn("inputs.phase == 'build'", field(python.jobs[name], "if"))

    def test_reusable_calls_allow_every_nested_job_permission_even_when_skipped(self):
        for name, caller in self.release.jobs.items():
            uses = field(caller, "uses")
            if uses is None:
                continue
            self.assertTrue(uses.startswith("./.github/workflows/"), uses)
            called = Workflow.load(Path(uses).name)
            allowed = permission_levels(caller)
            if allowed is None:
                allowed = permission_levels(self.release.header, indent=0)
            self.assertIsNotNone(allowed, name)
            # GitHub checks all nested jobs at startup, before evaluating if:.
            for nested_name, nested in called.jobs.items():
                requested = permission_levels(nested)
                if requested is None:
                    requested = permission_levels(called.header, indent=0)
                self.assertIsNotNone(requested, (uses, nested_name))
                for scope, level in requested.items():
                    with self.subTest(caller=name, nested=nested_name, permission=scope):
                        self.assertLessEqual(
                            level, allowed.get(scope, 0),
                            f"{name} must allow {uses}'s {nested_name} to request {scope}",
                        )

    def test_publishers_download_the_exact_tested_archives_without_rebuilding(self):
        cases = (
            ("node-sdk.yml", "package", "node-sdk-registry-staging", "javascript/release"),
            ("python-sdk.yml", "plan-publish", "python-sdk-pending", "dist"),
            ("pypi.yml", "build-wheels", "cli-pypi-staging", "dist-pypi"),
        )
        for filename, producer, artifact, destination in cases:
            with self.subTest(workflow=filename):
                workflow = Workflow.load(filename)
                self.assertIn("actions/upload-artifact@", workflow.jobs[producer])
                self.assertIn(f"name: {artifact}", workflow.jobs[producer])
                publish = workflow.jobs["publish"]
                self.assertIn("actions/download-artifact@", publish)
                if filename == "node-sdk.yml":
                    self.assertIn("artifact-ids: ${{ needs.cohort.outputs.artifact_id }}", publish)
                    self.assertIn("run-id: ${{ needs.cohort.outputs.run_id }}", publish)
                    self.assertIn("github-token: ${{ github.token }}", publish)
                    self.assertIn("artifact_id:\n        value: ${{ jobs.package.outputs.artifact_id }}", workflow.header)
                    self.assertIn("artifact_id: ${{ steps.staging.outputs.artifact-id }}", workflow.jobs[producer])
                else:
                    self.assertIn(f"name: {artifact}", publish)
                    self.assertNotRegex(publish, r"(?m)^\s+(?:run-id|github-token|repository):")
                self.assertIn(f"path: {destination}", publish)
                self.assertNotRegex(publish, r"(?:npm run (?:build|pack:release|prepare:)|maturin (?:build|sdist)|build-pypi-wheel\.sh|gh release download)")
        node = Workflow.load("node-sdk.yml")
        self.assertIn("name: node-sdk-registry-staging", node.jobs["verify"])
        self.assertIn("npm run test:package", node.jobs["verify"])
        python = Workflow.load("python-sdk.yml")
        self.assertIn("pattern: python-*", python.jobs["plan-publish"])
        pypi = Workflow.load("pypi.yml")
        self.assertIn("use_artifacts: true", self.release.jobs["prepare-pypi"])
        self.assertIn("use_artifacts: true", self.release.jobs["publish-pypi"])
        self.assertTrue({"linux-x64", "linux-arm64", "windows", "macos-x64", "macos-arm64"} <= self.release.needs["prepare-pypi"])
        self.assertIn("actions/download-artifact@", pypi.jobs["build-wheels"])
        self.assertIn("inputs.use_artifacts", pypi.jobs["build-wheels"])
        self.assertIn("name: crates-registry-staging", self.release.jobs["prepare-crates"])
        self.assertIn("cargo package --locked", self.release.jobs["prepare-crates"])
        self.assertNotIn("--no-verify", self.release.jobs["prepare-crates"])
        self.assertNotIn("--publish", self.release.jobs["prepare-crates"])

    def test_cli_wheel_download_patterns_match_actual_binary_artifact_names(self):
        binaries = ("linux-x64", "linux-arm64", "macos-x64", "macos-arm64", "windows")
        arches = re.findall(r"(?m)^\s+- arch: ([\w-]+)$", self.release.jobs["windows"])
        self.assertEqual(set(arches), {"x64", "arm64"})
        produced = {}
        for job in binaries:
            for options in action_options(self.release.jobs[job], "actions/upload-artifact"):
                template = field(options, "name", indent=0)
                path_template = field(options, "path", indent=0)
                self.assertIsNotNone(template)
                self.assertIsNotNone(path_template)
                for arch in arches if "${{ matrix.arch }}" in template else ("",):
                    name = template.replace("${{ matrix.arch }}", arch)
                    path = path_template.replace("${{ matrix.arch }}", arch)
                    self.assertNotIn("${{", name)
                    self.assertNotIn(name, produced)
                    produced[name] = path
        binary_names = {name for name, path in produced.items() if path.endswith((".tgz", ".zip"))}
        self.assertEqual(len(binary_names), 6)
        for arch in arches:
            # Artifact names are not the filenames contained inside the artifact.
            self.assertIn(f"kingfisher-windows-{arch}", binary_names)
            self.assertTrue(produced[f"kingfisher-windows-{arch}"].endswith(f"windows-{arch}.zip"))
        pypi = Workflow.load("pypi.yml")
        patterns = [field(options, "pattern", indent=0) for options in
                    action_options(pypi.jobs["build-wheels"], "actions/download-artifact")]
        self.assertTrue(patterns)
        matched = set()
        for pattern in patterns:
            self.assertIsNotNone(pattern)
            matches = {name for name in produced if fnmatch.fnmatchcase(name, pattern)}
            self.assertTrue(matches, f"Download pattern matches no produced artifact: {pattern}")
            matched.update(matches)
        self.assertEqual(matched, binary_names, "Download exactly the six binary artifacts, not deb/rpm packages")

    def test_standalone_sdk_cli_and_docker_runs_cannot_publish(self):
        for filename in ("node-sdk.yml", "python-sdk.yml", "pypi.yml", "release-docker.yml"):
            with self.subTest(workflow=filename):
                workflow = Workflow.load(filename)
                triggers = workflow.header.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
                call = field(triggers, "workflow_call", indent=2)
                self.assertRegex(call, r"(?s)phase:.*?default: build")
                dispatch = field(triggers, "workflow_dispatch", indent=2)
                self.assertNotIn("phase:", dispatch or "")
                if filename == "node-sdk.yml":
                    push = field(triggers, "push", indent=2)
                    self.assertIn("tags: ['npm-v*']", push)
                    self.assertIn("branches: [main, development]", push)
                    self.assertIn("release_run_id:", dispatch)
                    self.assertIn("default: false", dispatch)
                elif filename == "python-sdk.yml":
                    push = field(triggers, "push", indent=2)
                    self.assertNotIn("tags:", push or "")
                    self.assertNotRegex(push or "", r"\bmain\b")
                    self.assertNotIn("publish:", dispatch or "")
                if "publish" in workflow.jobs:
                    for event in ("pull_request", "workflow_dispatch", "push"):
                        context = {
                            "inputs.phase": "", "inputs.publish": False, "inputs.release_run_id": "",
                            "github.repository": "mongodb/kingfisher", "github.event_name": event,
                            "github.ref": "refs/tags/v1.2.3",
                        }
                        prerequisites = {name: "success" for name in workflow.needs["publish"]}
                        self.assertFalse(job_runs(workflow, "publish", context, prerequisites), event)
                else:
                    docker = workflow.jobs["build-and-push"]
                    # The standalone Docker route may still build, but its push
                    # and credentials must be restricted to the coordinator phase.
                    self.assertIn("inputs.phase == 'publish'", docker)
                    self.assertRegex(docker, r"docker/login-action@[^\n]+\n\s+if: inputs.phase == 'publish'")
                    push = field(docker, "push", indent=8)
                    self.assertIsNotNone(push)
                    for phase in ("", "build", "publish"):
                        self.assertEqual(expression_value(push, {"inputs.phase": phase}, {}), phase == "publish")
                    self.assertFalse(job_runs(workflow, "build-and-push", {
                        "inputs.phase": "publish", "github.repository": "fork/kingfisher",
                        "github.ref": "refs/tags/v1.2.3",
                    }, {}))
        self.assertIn("phase: publish", field(self.release.jobs["publish-docker"], "with"))


class ReleaseReaderTests(unittest.TestCase):
    def test_flow_block_scalar_dependencies_and_folded_conditions(self):
        self.assertEqual(dependencies("    needs: [a, 'b']\n"), {"a", "b"})
        self.assertEqual(dependencies("    needs:\n      - a\n      - b\n    runs-on: x\n"), {"a", "b"})
        self.assertEqual(dependencies("    needs: a\n"), {"a"})
        self.assertEqual(field("    if: >-\n      always() &&\n      !cancelled()\n    runs-on: x\n", "if"), "always() && !cancelled()")

    def test_permission_maps_distinguish_inheritance_from_explicit_denial(self):
        self.assertIsNone(permission_levels("    runs-on: x\n"))
        self.assertEqual(permission_levels("    permissions: {}\n"), {})
        self.assertEqual(
            permission_levels("permissions:\n  contents: read\n", indent=0),
            {"contents": 1},
        )
        self.assertEqual(
            permission_levels("    permissions:\n      actions: none\n      id-token: write\n"),
            {"actions": 0, "id-token": 2},
        )
        self.assertEqual(
            permission_levels("    permissions:\n      packages: write    # push to ghcr.io\n"),
            {"packages": 2},
        )
        for value in ("read-all", "contents: unknown", "contents: read\n      contents: write"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                permission_levels(f"    permissions:\n      {value}\n")

    def test_unknown_dynamic_duplicate_and_cyclic_dependencies_fail_closed(self):
        for value in ("${{ inputs.jobs }}", "*shared", "[a, a]", "[a,]"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                dependencies(f"    needs: {value}\n")
        for body in (
            "  a:\n    needs: missing\n",
            "  a:\n    needs: b\n  b:\n    needs: a\n",
            "  a:\n    runs-on: x\n  a:\n    runs-on: y\n",
        ):
            with self.subTest(body=body), self.assertRaises(AssertionError):
                Workflow("name: fixture\njobs:\n" + body)
        with self.assertRaises(AssertionError):
            expression_value("contains('unsafe', 'syntax')", {}, {})

    def test_implicit_success_and_explicit_always_have_different_skip_semantics(self):
        workflow = Workflow("name: fixture\njobs:\n  a:\n    runs-on: x\n  safe:\n    needs: a\n    if: true\n  bypass:\n    needs: a\n    if: always()\n")
        for status in ("failure", "cancelled", "skipped"):
            results = {"a": status}
            self.assertFalse(job_runs(workflow, "safe", {}, results))
            self.assertTrue(job_runs(workflow, "bypass", {}, results))


if __name__ == "__main__":
    unittest.main()
