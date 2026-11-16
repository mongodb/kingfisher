#!/usr/bin/env python3
"""Compare full-history mirror clones; never time scanning or verification.

Build the production-code driver first:
  cargo build --locked --release --example git_clone
Run WAN comparisons (fresh destinations, alternating engine order):
  python3 scripts/benchmark-git-clone.py run --output target/clone-benchmark/run \
    --gix target/release/examples/git_clone --rounds 2
Verify existing clones, including every stored object and HEAD file:
  python3 scripts/benchmark-git-clone.py verify --output target/clone-benchmark/parity.json \
    --repo git=target/clone-benchmark/run/git-r1.git \
    --repo gix=target/clone-benchmark/run/gix-r1.git --fsck

The mirror scope is intentional: Kingfisher fetches refs/*, whereas ordinary
Git clones fetch fewer refs. No depth, filter, alternates, checkout, or local
hardlink shortcuts are used. Verification is outside measured clone time.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shutil
import statistics
import subprocess
import time
import urllib.parse

try:
    import resource
except ImportError:  # Windows still supports wall-clock timing and parity checks.
    resource = None


def isolated_env():
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("GIT_CONFIG_", "GIT_TRACE")) or key in {
            "GIT_CURL_VERBOSE", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
        }:
            env.pop(key, None)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_ATTR_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    return env


def git_command(git, *args):
    return [git, "-c", "credential.helper=", "-c", "gc.auto=0", *map(str, args)]


def git_output(git, repo, *args):
    return subprocess.check_output(git_command(git, "-C", repo, *args), env=isolated_env())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cpu_times():
    if resource is None:
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime, usage.ru_stime


def path_without_git(path, windows=None):
    """Remove Git from PATH for the native engine.

    Elsewhere PATH is emptied. On Windows, a MinGW-linked executable still needs
    system directories to load its runtime DLLs, so only directories that provide
    git.exe are dropped.
    """
    if not (os.name == "nt" if windows is None else windows):
        return ""
    return os.pathsep.join(entry for entry in path.split(os.pathsep)
                           if entry and not (pathlib.Path(entry) / "git.exe").exists())


def parse_repositories(values):
    """Split NAME=PATH arguments, rejecting malformed values with a usage error."""
    repositories = []
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise ValueError(f"--repo must be NAME=PATH, got {value!r}")
        repositories.append((name, path))
    return repositories


def run(args):
    engines = args.engines.split(",")
    if (not engines or len(set(engines)) != len(engines)
            or any(engine not in {"git", "gix"} for engine in engines)):
        raise ValueError("engines must be git,gix or a subset without duplicates")
    url = urllib.parse.urlsplit(args.url)
    if url.scheme not in {"http", "https"} or not url.hostname:
        raise ValueError("this benchmark requires an HTTP(S) URL; local clone shortcuts are not comparable")
    if url.username is not None or url.password is not None:
        raise ValueError("benchmark URLs must not contain credentials")
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    git = str(pathlib.Path(shutil.which("git") or "git").resolve(strict=True))
    gix = str(args.gix.resolve(strict=True))
    record = {
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "url": args.url, "scope": "full-history mirror, all advertised refs, no checkout",
        "platform": platform.platform(), "architecture": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "git_version": subprocess.check_output([git, "--version"], text=True).strip(),
        "gix_executable": gix,
        "gix_executable_sha256": file_sha256(pathlib.Path(gix)),
        "runs": [],
    }
    save(root / "results.json", record)
    for number in range(1, args.rounds + 1):
        order = engines if number % 2 else list(reversed(engines))
        for engine in order:
            name = f"{engine}-r{number}"
            destination = root / f"{name}.git"
            command = (git_command(git, "clone", "--mirror", "--quiet", args.url, destination)
                       if engine == "git" else [gix, "mirror", args.url, str(destination)])
            env = isolated_env()
            if engine == "gix":
                # Resolve the benchmark executable before removing Git from PATH.
                env["PATH"] = path_without_git(env.get("PATH", ""))
                env["KF_GIT_BINARY"] = "kingfisher-no-git-must-be-needed"
            before = cpu_times()
            start = time.perf_counter()
            print(f"START {name}: {destination}", flush=True)
            with open(root / f"{name}.stdout", "wb") as out, open(root / f"{name}.stderr", "wb") as err:
                process = subprocess.Popen(command, env=env, stdout=out, stderr=err)
                (root / "active.json").write_text(json.dumps({"engine": engine, "pid": process.pid,
                                                             "destination": str(destination)}))
                code = process.wait()
            elapsed = time.perf_counter() - start
            after = cpu_times()
            result = {"engine": engine, "round": number, "command": list(map(str, command)),
                      "destination": str(destination), "wall_seconds": elapsed, "exit_code": code}
            if before is not None:
                result.update(user_seconds=after[0] - before[0], system_seconds=after[1] - before[1])
            record["runs"].append(result)
            save(root / "results.json", record)
            print(json.dumps(result), flush=True)
            if code:
                raise RuntimeError(f"{name} failed; inspect its stderr log (exit {code})")
    record["medians_seconds"] = {
        engine: statistics.median(item["wall_seconds"] for item in record["runs"] if item["engine"] == engine)
        for engine in engines
    }
    save(root / "results.json", record)
    print(json.dumps(record["medians_seconds"], sort_keys=True), flush=True)


def inventory(git, name, repo, fsck, oracle_refs=None):
    repo = repo.resolve(strict=True)
    if git_output(git, repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise RuntimeError(f"{name} is shallow")
    if (repo / "objects/info/alternates").exists():
        raise RuntimeError(f"{name} has alternates")
    head = git_output(git, repo, "rev-parse", "HEAD").strip().decode("ascii")
    refs = {}
    for line in git_output(git, repo, "for-each-ref", "--format=%(refname) %(objectname)").splitlines():
        ref, oid = line.split()
        refs[ref.decode("utf-8")] = oid.decode("ascii")
    # Never normalize the oracle itself: an origin-namespaced ref may be a real
    # advertised source ref. Only discard additional same-OID aliases in candidates.
    aliases = 0
    if oracle_refs is not None:
        for ref in list(refs):
            prefix = "refs/remotes/origin/"
            if ref not in oracle_refs and ref.startswith(prefix):
                original = "refs/" + ref[len(prefix):]
                if oracle_refs.get(original) == refs[ref] and refs.get(original) == refs[ref]:
                    del refs[ref]
                    aliases += 1
    counts = collections.Counter()
    digest = hashlib.sha256()
    command = git_command(git, "-C", repo, "cat-file", "--batch-all-objects",
                          "--batch-check=%(objectname) %(objecttype) %(objectsize)")
    # Git emits unique objects sorted by OID unless --unordered is passed.
    with subprocess.Popen(command, env=isolated_env(), stdout=subprocess.PIPE) as process:
        for line in process.stdout:
            _, kind, _ = line.split()
            counts[kind.decode("ascii")] += 1
            digest.update(line)
        if process.wait():
            raise RuntimeError(f"{name}: object enumeration failed")
    reachable = git_output(git, repo, "rev-list", "--objects", "--all", "--no-object-names").splitlines()
    reachable.sort()
    reachable_digest = hashlib.sha256()
    for oid in reachable:
        reachable_digest.update(oid + b"\n")
    tree = git_output(git, repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    files = sum(entry.split(b"\t", 1)[0].split()[1] == b"blob" for entry in tree.split(b"\0") if entry)
    result = {"name": name, "repository": str(repo), "head": head, "refs": refs,
              "extra_origin_aliases": aliases, "object_counts": dict(counts),
              "total_objects": sum(counts.values()), "all_objects_sha256": digest.hexdigest(),
              "reachable_objects": len(reachable), "reachable_objects_sha256": reachable_digest.hexdigest(),
              "head_files": files, "head_tree_sha256": hashlib.sha256(tree).hexdigest(),
              "pack_bytes": sum(path.stat().st_size for path in repo.glob("objects/pack/*.pack")),
              "index_bytes": sum(path.stat().st_size for path in repo.glob("objects/pack/*.idx"))}
    if fsck:
        subprocess.run(git_command(git, "-C", repo, "fsck", "--full", "--no-reflogs"),
                       env=isolated_env(), check=True, stdout=subprocess.DEVNULL)
        result["fsck_full"] = "passed"
    return result


def verify(args):
    if args.output.exists():
        raise FileExistsError(args.output)
    pairs = parse_repositories(args.repo)
    names = [name for name, _ in pairs]
    if len(names) < 2 or any(not name for name in names) or len(set(names)) != len(names):
        raise ValueError("verification requires at least two repositories with distinct names")
    paths = [pathlib.Path(path).resolve(strict=True) for _, path in pairs]
    if any(path.samefile(prior) for number, path in enumerate(paths) for prior in paths[:number]):
        raise ValueError("verification requires distinct repositories, not repeated paths")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git")
    repositories = []
    for name, path in pairs:
        print(f"INVENTORY {name}: {path}", flush=True)
        item = inventory(git, name, pathlib.Path(path), args.fsck,
                         repositories[0]["refs"] if repositories else None)
        repositories.append(item)
        save(args.output, {"repositories": repositories, "parity": "incomplete"})
        print(json.dumps({key: value for key, value in item.items() if key != "refs"}), flush=True)
    checks = ["head", "refs", "object_counts", "total_objects", "all_objects_sha256",
              "reachable_objects", "reachable_objects_sha256", "head_files", "head_tree_sha256"]
    mismatches = {key: [item["name"] for item in repositories[1:] if item[key] != repositories[0][key]]
                  for key in checks}
    mismatches = {key: names for key, names in mismatches.items() if names}
    save(args.output, {"repositories": repositories, "parity": not mismatches, "mismatches": mismatches})
    if mismatches:
        raise RuntimeError(f"clone parity failed: {mismatches}")
    print("PASS: refs, HEAD tree, stored object metadata, and reachable object IDs match"
          + ("; full content integrity verified by git fsck" if args.fsck
             else "; use --fsck to verify stored content integrity"), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="action", required=True)
    bench = commands.add_parser("run")
    bench.add_argument("--gix", type=pathlib.Path, required=True)
    bench.add_argument("--output", type=pathlib.Path, required=True)
    bench.add_argument("--url", default="https://github.com/mongodb/mongo.git")
    bench.add_argument("--rounds", type=int, default=2)
    bench.add_argument("--engines", default="git,gix")
    bench.set_defaults(handler=run)
    check = commands.add_parser("verify")
    check.add_argument("--repo", action="append", required=True, help="NAME=PATH; repeat for every clone")
    check.add_argument("--output", type=pathlib.Path, required=True)
    check.add_argument("--fsck", action="store_true")
    check.set_defaults(handler=verify)
    args = parser.parse_args()
    if getattr(args, "rounds", 1) < 1:
        parser.error("rounds must be positive")
    if args.action == "verify":
        try:
            parse_repositories(args.repo)
        except ValueError as error:
            parser.error(str(error))
    args.handler(args)


if __name__ == "__main__":
    main()
