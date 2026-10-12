#!/usr/bin/env python3
"""Reject an existing GitHub release whose recorded commit differs from this build."""
import json
import os
import urllib.error
import urllib.request


def check_release_target(repository, tag, commit, token):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/releases/tags/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "User-Agent": "kingfisher-release"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            release = json.load(response)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return
        raise
    if release["target_commitish"] != commit:
        raise ValueError(f"Existing release {tag} does not record build commit {commit}")


if __name__ == "__main__":
    check_release_target(os.environ["GITHUB_REPOSITORY"], os.environ["RELEASE_TAG"],
                         os.environ["GITHUB_SHA"], os.environ["GH_TOKEN"])
