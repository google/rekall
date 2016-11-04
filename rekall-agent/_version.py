
# Machine Generated - do not edit!

# This file is produced when the main "version.py update" command is run. That
# command copies this file to all sub-packages which contain
# setup.py. Configuration is maintain in version.yaml at the project's top
# level.

def get_versions():
    return tag_version_data(raw_versions(), """version.yaml""")

def raw_versions():
    return json.loads("""
{
    "codename": "Gotthard", 
    "version": "1.6.0", 
    "post": "0", 
    "rc": "0"
}
""")

import json
import os
import subprocess

try:
    # We are looking for the git repo which contains this file.
    MY_DIR = os.path.dirname(os.path.abspath(__file__))
except:
    MY_DIR = None

def is_tree_dirty():
    try:
        return bool(subprocess.check_output(
            ["git", "diff", "--name-only"], stderr=subprocess.PIPE,
            cwd=MY_DIR,
        ).splitlines())
    except (OSError, subprocess.CalledProcessError):
        return False

def get_version_file_path(version_file="version.yaml"):
    try:
        return os.path.join(subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.PIPE,
            cwd=MY_DIR,
        ).strip(), version_file)
    except (OSError, subprocess.CalledProcessError):
        return None

def number_of_commit_since(version_file="version.yaml"):
    """Returns the number of commits since version.yaml was changed."""
    try:
        last_commit_to_touch_version_file = subprocess.check_output(
            ["git", "log", "--no-merges", "-n", "1", "--pretty=format:%H",
             version_file], cwd=MY_DIR, stderr=subprocess.PIPE,
        ).strip()

        all_commits = subprocess.check_output(
            ["git", "log", "--no-merges", "-n", "1000", "--pretty=format:%H"],
            stderr=subprocess.PIPE, cwd=MY_DIR,
        ).splitlines()
        return all_commits.index(last_commit_to_touch_version_file)
    except (OSError, subprocess.CalledProcessError, ValueError):
        return None


def get_current_git_hash():
    try:
        return subprocess.check_output(
            ["git", "log", "--no-merges", "-n", "1", "--pretty=format:%H"],
            stderr=subprocess.PIPE, cwd=MY_DIR,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None

def tag_version_data(version_data, version_path="version.yaml"):
    current_hash = get_current_git_hash()
    # Not in a git repository.
    if current_hash is None:
        version_data["error"] = "Not in a git repository."

    else:
        version_data["revisionid"] = current_hash
        version_data["dirty"] = is_tree_dirty()
        version_data["dev"] = number_of_commit_since(
            get_version_file_path(version_path))

    # Format the version according to pep440:
    pep440 = version_data["version"]
    if int(version_data.get("post", 0)) > 0:
        pep440 += ".post" + version_data["post"]

    elif int(version_data.get("rc", 0)) > 0:
        pep440 += ".rc" + version_data["rc"]

    if version_data.get("dev", 0):
        pep440 += ".dev" + str(version_data["dev"])

    version_data["pep440"] = pep440

    return version_data
