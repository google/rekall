#!/usr/bin/python

"""Global version file.

This program is used to manage versions. Prior to each release, please run it
with update.
"""

import argparse
import json
import os
import yaml

_VERSION_CODE = '''
import json
import os
import subprocess

try:
    # We are looking for the git repo which contains this file.
    MY_DIR = os.path.dirname(__file__)
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
'''

ENV = {"__file__": __file__}
exec _VERSION_CODE in ENV
is_tree_dirty = ENV["is_tree_dirty"]
number_of_commit_since = ENV["number_of_commit_since"]
get_current_git_hash = ENV["get_current_git_hash"]
tag_version_data = ENV["tag_version_data"]


_VERSION_TEMPLATE = """
# Machine Generated - do not edit!

# This file is produced when the main "version.py update" command is run. That
# command copies this file to all sub-packages which contain
# setup.py. Configuration is maintain in version.yaml at the project's top
# level.

def get_versions():
    return tag_version_data(raw_versions(), \"\"\"%s\"\"\")

def raw_versions():
    return json.loads(\"\"\"
%s
\"\"\")
"""

def get_config_file(version_file="version.yaml"):
    version_path = os.path.join(os.path.dirname(__file__), version_file)

    return yaml.load(open(version_path).read()), version_path


def get_versions(version_file="version.yaml"):
    result, version_path = get_config_file(version_file)
    version_data = result["version_data"]

    return tag_version_data(version_data), version_path

def escape_string(instr):
    return instr.replace('"""', r'\"\"\"')


def update(args):
    if (args.version is None and
            args.post is None and
            args.rc is None and
            args.codename is None):
        raise AttributeError("You must set something in this release.")

    data, version_path = get_config_file(args.version_file)
    version_data = data["version_data"]
    if args.version:
        version_data["version"] = args.version

    if args.post:
        version_data["post"] = args.post

    if args.rc:
        version_data["rc"] = args.rc

    if args.codename:
        version_data["codename"] = args.codename

    # Write the updated version_data into the file.
    with open(version_path, "wb") as fd:
        fd.write(yaml.safe_dump(data, default_flow_style=False))

    # Should not happen but just in case...
    contents = _VERSION_TEMPLATE % (
        escape_string(args.version_file),
        escape_string(json.dumps(version_data, indent=4))) + _VERSION_CODE

    # Now copy the static version files to all locations.
    for path in data["dependent_versions"]:
        current_dir = os.path.abspath(os.path.dirname(__file__))
        version_path = os.path.abspath(os.path.join(current_dir, path))
        if not os.path.relpath(version_path, current_dir):
            raise TypeError("Dependent version path is outside tree.")

        with open(version_path, "wb") as fd:
            fd.write(contents)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--version_file", default="version.yaml",
        help="Version configuration file.")

    subparsers = parser.add_subparsers(help='sub-command help', dest='command')
    update_parser = subparsers.add_parser("update", help="Update the version")

    update_parser.add_argument(
        "--version", help="Set to this new version.")

    update_parser.add_argument(
        "--post", help="Set to this new post release.")

    update_parser.add_argument(
        "--rc", help="Set to this new release candidate.")

    update_parser.add_argument(
        "--codename", help="Set to this new codename.")


    subparsers.add_parser("version", help="Report the current version.")

    args = parser.parse_args()
    if args.command == "update":
        update(args)

    elif args.command == "version":
        version_data, version_path = get_versions(args.version_file)
        print "Scanning %s:\n%s" % (version_path, version_data)


if __name__ == "__main__":
    main()
