#!/usr/bin/env python

# Rekall
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
"""Installation and deployment script."""
__author__ = "Michael Cohen <scudette@gmail.com>"

import subprocess
import sys

try:
    from setuptools import find_packages, setup
except ImportError:
    from distutils.core import find_packages, setup

# Change PYTHONPATH to include rekall so that we can get the version.
sys.path.insert(0, '.')

from rekall import constants

rekall_description = "Rekall Memory Forensic Framework"


def run_git_describe():
    try:
        p = subprocess.Popen(
            ["git", "describe", "--tags", "--abbrev=10"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        p.stderr.close()
        return p.stdout.readlines()[0]
    except (OSError, IndexError):
        return None


def get_commits_since_tag(git_version):
    """Return the number of commits since the last git tag.

    The canonical format of git-describe is as follows:
    v$TAG-$COMMITS_SINCE_TAG-$REF

    We just want the second part, as integer.
    """
    try:
        return int(git_version.split("-")[1])
    except ValueError, IndexError:
        return None


def get_rekall_version():
    """Return the current rekall version as x.y.z or x.y.z.w.

    The first three digits are determined by the declared Rekall version in
    constants.py. Provided we are running from a git repo, and there is a tag
    for the current version, we append the number of commits since the tag.
    """
    release_version = constants.VERSION
    git_version = run_git_describe()

    # We're apparently not running in a git repo.
    if not git_version:
        return release_version

    # The release version string (like "1.3.2") should be inside the the
    # git version string (like "v1.3.2-59-5fd6fdb23") provided that it is tagged
    # properly.
    if release_version not in git_version:
        sys.stderr.write(
            "Release version %r is not the same as git tag %r." %
            (release_version, git_version))

        # Prefer the release version:
        return release_version

    # For our fourth version number, we use the number of commits since latest
    # git tag.
    commit_number = get_commits_since_tag(git_version)
    if not commit_number:
        return release_version

    return "%s.%d" % (release_version, commit_number)


setup(
    name="rekall",
    version=get_rekall_version(),
    description=rekall_description,
    long_description=open("README.rst").read(),
    license="GPL",
    url="https://www.rekall-forensic.com/",
    author="The Rekall team",
    author_email="rekall-discuss@googlegroups.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
    ],
    scripts=["rekall/rekal.py"],
    package_dir={'rekall': 'rekall'},
    packages=find_packages('.'),
    include_package_data=True,

    entry_points={
        "console_scripts": [
            "rekal = rekall.rekal:main",
            "rekall = rekall.rekal:main",
        ]
    },

    install_requires=[
        "argparse >= 0.9",
        "PyYAML >= 2.10",
        "pytz >= 2012",
        "intervaltree >= 2.0.4",
        "ipython >= 3.0.0",
        "pycrypto >= 2.3.1",
        "pyelftools >= 0.22",
        "distorm3 >= 0",
        "acora >= 1.8",
        "codegen >= 1.0",
        "Flask >= 0.10.1",
        "Flask-Sockets >= 0",
        "gevent == 1.0.2",
        "gevent-websocket >= 0.9.3",
        "PyAFF4 >= 0.13",
        "efilter == 1438631774",
    ],
)
