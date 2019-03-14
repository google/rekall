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
"""Meta-script for pulling in all Rekall components."""
from __future__ import print_function

__author__ = "Michael Cohen <scudette@gmail.com>"
import io
import os
import sys
import subprocess

from setuptools import setup
from setuptools.command.install import install as _install
from setuptools.command.develop import develop as _develop

import _version
VERSION = _version.get_versions()

rekall_description = "Rekall Memory Forensic Framework"

# This is a metapackage which pulls in the dependencies. There are two main
# installation scenarios:

# 1) We get installed from PyPi from our own sdist. In this case we need to
# declare dependencies on the released PyPi packages.

# 2) We get run from the root of the source tree (e.g. checked out from git). In
# this case we need to declare the setup.py as a dependency so it gets installed
# first.

class install(_install):
    def do_egg_install(self):
        path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "rekall-core", "setup.py"))

        if os.access(path, os.F_OK):
            print("Installing rekall-core from local directory.")

            subprocess.check_call([sys.executable, "setup.py", "install"],
                                  cwd="rekall-core")

        # Need to call this directly because _install.run does crazy stack
        # walking and falls back to compatibility mode.
        _install.do_egg_install(self)


class develop(_develop):
    def run(self):
        path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "rekall-core", "setup.py"))

        if os.access(path, os.F_OK):
            print("Installing rekall-core from local directory.")

            subprocess.check_call([sys.executable, "setup.py", "develop"],
                                  cwd="rekall-core")

        _develop.run(self)


def find_data_files(source):
    result = []
    for directory, _, files in os.walk(source):
        files = [os.path.join(directory, x) for x in files]
        result.append((directory, files))

    return result


commands = dict(
    install=install,
    develop=develop
)

# This requires an exact version to ensure that installing the meta package
# pulls in tested dependencies.
install_requires = [
    "rekall-agent >= 1.7.0rc1, < 1.8",
    "rekall-lib >= 1.7.0rc1, < 1.8",
    "rekall-core >= 1.7.0rc1, < 1.8",
    "ipython >= 5.0.0, < 7.0",
    
]

setup(
    name="rekall",
    version=VERSION["pep440"],
    cmdclass=commands,
    description=rekall_description,
    long_description=io.open("README.md", "rt", encoding='utf8').read(),
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
    install_requires=install_requires,
    extras_require={
        # The following requirements are needed in Windows.
        ':sys_platform=="win32"': [
            "pyreadline >= 2.0",
        ],
        ':sys_platform!="win32"': [
            "readline",
        ],

    },
    data_files=find_data_files("tools"),
)
