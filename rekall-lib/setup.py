#!/usr/bin/env python

# Rekall
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
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
__author__ = "Michael Cohen <scudette@google.com>"
import os
import sys
from setuptools import find_packages, setup, Command

ENV = {"__file__": __file__}
exec(open("rekall_lib/_version.py").read(), ENV)
VERSION = ENV["get_versions"]()

rekall_description = "Rekall Support Libraries"

def find_data_files(source):
    result = []
    for directory, _, files in os.walk(source):
        files = [os.path.join(directory, x) for x in files]
        result.append((directory, files))

    return result

install_requires = [
    "arrow==0.10.0",
    "future",
    "sortedcontainers >= 2.0, < 3.0",
]

data_files = (find_data_files("test_data") +
              find_data_files("messages"))


class CleanCommand(Command):
    description = ("custom clean command that forcefully removes "
                   "dist/build directories")
    user_options = []
    def initialize_options(self):
        self.cwd = None
    def finalize_options(self):
        self.cwd = os.getcwd()
    def run(self):
        if os.getcwd() != self.cwd:
            raise RuntimeError('Must be in package root: %s' % self.cwd)

        os.system('rm -rf ./build ./dist')

commands = {}
commands["clean"] = CleanCommand

setup(
    name="rekall_lib",
    version=VERSION["pep440"],
    cmdclass=commands,
    description=rekall_description,
    long_description="Support libraries for the Rekall framework.",
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
    package_dir={'.': 'rekall_lib'},
    packages=find_packages('.'),
    data_files=data_files,
    entry_points="""
    """,
    zip_safe=False,
    install_requires=install_requires,
    test_suite="nose2.collector.collector",
)
