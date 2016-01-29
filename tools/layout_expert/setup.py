#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Arkadiusz Socała <as277575@mimuw.edu.pl>
# Michael Cohen <scudette@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

"""Installation and deployment script."""
__author__ = "Michael Cohen <scudette@gmail.com>"
import os
import versioneer

try:
    from setuptools import find_packages, setup, Command
except ImportError:
    from distutils.core import find_packages, setup

from setuptools.command.test import test as TestCommand


current_directory = os.path.dirname(__file__)
install_requires = [
    "pyparsing==2.0.7",
    "rekall-core>=1.4.1",
    "mock==1.3.0",
]


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


class NoseTestCommand(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # Run nose ensuring that argv simulates running nosetests directly
        import nose
        nose.run_exit(argv=['nosetests'])


commands = versioneer.get_cmdclass()
commands["clean"] = CleanCommand
commands["test"] = NoseTestCommand


args = dict(
    name="rekall-layout-expert",
    version=versioneer.get_version(),
    cmdclass=commands,
    description="Rekall Layout Expert",
    long_description=open(os.path.join(current_directory, "README.md")).read(),
    license="Apache",
    url="https://www.rekall-forensic.com/",
    author="The Rekall team",
    author_email="rekall-discuss@googlegroups.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
    ],
    scripts=["layout_expert/layout_tool.py"],
    package_dir={'layout_expert': 'layout_expert'},
    packages=find_packages('.'),
    include_package_data=True,
    data_files=(),
    entry_points="""
    [console_scripts]
    layout_tool = layout_tool:main
    """,
    install_requires=install_requires,
)

setup(**args)
