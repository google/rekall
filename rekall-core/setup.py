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
from __future__ import print_function
__author__ = "Michael Cohen <scudette@gmail.com>"
import os
import subprocess
import setuptools

from setuptools import find_packages, setup, Command

rekall_description = "Rekall Memory Forensic Framework"

current_directory = os.path.dirname(__file__)

ENV = {"__file__": __file__}
exec(open("rekall/_version.py").read(), ENV)
VERSION = ENV["get_versions"]()


def find_data_files(source):
    result = []
    for directory, _, files in os.walk(source):
        files = [os.path.join(directory, x) for x in files]
        result.append((directory, files))

    return result


# These versions are fixed to the exact tested configuration. Prior to release,
# please use "setup.py pip_upgrade" to test with the latest version. This
# approach ensures that any Rekall version will always work as tested - even
# when external packages are upgraded in an incompatible way.
install_requires = [
    'PyYAML',
    'acora==2.1',
    'arrow==0.10.0',
    'artifacts==20170909',
    'future==0.16.0',
    'intervaltree==2.1.0',
    'ipaddr==2.2.0',
    'parsedatetime==2.4',
    "psutil >= 5.0, < 6.0",
    'pyaff4 ==0.26.post6',
    'pycryptodome==3.6.6',
    'pyelftools==0.24',
    'pyparsing==2.1.5',
    'python-dateutil==2.6.1',
    'pytsk3==20170802',
    'pytz==2017.3',
    'rekall-capstone==3.0.5.post2',
    "rekall-efilter >= 1.6, < 1.7",
    'pypykatz>=0.3.5;python_version>="3.5"',

    # Should match exactly the version of this package.
    'rekall-lib',
    'rekall-yara==3.6.3.1',
]


if "VIRTUAL_ENV" not in os.environ:
    print("*****************************************************")
    print("  WARNING: You are not installing Rekall in a virtual")
    print("  environment. This configuration is not supported!!!")
    print("  Expect breakage.")
    print("*****************************************************")

if int(setuptools.__version__.split(".")[0]) < 8:
    raise RuntimeError("Rekall requires at least setuptool version 8.0. "
                       "Please upgrade with 'pip install --upgrade setuptools'")


class PIPUpgrade(Command):
    description = "Upgrade all the dependencies in the current virtualenv."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        required = [x.split()[0] for x in install_requires]
        output = subprocess.check_output(
            ["pip", "install", "--upgrade"] + required)

        # Print the current versions.
        output = subprocess.check_output(
            ["pip", "freeze"], errors="ignore")

        result = []
        for package in required:
            try:
                result.append(
                    [x for x in output.splitlines()
                     if package in x][0])
            except IndexError:
                pass

        print("\n".join(sorted(result)))


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
commands["pip_upgrade"] = PIPUpgrade
commands["clean"] = CleanCommand

setup(
    name="rekall-core",
    version=VERSION["pep440"],
    cmdclass=commands,
    description=rekall_description,
    long_description=open(os.path.join(current_directory, "README.rst")).read(),
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
    data_files=find_data_files("resources"),

    entry_points="""
    [rekall.plugins]
    plugins=rekall.plugins

    [console_scripts]
    rekal = rekall.rekal:main
    rekall = rekall.rekal:main
    """,
    install_requires=install_requires,
    extras_require={
        # The following requirements are needed in Windows.
        ':sys_platform=="win32"': [
            # Just grab the latest since it is not the same version on
            # both python2 and python3.
            "pypiwin32",
        ],
    }
)
