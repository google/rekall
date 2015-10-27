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
import platform
import os
import versioneer

try:
    from setuptools import find_packages, setup
except ImportError:
    from distutils.core import find_packages, setup

rekall_description = "Rekall Memory Forensic Framework"

current_directory = os.path.dirname(__file__)


def find_data_files_directory(source):
    result = []
    for directory, _, files in os.walk(source):
        files = [os.path.join(directory, x) for x in files]
        result.append((directory, files))

    return result

install_requires = [
    "argparse >= 0.9",
    "arrow == 0.6.0",
    "PyYAML >= 2.10",
    "pytz >= 2012",
    "intervaltree >= 2.0.4",
    "pycrypto >= 2.3.1",
    "pyelftools >= 0.22",
    "distorm3 >= 0",
    "acora >= 1.8",
    "sortedcontainers == 0.9.6",
    "PyAFF4 >= 0.17",
    "efilter == 1445943458",
]

if platform.system() == "Windows":
    install_requires.append("pypiwin32 >= 219")

setup(
    name="rekall-core",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
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
    include_package_data=True,
    data_files=(
        find_data_files_directory('resources')
    ),
    entry_points="""
    [rekall.plugins]
    plugins=rekall.plugins

    [console_scripts]
    rekal = rekall.rekal:main
    rekall = rekall.rekal:main
    """,

    install_requires=install_requires,
)
