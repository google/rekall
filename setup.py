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

__author__ = "Michael Cohen <scudette@gmail.com>"

import versioneer

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

rekall_description = "Rekall Memory Forensic Framework"

MY_VERSION = versioneer.get_version()

setup(
    name="rekall",
    version=MY_VERSION,
    cmdclass=versioneer.get_cmdclass(),
    description=rekall_description,
    long_description=open("README.md").read(),
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

    # This requires an exact version to ensure that installing the meta package
    # pulls in tested dependencies.
    install_requires=[
        "rekall-core >= 1.4.0.pre3",
        "rekall-gui >= 1.4.0.pre3",
    ],
)
