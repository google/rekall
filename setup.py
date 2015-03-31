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

import sys

try:
    from setuptools import find_packages, setup
except ImportError:
    from distutils.core import find_packages, setup

# Change PYTHONPATH to include rekall so that we can get the version.
sys.path.insert(0, '.')

from rekall import constants

rekall_description = "Rekall Memory Forensic Framework"

setup(
    name="rekall",
    version=constants.VERSION,
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
        "ipython >= 3.0.0",
        "pycrypto >= 2.3.1",
        "pyelftools >= 0.22",
        "distorm3 >= 0",
        "acora >= 1.8",
        "codegen >= 1.0",
        "Flask >= 0.10.1",
        "Flask-Sockets >= 0",
        "gevent >= 1.0.1",
        "gevent-websocket >= 0.9.3",
        "PyAFF4 >= 0.13",
        ],
)
