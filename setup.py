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

__author__ = "Michael Cohen <scudette@gmail.com>"

try:
    from setuptools import find_packages, setup
except ImportError:
    from distutils.core import find_packages, setup

from rekall import constants

setup(name="rekall",
      version=constants.VERSION,
      description="Rekall Memory Forensic Framework",
      author="The Rekall team",
      author_email="rekall-discuss@googlegroups.com",
      url="https://code.google.com/p/rekall/",
      license="GPL",
      scripts=["rekall/rekal.py"],
      packages=find_packages('.'),
      package_dir={'rekall': 'rekall'},
      package_data={
        'rekall': ['profiles/*.zip']
        },

      entry_points={
        "console_scripts": [
            "rekal = rekall.rekal:main"
            ]
        }
      )

