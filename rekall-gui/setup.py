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
import os
import platform
import versioneer


try:
    from setuptools import find_packages, setup
except ImportError:
    from distutils.core import find_packages, setup

rekall_description = "Rekall Memory Forensic Framework"

def find_data_files_directory(source):
    result = []
    for directory, _, files in os.walk(source):
        files = [os.path.join(directory, x) for x in files]
        result.append((directory, files))

    return result


MY_VERSION = versioneer.get_version()
if "unknown" in MY_VERSION:
    try:
        import rekall
        MY_VERSION = rekall.__version__
    except ImportError:
        pass

install_requires = [
    "rekall-core >= 1.4.0.pre3",
    "ipython >= 3.0.0",
    "codegen >= 1.0",
    "Flask >= 0.10.1",
    "Flask-Sockets >= 0",
    "gevent >= 1.0.2",
    "gevent-websocket >= 0.9.3",
]


# IPython's setup.py is broken since it does not include this dependency on
# windows. For the other OS's this is OK.
if platform.system() == "Windows":
    install_requires.append("pyreadline >= 2.0")


setup(
    name="rekall_gui",
    version=MY_VERSION,
    cmdclass=versioneer.get_cmdclass(),
    description=rekall_description,
    long_description="This is the GUI component of the Rekall framework.",
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
    package_dir={'rekall_gui': 'rekall_gui'},
    packages=find_packages('.'),
    include_package_data=True,
    data_files=(
        find_data_files_directory('manuskript/static') +
        find_data_files_directory(
            'rekall_gui/plugins/webconsole/static')
    ),
    entry_points="""
      [rekall.plugins]
      webconsole=rekall_gui.plugins.webconsole_plugin:RekallWebConsole
    """,
    install_requires=install_requires,
)
