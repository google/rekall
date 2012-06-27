#/usr/bin/env python

# Volatility
# 
# Authors:
# AAron Walters <awalters@volatilesystems.com>
# Mike Auty <mike.auty@gmail.com>
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

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import volatility.constants
import sys
import os

opts = {}

opts['name'] = "volatility"
opts['version'] = volatility.constants.VERSION
opts['description'] = "Volatility -- Volatile memory framwork"
opts['author'] = "The volatility team"
opts['author_email'] = "vol-dev@volatilesystems.com"
opts['url'] = "http://www.volatilesystems.com"
opts['license'] = "GPL"
opts['scripts'] = ["vol.py"]
opts['packages'] = ["volatility",
                    "volatility.plugins",
                    "volatility.plugins.addrspaces",
                    "volatility.plugins.linux",
                    "volatility.plugins.overlays",
                    "volatility.plugins.overlays.linux",
                    "volatility.plugins.overlays.windows",
                    "volatility.plugins.windows",
                    "volatility.plugins.windows.malware",
                    "volatility.plugins.windows.registry",
                    ]

distrib = setup(**opts)
