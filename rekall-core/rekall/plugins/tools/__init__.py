#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

__author__ = "Michael Cohen <scudette@google.com>"
# pylint: disable=unused-import
import logging
import platform

from rekall.plugins.tools import aff4acquire
from rekall.plugins.tools import caching_url_manager
from rekall.plugins.tools import disassembler
from rekall.plugins.tools import dynamic_profiles
from rekall.plugins.tools import ewf
from rekall.plugins.tools import ipython
from rekall.plugins.tools import json_tools
from rekall.plugins.tools import mspdb
from rekall.plugins.tools import profile_tool
from rekall.plugins.tools import repository_manager

try:
    from rekall.plugins.tools import webconsole_plugin
except ImportError as e:
    logging.info("Webconsole disabled: %s", e)


system = platform.system()
if system == "Linux":
    from rekall.plugins.tools import live_linux
elif system == "Windows":
    from rekall.plugins.tools import live_windows
elif system == "Darwin":
    from rekall.plugins.tools import live_darwin
