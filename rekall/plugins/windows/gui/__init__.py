# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""These plugins implement analysis of the win32k graphic subsystem.

This work stemmed from the seminal work:

Kernel Attacks through user mode callbacks Tarjei Mandt.

http://mista.nu/blog/2011/08/11/windows-hooks-of-death-kernel-attacks-through-user-mode-callbacks/

Other interesting references:
http://volatility-labs.blogspot.de/2012/09/movp-13-desktops-heaps-and-ransomware.html
"""
# pylint: disable=unused-import

from rekall.plugins.windows.gui import atoms
from rekall.plugins.windows.gui import autodetect
#from rekall.plugins.windows.gui import clipboard
from rekall.plugins.windows.gui import windowstations
from rekall.plugins.windows.gui import sessions
from rekall.plugins.windows.gui import userhandles
