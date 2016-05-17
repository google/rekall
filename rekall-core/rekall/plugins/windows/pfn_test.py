# Rekall Memory Forensics
#
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

"""Tests for the pfn plugins."""
from rekall import testlib

class TestVtoP(testlib.SimpleTestCase):
    # Create a test case by running the vadmap plugin and selecting at least one
    # virtual address from each type.
    PARAMETERS = dict(
        commandline="vtop %(pids)s --virtual_address %(vaddr)s",
        vaddr="0x00010000 0x00036000"
    )

class TestPTE(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="pte %(pte)s",
        pte="0x3286b8"
    )


class TestPFN(testlib.SimpleTestCase):
    """Test the pfn module."""

    # This is the test data in json format. Keys are _EPROCESS and values is a
    # list of private addresses.
    PARAMETERS = dict(
        commandline="pfn %(pfn)s",
        pfn=0
    )
