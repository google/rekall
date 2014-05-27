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

"""Tests for the taskmod plugins."""

from rekall import testlib


class TestPS(testlib.RekallBaseUnitTestCase):
    """Test the pslist module."""

    PARAMETERS = dict(commandline="pslist")

    def testPslist(self):
        # Compare filenames.
        self.assertListEqual(self.ExtractColumn(self.current['output'], 1, 2),
                             self.ExtractColumn(self.baseline['output'], 1, 2))

        # Compare virtual addresses.
        self.assertListEqual(self.ExtractColumn(self.current['output'], 0, 2),
                             self.ExtractColumn(self.baseline['output'], 0, 2))


class TestDLLList(testlib.RekallBaseUnitTestCase):
    """Test the dlllist module."""

    PARAMETERS = dict(commandline="dlllist")

    def ParseDllist(self, output):
        map = {}
        for section in self.SplitLines(output, seperator="***********"):
            process_name, pid  = section[1].split("pid:")
            try:
                preamble, dlllist = list(self.SplitLines(section, seperator="-----"))
                map[int(pid)] = dlllist
            except ValueError:
                map[int(pid)] = []

        return map

    def testDlllist(self):
        previous_map = self.ParseDllist(self.baseline['output'])
        current_map = self.ParseDllist(self.current['output'])

        self.assertListEqual(previous_map, current_map)
        for pid in previous_map:
            # Base address.
            self.assertListEqual(
                self.ExtractColumn(previous_map[pid], 0, 1),
                self.ExtractColumn(current_map[pid], 0, 1))

            # Path address.
            self.assertListEqual(
                self.ExtractColumn(previous_map[pid], 2, 1),
                self.ExtractColumn(current_map[pid], 2, 1))


class TestMemmap(testlib.SimpleTestCase):
    """Test the pslist module."""

    PARAMETERS = dict(commandline="memmap --pid=%(pid)s",
                      pid=2624)


class TestMemmapCoalesce(testlib.SimpleTestCase):
    """Make sure that memmaps are coalesced properly."""

    PARAMETERS = dict(commandline="memmap --pid=%(pid)s --coalesce",
                      pid=2624)
