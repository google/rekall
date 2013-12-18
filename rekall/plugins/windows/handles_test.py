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

"""Tests for the handles plugins."""

from rekall import testlib


class TestHandles(testlib.RekallBaseUnitTestCase):
    """Test the Handler module."""

    PARAMETERS = dict(commandline="handles --pid 1484")

    def testHandle(self):
        """Test the modules plugin."""
        previous = self.baseline['output']
        current = self.current['output']

        # Compare virtual addresses.
        self.assertIntegerListEqual(
            sorted(self.ExtractColumn(current, 0, 2)),
            sorted(self.ExtractColumn(previous, 0, 2)))

        # Compare Handle.
        self.assertListEqual(
            sorted(self.ExtractColumn(previous, 2, 2)),
            sorted(self.ExtractColumn(current, 2, 2)))

        # Compare Type
        self.assertListEqual(
            sorted(self.ExtractColumn(previous, 4, 2)),
            sorted(self.ExtractColumn(current, 4, 2)))

        # Compare details.
        self.assertListEqual(
            sorted(self.ExtractColumn(previous, 5, 2)),
            sorted(self.ExtractColumn(current, 5, 2)))
