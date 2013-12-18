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

"""Tests for the FileScan plugins."""

from rekall import testlib


class TestDriverScan(testlib.RekallBaseUnitTestCase):
    PARAMETERS = dict(commandline="driverscan")

    def testDriver(self):
        previous = self.baseline['output']
        current = self.current['output']

        # Compare the entire table
        for i in range(8):
            self.assertListEqual(
                self.ExtractColumn(current, i, 2),
                self.ExtractColumn(previous, i, 2))


class TestPSScan(testlib.RekallBaseUnitTestCase):

    PARAMETERS = dict(commandline="psscan")

    def testPsScan(self):
        previous = self.baseline['output']
        current = self.current['output']

        # Compare the entire table
        for i in range(10):
            self.assertListEqual(
                self.ExtractColumn(current, i, 2),
                self.ExtractColumn(previous, i, 2))


class TestSymlinkScan(testlib.RekallBaseUnitTestCase):

    PARAMETERS = dict(commandline="symlinkscan")

    def testSymlink(self):
        previous = self.baseline['output']
        current = self.current['output']

        # Compare the entire table
        for i in range(6):
            self.assertListEqual(
                self.ExtractColumn(current, i, 2),
                self.ExtractColumn(previous, i, 2))


class TestMutantScan(testlib.RekallBaseUnitTestCase):

    PARAMETERS = dict(commandline="mutantscan")

    def testMutant(self):
        previous = self.baseline['output']
        current = self.current['output']

        # Compare the entire table
        for i in range(6):
            self.assertListEqual(
                self.ExtractColumn(current, i, 2),
                self.ExtractColumn(previous, i, 2))

        # Compare the name (We replace and empty entry with -)
        names = [ "-" if not n else n for n in self.ExtractColumn(previous, 7, 2)]
        self.assertListEqual(
            names,
            self.ExtractColumn(current, 7, 2))

