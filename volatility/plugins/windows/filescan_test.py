# Volatility
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

from volatility import testlib


class TestFileScanners(testlib.VolatilityBaseUnitTestCase):
    """Test the FileScan module."""

    trunk_launch_args = [#['filescan'],
                         ['driverscan'],
                         ['symlinkscan'],
                         ['mutantscan'],
                         ['psscan']]

    ng_launch_args = [#['filescan', {}],
                      ['driverscan', {}],
                      ['symlinkscan', {}],
                      ['mutantscan', {}],
                      ['psscan', {}]]

    def testDriver(self):
        previous_meta, current_meta = self.ReRunVolatilityTest('driverscan')
        previous = previous_meta['output']
        current = current_meta['output']

        # Compare the entire table
        for i in range(8):
            self.assertListEqual(
                self.ExtractColumn(current, i, 2),
                self.ExtractColumn(previous, i, 2))

    def testSymlink(self):
        previous_meta, current_meta = self.ReRunVolatilityTest('symlinkscan')
        previous = previous_meta['output']
        current = current_meta['output']

        # Compare the entire table
        for i in range(6):
            self.assertListEqual(
                self.ExtractColumn(current, i, 2),
                self.ExtractColumn(previous, i, 2))

    def testMutant(self):
        previous_meta, current_meta = self.ReRunVolatilityTest('mutantscan')
        previous = previous_meta['output']
        current = current_meta['output']

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

