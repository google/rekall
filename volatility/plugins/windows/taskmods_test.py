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

"""Tests for the taskmod plugins."""

from volatility import testlib


class TestPS(testlib.VolatilityBaseUnitTestCase):
    """Test the pslist module."""

    trunk_launch_args = [['pslist'],
                         ['dlllist'],
                         ['memmap', "--pid", "2624"]]

    ng_launch_args = [['pslist', {}],
                      ['dlllist', {}],
                      ['memmap', dict(pid=2624)]]

    def testPslist(self):
        previous, current = self.ReRunVolatilityTest('pslist')

        # Comparing against trunk we need to remap the columns a bit.
        if previous['mode'] == 'trunk':
            filenames = self.ExtractColumn(previous['output'], 1, 2)
        else:
            filenames = self.ExtractColumn(previous['output'], 2, 2)

        # Compare filenames.
        self.assertListEqual(self.ExtractColumn(current['output'], 2, 2, " +"),
                             filenames)

        # Compare virtual addresses.
        self.assertListEqual(self.ExtractColumn(current['output'], 0, 2, " +"),
                             self.ExtractColumn(previous['output'], 0, 2))

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
        previous, current = self.ReRunVolatilityTest('dlllist')
        previous_map = self.ParseDllist(previous['output'])
        current_map = self.ParseDllist(current['output'])

        self.assertListEqual(previous_map, current_map)
        for pid in previous_map:
            # Base address.
            self.assertListEqual(
                self.ExtractColumn(previous_map[pid], 0, 1),
                self.ExtractColumn(current_map[pid], 0, 1, " +"))

            # Path address.
            self.assertListEqual(
                self.ExtractColumn(previous_map[pid], 2, 1),
                self.ExtractColumn(current_map[pid], 2, 1, "0 +"))

    def testMemmap(self):
        previous, current = self.ReRunVolatilityTest('memmap', pid=2624)

        # Virtual address - Hex formatting might be different so convert it from
        # hex and compare the ints themselves.
        self.assertIntegerListEqual(
            self.ExtractColumn(previous['output'], 0, 3),
            self.ExtractColumn(current['output'], 0, 3, " +"))

        # Physical address.
        self.assertIntegerListEqual(
            self.ExtractColumn(previous['output'], 1, 3),
            self.ExtractColumn(current['output'], 1, 3, " +"))
